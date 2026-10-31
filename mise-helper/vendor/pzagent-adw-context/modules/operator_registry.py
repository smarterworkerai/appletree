"""Read release descriptors without downloading layers or consulting CI history."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.request import Request, urlopen

from .common import ContractError
from .oras_registry import OrasRegistry, access_denied
from .release_manifest import DIGEST_REF, release_kind, validate


def oras(*args: str, binary: bool = False):
    config = os.environ.get('DOCKER_CONFIG')
    command = ['oras', *args]
    if config:
        command += ['--registry-config', str(Path(config) / 'config.json')]
    try:
        result = subprocess.run(command, capture_output=True, text=not binary)
    except OSError as exc:
        raise ContractError('ORAS is unavailable; install the pinned mise tools') from exc
    if result.returncode:
        if access_denied(getattr(result, 'stderr', None)):
            raise ContractError('registry_access_denied')
        raise ContractError('registry operation failed; check registry access and selected reference')
    return result.stdout


@contextmanager
def authentication(values: dict[str, str]):
    token = values.get('REGISTRY_TOKEN') or values.get('GITHUB_TOKEN') or values.get('GH_TOKEN')
    if not token:
        # Preserve existing explicit Docker/ORAS authentication.
        yield
        return
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        # The workflow token is an installation token: it is valid for GHCR but
        # cannot identify itself through the user endpoint. GitHub provides the
        # matching login identity as an immutable default environment variable.
        username = os.environ.get('GITHUB_ACTOR', '')
        if not username:
            raise ContractError('cannot resolve registry credential identity')
    else:
        try:
            request = Request('https://api.github.com/user', headers={
                'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
            })
            with urlopen(request, timeout=20) as response:
                username = json.load(response).get('login')
            if not isinstance(username, str) or not username:
                raise ValueError('missing identity')
        except Exception as exc:
            raise ContractError('cannot resolve registry credential identity') from exc
    with tempfile.TemporaryDirectory(prefix='pz-registry-') as directory:
        path = Path(directory) / 'config.json'
        try:
            result = subprocess.run(['oras', 'login', 'ghcr.io', '--username', username,
                                     '--password-stdin', '--registry-config', str(path)],
                                    input=token, text=True, capture_output=True)
        except OSError as exc:
            raise ContractError('ORAS is unavailable; install the pinned mise tools') from exc
        if result.returncode:
            if access_denied(getattr(result, 'stderr', None)):
                raise ContractError('registry_access_denied')
            raise ContractError('registry login failed')
        path.chmod(0o600)
        previous = os.environ.get('DOCKER_CONFIG')
        os.environ['DOCKER_CONFIG'] = directory
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop('DOCKER_CONFIG', None)
            else:
                os.environ['DOCKER_CONFIG'] = previous


def read_manifest(reference: str) -> dict:
    match = DIGEST_REF.fullmatch(reference)
    if not match:
        raise ContractError('release reference must be immutable')
    try:
        raw = oras('manifest', 'fetch', reference, binary=True)
        if hashlib.sha256(raw).hexdigest() != match['digest']:
            raise ContractError('registry manifest digest differs')
        descriptor = json.loads(raw)
        layers = descriptor.get('layers', [])
        candidates = [item for item in layers if item.get('annotations', {}).get('org.opencontainers.image.title') == 'manifest.json']
        if len(candidates) != 1:
            raise ContractError('release artifact must contain exactly one manifest.json')
        layer = candidates[0]
        if not isinstance(layer.get('size'), int) or not 0 < layer['size'] <= 1048576:
            raise ContractError('release document size is invalid')
        blob = oras('blob', 'fetch', '--output', '-', match['repo'] + '@' + layer['digest'], binary=True)
        if len(blob) != layer['size'] or 'sha256:' + hashlib.sha256(blob).hexdigest() != layer['digest']:
            raise ContractError('release document digest differs')
        return json.loads(blob)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ContractError('registry release document is malformed') from exc


def inspect(adapter: dict, kind_name: str, *, source_sha: str | None = None,
            release_reference: str | None = None) -> dict:
    kind = release_kind(adapter, kind_name)
    if (source_sha is None) == (release_reference is None):
        raise ContractError('select exactly one source or release reference')
    if release_reference:
        match = DIGEST_REF.fullmatch(release_reference)
        if not match or match['repo'] != kind['manifest_package']:
            raise ContractError('release reference does not belong to the selected kind')
    reference = release_reference or kind['manifest_package'] + ':sha-' + source_sha[:12]
    registry = OrasRegistry()
    digest = registry.resolve(reference)
    if digest is None:
        return {'status': 'ok', 'available': False, 'kind': kind_name, 'source_sha': source_sha,
                'missing': ['release-manifest'], 'release_reference': None}
    immutable = kind['manifest_package'] + '@' + digest
    manifest = validate(read_manifest(immutable), adapter, kind_name)
    if source_sha is not None and manifest['source_sha'] != source_sha:
        raise ContractError('immutable source tag collides with the selected full SHA')
    missing = []
    for component, image in manifest['images'].items():
        observed = registry.resolve(image)
        if observed is None:
            missing.append(component)
        elif observed != image.split('@', 1)[1]:
            raise ContractError('component descriptor identity differs')
    return {'status': 'ok', 'available': not missing, 'kind': kind_name,
            'source_sha': manifest['source_sha'], 'release_reference': immutable,
            'manifest': manifest, 'missing': missing}

"""Provider-neutral hook image contract and routed HTTP observations."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import urlsplit

if __package__ in {None, ''}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = 'modules'

from .common import project_dir, ensure_contained, ContractError
from .hooks import HookFailure
from .http_probe import ProbeError, fetch
from .release_manifest import DIGEST_REF, image_variables


def blocked(reason: str) -> None:
    raise HookFailure('blocked', reason, reason)


def http_probe(binding: dict, operation: str) -> bool:
    probes = binding.get('probes')
    if probes is None:
        return False
    base = os.environ.get(probes['base_url_env'], '')
    parts = urlsplit(base)
    if (parts.scheme not in {'http', 'https'} or not parts.hostname or parts.username
            or parts.password or parts.query or parts.fragment or parts.path not in {'', '/'}):
        blocked('runtime-probe-base-url-invalid')
    reason = 'runtime-' + operation + '-endpoint-failed'
    try:
        response = fetch(base.rstrip('/') + probes[operation + '_path'])
        if not 200 <= response.status < 300:
            blocked(reason)
    except ProbeError:
        blocked(reason)
    return True


def _kind(repo: Path, adapter: dict, environment: str, keys: set[str] | None) -> dict:
    config = json.loads((project_dir(repo) / 'pz-release.json').read_text())
    names = [name for name, environments in config['kind_environments'].items()
             if environment in environments]
    kinds = [adapter['release_kinds'][name] for name in names
             if keys is None or set(image_variables(adapter['release_kinds'][name])) == keys]
    if not kinds:
        blocked('runtime-proof-image-set-differs')
    if len(kinds) > 1:
        blocked('runtime-release-kind-ambiguous')
    return kinds[0]


def _images(kind: dict, values: Any, *, temporary: bool) -> dict[str, str]:
    mapping = image_variables(kind)
    if not isinstance(values, list) or len(values) != len(mapping):
        blocked('runtime-proof-image-set-differs')
    result: dict[str, str] = {}
    for assignment in values:
        if not isinstance(assignment, str) or '=' not in assignment:
            blocked('runtime-proof-image-assignment-is-malformed')
        key, image = assignment.split('=', 1)
        if key not in mapping or key in result:
            blocked('runtime-proof-image-keys-differ')
        package = kind['components'][mapping[key]]['package']
        match = DIGEST_REF.fullmatch(image)
        if not (match and match['repo'] == package):
            if not temporary or not re.fullmatch(re.escape(package) + r':hotfix-[0-9a-f]{12}(?:-[0-9a-f]{12})?', image):
                blocked('runtime-proof-image-identity-differs')
        result[key] = image
    if set(result) != set(mapping):
        blocked('runtime-proof-image-keys-differ')
    return result


def build_hotfix(repo: Path, adapter: dict, environment: str, source_sha: str,
                 tag: str | None = None) -> list[str]:
    """Build the exact Git source's declared recipes without operator inputs."""
    import subprocess
    import tempfile
    from .operator_publish import source_snapshot
    from .operator_credentials import clean_environment
    kind = _kind(repo, adapter, environment, None)
    selected = image_variables(kind)
    tag = tag or 'hotfix-' + source_sha[:12]
    if not re.fullmatch('hotfix-' + source_sha[:12] + r'(?:-[0-9a-f]{12})?', tag):
        blocked('hotfix-image-tag-invalid')
    try:
        config = json.loads((project_dir(repo) / 'pz-release.json').read_bytes())
        platform = config['platforms']
        if not isinstance(platform, list) or len(platform) != 1 or not re.fullmatch(r'linux/(?:amd64|arm64)', platform[0]):
            raise ValueError()
        result = []
        with tempfile.TemporaryDirectory(prefix='pz-hotfix-source-') as raw:
            source = Path(raw) / 'source'
            source_snapshot(repo, source_sha, 'origin', source)
            for variable, component in sorted(selected.items()):
                recipe = config['components'][component]
                context = source if recipe['context'] == '.' else ensure_contained(source, recipe['context'])
                dockerfile = ensure_contained(source, recipe['dockerfile'])
                image = kind['components'][component]['package'] + ':' + tag
                environment_values = clean_environment()
                for key in ('SSH_AUTH_SOCK', 'DOCKER_CONFIG', 'DOCKER_AUTH_CONFIG', 'REGISTRY_AUTH_FILE', 'ORAS_CONFIG'):
                    environment_values.pop(key, None)
                built = subprocess.run(['docker', 'build', '--platform', platform[0],
                    '--label', 'org.opencontainers.image.revision=' + source_sha,
                    '--label', 'org.opencontainers.image.source=https://github.com/' + adapter['repository']['id'],
                    '-t', image, '-f', str(dockerfile), str(context)], env=environment_values,
                    capture_output=True, timeout=300)
                if built.returncode:
                    blocked('hotfix-image-build-failed')
                result.append(variable + '=' + image)
        return result
    except (OSError, ValueError, KeyError, TypeError, ContractError, subprocess.TimeoutExpired):
        blocked('hotfix-image-build-unavailable')



def dispatch(repo: Path, adapter: dict, operation: str, request: dict) -> dict:
    """Select a registered provider's default hook using the exact active target."""
    from .common import FULL_SHA
    if operation == 'describe':
        if (set(request) != {'schema_version', 'capability', 'operation', 'source_sha'}
                or request.get('schema_version') != '1.0.0' or request.get('capability') != 'adw:describe'
                or request.get('operation') != operation or not isinstance(request.get('source_sha'), str)
                or not FULL_SHA.fullmatch(request['source_sha'])):
            blocked('project-hook-request-invalid')
        return {'profile': 'project-adapter'}
    environment, target = request.get('environment'), request.get('target')
    group = adapter['targets'].get(environment) if isinstance(environment, str) else None
    selected = group['items'].get(target) if group and isinstance(target, str) else None
    if not selected or selected['mode'] != 'active':
        blocked('runtime-proof-target-differs')
    # Explicit closed dispatch: no project-controlled import or executable.
    if selected['provider'] == 'dokploy':
        from .providers.dokploy_hooks import dispatch as provider_dispatch
    elif selected['provider'] == 'kubernetes':
        from .providers.kubernetes_hooks import dispatch as provider_dispatch
    else:
        blocked('provider-unsupported')
    return provider_dispatch(repo, adapter, operation, request)


def main(argv: list[str]) -> int:
    from .adapter import load
    try:
        if len(argv) != 1:
            blocked('project-hook-request-invalid')
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            blocked('project-hook-request-invalid')
        repo = Path.cwd()
        result = dispatch(repo, load(project_dir(repo) / 'pzagent-adapter.json'), argv[0], request)
        response = {'schema_version': '1.0.0', 'status': 'ok', 'result': result}
    except HookFailure as exc:
        response = {'schema_version': '1.0.0', 'status': exc.status, 'reason_code': exc.reason_code}
    except (ContractError, OSError, ValueError, KeyError, TypeError):
        response = {'schema_version': '1.0.0', 'status': 'blocked', 'reason_code': 'provider-hook-request-invalid'}
    print(json.dumps(response, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))

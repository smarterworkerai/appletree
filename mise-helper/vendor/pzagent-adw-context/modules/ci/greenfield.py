"""Released, operator-only admission for a default branch without an ADW root.

No PR module or Mise configuration is executed here. A private process context
holds one immutable admission; neither CI output nor a serialized receipt can
create it. The normal controller path remains outside this admission.

The fixed greenfield sandbox repository alone may anchor an unreleased provider
candidate instead of a published release, so a release can be proven before
its tag exists. Every other repository refuses a candidate runtime.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

from .github_api import ApiError, GitHub, project_files
from .quality_proof import ProofError
from . import release_signature
from ..common import PROJECT_DIRECTORIES

PROVIDER = 'smarterworkerai/pzagent-adw-context'
GENERIC = 'smarterworkerai/agentic-delivery'
SANDBOX = 'smarterworkerai/pzagent-greenfield-sandbox'
SANDBOX_ID = 1430780300  # A deleted and recreated repository with the same name differs.
PROVIDER_ROOT = 'skills/pzagent/pzagent-adw-context/assets/mise/v2/'
GENERIC_ROOT = 'skills/adw/adw-core/assets/mise/v2/'
VENDOR = 'mise-helper/vendor/pzagent-adw-context/'
GENERIC_VENDOR = 'mise-helper/vendor/agentic-delivery/'
CONTROLLER = '.github/workflows/trust-root-bootstrap.yml'
WORKFLOWS = ('ci.yml', 'trust-root-bootstrap.yml', 'publish-release.yml', 'cleanup-retention.yml')
SHA = re.compile(r'[0-9a-f]{40}')
VERSION = re.compile(r'\d+\.\d+\.\d+')
MAX_DOWNLOAD = 8 * 1024 * 1024
MAX_UNPACKED = 64 * 1024 * 1024
_CURRENT = ContextVar('pz_greenfield_admission', default=None)


def require(value, reason):
    if not value:
        raise ProofError(reason)


def safe_path(value):
    return (isinstance(value, str) and value and not value.startswith('/') and '\\' not in value
            and all(part not in ('', '.', '..') for part in value.split('/'))
            and str(PurePosixPath(value)) == value)


def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def fetch(repository, path, *, binary=False):
    """Fixed read-only release origins. No PR-selected repository, URL or command."""
    require(repository in (PROVIDER, GENERIC), 'greenfield_release_repository_invalid')
    allowed = (r'releases/tags/v\d+\.\d+\.\d+', r'commits/v\d+\.\d+\.\d+',
               r'releases/assets/[1-9][0-9]*', r'git/commits/[0-9a-f]{40}',
               r'git/trees/[0-9a-f]{40}\?recursive=1',
               r'contents/releases/adw-mise-v2\.json\?ref=[0-9a-f]{40}')
    require(any(re.fullmatch(pattern, path) for pattern in allowed), 'greenfield_release_path_invalid')
    require(binary == bool(re.fullmatch(r'releases/assets/[1-9][0-9]*', path)), 'greenfield_release_encoding_invalid')
    accept = 'application/octet-stream' if binary else 'application/vnd.github+json'
    try:
        result = subprocess.run(['gh', 'api', '--method', 'GET', '-H', 'Accept: ' + accept,
                                 f'repos/{repository}/{path}'], capture_output=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ProofError('greenfield_release_lookup_failed') from None
    require(result.returncode == 0, 'greenfield_release_lookup_failed')
    require(len(result.stdout) <= MAX_DOWNLOAD, 'greenfield_release_response_too_large')
    if binary:
        return result.stdout
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeDecodeError):
        raise ProofError('greenfield_release_response_invalid') from None


def archive_files(payload):
    """Read regular files without extraction; bound both compressed and expanded data."""
    require(isinstance(payload, bytes) and len(payload) <= MAX_DOWNLOAD, 'greenfield_archive_too_large')
    files, modes, names, total = {}, {}, set(), 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive:
            for member in archive:
                name = member.name.rstrip('/') if member.isdir() else member.name
                require(safe_path(name) and name not in names, 'greenfield_archive_path_invalid')
                names.add(name)
                require(len(names) <= 4096, 'greenfield_archive_too_large')
                require(member.isdir() or member.isfile(), 'greenfield_archive_type_invalid')
                if member.isdir():
                    continue
                require(0 <= member.size <= MAX_DOWNLOAD, 'greenfield_archive_too_large')
                total += member.size
                require(total <= MAX_UNPACKED, 'greenfield_archive_too_large')
                stream = archive.extractfile(member)
                require(stream is not None, 'greenfield_archive_invalid')
                data = stream.read(MAX_DOWNLOAD + 1)
                require(len(data) == member.size, 'greenfield_archive_invalid')
                files[name] = data
                modes[name] = '100755' if member.mode & 0o111 else '100644'
    except (tarfile.TarError, OSError, EOFError):
        raise ProofError('greenfield_archive_invalid') from None
    return files, modes


def tree(api, sha):
    require(isinstance(sha, str) and SHA.fullmatch(sha), 'greenfield_source_invalid')
    try:
        commit = api.get('git/commits/' + sha)
        tree_sha = commit['tree']['sha']
        require(isinstance(tree_sha, str) and SHA.fullmatch(tree_sha), 'greenfield_tree_invalid')
        value = api.get('git/trees/' + tree_sha + '?recursive=1')
        return tree_entries(value)
    except (ApiError, KeyError, TypeError):
        raise ProofError('greenfield_tree_lookup_failed') from None


def tree_entries(value):
    require(isinstance(value, dict) and value.get('truncated') is False
            and isinstance(value.get('tree'), list) and len(value['tree']) <= 10000, 'greenfield_tree_invalid')
    result = {}
    for entry in value['tree']:
        require(isinstance(entry, dict) and safe_path(entry.get('path'))
                and entry['path'] not in result and entry.get('type') in ('tree', 'blob', 'commit')
                and isinstance(entry.get('sha'), str) and SHA.fullmatch(entry['sha']), 'greenfield_tree_invalid')
        result[entry['path']] = entry
    return result


def default_snapshot(api):
    """No checkout, cached ref, absent workflow listing or API error proves absence."""
    try:
        metadata = api.get('')
        branch = metadata['default_branch']
        require(metadata.get('full_name') == api.repository and isinstance(branch, str)
                and re.fullmatch(r'[A-Za-z0-9._/-]+', branch)
                and all(p not in ('', '.', '..') for p in branch.split('/')), 'greenfield_default_invalid')
        sha = api.get('git/ref/heads/' + branch)['object']['sha']
        entries = tree(api, sha)
    except (ApiError, KeyError, TypeError):
        raise ProofError('greenfield_default_lookup_failed') from None
    return {'branch': branch, 'sha': sha, 'absent': absent_root(entries)}


def absent_root(entries):
    from .provenance import TRUSTED_PATHS
    return not any(path in TRUSTED_PATHS or path == 'mise-helper/vendor'
                   or path.startswith('mise-helper/vendor/')
                   or any(path == directory or path.startswith(directory + '/') for directory in PROJECT_DIRECTORIES)
                   for path in entries)


@dataclass(frozen=True)
class Release:
    repository: str
    version: str
    source_sha: str
    snapshot_sha: str
    archive_sha256: str
    files: dict
    modes: dict
    candidate: bool = False


def released(repository, version):
    require(repository in (PROVIDER, GENERIC) and isinstance(version, str)
            and VERSION.fullmatch(version), 'greenfield_release_version_invalid')
    tag = 'v' + version
    release = fetch(repository, 'releases/tags/' + tag)
    require(isinstance(release, dict) and release.get('tag_name') == tag
            and release.get('draft') is False and release.get('prerelease') is False
            and isinstance(release.get('published_at'), str), 'greenfield_release_unpublished')
    commit = fetch(repository, 'commits/' + tag)
    require(isinstance(commit, dict) and isinstance(commit.get('sha'), str)
            and SHA.fullmatch(commit['sha']), 'greenfield_release_commit_invalid')
    source = commit['sha']
    name = ('pzagent-adw-context-skill-' if repository == PROVIDER else 'agentic-delivery-skills-') + version + '.tar.gz'
    launcher = repository == PROVIDER and tuple(int(part) for part in version.split('.')) >= (0, 15, 2)
    artifacts = (name, 'pzagent-greenfield') if launcher else (name,)
    assets = release.get('assets')
    expected = {*artifacts, 'SHA256SUMS'}
    # A signed provider release (#181) adds its self-authenticating statement and signature,
    # outside SHA256SUMS; the greenfield decision neither needs nor trusts them.
    signed = expected | {release_signature.STATEMENT_ASSET, release_signature.SIGNATURE_ASSET}
    require(isinstance(assets, list)
            and all(isinstance(a, dict) and isinstance(a.get('name'), str) for a in assets)
            and len({a['name'] for a in assets}) == len(assets)
            and ({a['name'] for a in assets} == expected
                 or (launcher and {a['name'] for a in assets} == signed)), 'greenfield_release_assets_invalid')
    payloads = {}
    for wanted in (*artifacts, 'SHA256SUMS'):
        matches = [a for a in assets if isinstance(a, dict) and a.get('name') == wanted]
        require(len(matches) == 1, 'greenfield_release_assets_invalid')
        asset = matches[0]
        require(type(asset.get('id')) is int and asset['id'] > 0 and type(asset.get('size')) is int
                and 0 < asset['size'] <= (4096 if wanted == 'SHA256SUMS' else MAX_DOWNLOAD), 'greenfield_release_assets_invalid')
        payload = fetch(repository, 'releases/assets/' + str(asset['id']), binary=True)
        require(isinstance(payload, bytes) and len(payload) == asset['size'], 'greenfield_release_asset_size')
        payloads[wanted] = payload
    try:
        rows = payloads['SHA256SUMS'].decode('ascii').splitlines()
    except UnicodeDecodeError:
        raise ProofError('greenfield_release_checksum_invalid') from None
    checksums = {}
    for row in rows:
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', row)
        require(match and match[2] in artifacts and match[2] not in checksums, 'greenfield_release_checksum_invalid')
        checksums[match[2]] = match[1]
    require(set(checksums) == set(artifacts), 'greenfield_release_checksum_invalid')
    require(all(hashlib.sha256(payloads[path]).hexdigest() == checksums[path] for path in artifacts),
            'greenfield_release_checksum_mismatch')
    checksum = checksums[name]
    all_files, all_modes = archive_files(payloads[name])
    prefix = PROVIDER_ROOT if repository == PROVIDER else GENERIC_ROOT
    files = {p[len(prefix):]: data for p, data in all_files.items() if p.startswith(prefix)}
    modes = {p[len(prefix):]: mode for p, mode in all_modes.items() if p.startswith(prefix)}
    require(files, 'greenfield_release_runtime_missing')
    snapshot = source
    if repository == PROVIDER:
        bundle_inventory(files, version)
    else:
        record = fetch(repository, 'contents/releases/adw-mise-v2.json?ref=' + source)
        try:
            require(record.get('encoding') == 'base64' and record.get('type') == 'file', 'greenfield_generic_index_invalid')
            raw = base64.b64decode(''.join(record['content'].split()), validate=True)
            require(len(raw) <= 65536 and blob(raw) == record['sha'], 'greenfield_generic_index_invalid')
            index = json.loads(raw)
            matches = [item for item in index['releases'] if item.get('version') == version]
            require(index.get('schema_version') == '1.0.0' and len(matches) == 1, 'greenfield_generic_index_invalid')
            item = matches[0]
            snapshot = item['ref']
            require(isinstance(snapshot, str) and SHA.fullmatch(snapshot)
                    and item.get('snapshot_path') == GENERIC_ROOT.rstrip('/')
                    and item.get('checksum') == 'sha256:' + hashlib.sha256(files['tasks.toml']).hexdigest(), 'greenfield_generic_index_invalid')
        except ProofError:
            raise
        except (ValueError, KeyError, TypeError):
            raise ProofError('greenfield_generic_index_invalid') from None
    # The checksummed assets must themselves match the exact published Git snapshot.
    source_commit = fetch(repository, 'git/commits/' + snapshot)
    try:
        snapshot_tree = fetch(repository, 'git/trees/' + source_commit['tree']['sha'] + '?recursive=1')
        entries = tree_entries(snapshot_tree)
        compare_files(entries, prefix, files, modes)
        if launcher:
            entry = entries.get('tools/pzagent-greenfield', {})
            require(entry.get('type') == 'blob' and entry.get('mode') in ('100644', '100755')
                    and entry.get('sha') == blob(payloads['pzagent-greenfield']), 'greenfield_launcher_source_mismatch')
    except (KeyError, TypeError):
        raise ProofError('greenfield_release_snapshot_invalid') from None
    return Release(repository, version, source, snapshot, checksum, files, modes)


def compare_files(entries, prefix, files, modes):
    actual = {p[len(prefix):]: item for p, item in entries.items()
              if p.startswith(prefix) and item['type'] != 'tree'}
    require(set(actual) == set(files), 'greenfield_release_file_set_mismatch')
    for path, data in files.items():
        require(actual[path]['type'] == 'blob' and actual[path].get('mode') == modes[path]
                and actual[path]['sha'] == blob(data), 'greenfield_release_file_mismatch')


def fetch_candidate(path):
    """Fixed read-only provider Git observations for a candidate. No release, URL or command choice."""
    allowed = (r'commits/[0-9a-f]{40}/branches-where-head', r'git/commits/[0-9a-f]{40}',
               r'git/trees/[0-9a-f]{40}\?recursive=1')
    require(any(re.fullmatch(pattern, path) for pattern in allowed), 'greenfield_candidate_path_invalid')
    try:
        result = subprocess.run(['gh', 'api', '--method', 'GET', '-H', 'Accept: application/vnd.github+json',
                                 f'repos/{PROVIDER}/{path}'], capture_output=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ProofError('greenfield_candidate_lookup_failed') from None
    require(result.returncode == 0, 'greenfield_candidate_lookup_failed')
    require(len(result.stdout) <= MAX_DOWNLOAD, 'greenfield_candidate_response_too_large')
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeDecodeError):
        raise ProofError('greenfield_candidate_response_invalid') from None


def bundle_inventory(files, version):
    """The complete, exact provider runtime its bundle.json declares."""
    try:
        descriptor = json.loads(files['bundle.json'])
        inventory = descriptor['files']
        require(descriptor.get('schema_version') == '1.0.0' and descriptor.get('package') == 'pzagent-adw-context'
                and descriptor.get('version') == version and isinstance(inventory, list), 'greenfield_bundle_invalid')
        expected = {'bundle.json'}
        for entry in inventory:
            path = entry['path']
            require(safe_path(path) and path not in expected and set(entry) == {'path', 'sha256'}
                    and isinstance(entry['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', entry['sha256']), 'greenfield_bundle_invalid')
            expected.add(path)
            require(path in files and hashlib.sha256(files[path]).hexdigest() == entry['sha256'], 'greenfield_bundle_inventory_mismatch')
        require(set(files) == expected, 'greenfield_bundle_inventory_mismatch')
    except ProofError:
        raise
    except (ValueError, KeyError, TypeError):
        raise ProofError('greenfield_bundle_invalid') from None


def candidate_head(source_sha):
    """A candidate is the current head of a provider branch, never a commit seen only via a fork."""
    heads = fetch_candidate('commits/' + source_sha + '/branches-where-head')
    require(isinstance(heads, list) and heads and all(
        isinstance(item, dict) and isinstance(item.get('name'), str) and isinstance(item.get('commit'), dict)
        and item['commit'].get('sha') == source_sha for item in heads), 'greenfield_candidate_not_branch_head')


def candidate(source_sha, version, files, modes):
    """Unreleased provider runtime bound to an exact provider branch-head commit and its bundle digest."""
    require(isinstance(source_sha, str) and SHA.fullmatch(source_sha) and isinstance(version, str)
            and VERSION.fullmatch(version) and isinstance(files, dict) and isinstance(modes, dict)
            and set(files) == set(modes), 'greenfield_candidate_invalid')
    bundle_inventory(files, version)
    candidate_head(source_sha)
    commit = fetch_candidate('git/commits/' + source_sha)
    try:
        tree_sha = commit['tree']['sha']
        require(isinstance(tree_sha, str) and SHA.fullmatch(tree_sha), 'greenfield_candidate_snapshot_invalid')
        entries = tree_entries(fetch_candidate('git/trees/' + tree_sha + '?recursive=1'))
        compare_files(entries, PROVIDER_ROOT, files, modes)
    except (KeyError, TypeError):
        raise ProofError('greenfield_candidate_snapshot_invalid') from None
    digest = hashlib.sha256(files['bundle.json']).hexdigest()
    return Release(PROVIDER, version, source_sha, source_sha, digest, files, modes, True)


def provider_anchor(version, anchor=None):
    """The published provider release, or the already verified sandbox candidate the lock names."""
    if anchor is None:
        return released(PROVIDER, version)
    require(type(anchor) is Release and anchor.candidate and anchor.repository == PROVIDER
            and anchor.version == version, 'greenfield_candidate_lock_mismatch')
    return anchor


def source_releases(api, source_sha, anchor=None):
    """Bind lock, source registry, complete provider/generic trees and workflows."""
    try:
        metadata = project_files(api, source_sha, 'adw-task-manifest.json', 'pzagent-context-lock.json')
        manifest = json.loads(metadata['adw-task-manifest.json'][1])
        lock = json.loads(metadata['pzagent-context-lock.json'][1])
        provider = provider_anchor(lock['package_version'], anchor)
        generic = released(GENERIC, manifest['contract']['version'])
        require(lock.get('schema_version') == '1.0.0' and lock.get('source_ref') == provider.source_sha
                and lock.get('bundle_sha256') == hashlib.sha256(provider.files['bundle.json']).hexdigest(), 'greenfield_lock_mismatch')
        sources = manifest['sources']
        for layer, release, prefix in (('context', provider, VENDOR), ('generic', generic, GENERIC_VENDOR)):
            matches = [s for s in sources.values() if isinstance(s, dict) and s.get('layer') == layer]
            require(len(matches) == 1 and matches[0].get('ref') == release.snapshot_sha
                    and matches[0].get('path') == prefix + 'tasks.toml'
                    and matches[0].get('checksum') == 'sha256:' + hashlib.sha256(release.files['tasks.toml']).hexdigest(), 'greenfield_manifest_source_mismatch')
        entries = tree(api, source_sha)
        for path, data in metadata.values():
            entry = entries.get(path, {})
            require(entry.get('type') == 'blob' and entry.get('mode') == '100644'
                    and entry.get('sha') == blob(data), 'greenfield_metadata_mismatch')
        compare_files(entries, VENDOR, provider.files, provider.modes)
        compare_files(entries, GENERIC_VENDOR, generic.files, generic.modes)
        for name in WORKFLOWS:
            expected = provider.files['templates/github/' + name]
            actual = entries.get('.github/workflows/' + name, {})
            require(actual.get('type') == 'blob' and actual.get('mode') == '100644'
                    and actual.get('sha') == blob(expected), 'greenfield_workflow_mismatch')
        return provider, generic
    except ProofError:
        raise
    except (ApiError, ValueError, KeyError, TypeError, AttributeError):
        raise ProofError('greenfield_source_invalid') from None


@dataclass(frozen=True)
class Admission:
    repository: str
    number: int
    head: str
    base: str
    source_branch: str
    target_branch: str
    default_branch: str
    default_sha: str
    provider_sha: str
    generic_sha: str
    fingerprint: str
    candidate: bool = False


def _pull(api, number):
    from .quality_proof import Pull
    value = api.get('pulls/' + str(number))
    try:
        require(value.get('number') == number and value.get('state') in ('open', 'closed')
                and type(value.get('merged')) is bool
                and (not value['merged'] or value.get('merge_commit_sha') == value['head']['sha']),
                'greenfield_pull_invalid')
        require(value['head']['repo']['full_name'] == api.repository
                and value['base']['repo']['full_name'] == api.repository, 'greenfield_fork_forbidden')
        return Pull(api.repository, number, value['head']['ref'], value['base']['ref'],
                    value['head']['sha'], value['base']['sha'], value.get('merge_commit_sha') or value['head']['sha'],
                    value['state'], True, None, value.get('merged') is True)
    except (KeyError, TypeError):
        raise ProofError('greenfield_pull_invalid') from None


def _operator_runtime(repo, provider):
    root = Path(__file__).resolve().parents[2]
    marker = root.parent / 'operator-release.json'
    require(not root.is_relative_to(repo.resolve()) and not root.is_symlink()
            and not root.parent.is_symlink() and not (root / '.git').exists()
            and marker.is_file() and not marker.is_symlink()
            and not (marker.stat().st_mode & 0o077) and marker.stat().st_size <= 4096
            and not (root.stat().st_mode & 0o077) and not (root.parent.stat().st_mode & 0o077),
            'greenfield_released_operator_required')
    expected = {'schema_version': '1.0.0', 'source_sha': provider.source_sha,
                'version': provider.version, 'archive_sha256': provider.archive_sha256}
    if provider.candidate:
        expected = {'schema_version': '1.0.0', 'source_sha': provider.source_sha, 'version': provider.version,
                    'bundle_sha256': provider.archive_sha256, 'candidate_repository': SANDBOX}
    try:
        value = json.loads(marker.read_bytes())
        require(value == expected, 'greenfield_operator_runtime_mismatch')
    except (ValueError, TypeError):
        raise ProofError('greenfield_operator_runtime_mismatch') from None
    require(not any(p.is_symlink() for p in root.rglob('*')), 'greenfield_operator_runtime_mismatch')
    actual = {p.relative_to(root).as_posix(): p for p in root.rglob('*')
              if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.pyc', '.pyo')}
    require(set(actual) == set(provider.files), 'greenfield_operator_runtime_mismatch')
    for path, expected in provider.files.items():
        mode = '100755' if actual[path].stat().st_mode & 0o111 else '100644'
        require(not actual[path].is_symlink() and actual[path].read_bytes() == expected
                and mode == provider.modes[path], 'greenfield_operator_runtime_mismatch')


def _candidate_marker():
    """The operator runtime's marker selects candidate mode; _operator_runtime checks it fully."""
    marker = Path(__file__).resolve().parents[2].parent / 'operator-release.json'
    if not marker.is_file() or marker.is_symlink() or marker.stat().st_size > 4096:
        return None
    try:
        value = json.loads(marker.read_bytes())
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) and 'candidate_repository' in value else None


def _sandbox_identity(api):
    """Live identity of the fixed sandbox: exact name, owner, private and not a fork."""
    require(api.repository == SANDBOX, 'greenfield_candidate_repository_forbidden')
    try:
        value = api.get('')
        require(value.get('full_name') == SANDBOX and type(value.get('id')) is int and value['id'] == SANDBOX_ID
                and value.get('owner', {}).get('login') == SANDBOX.split('/')[0]
                and value.get('private') is True and value.get('fork') is False, 'greenfield_candidate_repository_forbidden')
    except (ApiError, AttributeError):
        raise ProofError('greenfield_candidate_repository_forbidden') from None


def _candidate_runtime(api, marker):
    require(marker.get('candidate_repository') == SANDBOX, 'greenfield_candidate_repository_forbidden')
    _sandbox_identity(api)
    root = Path(__file__).resolve().parents[2]
    paths = [p for p in root.rglob('*') if '__pycache__' not in p.parts and p.suffix not in ('.pyc', '.pyo')]
    require(not any(p.is_symlink() for p in paths), 'greenfield_operator_runtime_mismatch')
    files = {p.relative_to(root).as_posix(): p.read_bytes() for p in paths if p.is_file()}
    modes = {p.relative_to(root).as_posix(): '100755' if p.stat().st_mode & 0o111 else '100644'
             for p in paths if p.is_file()}
    return candidate(marker.get('source_sha'), marker.get('version'), files, modes)


def _installed_seed(api, pull, snapshot):
    """Read-only bridge, valid only while the installed default is this seed SHA."""
    if pull.state != 'closed' or not pull.merged or pull.head_sha != snapshot['sha']:
        return False
    require(pull.same_repository and pull.repository == api.repository, 'greenfield_seed_repository_mismatch')
    live = _pull(api, pull.number)
    require(live.state == 'closed' and live.merged and live.merge_sha == snapshot['sha']
            and (live.head_sha, live.base_sha, live.source_branch, live.target_branch)
            == (pull.head_sha, pull.base_sha, pull.source_branch, pull.target_branch), 'greenfield_seed_pull_mismatch')
    if not absent_root(tree(api, pull.base_sha)):
        return False  # A normal repin must use the existing controller policy.
    root = Path(__file__).resolve().parents[2]
    paths = [p for p in root.rglob('*') if '__pycache__' not in p.parts and p.suffix not in ('.pyc', '.pyo')]
    require(not any(p.is_symlink() for p in paths), 'greenfield_seed_runtime_mismatch')
    files = {p.relative_to(root).as_posix(): p.read_bytes() for p in paths if p.is_file()}
    modes = {p.relative_to(root).as_posix(): '100755' if p.stat().st_mode & 0o111 else '100644'
             for p in paths if p.is_file()}
    installed = tree(api, snapshot['sha'])
    compare_files(installed, VENDOR, files, modes)
    for name in WORKFLOWS:
        entry = installed.get('.github/workflows/' + name, {})
        require(entry.get('type') == 'blob' and entry.get('mode') == '100644'
                and entry.get('sha') == blob(files.get('templates/github/' + name, b'')),
                'greenfield_seed_workflow_mismatch')
    _not_disabled(api, pull)
    fresh = default_snapshot(api)
    require(fresh['branch'] == snapshot['branch'] and fresh['sha'] == pull.head_sha and not fresh['absent'],
            'greenfield_seed_default_changed')
    return True


def _not_disabled(api, pull):
    """ENABLE comments confer nothing here; any current administrator denial blocks."""
    from .provenance import _changed_paths, _fingerprint
    fingerprint = _fingerprint(pull, _changed_paths(api, pull))
    try:
        for comment in api.list('issues/' + str(pull.number) + '/comments'):
            body = comment.get('body')
            if not isinstance(body, str) or body.strip() != 'BOOTSTRAP_DISABLED ' + fingerprint:
                continue
            actor = (comment.get('user') or {}).get('login')
            require(type(comment.get('id')) is int and comment['id'] > 0 and isinstance(actor, str)
                    and re.fullmatch(r'[A-Za-z0-9_-]+', actor), 'greenfield_denial_invalid')
            permission = api.get('collaborators/' + actor + '/permission')
            require(isinstance(permission, dict) and permission.get('permission') in
                    ('none', 'read', 'triage', 'write', 'maintain', 'admin'), 'greenfield_denial_invalid')
            require(permission['permission'] != 'admin', 'bootstrap_disabled')
    except ApiError:
        raise ProofError('greenfield_denial_lookup_failed') from None
    return fingerprint


def _validate(api, pull, admission, snapshot):
    require(type(admission) is Admission and admission.repository == api.repository == pull.repository
            and (admission.number, admission.head, admission.base) == (pull.number, pull.head_sha, pull.base_sha)
            and (admission.source_branch, admission.target_branch) == (pull.source_branch, pull.target_branch)
            and snapshot['absent'] and (admission.default_branch, admission.default_sha) == (snapshot['branch'], snapshot['sha']),
            'greenfield_admission_binding_mismatch')
    require(_not_disabled(api, pull) == admission.fingerprint, 'greenfield_admission_binding_mismatch')


@contextmanager
def operator_admission(repo, adapter, args):
    require(os.environ.get('GITHUB_ACTIONS', '').lower() != 'true', 'greenfield_operator_only')
    api = GitHub(adapter['repository']['id'])
    pull = _pull(api, args.pr)
    require(pull.target_branch == args.line, 'greenfield_pull_invalid')
    if pull.state != 'open' or pull.merged:
        # A lost ref-update acknowledgement may have closed the PR already.
        # This is readback-only recovery, never authority to repeat the write.
        directory = getattr(args, 'operation_dir', None)
        require(directory is not None and not directory.resolve().is_relative_to(repo.resolve()), 'greenfield_pull_invalid')
        path = directory / 'operation.json'
        require(path.is_file() and not path.is_symlink() and not (path.stat().st_mode & 0o077)
                and path.stat().st_size <= 65536, 'greenfield_pull_invalid')
        record = json.loads(path.read_bytes())
        require(pull.state == 'closed' and pull.merged and record.get('phase') in ('requested', 'complete')
                and record.get('workflow') == 'source-line' and record.get('pr_number') == pull.number
                and record.get('line') == pull.target_branch and record.get('source_sha') == pull.head_sha
                and record.get('previous_sha') == pull.base_sha and record.get('result_sha') == pull.head_sha
                and api.get('git/ref/heads/' + pull.target_branch)['object']['sha'] == pull.head_sha,
                'greenfield_pull_invalid')
    snapshot = default_snapshot(api)
    require(snapshot['absent'], 'greenfield_controller_present')
    marker = _candidate_marker()
    anchor = _candidate_runtime(api, marker) if marker is not None else None
    provider, generic = source_releases(api, pull.head_sha, anchor)
    metadata = project_files(api, pull.head_sha, 'pzagent-adapter.json', 'adw-task-manifest.json', 'pzagent-context-lock.json')
    for path, data in metadata.values():
        local = repo / path
        require(local.is_file() and not local.is_symlink() and local.read_bytes() == data,
                'greenfield_local_metadata_mismatch')
    _operator_runtime(repo, provider)
    admission = Admission(api.repository, pull.number, pull.head_sha, pull.base_sha, pull.source_branch, pull.target_branch,
                          snapshot['branch'], snapshot['sha'], provider.source_sha,
                          generic.snapshot_sha, _not_disabled(api, pull), provider.candidate)
    _validate(api, _pull(api, args.pr), admission, default_snapshot(api))
    token = _CURRENT.set(admission)
    try:
        yield admission
    finally:
        _CURRENT.reset(token)


def has_operator_admission():
    """Presence only selects validation; even a forged value grants no authority."""
    return _CURRENT.get() is not None


def trusted_decision(api, pull):
    """The sole provenance integration: absence requires this process's admission."""
    snapshot = default_snapshot(api)
    if not snapshot['absent']:
        return _installed_seed(api, pull, snapshot)
    admission = _CURRENT.get()
    require(admission is not None, 'greenfield_operator_admission_required')
    _validate(api, pull, admission, snapshot)
    return True


def before_mutation(api, number):
    """Re-read live identity, default tree and explicit denials at the write boundary."""
    admission = _CURRENT.get()
    if admission is not None and admission.candidate:
        _validate(api, _pull(api, number), admission, default_snapshot(api))
        _sandbox_identity(api)
        candidate_head(admission.provider_sha)
    elif admission is not None:
        _validate(api, _pull(api, number), admission, default_snapshot(api))
        require(fetch(PROVIDER, 'commits/v' + json.loads(
            (Path(__file__).resolve().parents[2] / 'bundle.json').read_bytes())['version'])['sha'] == admission.provider_sha,
            'greenfield_release_commit_changed')

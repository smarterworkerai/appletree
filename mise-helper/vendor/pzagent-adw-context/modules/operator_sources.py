"""Resolve one commit and read selected files without executing historical code."""
from contextlib import contextmanager
import base64
import os
from pathlib import Path
import re
import subprocess
import tempfile

from .common import ContractError, FULL_SHA, ensure_contained
from .providers import bind

# Local-only reads never fetch, take optional locks or prompt.
LOCAL_ONLY = {'GIT_NO_LAZY_FETCH': '1', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0'}


def local_environment() -> dict:
    return {**os.environ, **LOCAL_ONLY}


def _object_read(arguments: list[str], cwd: Path, local_only: bool) -> subprocess.CompletedProcess:
    """Raw object reads; local-only callers are bounded in time and never fetch."""
    if not local_only:
        return subprocess.run(arguments, cwd=cwd, capture_output=True)
    try:
        return subprocess.run(arguments, cwd=cwd, capture_output=True, env=local_environment(), timeout=30)
    except subprocess.TimeoutExpired as exc:
        raise ContractError('release_source_read_timeout') from exc


# GIT_NO_LAZY_FETCH is honoured from 2.44.1/2.45.1 on, not by 2.44.0; require a floor above both lines.
LAZY_FETCH_FLOOR = (2, 46, 0)


def lazy_fetch_suppressed(repo: Path) -> bool:
    """A partial clone fetches missing objects lazily unless Git honours GIT_NO_LAZY_FETCH."""
    try:
        promisor = subprocess.run(['git', 'config', '--get-regexp', r'^(extensions\.partialclone|remote\..*\.promisor)$'],
                                  cwd=repo, capture_output=True, text=True, env=local_environment(), timeout=30)
        if not promisor.stdout.strip():
            return True
        version = subprocess.run(['git', '--version'], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    match = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?', version)
    return match is not None and tuple(int(part or 0) for part in match.groups()) >= LAZY_FETCH_FLOOR


def git(repo: Path, *args: str, local_only: bool = False) -> str:
    environment = local_environment() if local_only else os.environ.copy()
    token = environment.get('GITHUB_TOKEN') or environment.get('GH_TOKEN')
    if token and args and args[0] in {'ls-remote', 'fetch'}:
        # GitHub's token is also usable for Git HTTPS. Scope its header to that
        # host and use environment config, never a credential-bearing URL/argv.
        count = int(environment.get('GIT_CONFIG_COUNT', '0'))
        entries = [('http.https://github.com/.extraheader', 'AUTHORIZATION: basic ' +
                    base64.b64encode(('x-access-token:' + token).encode()).decode()),
                   ('url.https://github.com/.insteadOf', 'git@github.com:')]
        for offset, (key, value) in enumerate(entries):
            environment[f'GIT_CONFIG_KEY_{count + offset}'] = key
            environment[f'GIT_CONFIG_VALUE_{count + offset}'] = value
        environment['GIT_CONFIG_COUNT'] = str(count + len(entries))
        environment['GIT_TERMINAL_PROMPT'] = '0'
    try:
        result = subprocess.run(['git', *args], cwd=repo, capture_output=True, text=True,
                                env=environment, timeout=60)
    except subprocess.TimeoutExpired as exc:
        raise ContractError('Git source lookup timed out') from exc
    if result.returncode:
        raise ContractError('Git source lookup failed; check ref and repository access')
    return result.stdout.strip()


def resolve(repo: Path, ref: str, remote: str = 'origin', *, local_only: bool = False) -> str:
    if not ref or ref.startswith('-') or '..' in ref or '\x00' in ref:
        raise ContractError('ref must select one commit')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', remote):
        raise ContractError('invalid Git remote name')
    if re.fullmatch(r'[0-9a-fA-F]{40}', ref):
        objects = object_repository(repo, ref.lower(), remote, local_only=local_only)
        sha = git(objects, 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}', local_only=local_only)
    elif ref == '@' or ref.startswith(('HEAD', 'refs/heads/', 'refs/remotes/')) or re.fullmatch(r'[0-9a-fA-F]{7,39}', ref):
        sha = git(repo, 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}')
    else:
        name = ref.removeprefix(remote + '/')
        if name.startswith('refs/tags/'):
            patterns = [name, name + '^{}']
        else:
            patterns = ['refs/heads/' + name, 'refs/tags/' + name, 'refs/tags/' + name + '^{}']
        rows = git(repo, 'ls-remote', '--', remote, *patterns)
        refs = dict((row.split('\t')[1], row.split('\t')[0]) for row in rows.splitlines() if '\t' in row)
        branch = refs.get('refs/heads/' + name)
        tag_name = name if name.startswith('refs/tags/') else 'refs/tags/' + name
        tag = refs.get(tag_name + '^{}', refs.get(tag_name))
        if branch and tag:
            raise ContractError('ambiguous branch/tag; use refs/heads/ or refs/tags/')
        sha = branch or tag
        if not sha and any(marker in ref for marker in ('~', '^', '@{')):
            # Explicit revision expressions and local-only tags are allowed.
            sha = git(repo, 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}')
        if not sha:
            raise ContractError('selected remote branch/tag is absent; use HEAD or refs/heads/ for an explicit local selection')
    if not FULL_SHA.fullmatch(sha):
        raise ContractError('ref does not resolve to a full commit identity')
    return sha


def object_repository(repo: Path, sha: str, remote: str = 'origin', *, local_only: bool = False) -> Path:
    if local_only and not lazy_fetch_suppressed(repo):
        raise ContractError('release_source_unavailable_locally')
    if _object_read(['git', 'cat-file', '-e', sha + '^{commit}'], repo, local_only).returncode == 0:
        return repo
    cache = repo / 'handover' / '.sources'
    if local_only:
        # Observation callers read an existing cache but never create or fetch into it.
        if (not cache.is_symlink() and (cache / 'objects').is_dir() and lazy_fetch_suppressed(cache)
                and _object_read(['git', 'cat-file', '-e', sha + '^{commit}'], cache, True).returncode == 0):
            return cache
        raise ContractError('release_source_unavailable_locally')
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    git(cache, 'init', '--bare', '--quiet')
    url = git(repo, 'remote', 'get-url', remote)
    git(cache, 'fetch', '--no-tags', '--depth=1', '--', url, sha)
    if git(cache, 'rev-parse', '--verify', sha + '^{commit}') != sha:
        raise ContractError('selected source is not a commit')
    return cache


@contextmanager
def config_source(repo: Path, adapter: dict, environment: str, target: str | None,
                  ref: str | None, remote: str = 'origin', *, local_only: bool = False):
    if ref is None:
        yield repo, git(repo, 'rev-parse', 'HEAD')
        return
    if local_only and not FULL_SHA.fullmatch(ref):
        raise ContractError('local configuration source requires a full commit identity')
    sha = resolve(repo, ref, remote, local_only=local_only)
    objects = object_repository(repo, sha, remote, local_only=local_only)
    group = adapter['targets'].get(environment)
    if not group or (target or group['default']) not in group['items']:
        raise ContractError('unknown configuration target')
    name = target or group['default']
    provider = bind(repo, adapter, name, group['items'][name])
    configuration = provider.configuration
    with tempfile.TemporaryDirectory(prefix='pz-config-') as directory:
        root = Path(directory)
        inputs = [configuration.definition_path, configuration.settings_schema_path]
        if configuration.render_definition is not None:
            # Renderers need the tracked tree (overlay plus local bases), never
            # a textual `git show` listing of a directory. Its first path
            # component bounds all renderer inputs; remote bases are refused.
            prefix = Path(configuration.definition_path).parts[0]
            rows = _object_read(['git', 'ls-tree', '-rz', sha, '--', prefix], objects, local_only)
            if rows.returncode:
                raise ContractError('selected configuration tree is unavailable')
            inputs = [configuration.settings_schema_path]
            records = rows.stdout.split(b'\0')
            if len(records) > 4097:
                raise ContractError('selected configuration tree is unbounded')
            for row in records:
                if not row:
                    continue
                try:
                    metadata, path = row.split(b'\t', 1)
                    mode, kind, identity = metadata.split(b' ')
                    if mode not in {b'100644', b'100755'} or kind != b'blob':
                        raise ValueError()
                    inputs.append(path.decode('utf-8'))
                except (UnicodeError, ValueError) as exc:
                    raise ContractError('selected configuration tree contains unsupported entries') from exc
        total = 0
        for relative in dict.fromkeys(inputs):
            destination = ensure_contained(root, relative)
            data = _object_read(['git', 'show', sha + ':' + relative], objects, local_only)
            if data.returncode:
                raise ContractError('selected revision lacks the declared configuration files')
            total += len(data.stdout)
            if len(data.stdout) > 8 * 1024 * 1024 or total > 64 * 1024 * 1024:
                raise ContractError('selected configuration tree is unbounded')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data.stdout)
        yield root, sha

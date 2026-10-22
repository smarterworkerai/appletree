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


def git(repo: Path, *args: str) -> str:
    environment = os.environ.copy()
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


def resolve(repo: Path, ref: str, remote: str = 'origin') -> str:
    if not ref or ref.startswith('-') or '..' in ref or '\x00' in ref:
        raise ContractError('ref must select one commit')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', remote):
        raise ContractError('invalid Git remote name')
    if re.fullmatch(r'[0-9a-fA-F]{40}', ref):
        objects = object_repository(repo, ref.lower(), remote)
        sha = git(objects, 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}')
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


def object_repository(repo: Path, sha: str, remote: str = 'origin') -> Path:
    if subprocess.run(['git', 'cat-file', '-e', sha + '^{commit}'], cwd=repo,
                      capture_output=True).returncode == 0:
        return repo
    cache = repo / 'handover' / '.sources'
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    git(cache, 'init', '--bare', '--quiet')
    url = git(repo, 'remote', 'get-url', remote)
    git(cache, 'fetch', '--no-tags', '--depth=1', '--', url, sha)
    if git(cache, 'rev-parse', '--verify', sha + '^{commit}') != sha:
        raise ContractError('selected source is not a commit')
    return cache


@contextmanager
def config_source(repo: Path, adapter: dict, environment: str, target: str | None,
                  ref: str | None, remote: str = 'origin'):
    if ref is None:
        yield repo, git(repo, 'rev-parse', 'HEAD')
        return
    sha = resolve(repo, ref, remote)
    objects = object_repository(repo, sha, remote)
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
            rows = subprocess.run(['git', 'ls-tree', '-rz', sha, '--', prefix],
                                  cwd=objects, capture_output=True)
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
            data = subprocess.run(['git', 'show', sha + ':' + relative], cwd=objects, capture_output=True)
            if data.returncode:
                raise ContractError('selected revision lacks the declared configuration files')
            total += len(data.stdout)
            if len(data.stdout) > 8 * 1024 * 1024 or total > 64 * 1024 * 1024:
                raise ContractError('selected configuration tree is unbounded')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data.stdout)
        yield root, sha

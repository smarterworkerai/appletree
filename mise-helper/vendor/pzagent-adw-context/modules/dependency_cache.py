"""Declared dependency caches; never project build, test or release evidence."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import tempfile
import subprocess

from .common import ContractError, project_dir

INTEGRITY_FILE = ".adw-dependency-integrity.json"
MAX_INTEGRITY_BYTES = 32 * 1024 * 1024


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def relative(value: str) -> Path:
    if not isinstance(value, str) or not value or any(c in value for c in '\n\r\x00\\'):
        raise ContractError('invalid cache path')
    path = Path(value)
    if path.is_absolute() or '..' in path.parts or value == '.':
        raise ContractError('cache path must be a bounded relative path')
    return path


def regular(root: Path, path: Path) -> None:
    if not path.is_relative_to(root):
        raise ContractError('cache input escapes source root')
    if any(item.is_symlink() for item in (path, *path.parents) if item.is_relative_to(root)):
        raise ContractError('cache symlink is unsupported')
    if not path.is_file():
        raise ContractError('required cache input is missing')


SECTIONS = ('dependencies', 'build_results')
LEGACY_BUILD_RESULTS = Path('adw-build-cache.json')


def declaration(root: Path, config: Path, section: str = 'dependencies') -> dict | None:
    """Resolve one section of the combined declaration, or the legacy one-file-per-section layout."""
    if section not in SECTIONS:
        raise ContractError('unknown cache declaration section')
    if config.exists():
        regular(root, config)
        value = json.loads(config.read_text())
        if isinstance(value, dict) and set(value) & set(SECTIONS):
            if set(value) - {'schema_version', *SECTIONS} or value.get('schema_version') != '2.0.0':
                raise ContractError('invalid combined cache declaration')
            return value.get(section)
        if section == 'dependencies':
            return value
    if section == 'build_results' and (project_dir(root) / LEGACY_BUILD_RESULTS).exists():
        legacy = project_dir(root) / LEGACY_BUILD_RESULTS
        regular(root, legacy)
        return json.loads(legacy.read_text())
    return None


def load(root: Path, config: Path, section: str = 'dependencies') -> dict:
    value = declaration(root, config, section)
    if value is None:
        raise ContractError('cache declaration section is absent')
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'namespace', 'epoch', 'groups'}
            or value['schema_version'] != '1.0.0'
            or not re.fullmatch(r'[a-z0-9-]{1,64}', value['namespace'])
            or type(value['epoch']) is not int or value['epoch'] < 1
            or not isinstance(value['groups'], dict) or not value['groups']):
        raise ContractError('invalid dependency cache declaration')
    paths = []
    for name, group in value['groups'].items():
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,40}', name):
            raise ContractError('invalid dependency cache group')
        if set(group) != {'inputs', 'optional_inputs', 'tools', 'paths', 'exclude'}:
            raise ContractError('invalid dependency cache group fields')
        for field in ('inputs', 'optional_inputs', 'paths', 'exclude'):
            if not isinstance(group[field], list):
                raise ContractError('invalid dependency cache list')
            for entry in group[field]:
                relative(entry)
        if not group['inputs'] or not group['paths'] or not isinstance(group['tools'], list):
            raise ContractError('dependency cache requires inputs and paths')
        for command in group['tools']:
            if not isinstance(command, list) or not command or any(not isinstance(arg, str) or not arg for arg in command):
                raise ContractError('invalid cache tool identity command')
        for entry in group['paths']:
            path = relative(entry)
            if path.parts[0] == INTEGRITY_FILE:
                raise ContractError('cache storage overlaps integrity metadata')
            if any(c in entry for c in '*?[') or any(path == old or path.is_relative_to(old) or old.is_relative_to(path) for old in paths):
                raise ContractError('cache storage paths overlap or contain globs')
            paths.append(path)
        for entry in group['exclude']:
            if any(c in entry for c in '*?[') or not any(relative(entry).is_relative_to(relative(p)) for p in group['paths']):
                raise ContractError('cache exclusion escapes declared storage')
    return value


def cache_root(root: Path, directory: Path) -> Path:
    # Mutating cleanup must never address the source, home or another broad tree.
    if not directory.is_absolute() or any(c in str(directory) for c in '\n\r\x00'):
        raise ContractError('cache root must be absolute')
    if any(p.is_symlink() for p in (directory, *directory.parents)):
        raise ContractError('cache root cannot contain symlinks')
    directory = directory.resolve()
    if directory == Path.home() or directory == Path('/') or root.is_relative_to(directory):
        raise ContractError('cache root overlaps source or home')
    if directory.is_relative_to(root) and not directory.is_relative_to(root / '.ci-cache'):
        raise ContractError('in-source cache must be beneath .ci-cache')
    return directory


def plan(root: Path, config: Path, directory: Path, *, trust: str = 'trusted', observe=None, section: str = 'dependencies') -> dict:
    root = root.resolve()
    declaration = load(root, config, section)
    directory = cache_root(root, directory)
    if trust not in {'trusted', 'local', 'github'}:
        raise ContractError('invalid dependency cache trust scope')
    def version(command):
        result = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=30, check=True)
        if not result.stdout.strip() or len(result.stdout) > 16384:
            raise ContractError('invalid cache tool identity')
        return result.stdout.strip()
    observe = observe or version
    identities = {}
    inventory = sorted(set(subprocess.check_output(
        ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root,
    ).decode().split('\0')) - {''})
    groups = {}
    host = {'os': platform.system(), 'architecture': platform.machine(), 'libc': platform.libc_ver()}
    for name, group in sorted(declaration['groups'].items()):
        files = {}
        for required, patterns in ((True, group['inputs']), (False, group['optional_inputs'])):
            for pattern in patterns:
                matches = [root / name for name in inventory if fnmatch.fnmatchcase(name, pattern)
                           or (pattern.startswith('**/') and fnmatch.fnmatchcase(name, pattern[3:]))]
                if required and not matches:
                    raise ContractError('required cache input pattern has no match: ' + pattern)
                for path in matches:
                    regular(root, path)
                    files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        tools = {}
        for command in group['tools']:
            key = tuple(command)
            if key not in identities:
                identities[key] = observe(command)
            tools[json.dumps(command)] = identities[key]
        fingerprint = digest({'files': files, 'tools': tools, 'host': host, 'group': group,
                              'policy': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
        key = f"{declaration['namespace']}-{name}-v{declaration['epoch']}-{trust}-{fingerprint}"
        groups[name] = {'key': key, 'paths': [str(directory / p) for p in group['paths']],
                        'input_count': len(files)}
    # One native Actions entry initially: entirely generic across project technologies.
    # Group keys remain available for independently restored entries in future adapters.
    key = f"{declaration['namespace']}-deps-v{declaration['epoch']}-{trust}-{digest({n:g['key'] for n,g in groups.items()})}"
    return {'schema_version': '1.0.0', 'key': key, 'groups': groups,
            'paths': [p for group in groups.values() for p in group['paths']] + [str(directory / INTEGRITY_FILE)]}


def clean(root: Path, config: Path, directory: Path, *, reset: bool = False, section: str = 'dependencies') -> None:
    """Drop only declared cache paths on an unconfirmed restore, or excluded outputs."""
    root = root.resolve()
    declaration = load(root, config, section)
    directory = cache_root(root, directory)
    if reset:
        metadata = directory / INTEGRITY_FILE
        if metadata.is_symlink() or metadata.is_file():
            metadata.unlink()
        elif metadata.exists():
            shutil.rmtree(metadata)
    for group in declaration['groups'].values():
        for entry in group['paths'] if reset else group['exclude']:
            path = directory / entry
            if any(p.is_symlink() for p in path.parents if p.is_relative_to(directory)):
                raise ContractError('cache cleanup parent is a symlink')
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.exists():
                shutil.rmtree(path)
        if not reset:
            for entry in group['paths']:
                path = directory / entry
                # Cached archives must never carry links into a credential/source tree.
                if (any(p.is_symlink() for p in (path, *path.parents) if p.is_relative_to(directory))
                        or any(p.is_symlink() for p in path.rglob('*'))):
                    raise ContractError('cache contents contain a symlink')



def inventory(root: Path, config: Path, directory: Path, *, section: str = 'dependencies') -> list[dict]:
    """Hash declared cache files only; technology-specific content stays opaque."""
    declaration = load(root, config, section)
    directory = cache_root(root, directory)
    files = []
    for group in declaration['groups'].values():
        for entry in group['paths']:
            base = directory / entry
            if any(path.is_symlink() for path in (base, *base.parents) if path.is_relative_to(directory)):
                raise ContractError('cache contents contain a symlink')
            if not base.exists():
                continue
            for path in sorted([base, *base.rglob('*')]):
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise ContractError('cache contents must be regular files')
                checksum = hashlib.sha256()
                with path.open('rb') as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b''):
                        checksum.update(chunk)
                files.append({'path': path.relative_to(directory).as_posix(),
                              'size': metadata.st_size, 'mode': stat.S_IMODE(metadata.st_mode),
                              'sha256': checksum.hexdigest()})
    return sorted(files, key=lambda item: item['path'])


def integrity(root: Path, config: Path, directory: Path, key: str, *, seal: bool = False, section: str = 'dependencies') -> None:
    if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,512}', key):
        raise ContractError('cache integrity requires the planned compatibility key')
    root = root.resolve()
    directory = cache_root(root, directory)
    metadata = directory / INTEGRITY_FILE
    if seal:
        clean(root, config, directory)
        value = {'schema_version': '1.0.0', 'key': key, 'files': inventory(root, config, directory, section=section)}
        payload = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        if len(payload) > MAX_INTEGRITY_BYTES:
            raise ContractError('cache integrity metadata exceeds bound')
        directory.mkdir(parents=True, exist_ok=True)
        if metadata.is_symlink() or metadata.is_dir():
            raise ContractError('cache integrity metadata must be a regular file')
        descriptor, temporary = tempfile.mkstemp(prefix='.cache-integrity-', dir=directory)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                output.write(payload)
            os.replace(temporary, metadata)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    else:
        if metadata.is_symlink() or not metadata.is_file() or metadata.stat().st_size > MAX_INTEGRITY_BYTES:
            raise ContractError('cache integrity metadata is missing or invalid')
        value = json.loads(metadata.read_text())
        if (not isinstance(value, dict) or set(value) != {'schema_version', 'key', 'files'}
                or value['schema_version'] != '1.0.0' or value['key'] != key):
            raise ContractError('cache integrity identity differs')
        if value['files'] != inventory(root, config, directory, section=section):
            raise ContractError('cache contents differ from the saved inventory')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['plan', 'sanitize', 'reset', 'seal', 'verify'])
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--config', type=Path, default=None)
    parser.add_argument('--cache-root', type=Path, required=True)
    parser.add_argument('--trust', choices=['trusted', 'local', 'github'], default='trusted')
    parser.add_argument('--github-output', type=Path)
    parser.add_argument('--key', help='exact key emitted by plan; required for seal/verify')
    parser.add_argument('--section', choices=SECTIONS, default='dependencies',
                        help='declaration section; build_results falls back to the legacy adw-build-cache.json')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        config = root / args.config if args.config is not None else project_dir(root) / 'adw-cache.json'
        if args.command == 'plan' and declaration(root, config, args.section) is None:
            # No declaration for this section: emit no key, so every cache step is skipped.
            print(json.dumps({'status': 'absent', 'section': args.section}, sort_keys=True))
            return 0
        if args.command == 'plan':
            result = plan(root, config, args.cache_root, trust=args.trust, section=args.section)
            if args.github_output:
                with args.github_output.open('a') as output:
                    output.write('key=' + result['key'] + '\n')
                    output.write('paths<<ADW_CACHE_PATHS\n' + '\n'.join(result['paths']) + '\nADW_CACHE_PATHS\n')
            print(json.dumps(result, sort_keys=True))
        elif args.command in {'seal', 'verify'}:
            integrity(root, config, args.cache_root, args.key, seal=args.command == 'seal', section=args.section)
        else:
            clean(root, config, args.cache_root, reset=args.command == 'reset', section=args.section)
        return 0
    except (ContractError, OSError, ValueError, TypeError, subprocess.SubprocessError):
        print('Dependency cache declaration, inputs or operation is invalid', file=__import__('sys').stderr)
        return 2

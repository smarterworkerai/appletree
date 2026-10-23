"""One private operator home: profile, journals and verified releases.

Paths are derived, never accepted from a project; everything stays outside
every checkout, private (0700/0600) and free of secret values. Resolution of
the home itself and of operation IDs is shared with the trusted operator state.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets

from .common import ContractError, IDENTIFIER
from .operator_credentials import private_profile_path
from .operator_state import OPERATION_ID, REPOSITORY, operator_home

LAYOUT = ('profile', 'journals', 'releases')
VERSION = re.compile(r'^[0-9]+\.[0-9]+\.[0-9]+$')
TERMINAL = {'complete', 'deprovisioned', 'retired', 'cancelled'}
KIND = re.compile(r'^[a-z][a-z0-9-]{0,40}$')


def default_root(environ=None) -> Path:
    source = dict(os.environ if environ is None else environ)
    source.pop('PZ_ADW_PROFILE_ROOT', None)
    return operator_home(environ=source)


def root(explicit: Path | None = None, environ=None) -> Path:
    """Explicit argument, then PZ_ADW_PROFILE_ROOT, then the same XDG default for every command."""
    return operator_home(explicit, environ)


def profile(home: Path) -> Path:
    return home / 'profile'


def ensure(home: Path, *, repo: Path | None = None) -> Path:
    """Create the private layout; refuse links at or below the root and any checkout."""
    try:
        home = private_profile_path(home.absolute(), home.absolute())
    except (OSError, ValueError, RuntimeError):
        raise ContractError('operator_home_invalid') from None
    if repo is not None:
        checkout = repo.resolve()
        if home == checkout or checkout in home.parents or home in checkout.parents:
            raise ContractError('operator_home_inside_checkout')
    if home.exists() and (not home.is_dir() or home.stat().st_mode & 0o077):
        raise ContractError('operator_home_not_private')
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in LAYOUT:
        path = home / name
        if path.is_symlink() or (path.exists() and (not path.is_dir() or path.stat().st_mode & 0o077)):
            raise ContractError('operator_home_not_private')
        path.mkdir(mode=0o700, exist_ok=True)
    return home


def repository_dir(repository: str) -> Path:
    if (not isinstance(repository, str) or not REPOSITORY.fullmatch(repository)
            or any(part in ('.', '..') for part in repository.split('/'))):
        raise ContractError('operator_home_repository_invalid')
    return Path(repository)


def new_operation_id(kind: str, *, now: datetime | None = None) -> str:
    if not isinstance(kind, str) or not KIND.fullmatch(kind):
        raise ContractError('operator_home_operation_kind_invalid')
    stamp = (now or datetime.now(timezone.utc)).strftime('%Y%m%d')
    return kind + '-' + stamp + '-' + secrets.token_hex(6)


def stable_key(environment: str, target: str, kind: str = 'provision') -> str:
    """Ownership journals are keyed by what they own, not by local paths."""
    if (not all(isinstance(v, str) and IDENTIFIER.fullmatch(v) for v in (environment, target))
            or not KIND.fullmatch(kind)):
        raise ContractError('operator_home_stable_key_invalid')
    return kind + '--' + environment + '--' + target


def ownership_journal(home: Path, repository: str, environment: str, target: str, kind: str = 'provision') -> Path:
    return home / 'journals' / repository_dir(repository) / 'ownership' / stable_key(environment, target, kind) / 'operation.json'


def release_dir(home: Path, version: str) -> Path:
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ContractError('operator_home_release_version_invalid')
    return home / 'releases' / version


def _private_record(path: Path) -> dict | None:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077 or path.stat().st_size > 1024 * 1024:
        return None
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def operations(root: Path) -> list[dict]:
    """Content-safe listing of operation journals under one root: ID, kind, phase, selection fields."""
    result = []
    if not root.is_dir() or root.is_symlink():
        return result
    for entry in sorted(root.iterdir()):
        if not OPERATION_ID.fullmatch(entry.name) or entry.is_symlink() or not entry.is_dir():
            continue
        path = entry / 'operation.json'
        if not path.exists() and not path.is_symlink():
            continue  # A receipt-only directory has no resumable workflow.
        record = _private_record(path)
        if record is None or record.get('schema_version') != '1.0.0':
            raise ContractError('operator_home_operation_invalid: ' + entry.name)
        selection = record.get('selection') if isinstance(record.get('selection'), dict) else {}
        result.append({'operation': entry.name, 'kind': entry.name.rsplit('-', 2)[0],
                       'phase': record.get('phase') if isinstance(record.get('phase'), str) else None,
                       **{key: record.get(key, selection.get(key)) for key in ('environment', 'target', 'line', 'pr_number')
                          if isinstance(record.get(key, selection.get(key)), (str, int))}})
    return result


def select_operation(root: Path, *, operation: str | None = None, kind: str | None = None, **match) -> str:
    """The single open operation for these fields, or the explicit ID; ambiguity refuses with candidates."""
    rows = operations(root)
    if operation is not None:
        selected = next((row for row in rows if row['operation'] == operation), None)
        if selected is None:
            raise ContractError('operator_home_operation_unknown')
        if any(selected.get(key) != value for key, value in match.items() if value is not None):
            raise ContractError('operator_home_operation_selection_changed')
        return operation
    candidates = [row['operation'] for row in rows if row['phase'] not in TERMINAL
                  and (kind is None or row['kind'] == kind)
                  and all(row.get(key) == value for key, value in match.items() if value is not None)]
    if not candidates:
        raise ContractError('operator_home_operation_missing')
    if len(candidates) > 1:
        raise ContractError('operator_home_operation_ambiguous: ' + ', '.join(candidates))
    return candidates[0]


def ownership_journals(home: Path, repository: str) -> list[Path]:
    base = home / 'journals' / repository_dir(repository) / 'ownership'
    if not base.is_dir() or base.is_symlink():
        return []
    return sorted(entry / 'operation.json' for entry in base.iterdir()
                  if not entry.is_symlink() and entry.is_dir() and (entry / 'operation.json').is_file())

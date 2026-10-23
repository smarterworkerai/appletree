"""Private local operation records; atomic writes, no credentials or provider env."""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

from .common import ContractError, load_json, project_dir

OPERATION_ID = re.compile(r'^[a-z][a-z0-9-]{0,40}-[0-9]{8}-[0-9a-f]{12}$')
REPOSITORY = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')


def write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ContractError('operation state must not be a symlink')
    fd, temporary = tempfile.mkstemp(prefix='.result-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def operator_home(explicit: Path | None = None, environ=None) -> Path:
    """One operator home: argument, PZ_ADW_PROFILE_ROOT, else the XDG state default.

    A path named `profile` denotes the profile directory inside that home.
    """
    source = os.environ if environ is None else environ
    raw = explicit or (Path(source['PZ_ADW_PROFILE_ROOT']) if source.get('PZ_ADW_PROFILE_ROOT') else None)
    if raw is None:
        state = source.get('XDG_STATE_HOME') or str(Path(source.get('HOME') or Path.home()) / '.local/state')
        return Path(state) / 'pzagent-adw-context'
    raw = Path(raw)
    return raw.parent if raw.name == 'profile' else raw


def repository_id(repo: Path) -> str:
    value = load_json(project_dir(repo) / 'pzagent-adapter.json')
    identifier = value.get('repository', {}).get('id') if isinstance(value, dict) else None
    if (not isinstance(identifier, str) or not REPOSITORY.fullmatch(identifier)
            or any(part in ('.', '..') for part in identifier.split('/'))):
        raise ContractError('operator_home_repository_invalid')
    return identifier


def journals(repo: Path, home: Path | None = None) -> Path:
    """Private journals of this repository; never inside the checkout."""
    home = (home or operator_home()).absolute()
    checkout = repo.resolve()
    resolved = home.resolve()
    if resolved == checkout or checkout in resolved.parents:
        raise ContractError('operator_home_inside_checkout')
    return home / 'journals' / repository_id(repo)


def operation_root(repo: Path, home: Path | None = None) -> Path:
    """Workflow operation journals live in the operator home, never in the checkout;
    trusted retention scans them and legacy handover/ journals."""
    return journals(repo, home)


def operation_path(repo: Path, operation: str, home: Path | None = None) -> Path:
    if not isinstance(operation, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', operation) or operation in {'.', '..'}:
        raise ContractError('operator_home_operation_id_invalid')
    path = operation_root(repo, home) / operation
    if not path.exists() and (repo / 'handover' / operation).exists():
        raise ContractError('operator_home_operation_legacy: finish or resume it with the previous release')
    if not OPERATION_ID.fullmatch(operation):
        raise ContractError('operator_home_operation_id_invalid')
    for directory in reversed((path, *path.parents[:4])):
        if directory.is_symlink():
            raise ContractError('operation state must not be a symlink')
        if directory.exists() and (not directory.is_dir() or directory.stat().st_mode & 0o077):
            raise ContractError('operator_home_not_private')
    return path


def new_operation(repo: Path, kind: str = 'release') -> Path:
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,40}', kind):
        raise ContractError('operator_home_operation_kind_invalid')
    operation = kind + '-' + datetime.now(timezone.utc).strftime('%Y%m%d') + '-' + secrets.token_hex(6)
    path = operation_path(repo, operation)
    for index, directory in enumerate(reversed(path.parents[:4])):
        if directory.is_symlink():
            raise ContractError('operation state must not be a symlink')
        directory.mkdir(mode=0o700, parents=index == 0, exist_ok=True)
    path.mkdir(mode=0o700)
    return path


@contextmanager
def locked(directory: Path):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / '.lock'
    if path.is_symlink():
        raise ContractError('operation lock must not be a symlink')
    with path.open('a+b') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ContractError('operation is already running') from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def read(path: Path) -> dict:
    value = load_json(path)
    if not isinstance(value, dict) or value.get('schema_version') != '1.0.0':
        raise ContractError('invalid operation record')
    return value

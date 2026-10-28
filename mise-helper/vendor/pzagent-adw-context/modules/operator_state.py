"""Private local operation records; atomic writes, no credentials or provider env."""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

from .common import ContractError, load_json, project_dir

OPERATION_ID = re.compile(r'^[a-z][a-z0-9-]{0,40}-[0-9]{8}-[0-9a-f]{12}$')
REPOSITORY = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
TERMINAL_PHASES = {'complete', 'deprovisioned', 'retired', 'cancelled'}


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def terminal(record: dict) -> bool:
    return record.get('phase') in TERMINAL_PHASES or record.get('status') in {'ok', 'cancelled'}


def require_resumable(record: dict) -> None:
    # Completed operations remain readable/idempotent. Retirement is irreversible.
    if record.get('phase') in {'cancelled', 'retired', 'deprovisioned'} or record.get('status') == 'cancelled':
        raise ContractError('operation_terminal_resume_refused')


def resolved_scope(adapter: dict, kind: str, environment: str | None, target: str | None) -> dict:
    """Capture immutable logical scope, hashing the binding instead of storing it."""
    scope = {'repository': adapter['repository']['id'], 'release_kind': kind}
    if environment is None:
        return scope
    group = adapter['targets'].get(environment)
    name = target or (group or {}).get('default')
    if not group or name not in group['items']:
        raise ContractError('operation_scope_target_invalid')
    item = group['items'][name]
    binding = adapter['providers'][item['provider']]['bindings'][item['provider_binding']]
    identity = {'provider': item['provider'], 'provider_binding': item['provider_binding'], 'binding': binding}
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {**scope, 'environment': environment, 'target': name,
            'provider': item['provider'], 'provider_binding': item['provider_binding'],
            'binding_sha256': 'sha256:' + digest}


def require_scope(adapter: dict, record: dict) -> dict | None:
    """New journals cannot silently resume against a rebound provider or default."""
    if 'scope' not in record:
        return None  # Legacy identity is unknown, never reconstructed from today's defaults.
    scope = record['scope']
    selection = record.get('selection') if isinstance(record.get('selection'), dict) else {}
    if not isinstance(scope, dict):
        raise ContractError('operation_scope_changed')
    kind = record.get('kind', selection.get('release_kind'))
    environment = record.get('environment', selection.get('environment'))
    target = scope.get('target')
    try:
        expected = resolved_scope(adapter, kind, environment, target)
    except (ContractError, KeyError, TypeError):
        raise ContractError('operation_scope_changed') from None
    if scope != expected or record.get('target', selection.get('target')) not in {None, target}:
        raise ContractError('operation_scope_changed')
    return scope


def private_directory(directory: Path) -> None:
    """Create every missing directory 0700; mkdir(parents=True, mode=...) leaves the parents at the default mode."""
    missing = []
    for candidate in (directory, *directory.parents):
        if candidate.exists() or candidate.is_symlink():
            break
        missing.append(candidate)
    for candidate in reversed(missing):
        candidate.mkdir(mode=0o700, exist_ok=True)


def write_journal(path: Path, value: dict) -> None:
    """Stamp operator journals without changing closed provider/evidence schemas."""
    if path.is_symlink():
        raise ContractError('operation state must not be a symlink')
    operator_journal = (value.get('workflow') in {'deploy-existing', 'publish', 'publish-deploy', 'retention', 'source-line'}
                        or (path.name == 'deployment.json' and isinstance(value.get('selection'), dict)))
    if operator_journal and path.name in {'operation.json', 'deployment.json'} and value.get('schema_version') == '1.0.0':
        now = timestamp()
        if not path.exists():
            value.setdefault('created_at', now)
        elif path.is_file():
            previous = read(path)
            # These identities may never be repaired from today's adapter or clock.
            for key in ('scope', 'created_at'):
                if key in previous:
                    if key in value and value[key] != previous[key]:
                        raise ContractError('operation_immutable_identity_changed')
                    value[key] = previous[key]
                elif key in value:
                    raise ContractError('operation_legacy_identity_unknown')
        value['updated_at'] = now
    write(path, value)


def write(path: Path, value: dict) -> None:
    private_directory(path.parent)
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
    private_directory(directory)
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

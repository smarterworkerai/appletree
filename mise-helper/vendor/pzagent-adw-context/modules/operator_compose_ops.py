"""Operator-only Dokploy tasks on one owned Compose (#187): routed domains,
private Environment values and project data import.

Everything goes through the capability-validated Dokploy API; no SSH or host
access. Secret values and imported data never reach output, receipts or
journals: only key names, counts, sizes and SHA-256 digests do.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from urllib.parse import urlparse

from .adapter import ENV_FILE, SERVICE_NAME as SERVICE, dokploy_routes as routes
from .common import ContractError
from .description_markers import verify_live
from .dokploy_lifecycle_api import identifier, one_named, placement, placement_server_id, rows
from .hooks import prove_source
from .provider_lifecycle import _binding, _client, _operator
from .providers.dokploy import environment_keys, target_lock
from .task_evidence import record_operator

ENV_KEY = re.compile(r'^[A-Z][A-Z0-9_]{0,127}$')
MAX_PRIVATE_FILE = 65536
MAX_SCRIPT = 65536
MAX_IMPORT = 16 * 1024 * 1024
CHUNK = 45000  # raw bytes per schedule command: ~60 KiB base64, below the observed transport limit
NEVER = '0 0 31 2 *'  # schedules stay disabled; this expression never fires either
SCHEDULE_PREFIX = 'adw-data-import-'


def _owned_compose(api, adapter, binding):
    """The declared, marker-owned Compose; same checks as pz:provider:servers.

    The installed Dokploy version and the typed lifecycle contract (including
    the domain, Environment and schedule operations) are validated first.
    """
    api.validate()
    def named(values, name):
        row = one_named(values, name)
        if row is None:
            raise ContractError('provider_resource_absent')
        return row
    project = named(api.projects(), binding['project'])
    parent = named(api.environments(identifier(project.get('projectId'))), binding['environment'])
    environment_id = identifier(parent.get('environmentId'))
    row = named(api.composes(environment_id), binding['resource'])
    detail = api.compose(identifier(row.get('composeId')))
    if detail.get('name') != binding['resource'] or detail.get('environmentId') != environment_id:
        raise ContractError('provider_resource_identity_changed')
    if verify_live(detail.get('description'), adapter['repository']['id'], 'compose', detail) is None:
        raise ContractError('provider_resource_unowned')
    placement_server_id(detail, placement(binding))
    return detail


def _select(adapter, environment, target):
    _operator()  # Refuse CI and unsafe run IDs before credentials or any API access.
    return _binding(adapter, environment, target)


def _receipt(operation_dir, result, private=()):
    record_operator(operation_dir, {key: value for key, value in result.items() if key not in private})
    return result


# --- routed domains -------------------------------------------------------

def _route_host(binding) -> str:
    key = (binding.get('probes') or {}).get('base_url_env')
    value = os.environ.get(key or '', '')
    if not key or not value:
        raise ContractError('provider_route_host_unavailable: set the binding probe base URL privately')
    parsed = urlparse(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.path not in {'', '/'} or parsed.query or parsed.port:
        raise ContractError('provider_route_host_invalid: the probe base URL must be https://<host>')
    return parsed.hostname


def _domain(row):
    return {key: row.get(key) for key in ('host', 'path', 'port', 'serviceName', 'https', 'certificateType',
                                          'domainType', 'stripPath', 'internalPath')}


def domains(repo: Path, adapter: dict, *, environment: str, target: str | None, profile_root,
            operation_dir: Path, apply: bool = False, api=None) -> dict:
    """Create the declared routed domains that are absent; never modify existing ones."""
    selected, binding = _select(adapter, environment, target)
    declared = routes(binding)
    source = prove_source(repo, adapter)
    result = {'status': 'ok', 'task': 'pz:provider:domains', 'environment': environment, 'target': selected,
              'apply': apply, 'routes': [], 'mutations_requested': 0, 'source_sha': source}
    if not declared:
        return _receipt(operation_dir, {**result, 'status': 'skipped', 'reason': 'routes_undeclared'})
    host = _route_host(binding)
    api = _client(profile_root, api)
    compose = _owned_compose(api, adapter, binding)
    compose_id = identifier(compose['composeId'])
    with target_lock(repo, selected):
        existing = [_domain(row) for row in rows(api.get('domain.byComposeId', composeId=compose_id))]
        for route in declared:
            desired = {'host': host, 'path': route['path'], 'port': route['port'], 'serviceName': route['service'],
                       'https': True, 'certificateType': 'letsencrypt', 'domainType': 'compose',
                       'stripPath': False, 'internalPath': '/'}
            same = [row for row in existing if row['host'] == host and (row['path'] or '/') == route['path']]
            if same:
                action = 'exists' if desired in same else 'exists-different'
            elif not apply:
                action = 'create'
            else:
                api.post('domain.create', dict(desired, composeId=compose_id))
                result['mutations_requested'] += 1
                existing = [_domain(row) for row in rows(api.get('domain.byComposeId', composeId=compose_id))]
                action = 'created' if desired in existing else 'readback-mismatch'
            result['routes'].append({**route, 'action': action})
    if any(route['action'] == 'readback-mismatch' for route in result['routes']):
        result['status'] = 'blocked'
        result['reason'] = 'provider_domain_readback_mismatch'
    elif any(route['action'] == 'exists-different' for route in result['routes']):
        result['status'] = 'review'
        result['reason'] = 'existing domain differs from the declaration; it was left unchanged'
    result['note'] = 'Dokploy applies new domains on the next deployment of the Compose'
    result['host'] = host
    return _receipt(operation_dir, result, private={'host'})


# --- private Environment values ------------------------------------------

def _private_file(repo: Path, binding, environment: str, explicit: str | None) -> Path:
    name = explicit or binding.get('env_file') or '.env.' + environment
    if not isinstance(name, str) or not ENV_FILE.fullmatch(name) or name.endswith('.example'):
        raise ContractError('provider_env_file_invalid: use .env.<name> in the repository root')
    return repo / name


def _read_private(path: Path, *, required: bool) -> dict[str, str]:
    if path.is_symlink():
        raise ContractError('provider_env_file_unsafe')
    if not path.exists():
        if required:
            raise ContractError(f'provider_env_file_missing: create {path.name} (mode 0600) in the repository root')
        return {}
    status = path.stat()
    if not path.is_file() or stat.S_IMODE(status.st_mode) & 0o077 or status.st_size > MAX_PRIVATE_FILE:
        raise ContractError(f'provider_env_file_not_private: {path.name} must be a regular mode-0600 file')
    values = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if '=' not in line:
            raise ContractError(f'provider_env_file_malformed: {path.name}')
        key, value = line.split('=', 1)
        key = key.strip()
        if not ENV_KEY.fullmatch(key) or key in values or '\r' in value:
            raise ContractError(f'provider_env_file_malformed: {path.name}')
        values[key] = value
    return values


def _write_private(path: Path, values: dict[str, str]) -> None:
    previous = path.read_text(encoding='utf-8') if path.exists() else ''
    lines, written = [], set()
    for line in previous.splitlines():
        key = line.split('=', 1)[0].strip() if '=' in line and not line.lstrip().startswith('#') else None
        if key in values:
            lines.append(f'{key}={values[key]}')
            written.add(key)
        else:
            lines.append(line)
    lines += [f'{key}={value}' for key, value in values.items() if key not in written]
    temporary = path.with_name(path.name + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(lines) + '\n')
    os.replace(temporary, path)


def _schema_keys(repo: Path, binding) -> tuple[set[str], set[str]]:
    document = json.loads((repo / binding['environment_schema_path']).read_text(encoding='utf-8'))
    keys, optional = set(document.get('keys', [])), set(document.get('optional_keys', []))
    if not all(isinstance(key, str) and ENV_KEY.fullmatch(key) for key in keys) or not optional <= keys:
        raise ContractError('provider_environment_schema_invalid')
    return keys, optional


def _image_keys(adapter) -> set[str]:
    return {key for kind in adapter.get('release_kinds', {}).values() for key in (kind.get('image_variables') or {})}


def _backup(operation_dir: Path, raw: bytes) -> dict:
    """Private copy of the live Environment before any write; only its path and digest are reported."""
    operation_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(operation_dir.stat().st_mode) & 0o077:
        raise ContractError('provider_environment_backup_not_private')
    path = operation_dir / 'environment-backup.env'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'keys': len(environment_keys(raw))}


def env_apply(repo: Path, adapter: dict, *, environment: str, target: str | None, profile_root,
              operation_dir: Path, env_file: str | None = None, generate=(), replace=(),
              apply: bool = False, api=None) -> dict:
    """Append missing schema keys from the private file; never overwrite unless named in replace."""
    selected, binding = _select(adapter, environment, target)
    path = _private_file(repo, binding, environment, env_file)
    keys, optional = _schema_keys(repo, binding)
    allowed = keys - _image_keys(adapter)
    for key in (*generate, *replace):
        if key not in allowed:
            raise ContractError(f'provider_env_key_not_settable: {key} is not a non-image key of the binding schema')
    values = _read_private(path, required=not generate)
    generated = sorted(key for key in generate if not values.get(key))
    if generated and apply:
        values.update({key: secrets.token_urlsafe(32) for key in generated})
        _write_private(path, {key: values[key] for key in generated})
    source = prove_source(repo, adapter)
    api = _client(profile_root, api)
    compose = _owned_compose(api, adapter, binding)
    compose_id = identifier(compose['composeId'])
    with target_lock(repo, selected):
        current = (api.compose(compose_id).get('env') or '').encode()
        present = environment_keys(current)
        add = sorted(key for key in values if key in allowed and values[key] and key not in present)
        if generated and not apply:
            add = sorted(set(add) | {key for key in generated if key not in present})
        replaced = sorted(key for key in replace if key in present and values.get(key))
        result = {'status': 'ok', 'task': 'pz:provider:env:apply', 'environment': environment, 'target': selected,
                  'env_file': path.name, 'apply': apply, 'present': sorted(present), 'append': add,
                  'replace': replaced, 'generated': generated,
                  'ignored_not_in_schema': sorted(key for key in values if key not in keys),
                  'missing_required': sorted((keys - optional - _image_keys(adapter)) - present - set(add)),
                  'mutations_requested': 0, 'source_sha': source}
        if apply and (add or replaced):
            output = []
            for line in current.splitlines(keepends=True):
                key = (line.split(b'=', 1)[0].strip().decode('ascii')
                       if b'=' in line and not line.strip().startswith(b'#') else None)
                output.append(f'{key}={values[key]}\n'.encode() if key in replaced else line)
            text = b''.join(output)
            if text and not text.endswith(b'\n'):
                text += b'\n'
            text += b''.join(f'{key}={values[key]}\n'.encode() for key in add)
            result['backup'] = _backup(operation_dir, current)
            api.post('compose.saveEnvironment', {'composeId': compose_id, 'env': text.decode()})
            result['mutations_requested'] = 1
            after = (api.compose(compose_id).get('env') or '').encode()
            # Every byte is compared (comments, order, line endings); none is reported.
            if after != text:
                result.update(status='blocked', reason='provider_environment_readback_mismatch')
            result['present'] = sorted(environment_keys(after))
    return _receipt(operation_dir, result)


# --- data import -----------------------------------------------------------

def data_import_spec(repo: Path, binding) -> dict:
    spec = binding.get('data_import')
    if spec is None:
        raise ContractError('provider_data_import_undeclared: declare data_import {service, script} on the binding')
    if (not isinstance(spec, dict) or set(spec) != {'service', 'script'} or not isinstance(spec['service'], str)
            or not SERVICE.fullmatch(spec['service']) or not isinstance(spec['script'], str)):
        raise ContractError('provider_data_import_invalid')
    script = (repo / spec['script']).resolve()
    if repo.resolve() not in script.parents or (repo / spec['script']).is_symlink() or not script.is_file() \
            or script.stat().st_size > MAX_SCRIPT:
        raise ContractError('provider_data_import_script_invalid')
    return {'service': spec['service'], 'script': script}


def _regular(path: Path, limit: int, reason: str) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ContractError(reason)
    return path.read_bytes()


def _chunks(data: bytes):
    for offset in range(0, len(data), CHUNK):
        yield base64.b64encode(data[offset:offset + CHUNK]).decode('ascii')


class _Schedule:
    """One disabled Compose schedule whose command is replaced per step and deleted at the end."""

    def __init__(self, api, compose, service, operation):
        self.api, self.compose, self.service = api, compose, service
        self.name = SCHEDULE_PREFIX + operation
        self.base = {'name': self.name, 'cronExpression': NEVER, 'scheduleType': 'compose',
                     'composeId': compose['composeId'], 'serviceName': service, 'shellType': 'sh',
                     'enabled': False, 'appName': compose['appName']}
        self.id = None

    def __enter__(self):
        listed = rows(self.api.get('schedule.list', id=self.compose['composeId'], scheduleType='compose'))
        if any(str(row.get('name', '')).startswith(SCHEDULE_PREFIX) for row in listed):
            raise ContractError('provider_data_import_schedule_leftover: delete the old adw-data-import-* schedule first')
        self.api.post('schedule.create', dict(self.base, command='true'))
        listed = rows(self.api.get('schedule.list', id=self.compose['composeId'], scheduleType='compose'))
        matches = [row for row in listed if row.get('name') == self.name]
        if len(matches) != 1:
            raise ContractError('provider_data_import_schedule_unproven')
        self.id = identifier(matches[0].get('scheduleId'))
        return self

    def run(self, command: str, step: str, *, timeout: int = 120):
        self.api.post('schedule.update', dict(self.base, scheduleId=self.id, command=command))
        before = len(self._runs())
        try:
            # Dokploy v0.29.2 runs the command synchronously and answers non-2xx on a non-zero exit.
            self.api.post('schedule.runManually', {'scheduleId': self.id}, timeout=timeout)
        except ContractError as exc:
            raise ContractError(f'provider_data_import_step_failed: {step}') from exc
        runs = self._runs()
        newest = max(runs, key=lambda row: str(row.get('createdAt', '')), default={})
        # A success answer alone is not proof: the newest run must be recorded as done.
        if len(runs) <= before or newest.get('status') != 'done':
            raise ContractError(f'provider_data_import_step_unproven: {step}')

    def _runs(self):
        return rows(self.api.get('deployment.allByType', id=self.id, type='schedule'))

    def __exit__(self, *_):
        if self.id is not None:
            self.api.post('schedule.delete', {'scheduleId': self.id})
        return False


def data_import(repo: Path, adapter: dict, *, environment: str, target: str | None, profile_root,
                operation_dir: Path, file: Path, confirm: str | None = None, apply: bool = False,
                api=None) -> dict:
    """Transport a data file and the project's import script into the declared service and run it once."""
    selected, binding = _select(adapter, environment, target)
    spec = data_import_spec(repo, binding)
    data = _regular(Path(file), MAX_IMPORT, 'provider_data_import_file_invalid: a regular file up to 16 MiB')
    script = _regular(spec['script'], MAX_SCRIPT, 'provider_data_import_script_invalid')
    digest, script_digest = hashlib.sha256(data).hexdigest(), hashlib.sha256(script).hexdigest()
    source = prove_source(repo, adapter)
    operation = operation_dir.name
    result = {'status': 'ok', 'task': 'pz:data:import', 'environment': environment, 'target': selected,
              'service': spec['service'], 'script': str(spec['script'].relative_to(repo.resolve())),
              'script_sha256': script_digest, 'file_sha256': digest, 'file_bytes': len(data),
              'chunks': -(-len(data) // CHUNK) + -(-len(script) // CHUNK), 'apply': apply,
              'mutations_requested': 0, 'source_sha': source}
    if apply and confirm != environment:
        raise ContractError(f'provider_data_import_unconfirmed: pass --confirm {environment}')
    api = _client(profile_root, api)
    compose = _owned_compose(api, adapter, binding)
    compose['composeId'] = identifier(compose['composeId'])
    if not apply:
        return _receipt(operation_dir, {**result, 'phase': 'planned'})
    directory = f'/tmp/adw-import-{operation}'
    steps = 0
    with target_lock(repo, selected), _Schedule(api, compose, spec['service'], operation) as schedule:
        try:
            schedule.run(f'rm -rf {directory} && mkdir -m 700 {directory}', 'prepare')
            for name, content in (('import.sh', script), ('data', data)):
                for index, chunk in enumerate(_chunks(content)):
                    schedule.run(f'echo {chunk} | base64 -d >> {directory}/{name}', f'transfer {name} {index}')
                    steps += 1
            schedule.run(f'test "$(sha256sum {directory}/import.sh | cut -c1-64)" = {script_digest}'
                         f' && test "$(sha256sum {directory}/data | cut -c1-64)" = {digest}', 'verify')
            schedule.run(f'sh {directory}/import.sh {directory}/data', 'import', timeout=1800)
            result['phase'] = 'complete'
        except ContractError as exc:
            result.update(status='blocked', phase='failed', reason=str(exc))
        finally:
            try:
                schedule.run(f'rm -rf {directory}', 'cleanup')
            except ContractError:
                # The private data may still be in the container: never report success.
                result.update(status='blocked', cleanup='failed',
                              reason=result.get('reason') or 'provider_data_import_cleanup_failed')
    result['mutations_requested'] = steps + 4
    return _receipt(operation_dir, result)

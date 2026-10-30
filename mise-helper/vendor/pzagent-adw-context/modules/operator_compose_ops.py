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
import stat
import tempfile
from urllib.parse import urlparse

from .adapter import SERVICE_NAME as SERVICE, dokploy_routes as routes, probe_url_key
from .common import ContractError
from .description_markers import verify_live
from .dokploy_lifecycle_api import identifier, one_named, placement, placement_server_id, rows
from .hooks import prove_source
from .key_schema import contract, sources as resolve_sources
from .operator_credentials import (BOOTSTRAP, CLOUDFLARE, CLUSTER_ONLY, DOKPLOY, GROUPS, REGISTRY, SSH,
                                   entry_command, vault_generate, vault_secrets)
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

def _schema(repo: Path, binding, adapter, environment: str):
    """(keys, optional, sources) of a binding's key schema (#193 per-key format or the legacy list).

    `generate` and `human` default to vault ID `<project>.<environment>.<KEY>` in vault
    `shared/<project>-<environment>`; when several Dokploy bindings share the environment
    they must name an explicit `id`, so distinct targets never alias one vault value.
    `shared` names its vault ID; `release` marks an image variable.
    """
    try:
        document = json.loads((repo / binding['environment_schema_path']).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise ContractError('provider_environment_schema_invalid') from None
    required, keys, raw = contract(document, 'provider_environment_schema_invalid')
    optional = keys - required
    project = adapter['repository']['id'].rsplit('/', 1)[-1]
    shared_env = sum(1 for other in adapter['providers'].get('dokploy', {}).get('bindings', {}).values()
                     if other.get('environment') == environment) > 1
    sources = resolve_sources(raw, project=project, environment=environment, images=_image_keys(adapter),
                              explicit_ids=shared_env)
    return keys, optional, sources


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
              operation_dir: Path, replace=(),
              apply: bool = False, api=None) -> dict:
    """Append missing schema keys from the agent vault; replace only keys named in `replace` (#193).

    Each settable key's schema source decides its value: `shared` IDs are copied,
    a `generate` ID is created in the vault on apply only when neither the vault nor
    the target has a value, missing `human` IDs are listed with the exact entry command,
    and a value present only in the target is reported for import, never regenerated.
    Kubernetes targets get the same semantics on their own `"key-schema"` Secret.
    """
    group = adapter['targets'].get(environment, {})
    alias = target or group.get('default')
    if group.get('items', {}).get(alias, {}).get('provider') == 'kubernetes':
        _operator()
        from .providers.kubernetes_lifecycle import env_apply as kubernetes_env_apply
        return _receipt(operation_dir, kubernetes_env_apply(
            repo, adapter, environment=environment, target=alias, profile_root=profile_root,
            operation_dir=operation_dir, source_sha=prove_source(repo, adapter), replace=replace, apply=apply))
    selected, binding = _select(adapter, environment, target)
    keys, optional, sources = _schema(repo, binding, adapter, binding.get('environment', environment))
    allowed = keys - _image_keys(adapter)
    for key in replace:
        if key not in allowed:
            raise ContractError(f'provider_env_key_not_settable: {key} is not a non-image key of the binding schema')
    source = prove_source(repo, adapter)
    parent = dict(os.environ)
    vault, _ = vault_secrets({entry['id'] for entry in sources.values()}, parent) if sources else ({}, set())
    api = _client(profile_root, api)
    compose = _owned_compose(api, adapter, binding)
    compose_id = identifier(compose['composeId'])
    with target_lock(repo, selected):
        current = (api.compose(compose_id).get('env') or '').encode()
        present = environment_keys(current)
        values, generated, missing_human, missing_shared, import_needed = {}, [], [], [], []
        for key, entry in sorted(sources.items()):
            if entry['id'] in vault:
                values[key] = vault[entry['id']]
            elif key in present:
                import_needed.append(key)            # import the live value; never diverge
            elif entry['source'] == 'generate':
                generated.append(key)
            elif entry['source'] == 'human':
                missing_human.append({'key': key, 'vault': entry['vault'], 'id': entry['id'],
                                      'command': entry_command(entry['vault'], entry['id'], entry['description'], parent)})
            else:
                missing_shared.append({'key': key, 'id': entry['id']})
        if generated and apply:
            for key in generated:
                entry = sources[key]
                vault_generate(entry['vault'], entry['id'], entry['kind'], parent, length=entry['length'],
                               description=entry['description'])
            fresh, still = vault_secrets({sources[key]['id'] for key in generated}, parent)
            if still:
                raise ContractError('vault_generate_readback_failed')
            values.update({key: fresh[sources[key]['id']] for key in generated})
        add = sorted(key for key in values if key in allowed and values[key] and key not in present)
        if not apply:
            add = sorted(set(add) | {key for key in generated if key not in present})
        replaced = sorted(key for key in replace if key in present and values.get(key))
        result = {'status': 'ok', 'task': 'pz:provider:env:apply', 'environment': environment, 'target': selected,
                  'apply': apply, 'present': sorted(present), 'append': add, 'replace': replaced,
                  'vault': {'sourced': sorted(sources), 'generated': generated if apply else [],
                            'would_generate': [] if apply else generated,
                            'missing_human': missing_human, 'missing_shared': missing_shared,
                            'missing_in_vault_present_in_target': import_needed,
                            'push_required': bool(generated and apply)},
                  'unsourced': sorted(allowed - set(sources)),
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


# --- secrets overview (#193 item 6) ----------------------------------------

def _environment_values(text: bytes) -> dict[str, str]:
    values = {}
    for line in text.decode(errors='replace').splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            values[key.strip()] = value
    return values


def _state(live: dict | None, key: str, vault_id: str | None, vault: dict) -> str:
    if not live or not live.get(key):
        return 'missing'
    if vault_id is not None and vault_id in vault:
        return 'same' if live[key] == vault[vault_id] else 'differs'
    return 'present'


def _kubernetes_rows(repo, adapter, environment, alias, profile_root, parent, rows, skipped) -> None:
    """Rows for one Kubernetes target's application Secrets, compared like Dokploy's (#193)."""
    from .providers.kubernetes_lifecycle import observe_app_secrets
    declared = observe_app_secrets(repo, adapter, environment=environment, target=alias, profile_root=profile_root)
    if not declared:
        skipped.append({'target': alias, 'provider': 'kubernetes', 'reason': 'no_app_secrets'})
        return
    ids = {field['vault'] for secret in declared for field in secret['fields'].values() if 'vault' in field}
    locations = {}
    vault, _missing = vault_secrets(ids, parent, locations=locations) if ids else ({}, set())
    for secret in declared:
        if not secret['owned']:
            skipped.append({'target': alias, 'provider': 'kubernetes', 'secret': secret['name'],
                            'reason': 'secret_not_owned'})
            continue
        for key, field in sorted(secret['fields'].items()):
            entry = secret['schema'].get(key)
            vault_id = field.get('vault')
            if entry is not None and entry['id'] == vault_id:
                kind, scope = entry['source'], entry.get('vault') or locations.get(vault_id)
            else:
                # Deprecated per-key profile sources: operator variable, cluster-generated or explicit vault ID.
                kind = 'vault' if vault_id else 'operator-env' if 'env' in field else 'cluster-generated'
                scope = field.get('scope')
            rows.append({'target': alias, 'secret': secret['name'], 'key': key,
                         'required': key not in secret['optional'], 'source': kind, 'vault_scope': scope,
                         'vault_id': vault_id,
                         'vault': None if vault_id is None else ('present' if vault_id in vault else 'missing'),
                         'state': _state(secret['values'], key, vault_id, vault)})


def _attention(row) -> bool:
    """Drift, a value only in the target (import it), or a required value missing anywhere."""
    if row['state'] == 'differs':
        return True
    if row['vault'] == 'missing' and row['state'] != 'missing':
        return True
    return row['required'] and (row['state'] == 'missing' or row['vault'] == 'missing')


def _offline_rows(repo: Path, adapter: dict, environment: str, group: dict) -> list[dict]:
    """What each target expects, from the committed adapter and key schemas alone (#193)."""
    from .providers.kubernetes_lifecycle import schema_sources
    rows = []
    for alias in sorted(group['items']):
        declaration = group['items'][alias]
        provider = declaration.get('provider')
        if provider == 'dokploy':
            _, binding = _binding(adapter, environment, alias)
            keys, optional, sources = _schema(repo, binding, adapter, binding.get('environment', environment))
            images = _image_keys(adapter)
        elif provider == 'kubernetes':
            binding = adapter['providers']['kubernetes']['bindings'][declaration['provider_binding']]
            sources, optional = schema_sources(repo, adapter, binding)
            try:
                document = json.loads((repo / binding['config_schema_path']).read_text(encoding='utf-8'))
            except (OSError, ValueError):
                raise ContractError('kubernetes_key_schema_invalid') from None
            keys = contract(document, 'kubernetes_key_schema_invalid')[1]
            images = set(binding.get('image_variables') or {})
        else:
            continue
        for key in sorted(keys):
            entry = sources.get(key)
            rows.append({'target': alias, 'provider': provider, 'key': key, 'required': key not in optional,
                         'source': 'release' if key in images else (entry['source'] if entry else 'unsourced'),
                         'vault_scope': entry.get('vault') if entry else None,
                         'vault_id': entry['id'] if entry else None})
    return rows


EXAMPLES = ('.env.example', '.env.deploy.example')
ENV_NAME = re.compile(r'^[A-Z][A-Z0-9_]{0,127}$')
GUIDE = 'references/secrets.md of the pzagent-adw-context skill'


# Notes for the operator credentials the resolver grants; names come from its constants.
CREDENTIAL_NOTES = {'DOKPLOY_URL': 'Dokploy manager URL', 'DOKPLOY_API_KEY': 'Dokploy API key',
                    'GITHUB_TOKEN': 'releases, promotion and registry readback',
                    'REGISTRY_TOKEN': 'optional separate registry publication token',
                    'GHCR_USERNAME': 'Kubernetes pull Secret user (name set in kubernetes-provisioning.json)',
                    'GHCR_PULL_TOKEN': 'Kubernetes pull Secret, read:packages only',
                    'PZ_ADW_SSH_ALIAS': 'hotfix SSH transport: an ssh_config alias, or the TERMINAL_SSH_* parts',
                    'TERMINAL_SSH_HOST': 'hotfix SSH transport without an alias: host',
                    'TERMINAL_SSH_USER': 'hotfix SSH transport without an alias: user',
                    'TERMINAL_SSH_PORT': 'hotfix SSH transport without an alias: port',
                    'TERMINAL_SSH_KEY': 'hotfix SSH transport without an alias: private key'}


def _credentials(keys: set[str]) -> list[str]:
    """The canonical names of a resolver key set (one per alias group), sorted."""
    aliases = {alias for group in GROUPS for alias in group[1:]}
    return sorted(set(keys) - aliases)


def _example_line(key: str, note: str) -> str:
    return f'{key}='.ljust(44) + '  # ' + note + '\n'


def render_examples(repo: Path, adapter: dict) -> dict[str, bytes]:
    """The keys-only root `.env.example` and `.env.deploy.example`, from committed files alone.

    Documentation for readers without tooling: nobody fills them and no task reads them.
    Every value comes from pz-secretctl; the vault ID is in each line's comment.
    """
    app = adapter['repository']['id'].rsplit('/', 1)[-1]
    providers = adapter.get('providers') or {}
    head = ('# KEYS ONLY - generated by `mise run pz:secrets:examples` from the committed adapter\n'
            '# and key schemas; `mise run pz:secrets:examples:check` (CI) keeps it current.\n'
            '# Nobody fills this file and no task reads it: every value comes from pz-secretctl\n'
            f'# (the agent vault). Recipes: {GUIDE}.\n')
    deploy = [head, '\n# Operator credentials of the ADW tasks (shared vault IDs = these names).\n']
    granted = set(REGISTRY)
    if providers.get('dokploy', {}).get('bindings'):
        granted |= DOKPLOY
    if providers.get('kubernetes', {}).get('bindings'):
        granted |= BOOTSTRAP - CLOUDFLARE - CLUSTER_ONLY           # the pull Secret inputs
    transports = (adapter.get('hotfix') or {}).get('transports', [])
    # The adapter contract: a list, or one list per provider (codex-1725).
    if 'ssh-docker' in ([value for values in transports.values() for value in values]
                        if isinstance(transports, dict) else transports):
        granted |= SSH
    deploy += [_example_line(key, CREDENTIAL_NOTES.get(key, 'operator credential'))
               for key in _credentials(granted)]
    templates = sorted({probe_url_key(provider, binding['environment'])
                        for provider, settings in providers.items()
                        for binding in (settings.get('bindings') or {}).values()
                        if binding.get('environment') and binding.get('probes', {}).get('base_url') is None
                        and (binding.get('probes') or provider == 'kubernetes')})
    if templates:
        deploy.append(f'\n# Probe URL templates, {{app}} = {app} (literal probes.base_url bindings need none).\n')
        deploy += [_example_line(key, 'shared vault ID') for key in templates]
    application = [head, '\n# Application secrets per environment: what pz:provider:env:apply and Kubernetes\n'
                   '# provisioning write into the Dokploy Environment or the Secret. Image variables are\n'
                   '# set by deployment; non-secret settings live in Compose files and ConfigMaps in Git;\n'
                   '# local development inputs, if any, live in .env.local.example.\n']
    for environment in sorted(adapter.get('targets', {})):
        rows = _offline_rows(repo, adapter, environment, adapter['targets'][environment])
        secrets = {}
        for row in rows:
            if row['source'] in {'generate', 'human', 'shared'}:
                entry = secrets.setdefault((row['key'], row['vault_id']), dict(row, targets=[]))
                entry['targets'].append(row['target'])
                entry['required'] = entry['required'] or row['required']
        if not secrets:
            continue
        targets = sorted({row['target'] for row in rows})
        application.append(f'\n# --- {environment} ({", ".join(targets)})\n')
        for (key, _), row in sorted(secrets.items()):
            note = row['source'] + ' -> ' + row['vault_id'] + (f' ({row["vault_scope"]})' if row['vault_scope'] else '')
            if len(row['targets']) < len(targets):
                note += ', only ' + ', '.join(sorted(row['targets']))
            application.append(_example_line(key, note + ('' if row['required'] else ', optional')))
    if not any(line.startswith('# --- ') for line in application):
        application.append('\n# No environment declares an application secret.\n')
    return {'.env.example': ''.join(application).encode(), '.env.deploy.example': ''.join(deploy).encode()}


def _example_current(repo: Path, name: str) -> bytes | None:
    """The committed output's bytes; a link, hardlink or non-regular file refuses before any read."""
    path = repo / name
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ContractError('secret_examples_path_unsafe: ' + name)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as handle:
        return handle.read()


def secret_examples(repo: Path, adapter: dict, *, check: bool = False) -> dict:
    """`pz:secrets:examples` writes the two files; `pz:secrets:examples:check` only compares them.

    Each output is replaced atomically by its own new file, so no other name or link
    target can change (codex-1726).
    """
    desired = render_examples(repo, adapter)
    stale = sorted(name for name, data in desired.items() if _example_current(repo, name) != data)
    result = {'status': 'ok', 'task': 'pz:secrets:examples:check' if check else 'pz:secrets:examples',
              'files': list(EXAMPLES), 'stale' if check else 'written': stale}
    if check:
        if stale:
            result.update(status='blocked', reason='secret_examples_stale: run mise run pz:secrets:examples')
        return result
    for name in stale:
        descriptor, temporary = tempfile.mkstemp(prefix='.pz-secret-examples-', dir=repo)
        try:
            with os.fdopen(descriptor, 'wb') as handle:
                handle.write(desired[name])
            os.chmod(temporary, 0o644)
            os.replace(temporary, repo / name)
        finally:
            Path(temporary).unlink(missing_ok=True)
    return result


def secrets_show(repo: Path, adapter: dict, *, environment: str, profile_root, operation_dir: Path | None,
                 api=None, offline: bool = False) -> dict:
    """Every key one environment's Dokploy and Kubernetes targets get: source, vault ID and state.

    Values are compared in memory only (`same` / `differs`); the result and the receipt
    hold names, IDs and states, never a value. Values themselves are shown only by
    `pz-secretctl reveal` in an unlocked human terminal; `reveal` lists those commands
    per vault scope. `offline` lists what each target expects from the committed adapter
    and key schemas only: no credential, vault or provider access, no states, and no
    receipt or operator-home write.
    """
    group = adapter['targets'].get(environment)
    if not group:
        raise ContractError('provider_environment_undeclared')
    source = prove_source(repo, adapter)
    if offline:
        return {'status': 'ok', 'task': 'pz:secrets:show', 'environment': environment, 'offline': True,
                'rows': _offline_rows(repo, adapter, environment, group), 'mutations_requested': 0,
                'source_sha': source}
    parent = dict(os.environ)
    images = _image_keys(adapter)
    rows, skipped, client = [], [], None
    for alias in sorted(group['items']):
        declaration = group['items'][alias]
        if declaration.get('provider') == 'kubernetes':
            _kubernetes_rows(repo, adapter, environment, alias, profile_root, parent, rows, skipped)
            continue
        if declaration.get('provider') != 'dokploy':
            skipped.append({'target': alias, 'provider': declaration.get('provider'), 'reason': 'not_compared_yet'})
            continue
        selected, binding = _select(adapter, environment, alias)
        keys, optional, sources = _schema(repo, binding, adapter, binding.get('environment', environment))
        locations = {}
        vault, _missing = (vault_secrets({entry['id'] for entry in sources.values()}, parent, locations=locations)
                           if sources else ({}, set()))
        client = client or _client(profile_root, api)
        compose = _owned_compose(client, adapter, binding)
        live = _environment_values((client.compose(identifier(compose['composeId'])).get('env') or '').encode())
        for key in sorted(keys):
            entry = sources.get(key)
            kind = 'release' if key in images else (entry['source'] if entry else 'unsourced')
            vault_id = entry['id'] if entry else None
            in_vault = None if vault_id is None else ('present' if vault_id in vault else 'missing')
            state = _state(live, key, vault_id, vault)
            rows.append({'target': selected, 'key': key, 'required': key not in optional, 'source': kind,
                         'vault_scope': (entry.get('vault') or locations.get(vault_id)) if entry else None,
                         'vault_id': vault_id, 'vault': in_vault, 'state': state})
    result = {'status': 'ok', 'task': 'pz:secrets:show', 'environment': environment, 'rows': rows,
              'not_compared': skipped,
              'attention': sorted({row['key'] for row in rows if _attention(row)}),
              'reveal': [f'pz-secretctl --operator <operator> reveal --vault {scope}'
                         for scope in sorted({row['vault_scope'] for row in rows if row['vault_scope']})],
              'mutations_requested': 0, 'source_sha': source}
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
        before = set(self._runs())
        try:
            # Dokploy v0.29.2 runs the command synchronously and answers non-2xx on a non-zero exit.
            self.api.post('schedule.runManually', {'scheduleId': self.id}, timeout=timeout)
        except ContractError as exc:
            raise ContractError(f'provider_data_import_step_failed: {step}') from exc
        # A success answer alone is not proof: exactly one run that was not there
        # before must be recorded as done (identities, so a bounded history works).
        fresh = [status for identity, status in self._runs().items() if identity not in before]
        if fresh != ['done']:
            raise ContractError(f'provider_data_import_step_unproven: {step}')

    def _runs(self) -> dict:
        runs = {}
        for row in rows(self.api.get('deployment.allByType', id=self.id, type='schedule')):
            identity = row.get('deploymentId')
            if not isinstance(identity, str) or not identity or identity in runs:
                raise ContractError('provider_data_import_run_history_invalid')
            runs[identity] = row.get('status')
        return runs

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

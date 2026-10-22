"""Operator-only, owned Dokploy provisioning with private resumable state."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets

from .common import ContractError, IDENTIFIER, ensure_contained
from .dokploy_lifecycle_api import API, HTTP, Missing, RESOURCE_FIELDS, identifier, one_named, rows
from .execution import human
from .hooks import prove_source
from .operator_state import locked, read, write
from .providers.dokploy import ProviderNames, discover_binding, profile_credentials, _key_contract
from .release_manifest import image_variables

NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 _-]{0,126}$')
ENV_KEY = re.compile(r'^[A-Z][A-Z0-9_]{0,127}$')
MARKER = 'adw-provision:v1:'


def _marker(state, role):
    selection = state['selection']
    parents = ('project', 'environment') if role == 'compose' else (('project',) if role == 'environment' else ())
    return MARKER + json.dumps({'operation': state['operation_id'], 'nonce': state['nonce'],
        'repository': selection['repository'], 'environment': selection['environment'],
        'target': selection['target'], 'role': role,
        'parents': {name: state['resources'][name]['created'] for name in parents},
        'runtime': state['resources'].get(role, {}).get('pending_runtime_scope',
                   state['resources'].get(role, {}).get('runtime_scope'))},
        sort_keys=True, separators=(',', ':'))


def _parse_marker(description, operation, role):
    if not isinstance(description, str) or not description.startswith(MARKER):
        return None
    try:
        value = json.loads(description[len(MARKER):])
    except (ValueError, TypeError):
        if operation in description:
            raise ContractError('provider_ownership_marker_invalid') from None
        return None
    if not isinstance(value, dict) or value.get('operation') != operation:
        return None
    if (set(value) != {'operation', 'nonce', 'repository', 'environment', 'target', 'role', 'parents', 'runtime'}
            or value['role'] != role or not isinstance(value['nonce'], str)
            or not re.fullmatch(r'[0-9a-f]{32}', value['nonce'])
            or any(not isinstance(value[k], str) or not IDENTIFIER.fullmatch(value[k]) for k in ('environment', 'target'))
            or not isinstance(value['repository'], str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value['repository'])
            or not isinstance(value['parents'], dict)
            or set(value['parents']) != ({'project', 'environment'} if role == 'compose' else ({'project'} if role == 'environment' else set()))
            or any(not isinstance(v, bool) for v in value['parents'].values())):
        raise ContractError('provider_ownership_marker_invalid')
    if value['runtime'] is not None:
        _validate_runtime_scope(value['runtime'])
    return value


def _validate_runtime_scope(value):
    if not isinstance(value, dict) or set(value) != {'environment', 'compose'}:
        raise ContractError('provider_runtime_marker_invalid')
    for role, fields in (('environment', {'id', 'name', 'created', 'parent', 'is_default'}),
                         ('compose', {'id', 'name', 'created', 'parent', 'app_name', 'server_id'})):
        entry = value[role]
        if (not isinstance(entry, dict) or set(entry) != fields or not isinstance(entry['created'], bool)
                or not isinstance(entry['name'], str) or not NAME.fullmatch(entry['name'])):
            raise ContractError('provider_runtime_marker_invalid')
        identifier(entry['id']); identifier(entry['parent'])
    compose, environment = value['compose'], value['environment']
    if (compose['created'] is not True or compose['parent'] != environment['id']
            or not isinstance(environment['is_default'], bool)
            or not isinstance(compose['app_name'], str)
            or not re.fullmatch(r'[a-zA-Z0-9._-]{1,128}', compose['app_name'])):
        raise ContractError('provider_runtime_marker_invalid')
    identifier(compose['server_id'])


def _retain_runtime_scope(api, state, save):
    """Keep the runtime label/server on an owned ancestor before child deletion."""
    resources = state['resources']
    if 'compose' not in resources or not resources['compose']['created']:
        return 0
    role = next((name for name in ('project', 'environment')
                 if resources.get(name, {}).get('created') and not resources[name].get('is_default')), None)
    if role is None and resources.get('project', {}).get('created'):
        role = 'project'
    if role is None:
        return 0  # Adopted ancestors are never modified.
    snapshot = {name: {key: value for key, value in resources[name].items()
                      if key not in {'deleted', 'runtime_scope', 'pending_runtime_scope'}}
                for name in ('environment', 'compose')}
    _validate_runtime_scope(snapshot)
    entry = resources[role]
    if entry.get('runtime_scope') == snapshot:
        return 0
    current = _get_resource(api, role, entry)
    if current is None:
        raise ContractError('provider_runtime_marker_parent_absent')
    _identity(role, current, entry, _marker(state, role))
    if entry.get('pending_runtime_scope'):
        # A lost acknowledgement is reconciled by exact readback, not a retry.
        entry['runtime_scope'] = entry.pop('pending_runtime_scope')
        save()
        return 0
    entry['pending_runtime_scope'] = snapshot
    save()
    key = 'projectId' if role == 'project' else 'environmentId'
    api.post(role + '.update', {key: entry['id'], 'name': entry['name'], 'description': _marker(state, role)})
    actual = _get_resource(api, role, entry)
    if actual is None:
        raise ContractError('provider_runtime_marker_parent_absent')
    _identity(role, actual, entry, _marker(state, role))
    entry['runtime_scope'] = entry.pop('pending_runtime_scope')
    save()
    return 1


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _operator():
    if not human():
        raise ContractError('provider_lifecycle_operator_only')
    from .task_evidence import run_id
    run_id()  # Fail before any access, rather than after a completed mutation.


def journal_path(repo: Path, profile: Path, operation: Path) -> Path:
    """IDs never live below a consumer checkout or its public evidence directory."""
    if profile is None:
        raise ContractError('provider_private_profile_required')
    profile, repo, operation = profile.absolute(), repo.resolve(), operation.resolve()
    if any(p.is_symlink() for p in (profile, *profile.parents)) or profile.resolve() == repo or repo in profile.resolve().parents:
        raise ContractError('provider_private_profile_invalid')
    if profile.exists() and (not profile.is_dir() or profile.stat().st_mode & 0o077):
        raise ContractError('provider_private_profile_not_private')
    profile.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = _hash({'repository_path': str(repo), 'operation_path': str(operation)})
    path = profile / 'provider-operations' / key / 'operation.json'
    if any(p.is_symlink() for p in (path, path.parent, path.parent.parent)):
        raise ContractError('provider_private_profile_invalid')
    return path


def _binding(adapter, environment, target):
    group = adapter['targets'].get(environment)
    if not group:
        raise ContractError('provider_environment_undeclared')
    target = target or group['default']
    declaration = group['items'].get(target)
    if not declaration or declaration['provider'] != 'dokploy':
        raise ContractError('provider_target_unsupported')
    binding = adapter['providers']['dokploy']['bindings'][declaration['provider_binding']]
    for field in ('project', 'environment', 'resource'):
        if not isinstance(binding.get(field), str) or not NAME.fullmatch(binding[field]):
            raise ContractError('provider_logical_name_invalid')
    if not ENV_KEY.fullmatch(binding.get('child_binding', '')):
        raise ContractError('provider_binding_invalid')
    return target, binding


def _client(profile, api):
    if api is not None:
        return api
    endpoint, credential = profile_credentials(profile)
    return API(HTTP(endpoint, credential))


def _load(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077 or path.stat().st_size > 262144:
        raise ContractError('provider_private_journal_invalid')
    value = read(path)
    required = {'schema_version', 'workflow', 'selection', 'nonce', 'operation_id', 'phase', 'resources', 'intents', 'server_id'}
    if (set(value) - (required | {'decommission'}) or not required <= set(value)
            or value['workflow'] != 'provider-provision' or not re.fullmatch(r'[0-9a-f]{32}', value.get('nonce', ''))
            or not isinstance(value['operation_id'], str) or not IDENTIFIER.fullmatch(value['operation_id'])
            or not isinstance(value['resources'], dict) or not isinstance(value['intents'], dict)):
        raise ContractError('provider_private_journal_invalid')
    return value


def _receipt(operation, state_path, state, *, phase, task, source, mutations, actions=(), **extra):
    selection = state['selection']
    result = {'status': 'ok', 'phase': phase, 'task': task, 'source_sha': source,
              'operation': state['operation_id'],
              'ownership': {role: 'created' if entry['created'] else 'adopted' for role, entry in state['resources'].items()},
              'environment': selection['environment'], 'target': selection['target'],
              'binding': selection['binding'], 'runtime_activated': False,
              'mutations_requested': mutations, 'actions': list(actions),
              'operation_digest': 'sha256:' + _hash({'selection': selection, 'nonce': state['nonce'],
                  'server_id': state['server_id'], 'image_variable_keys': state['intents'].get('compose-image-keys', [])}),
              'private_journal_sha256': hashlib.sha256(state_path.read_bytes()).hexdigest(), **extra}
    # pz operator receipts are distinct from generic adw quality evidence.
    from .task_evidence import record_operator
    record_operator(operation, result)
    return result


def _entry(role, row, *, created, parent=None):
    key = {'project': 'projectId', 'environment': 'environmentId', 'default_environment': 'environmentId', 'compose': 'composeId'}[role]
    result = {'id': identifier(row.get(key)), 'name': row.get('name'), 'created': created, 'deleted': False}
    if not isinstance(result['name'], str) or not NAME.fullmatch(result['name']):
        raise ContractError('provider_inventory_invalid')
    if parent is not None:
        result['parent'] = identifier(parent)
    if role in {'environment', 'default_environment'}:
        if not isinstance(row.get('isDefault'), bool):
            raise ContractError('provider_inventory_invalid')
        result['is_default'] = row['isDefault']
    if role == 'compose':
        from .dokploy_lifecycle_api import APP_NAME
        app_name = row.get('appName')
        if not isinstance(app_name, str) or not APP_NAME.fullmatch(app_name):
            raise ContractError('provider_runtime_scope_invalid')
        result.update(app_name=app_name, server_id=identifier(row.get('serverId')))
    description = row.get('description')
    if created and isinstance(description, str) and description.startswith(MARKER):
        try:
            runtime = json.loads(description[len(MARKER):]).get('runtime')
        except (ValueError, AttributeError):
            raise ContractError('provider_ownership_marker_invalid') from None
        if runtime is not None:
            _validate_runtime_scope(runtime)
            result['runtime_scope'] = runtime
    return result


def _identity(role, row, entry, marker):
    key = {'project': 'projectId', 'environment': 'environmentId', 'default_environment': 'environmentId', 'compose': 'composeId'}[role]
    if row.get(key) != entry['id'] or row.get('name') != entry['name']:
        raise ContractError('provider_resource_identity_changed')
    parent_key = 'environmentId' if role == 'compose' else 'projectId'
    if 'parent' in entry and row.get(parent_key) != entry['parent']:
        raise ContractError('provider_resource_parent_changed')
    implicit_default = role in {'environment', 'default_environment'} and entry.get('is_default') is True
    if role in {'environment', 'default_environment'} and (
            row.get('isDefault') is not entry.get('is_default')
            or (implicit_default and (row.get('name') != 'production' or entry.get('name') != 'production'))
            or (role == 'default_environment' and not implicit_default)):
        raise ContractError('provider_default_environment_changed')
    if entry['created'] and not implicit_default and row.get('description') != marker:
        raise ContractError('provider_resource_ownership_changed')
    if role == 'compose' and (row.get('appName') != entry['app_name'] or row.get('serverId') != entry['server_id']):
        raise ContractError('provider_runtime_scope_changed')


def _server(api, selector_key):
    values = rows(api.servers())
    requested = None
    if selector_key:
        if not ENV_KEY.fullmatch(selector_key) or not os.environ.get(selector_key):
            raise ContractError('provider_server_selection_required')
        requested = os.environ[selector_key]
    matches = [row for row in values if requested is None or row.get('name') == requested]
    if len(matches) != 1:
        raise ContractError('provider_server_selection_ambiguous')
    return identifier(matches[0].get('serverId'))


def _image_slot_keys(repo, adapter, binding):
    kinds = adapter.get('release_kinds', {})
    if not kinds:
        return ()
    path = ensure_contained(repo, binding['environment_schema_path'])
    if not path.is_file() or path.stat().st_size > 262144:
        raise ContractError('provider_image_key_schema_invalid')
    try:
        _, allowed = _key_contract(json.loads(path.read_text()))
    except (OSError, ValueError, TypeError):
        raise ContractError('provider_image_key_schema_invalid') from None
    if len(allowed) > 128 or any(not isinstance(key, str) or not ENV_KEY.fullmatch(key) for key in allowed):
        raise ContractError('provider_image_key_schema_invalid')
    matches = [tuple(sorted(set(image_variables(kind)) & allowed)) for kind in kinds.values()]
    matches = [keys for keys in matches if keys]
    if len(matches) > 1:
        raise ContractError('provider_image_release_kind_ambiguous')
    return matches[0] if matches else ()


def _initialize_created_compose(api, state, image_keys, save):
    entry = state['resources']['compose']
    if not entry['created']:
        return 0
    actual = api.compose(entry['id'])
    _identity('compose', actual, entry, _marker(state, 'compose'))
    intents = state['intents']
    expected = ''.join(key + '=\n' for key in image_keys)
    source_pending = intents.get('compose-source') == 'raw-requested'
    images_pending = intents.get('compose-images') == 'empty-requested'
    if source_pending or images_pending:
        if (actual.get('sourceType') != 'raw' or (images_pending and actual.get('env') != expected)
                or actual.get('composeFile') != '' or api.containers(entry['app_name'], entry['server_id'])):
            raise ContractError('provider_initialization_outcome_unproven')
        if source_pending:
            intents['compose-source'] = 'raw-confirmed'
        if images_pending:
            intents['compose-images'] = 'empty-confirmed'
        save()
        if images_pending or not image_keys:
            return 0
    needs_raw = actual.get('sourceType') != 'raw'
    needs_images = bool(image_keys) and actual.get('env') in (None, '')
    if not needs_raw and not needs_images:
        return 0  # Never change an adopted or already-configured Environment.
    if (actual.get('sourceType') not in {'github', 'raw'} or actual.get('composeFile') != ''
            or 'env' not in actual or actual['env'] not in (None, '')
            or api.containers(entry['app_name'], entry['server_id'])):
        raise ContractError('provider_created_initialization_not_pristine')
    payload = {'composeId': entry['id'], 'sourceType': 'raw'}
    if needs_raw:
        intents['compose-source'] = 'raw-requested'
    if needs_images:
        payload['env'] = expected
        intents['compose-images'] = 'empty-requested'
    save()
    api.post('compose.update', payload)
    actual = api.compose(entry['id'])
    _identity('compose', actual, entry, _marker(state, 'compose'))
    if (actual.get('sourceType') != 'raw' or (needs_images and actual.get('env') != expected)
            or actual.get('composeFile') != '' or api.containers(entry['app_name'], entry['server_id'])):
        raise ContractError('provider_created_initialization_readback_differs')
    if needs_raw:
        intents['compose-source'] = 'raw-confirmed'
    if needs_images:
        intents['compose-images'] = 'empty-confirmed'
    save()
    return 1


def provision(repo: Path, adapter: dict, *, environment: str, target: str | None,
              profile_root: Path, operation_dir: Path, adopt=False, plan=False,
              server_name_env: str | None = None, api=None) -> dict:
    _operator()
    source = prove_source(repo, adapter)
    group = adapter['targets'].get(environment, {})
    declaration = group.get('items', {}).get(target or group.get('default'), {})
    if declaration.get('provider') == 'kubernetes':
        from .providers.kubernetes_lifecycle import provision as provision_kubernetes
        return provision_kubernetes(repo, adapter, environment=environment, target=target,
            profile_root=profile_root, operation_dir=operation_dir, adopt=adopt, plan=plan,
            server_name_env=server_name_env, source_sha=source)
    target, binding = _binding(adapter, environment, target)
    image_keys = _image_slot_keys(repo, adapter, binding)
    if server_name_env is not None and not ENV_KEY.fullmatch(server_name_env):
        raise ContractError('provider_server_selector_invalid')
    private = journal_path(repo, profile_root, operation_dir)
    selection = {'repository': adapter['repository']['id'], 'environment': environment, 'target': target,
                 'binding': binding, 'adopt': adopt, 'server_name_env': server_name_env}
    api = _client(profile_root, api)
    api.validate()
    with locked(private.parent), locked(operation_dir):
        state = _load(private) if private.exists() else {
            'schema_version': '1.0.0', 'workflow': 'provider-provision', 'selection': selection,
            'operation_id': 'provision-' + secrets.token_hex(16),
            'nonce': secrets.token_hex(16), 'phase': 'planned', 'resources': {}, 'intents': {}, 'server_id': None}
        if state['selection'] != selection:
            raise ContractError('provider_operation_selection_changed')
        prior_keys = state['intents'].get('compose-image-keys')
        if prior_keys is not None and prior_keys != list(image_keys):
            raise ContractError('provider_image_key_selection_changed')
        state['intents']['compose-image-keys'] = list(image_keys)
        if state.get('decommission'):
            raise ContractError('provider_operation_decommissioned')
        resources, actions, mutations = state['resources'], [], 0

        # Resolve every missing input before the first create. Bind the selected
        # registered server privately so a plan cannot silently switch servers.
        project_before = one_named(api.projects(), binding['project'])
        environment_before = (one_named(api.environments(identifier(project_before['projectId'])), binding['environment'])
                              if project_before is not None else None)
        compose_before = (one_named(api.composes(identifier(environment_before['environmentId'])), binding['resource'])
                          if environment_before is not None else None)
        server = (identifier(api.compose(identifier(compose_before['composeId'])).get('serverId'))
                  if compose_before is not None else _server(api, server_name_env))
        if server_name_env and server != _server(api, server_name_env):
            raise ContractError('provider_server_selection_changed')
        if state['server_id'] not in {None, server}:
            raise ContractError('provider_server_selection_changed')
        state['server_id'] = server
        write(private, state)

        def save():
            write(private, state)

        def ensure(role, existing, request, *, parent=None):
            nonlocal mutations
            marker = _marker(state, role)
            recorded = resources.get(role)
            if recorded:
                if not recorded['created'] and not adopt and not plan:
                    raise ContractError('provider_adoption_requires_explicit_flag')
                if existing is None:
                    raise ContractError('provider_recorded_resource_absent')
                _identity(role, existing, recorded, marker)
                actions.append('owned' if recorded['created'] else 'adopted')
                return existing
            intent = state['intents'].get(role)
            if existing is not None:
                created = intent == 'create-requested' and existing.get('description') == marker
                if not created and not adopt and not plan:
                    raise ContractError('provider_adoption_requires_explicit_flag')
                if intent and not created:
                    raise ContractError('provider_create_readback_conflict')
                resources[role] = _entry(role, existing, created=created, parent=parent)
                save()
                actions.append('create-confirmed' if created else 'adopt')
                return existing
            actions.append('create-' + role)
            if plan:
                return None
            if intent:
                raise ContractError('provider_create_outcome_unproven')
            state['intents'][role] = 'create-requested'
            state['phase'] = 'creating-' + role
            save()
            method, payload = request
            mutations += 1
            value = api.post(method, payload)
            row = value.get('project') if role == 'project' and isinstance(value, dict) else value
            if not isinstance(row, dict):
                raise ContractError('provider_create_response_invalid')
            resources[role] = _entry(role, row, created=True, parent=parent)
            _identity(role, row, resources[role], marker)
            save()
            return row

        project = project_before
        project = ensure('project', project, ('project.create', {'name': binding['project'], 'description': _marker(state, 'project')}))
        if project is None:
            actions.extend(['create-environment', 'create-compose'])
        else:
            project_id = identifier(project['projectId'])
            detail = api.project(project_id)
            _identity('project', detail, resources['project'], _marker(state, 'project'))
            environments = api.environments(project_id)
            if resources['project']['created']:
                defaults = [row for row in environments if row.get('isDefault') is True]
                if len(defaults) != 1 or defaults[0].get('name') != 'production':
                    raise ContractError('provider_default_environment_unproven')
                default = defaults[0]
                role = 'environment' if binding['environment'] == 'production' else 'default_environment'
                prior = resources.get(role)
                entry = _entry(role, default, created=True, parent=project_id)
                if prior and prior != entry:
                    raise ContractError('provider_default_environment_changed')
                resources[role] = entry
                save()
            env = one_named(environments, binding['environment'])
            if binding['environment'] == 'production' and env is None:
                raise ContractError('provider_default_environment_unproven')
            env = ensure('environment', env, ('environment.create', {
                'name': binding['environment'], 'projectId': project_id, 'description': _marker(state, 'environment')}), parent=project_id)
            if env is None:
                actions.append('create-compose')
            else:
                env_id = identifier(env['environmentId'])
                existing = one_named(api.composes(env_id), binding['resource'])
                if existing is not None:
                    existing = api.compose(identifier(existing.get('composeId')))
                if existing is not None and existing.get('serverId') != server:
                    raise ContractError('provider_server_selection_changed')
                ensure('compose', existing, ('compose.create', {
                    'name': binding['resource'], 'environmentId': env_id, 'serverId': server,
                    'description': _marker(state, 'compose'), 'composeType': 'docker-compose'}), parent=env_id)
        if not plan:
            resolved = discover_binding(api, ProviderNames(binding['project'], binding['environment'],
                                        binding['resource'], binding['child_binding']))
            if resolved.environment_id != resources['environment']['id'] or resolved.resource_id != resources['compose']['id']:
                raise ContractError('provider_created_binding_readback_differs')
            actual = api.compose(resolved.resource_id)
            _identity('compose', actual, resources['compose'], _marker(state, 'compose'))
            mutations += _initialize_created_compose(api, state, image_keys, save)
            mutations += _retain_runtime_scope(api, state, save)
            state['phase'] = 'complete'
            save()
        return _receipt(operation_dir, private, state, phase='planned' if plan else 'complete',
                        task='pz:provider:provision', source=source, mutations=mutations, actions=actions,
                        image_variable_keys=list(image_keys))


def _get_resource(api, role, entry):
    try:
        if role == 'project':
            return api.project(entry['id'])
        if role == 'compose':
            return api.compose(entry['id'])
        return api.environment(entry['id'])
    except Missing:
        return None


def _empty_environment(api, entry, owned_compose=None):
    current = api.environment(entry['id'])
    for field in RESOURCE_FIELDS:
        for child in rows(current.get(field)):
            if field != 'compose' or owned_compose is None or child.get('composeId') != owned_compose:
                raise ContractError('provider_foreign_child_present')


def _cleanup_scope(api, state):
    resources = state['resources']
    compose = resources.get('compose')
    for role, entry in resources.items():
        if not entry['created']:
            continue
        row = _get_resource(api, role, entry)
        if row is not None:
            _identity(role, row, entry, _marker(state, role) if role != 'default_environment' else '')
            if role in {'environment', 'default_environment'}:
                _empty_environment(api, entry, compose['id'] if compose and compose['created'] else None)
            if role == 'project':
                owned = {value['id'] for key, value in resources.items() if key in {'environment', 'default_environment'} and value['created']}
                if any(env['environmentId'] not in owned for env in api.environments(entry['id'])):
                    raise ContractError('provider_foreign_child_present')


def runtime_absence(api, state):
    """Return raw bounded observations; trusted retirement validates them itself."""
    entry = state['resources'].get('compose')
    if not entry:
        raise ContractError('provider_runtime_scope_unproven')
    return {'resource': _get_resource(api, 'compose', entry),
            'containers': api.containers(entry['app_name'], entry['server_id']),
            'app_name': entry['app_name'], 'server_id': entry['server_id']}


def _server_inventory(api):
    projects, environments, inventory = {}, {}, []
    count = 0
    for project in rows(api.projects()):
        project_id = identifier(project.get('projectId'))
        if project_id in projects:
            raise ContractError('provider_marker_inventory_ambiguous')
        project = api.project(project_id)
        projects[project_id] = project
        inventory.append(('project', project))
        for environment in rows(api.environments(project_id)):
            env_id = identifier(environment.get('environmentId'))
            if env_id in environments:
                raise ContractError('provider_marker_inventory_ambiguous')
            environments[env_id] = environment
            inventory.append(('environment', environment))
            for compose in rows(api.composes(env_id)):
                inventory.append(('compose', compose))
        count = len(inventory)
        if count > 4096:
            raise ContractError('provider_marker_inventory_unbounded')
    return inventory, projects, environments


def list_operations(adapter, *, profile_root=None, api=None):
    _operator()
    api = _client(profile_root, api)
    api.validate()
    inventory, _, _ = _server_inventory(api)
    operations = {}
    for role, row in inventory:
        description = row.get('description')
        if not isinstance(description, str) or not description.startswith(MARKER):
            continue
        try:
            operation = json.loads(description[len(MARKER):])['operation']
        except (ValueError, TypeError, KeyError):
            raise ContractError('provider_ownership_marker_invalid') from None
        if not isinstance(operation, str) or not IDENTIFIER.fullmatch(operation):
            raise ContractError('provider_ownership_marker_invalid')
        marker = _parse_marker(description, operation, role)
        if marker['repository'] != adapter['repository']['id']:
            continue
        item = operations.setdefault(operation, {'operation': operation, 'environment': marker['environment'],
            'target': marker['target'], 'created_roles': [], '_nonce': marker['nonce']})
        if (item['environment'] != marker['environment'] or item['target'] != marker['target']
                or item['_nonce'] != marker['nonce'] or role in item['created_roles']):
            raise ContractError('provider_ownership_marker_collision')
        item['created_roles'].append(role)
    return {'status': 'ok', 'task': 'pz:provider:deprovision', 'phase': 'listed', 'mutations_requested': 0,
            'operations': [{k: sorted(v) if k == 'created_roles' else v for k, v in item.items() if k != '_nonce'}
                           for _, item in sorted(operations.items())]}


def _discover_operation(api, adapter, operation, previous=None):
    """Reconstruct deletion scope from server markers, never from a local path."""
    found, markers = {}, {}
    inventory, projects, environments = _server_inventory(api)
    for role, row in inventory:
        marker = _parse_marker(row.get('description'), operation, role)
        if marker is None:
            continue
        if role in found:
            raise ContractError('provider_ownership_marker_collision')
        if role == 'compose':
            row = api.compose(identifier(row.get('composeId')))
            if _parse_marker(row.get('description'), operation, role) != marker:
                raise ContractError('provider_ownership_marker_changed')
        found[role], markers[role] = row, marker
    if not found:
        # A cache can reconcile absent resources after an acknowledged/lost
        # delete. Every still-present created resource must retain its marker.
        if previous is None:
            raise ContractError('provider_owned_operation_not_found')
        return previous
    context = next(iter(markers.values()))
    keys = ('operation', 'nonce', 'repository', 'environment', 'target')
    if any(any(marker[k] != context[k] for k in keys) for marker in markers.values()):
        raise ContractError('provider_ownership_marker_collision')
    snapshots = {json.dumps(marker['runtime'], sort_keys=True) for marker in markers.values() if marker['runtime'] is not None}
    if len(snapshots) > 1:
        raise ContractError('provider_runtime_marker_changed')
    snapshot = json.loads(next(iter(snapshots))) if snapshots else None
    if context['repository'] != adapter['repository']['id']:
        raise ContractError('provider_operation_repository_changed')
    target, binding = _binding(adapter, context['environment'], context['target'])
    project = found.get('project')
    environment = found.get('environment')
    compose = found.get('compose')
    if compose is not None:
        parent = environments.get(compose.get('environmentId'))
        if parent is None or (environment is not None and parent['environmentId'] != environment['environmentId']):
            raise ContractError('provider_resource_parent_changed')
        environment = parent
    if environment is not None:
        parent = projects.get(environment.get('projectId'))
        if parent is None or (project is not None and parent['projectId'] != project['projectId']):
            raise ContractError('provider_resource_parent_changed')
        project = parent
    if project is None:
        raise ContractError('provider_marker_inventory_ambiguous')
    resources = {'project': _entry('project', project, created='project' in found)}
    defaults = [env for env in environments.values() if env.get('projectId') == project['projectId'] and env.get('isDefault') is True]
    if resources['project']['created']:
        if len(defaults) != 1 or defaults[0].get('name') != 'production':
            raise ContractError('provider_default_environment_unproven')
        default = defaults[0]
        role = 'environment' if binding['environment'] == 'production' else 'default_environment'
        resources[role] = _entry(role, default, created=True, parent=project['projectId'])
        if role == 'environment':
            if environment is not None and environment['environmentId'] != default['environmentId']:
                raise ContractError('provider_resource_parent_changed')
            environment = default
    if environment is not None:
        default_owned = (resources['project']['created'] and environment.get('isDefault') is True
                         and environment.get('name') == 'production')
        resources['environment'] = _entry('environment', environment,
            created='environment' in found or default_owned, parent=project['projectId'])
    if compose is not None:
        resources['compose'] = _entry('compose', compose, created=True, parent=environment['environmentId'])
    if snapshot is not None:
        if snapshot['environment']['parent'] != project['projectId']:
            raise ContractError('provider_runtime_marker_changed')
        for role, cached in snapshot.items():
            actual = resources.get(role)
            if actual and any(actual.get(key) != value for key, value in cached.items()):
                raise ContractError('provider_runtime_marker_changed')
            resources.setdefault(role, {**cached, 'deleted': False})
    for role, marker in markers.items():
        if any(resources.get(parent, {}).get('created') is not expected for parent, expected in marker['parents'].items()):
            raise ContractError('provider_parent_ownership_marker_changed')
    for role, key in (('project', 'project'), ('environment', 'environment'), ('compose', 'resource')):
        if role in resources and resources[role]['name'] != binding[key]:
            raise ContractError('provider_resource_identity_changed')
    selection = {'repository': context['repository'], 'environment': context['environment'], 'target': target,
                 'binding': binding, 'adopt': any(not row['created'] for row in resources.values()), 'server_name_env': None}
    state = {'schema_version': '1.0.0', 'workflow': 'provider-provision', 'selection': selection,
             'operation_id': operation, 'nonce': context['nonce'], 'phase': 'complete', 'resources': resources,
             'intents': {}, 'server_id': resources.get('compose', {}).get('server_id')}
    if previous is not None:
        if (previous['operation_id'] != operation or previous['nonce'] != state['nonce']
                or any(previous['selection'][key] != selection[key] for key in ('repository', 'environment', 'target', 'binding'))):
            raise ContractError('provider_operation_selection_changed')
        for role, entry in resources.items():
            old = previous['resources'].get(role)
            if old and any(old.get(k) != entry.get(k) for k in ('id', 'created', 'parent', 'app_name', 'server_id')):
                raise ContractError('provider_resource_identity_changed')
        state['resources'] = {**previous['resources'], **resources}
        state['selection'] = previous['selection']
        state['server_id'] = previous['server_id'] or state['server_id']
        if 'decommission' in previous:
            state['decommission'] = previous['decommission']
    return state


def deprovision(repo: Path, adapter: dict, *, profile_root: Path, operation_dir: Path,
                operation_id=None, plan=False, api=None) -> dict:
    _operator()
    source = prove_source(repo, adapter)
    if profile_root is None:
        profile_root = Path(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local/state'))) / 'pzagent-adw-context'
    private = journal_path(repo, profile_root, operation_dir)
    if private.exists() and read(private).get('workflow') == 'kubernetes-provision':
        from .providers.kubernetes_lifecycle import deprovision as deprovision_kubernetes
        if operation_id is not None and operation_id != read(private).get('operation_id'):
            raise ContractError('provider_operation_selection_changed')
        return deprovision_kubernetes(repo, adapter, profile_root=profile_root,
                                     operation_dir=operation_dir, plan=plan, source_sha=source)
    api = _client(profile_root, api)
    api.validate()
    with locked(private.parent), locked(operation_dir):
        previous = _load(private) if private.exists() else None
        operation = operation_id or (previous['operation_id'] if previous else None)
        if not isinstance(operation, str) or not IDENTIFIER.fullmatch(operation):
            raise ContractError('provider_operation_id_required')
        if previous and previous['operation_id'] != operation:
            raise ContractError('provider_operation_selection_changed')
        state = _discover_operation(api, adapter, operation, previous)
        if state['selection']['repository'] != adapter['repository']['id']:
            raise ContractError('provider_operation_repository_changed')
        _cleanup_scope(api, state)
        write(private, state)
        if plan:
            return _receipt(operation_dir, private, state, phase='deprovision-planned',
                            task='pz:provider:deprovision', source=source, mutations=0)
        cleanup = state.setdefault('decommission', {'phase': 'deleting', 'requested': [], 'deleted': []})
        mutations = _retain_runtime_scope(api, state, lambda: write(private, state))
        for role in ('compose', 'environment', 'project'):
            entry = state['resources'].get(role)
            if not entry or not entry['created'] or (role == 'environment' and entry.get('is_default')):
                continue
            current = _get_resource(api, role, entry)
            if current is not None:
                _cleanup_scope(api, state)
                if role in cleanup['requested']:
                    raise ContractError('provider_delete_outcome_unproven')
                cleanup['requested'].append(role)
                write(private, state)
                payload = {'composeId': entry['id'], 'deleteVolumes': False} if role == 'compose' else {
                    'environmentId' if role == 'environment' else 'projectId': entry['id']}
                mutations += 1
                api.post('compose.delete' if role == 'compose' else role + '.remove', payload)
                if _get_resource(api, role, entry) is not None:
                    raise ContractError('provider_delete_readback_differs')
            if role == 'compose' and api.containers(entry['app_name'], entry['server_id']):
                raise ContractError('provider_runtime_leftovers')
            if role not in cleanup['deleted']:
                cleanup['deleted'].append(role)
                entry['deleted'] = True
                write(private, state)
        for role in ('environment', 'default_environment'):
            default = state['resources'].get(role)
            if default and default['created'] and default.get('is_default'):
                if _get_resource(api, role, default) is not None:
                    raise ContractError('provider_default_environment_leftover')
                default['deleted'] = True
        observation = runtime_absence(api, state) if 'compose' in state['resources'] else None
        if state['resources'].get('compose', {}).get('created') and (observation['resource'] is not None or observation['containers']):
            raise ContractError('provider_runtime_leftovers')
        cleanup['phase'] = 'complete'
        write(private, state)
        return _receipt(operation_dir, private, state, phase='deprovisioned',
                        task='pz:provider:deprovision', source=source, mutations=mutations,
                        adopted_resources_preserved=sum(not row['created'] for row in state['resources'].values()),
                        owned_runtime_absent=observation is not None and observation['resource'] is None and not observation['containers'],
                        retirement_offered=observation is not None and observation['resource'] is None and not observation['containers'])

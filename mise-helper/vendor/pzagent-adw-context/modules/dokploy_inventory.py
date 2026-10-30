"""Operator-only Dokploy server observations; names never enter persisted receipts."""
from __future__ import annotations

from pathlib import Path
import re

from .common import ContractError
from .description_markers import parse, verify_live
from .dokploy_lifecycle_api import identifier, one_named, placement, placement_server_id, rows
from .hooks import prove_source
from .provider_lifecycle import _binding, _client, _operator
from .task_evidence import record_operator


SERVER_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 _-]{0,126}$')


def _registered(api) -> dict[str, str]:
    """Validate bounded, unambiguous names while retaining IDs only in memory."""
    names = {}
    for row in rows(api.servers()):
        remote_id = identifier(row.get('serverId'))
        name = row.get('name')
        if (not isinstance(name, str) or not SERVER_NAME.fullmatch(name)
                or name != name.strip() or remote_id in names or name in names.values()):
            raise ContractError('provider_server_inventory_invalid')
        names[remote_id] = name
    return names


def _named(values, name):
    row = one_named(values, name)
    if row is None:
        raise ContractError('provider_server_resource_absent')
    return row


def environment_servers(api, registered: dict[str, str]) -> dict[str, dict]:
    """Observe every marker-owned Compose across projects, retaining IDs privately.

    The provider environment name is the convention shared across projects.
    Unmarked resources never establish a default; malformed marked identities
    refuse rather than quietly narrowing an otherwise ambiguous observation.
    """
    result = {}
    for project in rows(api.projects()):
        project_id = identifier(project.get('projectId'))
        for parent in rows(api.environments(project_id)):
            environment_id = identifier(parent.get('environmentId'))
            environment = parent.get('name')
            for row in rows(api.composes(environment_id)):
                compose_id = identifier(row.get('composeId'))
                detail = api.compose(compose_id)
                marker = parse(detail.get('description'))
                if marker is None:
                    continue
                # Only environments that hold a marker-owned resource must be well-formed;
                # an unrelated project's naming never blocks discovery for everyone.
                if not isinstance(environment, str) or not SERVER_NAME.fullmatch(environment):
                    raise ContractError('provider_server_environment_invalid')
                if (detail.get('composeId') != compose_id or detail.get('environmentId') != environment_id
                        or detail.get('name') != row.get('name')):
                    raise ContractError('provider_server_resource_identity_changed')
                verify_live(detail.get('description'), marker['repository'], 'compose', detail)
                selected = 'local' if detail.get('serverId') is None else 'remote'
                server_id = placement_server_id(detail, selected)
                if server_id is not None and server_id not in registered:
                    raise ContractError('provider_server_not_registered')
                entry = result.setdefault(environment, {'servers': set(), 'projects': set(), 'resources': 0})
                entry['servers'].add(server_id)
                entry['projects'].add(project_id)
                entry['resources'] += 1
    return result


def discovered_server(api, environment: str) -> str:
    """A default exists only when all observed resources agree on one remote server."""
    registered = _registered(api)
    observation = environment_servers(api, registered).get(environment)
    if observation is None:
        raise ContractError('provider_server_selection_required: pass --server <name>')
    candidates = observation['servers']
    if len(candidates) != 1 or None in candidates:
        raise ContractError('provider_server_selection_ambiguous: pass --server <name>')
    return next(iter(candidates))


def _resource(api, adapter, environment, target, binding, registered):
    project = _named(api.projects(), binding['project'])
    project_id = identifier(project.get('projectId'))
    parent = _named(api.environments(project_id), binding['environment'])
    environment_id = identifier(parent.get('environmentId'))
    row = _named(api.composes(environment_id), binding['resource'])
    detail = api.compose(identifier(row.get('composeId')))
    if detail.get('name') != binding['resource'] or detail.get('environmentId') != environment_id:
        raise ContractError('provider_server_resource_identity_changed')
    if verify_live(detail.get('description'), adapter['repository']['id'], 'compose', detail) is None:
        raise ContractError('provider_server_resource_unowned')
    selected = placement(binding)
    server_id = placement_server_id(detail, selected)
    if selected == 'remote' and server_id not in registered:
        raise ContractError('provider_server_not_registered')
    return {'environment': environment, 'target': target, 'owned': True,
            'placement': selected, 'server_name': registered[server_id] if selected == 'remote' else None}


def servers(repo: Path, adapter: dict, *, environment: str | None, target: str | None,
            profile_root: Path, operation_dir: Path, api=None) -> dict:
    """List registered names, optionally locating one declared and marker-owned Compose."""
    _operator()  # Refuse CI and unsafe run IDs before credentials or any API access.
    if environment is None and target is not None:
        raise ContractError('provider_server_environment_required')
    selected, binding = _binding(adapter, environment, target) if environment is not None else (None, None)
    source = prove_source(repo, adapter)
    api = _client(profile_root, api)
    registered = _registered(api)
    observations = environment_servers(api, registered)
    environments = [{'environment': name, 'project_count': len(value['projects']),
                     'resource_count': value['resources'],
                     'server_names': sorted(registered[key] for key in value['servers'] if key is not None),
                     'local': None in value['servers'], 'unambiguous': len(value['servers']) == 1}
                    for name, value in sorted(observations.items())]
    resource = (_resource(api, adapter, environment, selected, binding, registered)
                if environment is not None else None)
    result = {'status': 'ok', 'task': 'pz:provider:servers', 'provider': 'dokploy',
              'server_count': len(registered), 'servers': [{'name': name} for name in sorted(registered.values())],
              'resource': resource, 'environments': environments,
              'mutations_requested': 0, 'source_sha': source}
    # Names are operator selection inputs, not suitable for shareable evidence.
    receipt = {key: value for key, value in result.items() if key not in {'servers', 'resource', 'environments'}}
    receipt['environment_count'] = len(environments)
    receipt['resource'] = ({key: value for key, value in resource.items() if key != 'server_name'}
                           if resource is not None else None)
    record_operator(operation_dir, receipt)
    return result

"""Repository-scoped Dokploy ancestor claims, shared by independent target operations."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .common import ContractError
from .dokploy_lifecycle_api import Missing, RESOURCE_FIELDS, identifier, rows
from .operator_home import ensure, repository_dir
from .operator_state import read, write

PREFIX = 'adw-ancestor:v1:'


def marker(repository: str, role: str, entry: dict, nonce: str, *, original='') -> str:
    from .description_markers import render
    return render(original, {'repository': repository, 'role': role, 'id': entry['id'],
                             'name': entry['name'], 'parent': entry.get('parent')})


def parse(description, repository: str, role: str, entry: dict) -> dict | None:
    from .description_markers import parse as parse_line, reference
    line = parse_line(description)
    if line is None:
        return None
    value = {'repository': repository, 'role': role, 'id': entry['id'],
             'name': entry['name'], 'parent': entry.get('parent')}
    if (line['repository'] != repository or line['role'] != role):
        raise ContractError('provider_claim_foreign_marker')
    if line['ref'] != reference(value):
        raise ContractError('provider_ancestor_claim_conflict')
    return value


def journal(home: Path, repository: str, role: str, entry: dict) -> Path:
    ensure(home)
    key = hashlib.sha256((role + ':' + entry['id']).encode()).hexdigest()
    path = home / 'journals' / repository_dir(repository) / 'ancestors' / key / 'operation.json'
    current = home
    for part in path.relative_to(home).parts[:-1]:
        current /= part
        if current.is_symlink() or (current.exists() and (not current.is_dir() or current.stat().st_mode & 0o077)):
            raise ContractError('provider_private_profile_invalid')
        current.mkdir(mode=0o700, exist_ok=True)
    if path.is_symlink():
        raise ContractError('provider_private_journal_invalid')
    return path


def reference(home, repository, role, entry, row, *, rebuild=False, allow_missing=False):
    """Verify both pieces; only explicit rebuild may create a missing private half."""
    description = row.get('description')
    value = parse(description, repository, role, entry)
    if value is None:
        return None
    path = journal(home, repository, role, entry)
    expected = {'schema_version': '1.0.0', 'workflow': 'provider-ancestor-claim', 'marker': description}
    if path.exists():
        if not path.is_file() or path.stat().st_mode & 0o077 or path.stat().st_size > 262144:
            raise ContractError('provider_ancestor_claim_conflict')
        try:
            actual = read(path)
        except ContractError:
            raise ContractError('provider_ancestor_claim_conflict') from None
        if actual != expected:
            raise ContractError('provider_ancestor_claim_conflict')
    elif rebuild:
        write(path, expected)
    elif not allow_missing:
        raise ContractError('provider_ancestor_journal_required')
    return description


def record(home, repository, role, entry, description):
    parse(description, repository, role, entry)
    path = journal(home, repository, role, entry)
    value = {'schema_version': '1.0.0', 'workflow': 'provider-ancestor-claim', 'marker': description}
    if path.exists() and read(path) != value:
        raise ContractError('provider_ancestor_claim_conflict')
    write(path, value)


def _get(api, role, entry):
    try:
        return api.project(entry['id']) if role == 'project' else api.environment(entry['id'])
    except Missing:
        return None


def verify(api, state):
    for role in ('project', 'environment', 'default_environment'):
        entry = state['resources'].get(role, {})
        expected = entry.get('ancestor_claim')
        if expected is None:
            continue
        row = _get(api, role, entry)
        if row is None:
            if not entry.get('deleted') and not state.get('decommission'):
                raise ContractError('provider_ancestor_claim_absent')
            continue
        if row.get('description') != expected:
            raise ContractError('provider_ancestor_claim_conflict')
        from .provider_lifecycle import _identity
        _identity(role, row, entry, expected)
        parse(expected, state['selection']['repository'], 'project' if role == 'project' else 'environment', entry)


def _children(api, row, repository):
    children = [(field, child) for field in RESOURCE_FIELDS for child in rows(row.get(field))]
    for field, child in children:
        from .description_markers import verify_live
        if field == 'compose':
            detail = api.compose(identifier(child.get('composeId')))
            if detail.get('environmentId') != row.get('environmentId'):
                raise ContractError('provider_foreign_child_present')
            owned = verify_live(detail.get('description', ''), repository, 'compose', detail)
        else:
            owned = None
        if owned is None:
            raise ContractError('provider_foreign_child_present')
    return children


def _referenced(home, repository, marker, operation):
    from .operator_home import ownership_journals
    for path in ownership_journals(home, repository):
        if path.is_symlink() or path.stat().st_mode & 0o077 or path.stat().st_size > 262144:
            raise ContractError('provider_private_journal_invalid')
        record = read(path)
        if (record.get('operation_id') == operation
                or record.get('decommission', {}).get('phase') == 'complete'):
            continue
        if any(entry.get('ancestor_claim') == marker for entry in record.get('resources', {}).values()):
            return True
    return False


def cleanup(api, state, save, home):
    """Remove empty shared ancestors only; sibling claims survive, foreign children refuse."""
    verify(api, state)
    repository = state['selection']['repository']
    mutations = 0
    resources = state['resources']
    for role in ('environment', 'project'):
        entry = resources.get(role, {})
        if not entry.get('ancestor_claim'):
            continue
        row = _get(api, role, entry)
        if row is None:
            entry['deleted'] = True
            save()
            continue
        if _referenced(home, repository, entry['ancestor_claim'], state['operation_id']):
            continue
        if role == 'environment':
            children = _children(api, row, repository)
            if children or entry.get('is_default'):
                continue
        else:
            environments = api.environments(entry['id'])
            retained = False
            for child in environments:
                child_entry = {'id': child['environmentId'], 'name': child['name'], 'parent': entry['id']}
                # The provider's implicit empty default can disappear with its project.
                if child.get('isDefault') and child.get('name') == 'production':
                    if _children(api, api.environment(child['environmentId']), repository):
                        retained = True
                    continue
                if parse(child.get('description'), repository, 'environment', child_entry) is None:
                    raise ContractError('provider_foreign_child_present')
                _children(api, api.environment(child['environmentId']), repository)
                retained = True
            if retained:
                continue
        cleanup_state = state['decommission']
        if role in cleanup_state.setdefault('ancestor_requested', []):
            raise ContractError('provider_delete_outcome_unproven')
        cleanup_state['ancestor_requested'].append(role)
        save()
        api.post(role + '.remove', {role + 'Id': entry['id']})
        mutations += 1
        if _get(api, role, entry) is not None:
            raise ContractError('provider_delete_readback_differs')
        entry['deleted'] = True
        save()
    return mutations

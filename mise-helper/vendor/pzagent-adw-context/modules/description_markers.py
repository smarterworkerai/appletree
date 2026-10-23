"""Compact ownership lines whose reference recomputes from live object identity."""
from __future__ import annotations

import hashlib
import json
import re

from .common import ContractError

PREFIX = 'adw:v1 '
LINE = re.compile(r'adw:v1 owner=([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+) '
                  r'role=(project|environment|compose) ref=([0-9a-f]{12})')


def reference(identity: dict) -> str:
    if not isinstance(identity, dict):
        raise ContractError('provider_marker_identity_invalid')
    repository, role = identity.get('repository'), identity.get('role')
    if (not isinstance(repository, str)
            or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
            or any(part in ('.', '..') for part in repository.split('/'))
            or role not in {'project', 'environment', 'compose'}):
        raise ContractError('provider_marker_identity_invalid')
    remote_id, name, parent = identity.get('id'), identity.get('name'), identity.get('parent')
    valid_id = lambda value: isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value)
    if (not valid_id(remote_id) or not isinstance(name, str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 _-]{0,126}', name)
            or (parent is not None if role == 'project' else not valid_id(parent))):
        raise ContractError('provider_marker_identity_invalid')
    # Deliberately exclude local operation history, nonces and human text. A new
    # machine can recover this exact identity from Dokploy and the adapter alone.
    value = {'repository': repository, 'role': role, 'id': remote_id, 'name': name, 'parent': parent}
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()[:12]


def parse(description) -> dict | None:
    """Accept one exact final line; ambiguous marker-looking text always refuses."""
    if not isinstance(description, str):
        return None
    lines = description.splitlines()
    prefixes = ('adw:', 'adw-provision:v1:', 'adw-ancestor:v1:')
    marked = [index for index, line in enumerate(lines) if line.strip().casefold().startswith(prefixes)]
    if not marked:
        return None
    last = description.rsplit('\n', 1)[-1]
    if any(lines[index].strip().casefold().startswith(('adw-provision:v1:', 'adw-ancestor:v1:'))
           for index in marked):
        raise ContractError('provider_claim_foreign_marker')
    match = LINE.fullmatch(last)
    if match is None or marked != [len(lines) - 1] or lines[-1] != last:
        raise ContractError('provider_marker_line_invalid')
    repository, role, ref = match.groups()
    if any(part in ('.', '..') for part in repository.split('/')):
        raise ContractError('provider_marker_line_invalid')
    return {'repository': repository, 'role': role, 'ref': ref}


def render(original, identity: dict) -> str:
    ref = reference(identity)
    if original is None:
        original = ''
    if not isinstance(original, str) or len(original.encode()) > 65536:
        raise ContractError('provider_marker_description_invalid')
    if parse(original) is not None:
        raise ContractError('provider_marker_already_present')
    line = f"{PREFIX}owner={identity['repository']} role={identity['role']} ref={ref}"
    return original + ('\n' if original else '') + line


def verify(description, identity: dict, original) -> None:
    expected = {'repository': identity.get('repository'), 'role': identity.get('role'),
                'ref': reference(identity)}
    if parse(description) != expected or description != render(original, identity):
        raise ContractError('provider_marker_description_changed')


def observed(repository: str, role: str, row: dict) -> dict:
    """Normalize only the object's own observed ID/name/parent, never another row."""
    result = {'repository': repository, 'role': role, 'id': row.get(role + 'Id'), 'name': row.get('name'),
              'parent': None if role == 'project' else row.get('environmentId' if role == 'compose' else 'projectId')}
    reference(result)
    return result


def verify_live(description, repository: str, role: str, row: dict) -> dict | None:
    line = parse(description)
    if line is None:
        return None
    if line['repository'] != repository or line['role'] != role:
        raise ContractError('provider_claim_foreign_marker')
    item = observed(repository, role, row)
    if line['ref'] != reference(item):
        raise ContractError('provider_marker_identity_changed')
    return item

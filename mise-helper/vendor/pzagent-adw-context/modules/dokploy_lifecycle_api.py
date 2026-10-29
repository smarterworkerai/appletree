"""Bounded Dokploy lifecycle observations and transport; no ownership decisions."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .common import ContractError

REMOTE_ID = re.compile(r'^[A-Za-z0-9_-]{1,128}$')
APP_NAME = re.compile(r'^[a-zA-Z0-9._-]{1,128}$')
MAX_BYTES = 8 * 1024 * 1024
MAX_ITEMS = 4096
RESOURCE_FIELDS = ('applications', 'compose', 'libsql', 'mariadb', 'mongo', 'mysql', 'postgres', 'redis')
SCHEMA_KEYS = frozenset({'type', 'enum', 'anyOf', 'oneOf', 'allOf', 'nullable', 'required',
                         'properties', 'items', 'minLength', 'maxLength', 'minimum', 'maximum',
                         'pattern', 'format', 'additionalProperties'})
CONTRACT = Path(__file__).with_name('dokploy_lifecycle_contract.json')


class Missing(ContractError):
    """Only an actual HTTP 404, after API capability validation."""


class _SameOrigin(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urlparse(req.full_url), urlparse(newurl)
        if (old.scheme, old.netloc) != (new.scheme, new.netloc):
            raise ContractError('provider_cross_origin_redirect_refused')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HTTP:
    def __init__(self, endpoint: str, credential: str):
        parsed = urlparse(endpoint)
        if parsed.scheme not in {'http', 'https'} or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment or not credential:
            raise ContractError('provider_operator_inputs_invalid')
        self.endpoint, self.credential = endpoint.rstrip('/'), credential
        self.opener = build_opener(_SameOrigin())

    def request(self, method: str, route: str, payload=None, timeout: int = 25):
        if method not in {'GET', 'POST'} or not route.startswith('/api/') or route.startswith('//'):
            raise ContractError('provider_api_route_invalid')
        data = None if payload is None else json.dumps(payload, separators=(',', ':')).encode()
        req = Request(self.endpoint + route, data=data, method=method, headers={
            'x-api-key': self.credential, 'Accept': 'application/json', 'Content-Type': 'application/json'})
        try:
            with self.opener.open(req, timeout=timeout) as response:
                raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ContractError('provider_api_response_unbounded')
            return json.loads(raw) if raw else {}
        except HTTPError as exc:
            if exc.code == 404:
                raise Missing('provider_resource_absent') from exc
            raise ContractError('provider_api_request_failed') from exc
        except (URLError, TimeoutError, UnicodeError, ValueError) as exc:
            raise ContractError('provider_api_request_failed') from exc


def _unwrap(value):
    for _ in range(4):
        if not isinstance(value, dict):
            break
        key = next((key for key in ('result', 'data', 'json') if key in value), None)
        if key is None:
            break
        value = value[key]
    return value


def _schema(document, value, depth=0):
    if depth > 32 or not isinstance(value, dict):
        raise ContractError('provider_api_schema_invalid')
    if '$ref' in value:
        reference = value['$ref']
        if not isinstance(reference, str) or not reference.startswith('#/'):
            raise ContractError('provider_api_schema_invalid')
        node = document
        try:
            for part in reference[2:].split('/'):
                node = node[part.replace('~1', '/').replace('~0', '~')]
        except (KeyError, TypeError) as exc:
            raise ContractError('provider_api_schema_invalid') from exc
        return _schema(document, node, depth + 1)
    result = {}
    for key, child in value.items():
        if key not in SCHEMA_KEYS:
            continue
        if key == 'properties':
            result[key] = {name: _schema(document, entry, depth + 1) for name, entry in child.items()}
        elif key in {'anyOf', 'oneOf', 'allOf'}:
            result[key] = [_schema(document, entry, depth + 1) for entry in child]
        elif key in {'items', 'additionalProperties'} and isinstance(child, dict):
            result[key] = _schema(document, child, depth + 1)
        else:
            result[key] = child
    return result


def validate_capabilities(transport) -> str:
    expected = json.loads(CONTRACT.read_text())
    suffix = '?' + urlencode({'input': json.dumps({'json': None}, separators=(',', ':'))})
    version = _unwrap(transport.request('GET', '/api/trpc/settings.getDokployVersion' + suffix))
    if version != expected['software_version']:
        raise ContractError('provider_api_version_unsupported')
    document = _unwrap(transport.request('GET', '/api/trpc/settings.getOpenApiDocument' + suffix))
    try:
        if document['info']['version'] != version:
            raise ContractError('provider_api_schema_mismatch')
        for path, methods in expected['operations'].items():
            actual = {}
            for method, operation in document['paths'][path].items():
                if method not in {'get', 'post', 'put', 'patch', 'delete'}:
                    continue
                actual[method.upper()] = {
                    'body': _schema(document, operation.get('requestBody', {}).get('content', {}).get('application/json', {}).get('schema', {})),
                    'query': sorted([{'name': p['name'], 'required': p.get('required', False),
                                      'schema': _schema(document, p.get('schema', {}))}
                                     for p in operation.get('parameters', []) if p.get('in') == 'query'], key=lambda p: p['name'])}
            if actual != methods:
                raise ContractError('provider_api_schema_mismatch')
    except (KeyError, TypeError, AttributeError, ValueError, RecursionError) as exc:
        raise ContractError('provider_api_schema_mismatch') from exc
    return version


def identifier(value):
    if not isinstance(value, str) or not REMOTE_ID.fullmatch(value):
        raise ContractError('provider_inventory_invalid')
    return value


def rows(value):
    if not isinstance(value, list) or len(value) > MAX_ITEMS or any(not isinstance(row, dict) for row in value):
        raise ContractError('provider_inventory_invalid')
    return value


def one_named(values, name):
    matches = [row for row in rows(values) if row.get('name') == name]
    if len(matches) > 1:
        raise ContractError('provider_name_conflict')
    return matches[0] if matches else None


class API:
    """Raw observations stay in memory or private ownership journals."""

    def __init__(self, transport):
        self.transport = transport

    def validate(self):
        return validate_capabilities(self.transport)

    def get(self, name, **query):
        route = '/api/' + name
        if query:
            route += '?' + urlencode(query)
        return self.transport.request('GET', route)

    def post(self, name, data, timeout=None):
        # Only long synchronous runs (schedule.runManually) pass a timeout.
        if timeout is None:
            return self.transport.request('POST', '/api/' + name, data)
        return self.transport.request('POST', '/api/' + name, data, timeout=timeout)

    def projects(self):
        return rows(self.get('project.all'))

    def project(self, project_id):
        value = self.get('project.one', projectId=identifier(project_id))
        if not isinstance(value, dict) or value.get('projectId') != project_id:
            raise ContractError('provider_inventory_invalid')
        rows(value.get('environments'))
        return value

    def environments(self, project_id):
        project_id = identifier(project_id)
        values = rows(self.get('environment.byProjectId', projectId=project_id))
        result, seen = [], set()
        for value in values:
            key = identifier(value.get('environmentId'))
            parent = value.get('project')
            # v0.29.2 selects the parent relation, not the projectId column.
            # Normalize only a verified observation; never infer the parent
            # from the requested filter or accept contradictory identities.
            if (not isinstance(parent, dict) or parent.get('projectId') != project_id
                    or ('projectId' in value and value['projectId'] != project_id)
                    or key in seen):
                raise ContractError('provider_inventory_invalid')
            seen.add(key)
            result.append({**value, 'projectId': project_id})
        return result

    def environment(self, environment_id):
        value = self.get('environment.one', environmentId=identifier(environment_id))
        if not isinstance(value, dict) or value.get('environmentId') != environment_id:
            raise ContractError('provider_inventory_invalid')
        return value

    def composes(self, environment_id):
        result, offset = [], 0
        while True:
            page = self.get('compose.search', environmentId=identifier(environment_id), limit=100, offset=offset)
            if not isinstance(page, dict) or not isinstance(page.get('total'), int) or page['total'] < 0:
                raise ContractError('provider_inventory_invalid')
            values = rows(page.get('items'))
            if len(result) + len(values) > MAX_ITEMS or (not values and offset < page['total']):
                raise ContractError('provider_inventory_invalid')
            result.extend(values)
            offset += len(values)
            if offset >= page['total']:
                break
        seen = set()
        for row in result:
            key = identifier(row.get('composeId'))
            if key in seen or row.get('environmentId') != environment_id:
                raise ContractError('provider_inventory_invalid')
            seen.add(key)
        return result

    def compose(self, compose_id):
        value = self.get('compose.one', composeId=identifier(compose_id))
        if not isinstance(value, dict) or value.get('composeId') != compose_id:
            raise ContractError('provider_inventory_invalid')
        return value

    def containers(self, app_name, server_id, *, placement='remote'):
        if not isinstance(app_name, str) or not APP_NAME.fullmatch(app_name):
            raise ContractError('provider_runtime_scope_invalid')
        return rows(self.get('docker.getContainersByAppLabel', appName=app_name,
                             **server_query(server_id, placement), type='standalone'))

    def servers(self):
        return rows(self.get('server.all'))


_FINGERPRINT = re.compile(r'^[0-9a-f]{64}$')
_SETTINGS_QUERY = '/api/trpc/settings.getWebServerSettings?input=%7B%22json%22%3Anull%7D'


def placement(binding):
    value = binding.get('placement', 'remote')
    if not isinstance(value, str) or value not in {'local', 'remote'}:
        raise ContractError('provider_placement_invalid')
    return value


def placement_server_id(row, selected='remote'):
    """Require an explicit nullable field locally and a real registered ID remotely."""
    if not isinstance(selected, str) or selected not in {'local', 'remote'}:
        raise ContractError('provider_placement_invalid')
    if not isinstance(row, dict) or 'serverId' not in row:
        raise ContractError('provider_runtime_scope_invalid')
    value = row['serverId']
    if selected == 'local':
        if value is not None:
            raise ContractError('provider_placement_changed')
    elif not isinstance(value, str) or not REMOTE_ID.fullmatch(value):
        raise ContractError('provider_placement_changed')
    return value


def server_query(value, selected='remote'):
    placement_server_id({'serverId': value}, selected)
    return {} if selected == 'local' else {'serverId': value}


def manager_identity(client):
    """Discard sensitive settings immediately; only a domain-separated fingerprint survives."""
    value = (client.request('GET', _SETTINGS_QUERY) if hasattr(client, 'request')
             else client._get(_SETTINGS_QUERY))
    for _ in range(4):
        if not isinstance(value, dict):
            break
        key = next((key for key in ('result', 'data', 'json') if key in value), None)
        if key is None:
            break
        value = value[key]
    identity = value.get('id') if isinstance(value, dict) else None
    if not isinstance(identity, str) or not REMOTE_ID.fullmatch(identity):
        raise ContractError('provider_manager_identity_unproven')
    return hashlib.sha256(('dokploy-local-manager/v1\0' + identity).encode()).hexdigest()


def check_manager(client, expected):
    if (not isinstance(expected, str) or not _FINGERPRINT.fullmatch(expected)
            or manager_identity(client) != expected):
        raise ContractError('provider_manager_identity_changed')

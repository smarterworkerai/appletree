"""Default Dokploy hook ABI: exact runtime identity and configured HTTP probes."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

if __package__ in {None, ''}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from modules.adapter import load as load_adapter
from modules.common import project_dir
from modules.common import ContractError, FULL_SHA, ensure_contained
from modules.hooks import HookFailure
from modules.providers import binding_for, require
from modules.providers.dokploy import (DokployClient, profile_credentials,
    runtime_service_variables, observe_runtime as provider_observe_runtime)
from modules.release_manifest import DIGEST_REF, image_variables
from modules.runtime_proof import parse_environment
from modules.provider_hooks import blocked, http_probe, _kind, _images

WIRE_KEYS = {'schema_version', 'capability', 'operation', 'source_sha', 'environment', 'target'}
OPERATIONS = {'config-plan': 'adw:deploy:config:plan', 'deploy-status': 'adw:deploy:status',
              'health': 'adw:health', 'readiness': 'adw:readiness',
              'runtime-proof': 'adw:validate-deployment'}
PHASES = {'normal-release', 'operator-preflight', 'operator-release', 'hotfix',
          'automatic-restore', 'manual-restore'}
PROJECT = re.compile(r'^[a-z0-9][a-z0-9_.-]{0,127}$')
REMOTE_ID = re.compile(r'^[A-Za-z0-9_-]{1,128}$')



def service_variables(definition: bytes, owned: set[str]) -> dict[str, str]:
    try:
        return runtime_service_variables(definition, owned)
    except ContractError as exc:
        blocked(str(exc))


def _get(client: DokployClient, route: str, reason: str) -> Any:
    try:
        return client._get(route)
    except ContractError:
        blocked(reason)


def verify_runtime(client: DokployClient, resource: str, expected: dict[str, str],
                   services: dict[str, str], *, placement: str = 'remote') -> None:
    first = _get(client, '/api/compose.one?' + urlencode({'composeId': resource}),
                 'runtime-container-discovery-failed')
    if not isinstance(first, dict) or not isinstance(first.get('appName'), str) or not PROJECT.fullmatch(first['appName']):
        blocked('runtime-project-identity-absent')
    if not isinstance(first.get('env'), str) or not isinstance(first.get('composeFile'), str):
        blocked('runtime-container-discovery-failed')
    try:
        values = parse_environment(first['env'])
    except ContractError:
        blocked('runtime-image-pointer-invalid')
    if any(values.get(key) != image for key, image in expected.items()):
        blocked('runtime-environment-image-identity-differs')
    seen = observe_runtime(client, resource, services, first=first, placement=placement)
    for service, key in services.items():
        metadata = seen[service][0]
        state = metadata.get('State')
        if (metadata['Config'].get('Image') != expected[key] or not isinstance(state, dict)
                or state.get('Status') != 'running' or not isinstance(state.get('Health'), dict)
                or state['Health'].get('Status') != 'healthy'):
            blocked('runtime-image-identity-or-health-mismatch')


def observe_runtime(*args, **kwargs):
    try:
        return provider_observe_runtime(*args, **kwargs)
    except ContractError as exc:
        blocked(str(exc))








def dispatch(repo: Path, adapter: dict, operation: str, request: dict) -> dict:
    if request.get('schema_version') != '1.0.0':
        blocked('project-hook-schema-incompatible')
    if operation == 'describe':
        if (set(request) != {'schema_version', 'capability', 'operation', 'source_sha'}
                or request.get('capability') != 'adw:describe' or request.get('operation') != operation
                or request.get('schema_version') != '1.0.0' or not FULL_SHA.fullmatch(request.get('source_sha', ''))):
            blocked('project-hook-request-invalid')
        return {'profile': 'project-adapter'}
    keys = WIRE_KEYS | ({'phase', 'expected_images'} if operation == 'runtime-proof' else set())
    if (set(request) != keys or operation not in OPERATIONS or request.get('capability') != OPERATIONS[operation]
            or request.get('operation') != operation or request.get('schema_version') != '1.0.0'
            or not isinstance(request.get('source_sha'), str) or not FULL_SHA.fullmatch(request['source_sha'])):
        blocked('project-hook-request-invalid')
    environment, name = request.get('environment'), request.get('target')
    group = adapter['targets'].get(environment) if isinstance(environment, str) else None
    if not group or not isinstance(name, str) or name not in group['items'] or group['items'][name]['mode'] not in ({'active', 'shadow'} if operation == 'config-plan' else {'active'}):
        blocked('runtime-proof-target-differs')
    target = group['items'][name]
    require(target['provider'])
    binding = dict(binding_for(adapter, target))
    if operation == 'config-plan':
        return binding.get('plan', {'role': 'deployment', 'order': 'deployment only'})
    if operation in {'health', 'readiness'} and http_probe(binding, operation):
        return {'status': 'passed'}
    expected = None
    if operation == 'runtime-proof':
        if request['phase'] not in PHASES:
            blocked('runtime-proof-phase-differs')
        temporary = environment in adapter['hotfix']['supported_environments']
        if request['phase'] == 'hotfix' and not temporary:
            blocked('runtime-proof-hotfix-phase-differs')
        assignments = request['expected_images']
        keys = {item.split('=', 1)[0] for item in assignments if isinstance(item, str)} if isinstance(assignments, list) else set()
        kind = _kind(repo, adapter, environment, keys)
        expected = _images(kind, assignments, temporary=temporary)
        if request['phase'] == 'operator-preflight':
            return {'images': assignments}
    else:
        kind = _kind(repo, adapter, environment, None)
    endpoint, credential = profile_credentials(None)
    resource = os.environ.get(binding['child_binding'], '')
    if not REMOTE_ID.fullmatch(resource):
        blocked('runtime-project-identity-absent')
    client = DokployClient(endpoint, credential)
    if expected is None:
        payload = _get(client, '/api/compose.one?' + urlencode({'composeId': resource}), 'runtime-container-discovery-failed')
        if not isinstance(payload, dict) or not isinstance(payload.get('env'), str):
            blocked('runtime-image-pointer-invalid')
        values = parse_environment(payload['env'])
        expected = _images(kind, [key + '=' + values.get(key, '') for key in image_variables(kind)],
                           temporary=environment in adapter['hotfix']['supported_environments'])
    definition = ensure_contained(repo, binding['compose_path']).read_bytes()
    services = service_variables(definition, set(expected))
    from modules.dokploy_lifecycle_api import placement
    verify_runtime(client, resource, expected, services, placement=placement(binding))
    if operation == 'runtime-proof':
        if request['phase'] != 'operator-release':
            http_probe(binding, 'health')
            http_probe(binding, 'readiness')
        return {'images': request['expected_images']}
    return {'status': 'passed'}


def main(argv: list[str]) -> int:
    try:
        if len(argv) != 1:
            blocked('project-hook-request-invalid')
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            blocked('project-hook-request-invalid')
        repo = Path.cwd()
        result = dispatch(repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'), argv[0], request)
        response = {'schema_version': '1.0.0', 'status': 'ok', 'result': result}
    except HookFailure as failure:
        response = {'schema_version': '1.0.0', 'status': failure.status, 'reason_code': failure.reason_code}
    except (ContractError, OSError, ValueError, KeyError, TypeError):
        response = {'schema_version': '1.0.0', 'status': 'blocked', 'reason_code': 'provider-hook-request-invalid'}
    print(json.dumps(response, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))

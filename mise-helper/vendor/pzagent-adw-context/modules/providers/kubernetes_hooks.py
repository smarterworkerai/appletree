"""Kubernetes hook ABI: ready replicas, observed image IDs and routed probes."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

if __package__ in {None, ''}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from modules.adapter import load as load_adapter
from modules.common import ContractError, FULL_SHA, project_dir
from modules.hooks import HookFailure
from modules.provider_hooks import blocked, http_probe, _kind, _images, build_hotfix
from modules.providers import binding_for
from modules.providers.kubernetes import KubernetesProvider

WIRE_KEYS = {'schema_version', 'capability', 'operation', 'source_sha', 'environment', 'target'}
OPERATIONS = {'config-plan': 'adw:deploy:config:plan', 'deploy-status': 'adw:deploy:status',
              'health': 'adw:health', 'readiness': 'adw:readiness',
              'runtime-proof': 'adw:validate-deployment', 'hotfix-build': 'adw:hotfix:apply'}
PHASES = {'normal-release', 'operator-preflight', 'operator-release', 'hotfix',
          'automatic-restore', 'manual-restore'}


def _probe(binding: dict, operation: str) -> None:
    if not http_probe(binding, operation):
        blocked('kubernetes-probes-not-configured')


def dispatch(repo: Path, adapter: dict, operation: str, request: dict) -> dict:
    if operation == 'describe':
        if (set(request) != {'schema_version', 'capability', 'operation', 'source_sha'}
                or request.get('schema_version') != '1.0.0' or request.get('capability') != 'adw:describe'
                or request.get('operation') != operation or not isinstance(request.get('source_sha'), str)
                or not FULL_SHA.fullmatch(request['source_sha'])):
            blocked('project-hook-request-invalid')
        return {'profile': 'project-adapter'}
    extras = ({'phase', 'expected_images'} if operation == 'runtime-proof' else
              {'phase'} | ({'image_tag'} if 'image_tag' in request else set()) if operation == 'hotfix-build' else set())
    keys = WIRE_KEYS | extras
    if (set(request) != keys or operation not in OPERATIONS
            or request.get('capability') != OPERATIONS[operation]
            or request.get('operation') != operation or request.get('schema_version') != '1.0.0'
            or not isinstance(request.get('source_sha'), str) or not FULL_SHA.fullmatch(request['source_sha'])):
        blocked('project-hook-request-invalid')
    environment, name = request.get('environment'), request.get('target')
    group = adapter['targets'].get(environment) if isinstance(environment, str) else None
    if not group or not isinstance(name, str) or name not in group['items']:
        blocked('runtime-proof-target-differs')
    target = group['items'][name]
    if target['mode'] != 'active' or target['provider'] != 'kubernetes':
        blocked('runtime-proof-target-differs')
    binding = dict(binding_for(adapter, target))
    if operation == 'hotfix-build':
        if request['phase'] != 'build' or environment not in adapter['hotfix']['supported_environments']:
            blocked('hotfix-environment-unsupported')
        return {'images': build_hotfix(repo, adapter, environment, request['source_sha'], request.get('image_tag'))}
    if operation == 'config-plan':
        return binding.get('plan', {'role': 'deployment', 'order': 'deployment only'})
    if operation in {'health', 'readiness'}:
        _probe(binding, operation)
        return {'status': 'passed'}
    expected = None
    if operation == 'runtime-proof':
        if request['phase'] not in PHASES:
            blocked('runtime-proof-phase-differs')
        temporary = environment in adapter['hotfix']['supported_environments']
        if request['phase'] == 'hotfix' and not temporary:
            blocked('runtime-proof-hotfix-phase-differs')
        assignments = request['expected_images']
        expected_keys = {v.split('=', 1)[0] for v in assignments if isinstance(v, str)} if isinstance(assignments, list) else set()
        kind = _kind(repo, adapter, environment, expected_keys)
        expected = _images(kind, assignments, temporary=False)
        if set(expected) != set(binding['image_variables']):
            blocked('runtime-proof-image-keys-differ')
        if request['phase'] == 'operator-preflight':
            return {'images': assignments}
    else:
        kind = _kind(repo, adapter, environment, None)
    provider = KubernetesProvider(repo, name, binding)
    try:
        provider.discover(binding)
        if expected is None:
            configured = provider.readback()
            expected = _images(kind, [key + '=' + configured.get(key, '') for key in binding['image_variables']], temporary=False)
        observed = provider.observed_image_refs(set(expected))
        if observed != expected:
            blocked('kubernetes-runtime-image-mismatch')
    except ContractError as exc:
        reason = str(exc).replace('_', '-')
        blocked(reason if re.fullmatch(r'kubernetes-[a-z0-9-]{1,100}', reason) else 'kubernetes-runtime-observation-failed')
    _probe(binding, 'health')
    _probe(binding, 'readiness')
    return {'images': request['expected_images']} if operation == 'runtime-proof' else {'status': 'passed'}


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

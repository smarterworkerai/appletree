"""Resolve a live logical target then invoke one read-only probe."""
from __future__ import annotations
from contextlib import nullcontext
from pathlib import Path
from .common import ContractError
from .hooks import HookFailure, invoke, prove_source, request
from .providers import bind, binding_for
ALLOWED = {'adw:deploy:status', 'adw:health', 'adw:readiness'}


def run(repo: Path, adapter: dict, *, capability: str, environment: str,
        requested_target: str | None, profile_root: Path | None,
        registry_auth=nullcontext) -> dict:
    if capability not in ALLOWED:
        raise ContractError('capability is not a read-only remote probe')
    cap = adapter['capabilities'][capability]
    if cap['status'] != 'supported' or cap['side_effect'] != 'read-only' or environment not in cap['environments']:
        raise ContractError('probe is unsupported for environment')
    prove_source(repo, adapter)
    group = adapter['targets'].get(environment)
    if not group:
        raise ContractError('environment has no target inventory')
    name = requested_target or group['default']
    if name not in group['items']:
        raise ContractError('logical target is not allowlisted')
    target = group['items'][name]
    if target['mode'] != 'active':
        raise ContractError('target mode or provider is unsupported')
    provider = bind(repo, adapter, name, target, profile_root)
    provider.discover(binding_for(adapter, target))
    if capability != 'adw:deploy:status':
        return invoke(repo, adapter, capability, request(capability, environment=environment, target=name),
                      extra_env=provider.probe(capability))
    from .status_identity import read
    try:
        health = invoke(repo, adapter, capability, request(capability, environment=environment, target=name),
                        extra_env=provider.probe(capability))
    except HookFailure as exc:
        health = {'status': exc.status, 'reason': str(exc), 'reason_code': exc.reason_code}
    except ContractError:
        health = {'status': 'blocked', 'reason': 'status_health_unproven'}
    release = read(repo, adapter, environment, name, provider, registry_auth)
    result = dict(health)
    result.update(target=name, health=health, release=release)
    if release['status'] != 'ok':
        result.update(status='blocked', reason=release['reason'])
    return result

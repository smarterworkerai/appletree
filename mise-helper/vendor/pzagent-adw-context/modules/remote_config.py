"""Approved provider-neutral configuration orchestration."""
from __future__ import annotations

import json
from pathlib import Path
from .approval import validate as validate_approval
from .common import ContractError, ensure_contained
from .hooks import invoke, prove_source, request
from .providers import bind, binding_for

def _key_contract(data):
 if not isinstance(data,dict):raise ContractError('Environment key schema is not closed')
 keys=data.get('keys');optional=data.get('optional_keys',[])
 if set(data) not in ({'keys'},{'keys','optional_keys'}) or not isinstance(keys,list) or not isinstance(optional,list) or len(keys)!=len(set(keys)) or len(optional)!=len(set(optional)) or not set(optional)<=set(keys):raise ContractError('Environment key schema is not closed')
 allowed=set(keys);return allowed-set(optional),allowed


def _target(adapter, environment, requested):
    group = adapter['targets'].get(environment)
    if not group:
        raise ContractError('environment has no target inventory')
    name = requested or group['default']
    if name not in group['items']:
        raise ContractError('logical target is not allowlisted')
    target = group['items'][name]
    if target['mode'] != 'active':
        raise ContractError('target mode or provider is unsupported')
    return name, target


def config_pull(repo: Path, adapter: dict, *, environment: str,
                requested_target: str | None, profile_root: Path | None) -> dict:
    capability = 'adw:deploy:config:pull'
    cap = adapter['capabilities'][capability]
    if cap['status'] != 'supported' or environment not in cap['environments']:
        raise ContractError('configuration pull is unsupported for environment')
    source = prove_source(repo, adapter)
    name, target = _target(adapter, environment, requested_target)
    provider = bind(repo, adapter, name, target, profile_root)
    provider.discover(binding_for(adapter, target))
    return {'status': 'ok', 'source_sha': source, 'environment': environment,
            'target': name, **provider.config_pull()}


def _desired(provider, root):
    definition = ensure_contained(root, provider.configuration.definition_path)
    schema = ensure_contained(root, provider.configuration.settings_schema_path)
    if (not definition.is_file() and not (definition.is_dir() and provider.configuration.render_definition is not None)) or not schema.is_file():
        raise ContractError('tracked desired state or key schema is missing')
    try:
        keys = json.loads(schema.read_text())
    except json.JSONDecodeError as exc:
        raise ContractError('Environment key schema malformed') from exc
    required, allowed = _key_contract(keys)
    return definition, required, allowed


def config_apply(repo: Path, adapter: dict, *, environment: str,
                 requested_target: str | None, approval_path: Path | None,
                 profile_root: Path | None, desired_root: Path | None = None,
                 snapshot_path: Path | None = None) -> dict:
    source = prove_source(repo, adapter)
    capability = 'adw:deploy:config:apply'
    cap = adapter['capabilities'][capability]
    if cap['status'] != 'supported' or environment not in cap['environments']:
        raise ContractError('configuration apply is unsupported for environment')
    name, target = _target(adapter, environment, requested_target)
    validate_approval(approval_path, source_sha=source, capability=capability,
                      environment=environment, target=name)
    provider = bind(repo, adapter, name, target, profile_root)
    # Discovery order matches the existing configuration-apply path.
    provider.discover(binding_for(adapter, target))
    definition, required, allowed = _desired(provider, desired_root or repo)
    before = provider.read_state()
    renderer = provider.configuration.render_definition
    desired = provider.plan({}, definition=renderer(definition) if renderer is not None else definition.read_bytes(), current=before)
    result = provider.config_apply(desired, set(), current=before, required=required,
                                   allowed=allowed, snapshot_path=snapshot_path)
    return {'status': 'ok', 'source_sha': source, 'environment': environment,
            'target': name, **result}


def config_plan(repo: Path, adapter: dict, *, environment: str,
                requested_target: str | None, profile_root: Path | None,
                desired_root: Path | None = None) -> dict:
    capability = 'adw:deploy:config:plan'
    cap = adapter['capabilities'][capability]
    if cap['status'] != 'supported' or cap['side_effect'] != 'read-only' or environment not in cap['environments']:
        raise ContractError('configuration plan is unsupported for environment')
    source = prove_source(repo, adapter)
    name, target = _target(adapter, environment, requested_target)
    provider = bind(repo, adapter, name, target, profile_root)
    definition, required, allowed = _desired(provider, desired_root or repo)
    provider.discover(binding_for(adapter, target))
    renderer = provider.configuration.render_definition
    result = provider.config_plan(renderer(definition) if renderer is not None else definition.read_bytes(), required, allowed)
    semantic = invoke(repo, adapter, capability,
                      request(capability, environment=environment, target=name))['result']
    return {'status': 'ok', 'source_sha': source, 'environment': environment,
            'target': name, 'role': semantic['role'], 'order': semantic['order'],
            'compose': provider.configuration.definition_path, **result}

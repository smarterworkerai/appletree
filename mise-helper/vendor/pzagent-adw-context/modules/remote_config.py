"""Approved provider-neutral configuration orchestration."""
from __future__ import annotations

import json
import re
from pathlib import Path
from .approval import validate as validate_approval
from .common import ContractError, ensure_contained
from .hooks import invoke, prove_source, request
from .providers import bind, binding_for

def _key_contract(data):
 if not isinstance(data,dict):raise ContractError('Environment key schema is not closed')
 keys=data.get('keys');optional=data.get('optional_keys',[])
 # #193: one object per key (its source); only the names matter here. No new import: decision closure.
 if isinstance(keys,dict) and all(isinstance(entry,dict) for entry in keys.values()):keys=list(keys)
 if set(data) not in ({'keys'},{'keys','optional_keys'}) or not isinstance(keys,list) or not isinstance(optional,list) or len(keys)!=len(set(keys)) or len(optional)!=len(set(optional)) or not set(optional)<=set(keys):raise ContractError('Environment key schema is not closed')
 allowed=set(keys);return allowed-set(optional),allowed


def _target(adapter, environment, requested, *, planning=False):
    group = adapter['targets'].get(environment)
    if not group:
        raise ContractError('environment has no target inventory')
    name = requested or group['default']
    if name not in group['items']:
        raise ContractError('logical target is not allowlisted')
    target = group['items'][name]
    if target['mode'] not in ({'active', 'shadow'} if planning else {'active'}):
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
    name, target = _target(adapter, environment, requested_target, planning=True)
    provider = bind(repo, adapter, name, target, profile_root)
    definition, required, allowed = _desired(provider, desired_root or repo)
    provider.discover(binding_for(adapter, target))
    renderer = provider.configuration.render_definition
    rendered = renderer(definition) if renderer is not None else definition.read_bytes()
    result = provider.config_plan(rendered, required, allowed)
    semantic = invoke(repo, adapter, capability,
                      request(capability, environment=environment, target=name))['result']
    warnings = shared_network_warnings(rendered) if target['provider'] == 'dokploy' else []
    return {'status': 'ok', 'source_sha': source, 'environment': environment,
            'target': name, 'role': semantic['role'], 'order': semantic['order'],
            'compose': provider.configuration.definition_path, **result,
            **({'warnings': warnings} if warnings else {})}


def shared_network_warnings(definition: bytes) -> list[dict]:
    """Best-effort advice for conventional Compose YAML; never a deployment gate."""
    if len(definition) > 8 * 1024 * 1024:
        return []
    try:
        text = definition.decode('utf-8')
    except UnicodeError:
        return []
    # Limit the heuristic to ordinary two-space service/network mappings. An
    # unfamiliar YAML shape gets no advice; the provider's real plan still runs.
    sections = re.split(r'(?m)^([a-zA-Z][\w-]*):[^\n]*\n', text)
    blocks = dict(zip(sections[1::2], sections[2::2]))
    aliases = {'dokploy-network'}
    networks = re.split(r'(?m)^  ([a-zA-Z0-9_.-]+):[^\n]*', blocks.get('networks', ''))
    for name, body in zip(networks[1::2], networks[2::2]):
        if re.search(r'(?m)^    name:\s*[\"\']?dokploy-network[\"\']?\s*(?:#.*)?$', body):
            aliases.add(name)
    services = re.split(r'(?m)^  ([a-zA-Z0-9_.-]+):[^\n]*', blocks.get('services', ''))
    generic = {'app', 'api', 'backend', 'frontend', 'web', 'server', 'gateway', 'nginx',
               'db', 'database', 'postgres', 'mysql', 'redis'}
    collisions = []
    for name, body in zip(services[1::2], services[2::2]):
        network = re.search(r'(?m)^    networks:([^\n]*(?:\n {6,}[^\n]*)*)', body)
        if name in generic and network and any(re.search(r'(?<![\w.-])' + re.escape(alias) + r'(?![\w.-])', network[1]) for alias in aliases):
            collisions.append(name)
    return ([{'reason_code': 'shared-network-generic-service-name', 'network': 'dokploy-network',
              'services': sorted(collisions),
              'advice': 'Use project-scoped service names or aliases for routed upstreams on the shared network.'}]
            if collisions else [])

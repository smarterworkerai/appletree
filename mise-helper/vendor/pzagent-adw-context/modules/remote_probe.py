"""Resolve a live logical target then invoke one read-only project probe."""
from __future__ import annotations
from pathlib import Path
from .common import ContractError
from .dokploy_preflight import DokployClient,ProviderNames,discover_binding,profile_credentials
from .hooks import invoke,prove_source,request
ALLOWED={'adw:deploy:status','adw:health','adw:readiness'}
def run(repo:Path,adapter:dict,*,capability:str,environment:str,requested_target:str|None,profile_root:Path|None)->dict:
 if capability not in ALLOWED:raise ContractError('capability is not a read-only remote probe')
 cap=adapter['capabilities'][capability]
 if cap['status']!='supported' or cap['side_effect']!='read-only' or environment not in cap['environments']:raise ContractError('probe is unsupported for environment')
 source=prove_source(repo,adapter)
 group=adapter['targets'].get(environment)
 if not group:raise ContractError('environment has no target inventory')
 name=requested_target or group['default']
 if name not in group['items']:raise ContractError('logical target is not allowlisted')
 target=group['items'][name]
 if target['mode']!='active' or target['provider']!='dokploy':raise ContractError('target mode or provider is unsupported')
 binding=adapter['providers']['dokploy']['bindings'][target['provider_binding']]
 endpoint,credential=profile_credentials(profile_root);resolved=discover_binding(DokployClient(endpoint,credential),ProviderNames(binding['project'],binding['environment'],binding['resource'],binding['child_binding']))
 return invoke(repo,adapter,capability,request(capability,environment=environment,target=name),extra_env={'DOKPLOY_URL':endpoint,'DOKPLOY_TOKEN':credential,binding['child_binding']:resolved.resource_id})

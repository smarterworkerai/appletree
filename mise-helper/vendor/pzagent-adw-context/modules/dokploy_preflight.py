"""Hermes-aware, secret-safe Dokploy discovery and child binding."""
from __future__ import annotations
import json,os,subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any,Protocol
from urllib.parse import urlencode
from urllib.request import Request,urlopen
from urllib.error import HTTPError,URLError
from .common import ContractError,IDENTIFIER
@dataclass(frozen=True)
class ProviderNames: project:str; environment:str; resource:str; child_binding:str
@dataclass(frozen=True)
class ResolvedBinding: environment_id:str; resource_id:str
class InventoryClient(Protocol):
    def projects(self)->Any: ...
class DokployClient:
    def __init__(self,endpoint:str,credential:str):
        if not endpoint.startswith(('http://','https://')) or not credential: raise ContractError('Dokploy operator inputs are missing or invalid')
        self._endpoint=endpoint.rstrip('/'); self._credential=credential
    def _get(self,path:str)->Any:
        request=Request(self._endpoint+path,headers={'x-api-key':self._credential,'Accept':'application/json'},method='GET')
        try:
            with urlopen(request,timeout=15) as response:
                return json.loads(response.read(1024*1024).decode())
        except (HTTPError,URLError,TimeoutError,UnicodeDecodeError,json.JSONDecodeError) as exc: raise ContractError('Dokploy read-only discovery failed') from exc
    def projects(self)->Any: return self._get('/api/project.all')
    def composes(self,environment_id:str)->Any:
        return self._get('/api/compose.search?'+urlencode({'limit':100,'offset':0,'environmentId':environment_id}))
    @property
    def endpoint(self)->str:return self._endpoint
    @property
    def credential(self)->str:return self._credential

def profile_credentials(profile_root:Path|None)->tuple[str,str]:
    endpoint=os.environ.get('DOKPLOY_URL','')
    credential=os.environ.get('DOKPLOY_TOKEN') or os.environ.get('DOKPLOY_API_KEY','')
    if endpoint and credential:return endpoint,credential
    if profile_root is None:raise ContractError('Dokploy operator inputs are absent; pass --profile-root')
    config=profile_root/'config.yaml'
    if not config.is_file() or config.is_symlink():raise ContractError('Hermes profile config is unavailable')
    values={}; in_env=False; indent=0
    for raw in config.read_text(encoding='utf-8').splitlines():
        stripped=raw.strip(); current=len(raw)-len(raw.lstrip())
        if stripped=='env:':in_env=True;indent=current;continue
        if in_env and current<=indent and stripped:in_env=False
        if in_env and ':' in stripped:
            key,value=stripped.split(':',1)
            if key in {'DOKPLOY_URL','DOKPLOY_API_KEY'}:values[key]=value.strip().strip('"\'')
    endpoint=values.get('DOKPLOY_URL','');credential=values.get('DOKPLOY_API_KEY','')
    if not endpoint or not credential:raise ContractError('Hermes profile lacks Dokploy operator inputs')
    return endpoint,credential

def discover_binding(client:DokployClient,names:ProviderNames)->ResolvedBinding:
    payload=client.projects();items=payload.get('data',payload) if isinstance(payload,dict) else payload
    if not isinstance(items,list):raise ContractError('provider project inventory is malformed')
    projects=[x for x in items if isinstance(x,dict) and x.get('name')==names.project]
    if len(projects)!=1:raise ContractError('provider project match is not unique')
    environments=projects[0].get('environments')
    if not isinstance(environments,list):raise ContractError('provider environment inventory is malformed')
    matches=[x for x in environments if isinstance(x,dict) and x.get('name')==names.environment and isinstance(x.get('environmentId'),str)]
    if len(matches)!=1:raise ContractError('provider environment match is not unique')
    environment_id=matches[0]['environmentId'];payload=client.composes(environment_id)
    records=payload.get('items',payload.get('data',payload)) if isinstance(payload,dict) else payload
    if not isinstance(records,list):raise ContractError('provider resource inventory is malformed')
    resources=[x for x in records if isinstance(x,dict) and x.get('name')==names.resource and isinstance(x.get('composeId'),str)]
    if len(resources)!=1:raise ContractError('provider resource match is not unique')
    return ResolvedBinding(environment_id,resources[0]['composeId'])
def resolve_inventory(payload:Any,names:ProviderNames)->ResolvedBinding:
    items=payload.get('data',payload) if isinstance(payload,dict) else payload
    if not isinstance(items,list): raise ContractError('provider project inventory is malformed')
    projects=[x for x in items if isinstance(x,dict) and x.get('name')==names.project]
    if len(projects)!=1: raise ContractError('provider project match is not unique')
    environments=projects[0].get('environments')
    if not isinstance(environments,list): raise ContractError('provider environment inventory is malformed')
    envs=[x for x in environments if isinstance(x,dict) and x.get('name')==names.environment and isinstance(x.get('environmentId'),str) and x['environmentId']]
    if len(envs)!=1: raise ContractError('provider environment match is not unique')
    resources=envs[0].get('composes',envs[0].get('resources'))
    if not isinstance(resources,list): raise ContractError('provider resource inventory is malformed')
    matches=[x for x in resources if isinstance(x,dict) and x.get('name')==names.resource and isinstance(x.get('composeId'),str) and x['composeId']]
    if len(matches)!=1: raise ContractError('provider resource match is not unique')
    return ResolvedBinding(envs[0]['environmentId'],matches[0]['composeId'])
def discover(*,capability:dict[str,Any],environment:str,target_provider:str,names:ProviderNames,client:InventoryClient)->ResolvedBinding:
    if capability.get('status')!='supported' or environment not in capability.get('environments',[]): raise ContractError('capability is unsupported for the requested environment')
    if target_provider!='dokploy': raise ContractError('logical target does not select the Dokploy provider')
    if not IDENTIFIER.fullmatch(environment) or not names.child_binding.isupper(): raise ContractError('provider mapping is invalid')
    return resolve_inventory(client.projects(),names)
def child_environment(parent:dict[str,str],binding_name:str,resource_id:str,*,endpoint:str,credential:str)->dict[str,str]:
    child=parent.copy()
    for key in list(child):
        if key.endswith('_COMPOSE_ID') or key in {'DOKPLOY_URL','DOKPLOY_TOKEN','DOKPLOY_API_KEY'}: child.pop(key,None)
    child[binding_name]=resource_id; child['DOKPLOY_URL']=endpoint; child['DOKPLOY_TOKEN']=credential
    return child

"""Approved logical-target Dokploy Compose orchestration."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError,URLError
from .approval import validate as validate_approval
from .common import ContractError,ensure_contained
from .dokploy_preflight import DokployClient,ProviderNames,discover_binding,profile_credentials
from .dokploy_transaction import Snapshot,apply,environment_keys
from .hooks import invoke,prove_source,request
def _key_contract(data):
 if not isinstance(data,dict):raise ContractError('Environment key schema is not closed')
 keys=data.get('keys');optional=data.get('optional_keys',[])
 if set(data) not in ({'keys'},{'keys','optional_keys'}) or not isinstance(keys,list) or not isinstance(optional,list) or len(keys)!=len(set(keys)) or len(optional)!=len(set(optional)) or not set(optional)<=set(keys):raise ContractError('Environment key schema is not closed')
 allowed=set(keys);return allowed-set(optional),allowed
class ComposeBackend:
 def __init__(self,endpoint:str,credential:str,compose_id:str):self.endpoint=endpoint.rstrip('/');self.credential=credential;self.compose_id=compose_id
 def _request(self,method,path,payload=None):
  data=None if payload is None else json.dumps(payload,separators=(',',':')).encode();request=Request(self.endpoint+path,data=data,method=method,headers={'x-api-key':self.credential,'Accept':'application/json','Content-Type':'application/json'})
  try:
   with urlopen(request,timeout=20) as response:raw=response.read(2*1024*1024)
  except (HTTPError,URLError,TimeoutError) as exc:raise ContractError('Dokploy configuration operation failed') from exc
  try:return json.loads(raw) if raw else {}
  except json.JSONDecodeError as exc:raise ContractError('Dokploy configuration response malformed') from exc
 def _state(self):
  value=self._request('GET',f'/api/compose.one?composeId={self.compose_id}')
  if not isinstance(value,dict) or not isinstance(value.get('composeFile'),str) or not isinstance(value.get('env'),str):raise ContractError('Dokploy raw configuration readback malformed')
  return value
 def read_compose(self):return self._state()['composeFile'].encode()
 def read_environment(self):return self._state()['env'].encode()
 def write_compose(self,value):self._request('POST','/api/compose.update',{'composeId':self.compose_id,'composeFile':value.decode()})
 def write_environment(self,value):self._request('POST','/api/compose.saveEnvironment',{'composeId':self.compose_id,'env':value.decode()})
def config_pull(repo:Path,adapter:dict,*,environment:str,requested_target:str|None,profile_root:Path)->dict:
 capability='adw:deploy:config:pull';cap=adapter['capabilities'][capability]
 if cap['status']!='supported' or environment not in cap['environments']:raise ContractError('configuration pull is unsupported for environment')
 source=prove_source(repo,adapter);group=adapter['targets'].get(environment)
 if not group:raise ContractError('environment has no target inventory')
 target_name=requested_target or group['default']
 if target_name not in group['items']:raise ContractError('logical target is not allowlisted')
 target=group['items'][target_name]
 if target['mode']!='active' or target['provider']!='dokploy':raise ContractError('target mode or provider is unsupported')
 binding=adapter['providers']['dokploy']['bindings'][target['provider_binding']]
 endpoint,credential=profile_credentials(profile_root);resolved=discover_binding(DokployClient(endpoint,credential),ProviderNames(binding['project'],binding['environment'],binding['resource'],binding['child_binding']))
 backend=ComposeBackend(endpoint,credential,resolved.resource_id);compose=backend.read_compose();raw_environment=backend.read_environment()
 return {'status':'ok','source_sha':source,'environment':environment,'target':target_name,'compose_sha256':hashlib.sha256(compose).hexdigest(),'environment_key_count':len(environment_keys(raw_environment))}
def config_apply(repo:Path,adapter:dict,*,environment:str,requested_target:str|None,approval_path:Path,profile_root:Path)->dict:
 source=prove_source(repo,adapter);capability='adw:deploy:config:apply';cap=adapter['capabilities'][capability]
 if cap['status']!='supported' or environment not in cap['environments']:raise ContractError('configuration apply is unsupported for environment')
 group=adapter['targets'].get(environment)
 if not group:raise ContractError('environment has no target inventory')
 target_name=requested_target or group['default']
 if target_name not in group['items']:raise ContractError('logical target is not allowlisted')
 target=group['items'][target_name]
 if target['mode']!='active' or target['provider']!='dokploy':raise ContractError('target mode or provider is unsupported')
 validate_approval(approval_path,source_sha=source,capability=capability,environment=environment,target=target_name)
 binding=adapter['providers']['dokploy']['bindings'][target['provider_binding']]
 endpoint,credential=profile_credentials(profile_root);client=DokployClient(endpoint,credential)
 resolved=discover_binding(client,ProviderNames(binding['project'],binding['environment'],binding['resource'],binding['child_binding']))
 compose=ensure_contained(repo,binding['compose_path']);schema=ensure_contained(repo,binding['environment_schema_path'])
 if not compose.is_file() or not schema.is_file():raise ContractError('tracked desired state or key schema is missing')
 try:key_data=json.loads(schema.read_text())
 except json.JSONDecodeError as exc:raise ContractError('Environment key schema malformed') from exc
 required,allowed=_key_contract(key_data)
 backend=ComposeBackend(endpoint,credential,resolved.resource_id);current_environment=backend.read_environment();actual=environment_keys(current_environment)
 if required-actual or actual-allowed:raise ContractError(f'Environment key drift blocks apply (missing={sorted(required-actual)}, extra={sorted(actual-allowed)})')
 result=apply(repo,target_name,backend,Snapshot(compose.read_bytes(),current_environment),set())
 return {'status':'ok','source_sha':source,'environment':environment,'target':target_name,'compose_changed':result.compose_changed,'environment_key_count':len(actual)}

def config_plan(repo:Path,adapter:dict,*,environment:str,requested_target:str|None,profile_root:Path|None)->dict:
 capability='adw:deploy:config:plan';cap=adapter['capabilities'][capability]
 if cap['status']!='supported' or cap['side_effect']!='read-only' or environment not in cap['environments']:raise ContractError('configuration plan is unsupported for environment')
 source=prove_source(repo,adapter);group=adapter['targets'].get(environment)
 if not group:raise ContractError('environment has no target inventory')
 target_name=requested_target or group['default']
 if target_name not in group['items']:raise ContractError('logical target is not allowlisted')
 target=group['items'][target_name]
 if target['mode']!='active' or target['provider']!='dokploy':raise ContractError('target mode or provider is unsupported')
 binding=adapter['providers']['dokploy']['bindings'][target['provider_binding']]
 compose=ensure_contained(repo,binding['compose_path']);schema=ensure_contained(repo,binding['environment_schema_path'])
 if not compose.is_file() or not schema.is_file():raise ContractError('tracked desired state or key schema is missing')
 try:key_data=json.loads(schema.read_text())
 except json.JSONDecodeError as exc:raise ContractError('Environment key schema malformed') from exc
 required,allowed=_key_contract(key_data)
 endpoint,credential=profile_credentials(profile_root);client=DokployClient(endpoint,credential)
 resolved=discover_binding(client,ProviderNames(binding['project'],binding['environment'],binding['resource'],binding['child_binding']))
 actual=environment_keys(ComposeBackend(endpoint,credential,resolved.resource_id).read_environment())
 semantic=invoke(repo,adapter,capability,request(capability,environment=environment,target=target_name))['result']
 return {'status':'ok','source_sha':source,'environment':environment,'target':target_name,'role':semantic['role'],'compose':binding['compose_path'],'expected_key_count':len(required),'missing_keys':sorted(required-actual),'dokploy_only_keys':sorted(actual-allowed),'order':semantic['order']}

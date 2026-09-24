"""Operator-serialized immutable-digest preview hotfix orchestration."""
from __future__ import annotations
import hashlib,json,os,re,stat,sys,time
from pathlib import Path

from .approval import validate as approve
from .common import ContractError,ensure_contained
from .dokploy_preflight import DokployClient,ProviderNames,discover_binding,profile_credentials
from .hooks import HookFailure,invoke,prove_source,request
from .hotfix_registry import transfer
from .hotfix_state import apply as apply_state,restore as restore_state
from .hotfix_transfer import TransferPlan,authorize,prove_upstream_head,transfer_ssh,verify_build
from .remote_config import ComposeBackend
from .remote_deploy import DeployClient,TRANSIENT_RUNTIME_REASONS,_deploy as _deploy_correlated
KEY=re.compile(r'^[A-Z][A-Z0-9_]{0,127}$')
def _trace(stage,status,**fields):
 payload={'event':'pzagent-hotfix','stage':stage,'status':status,**fields}
 print(json.dumps(payload,sort_keys=True,separators=(',',':')),file=sys.stderr,flush=True)
def _safe_failure(stage,exc):
 if isinstance(exc,(ContractError,HookFailure)):
  reason=str(exc)
  if reason and len(reason)<=512 and '\n' not in reason and '\r' not in reason:return stage+': '+reason
 return stage+': unexpected-error'
class HotfixBackend:
 def __init__(self,endpoint,credential,compose_id):self.inner=ComposeBackend(endpoint,credential,compose_id)
 def read_compose(self):return self.inner.read_compose()
 def read_environment(self):return self.inner.read_environment()
 def write_environment(self,value):self.inner._request('POST','/api/compose.saveEnvironment',{'composeId':self.inner.compose_id,'env':value.decode()})
def _target(adapter,environment,requested):
 if environment in {'demo','production'}:raise ContractError('temporary hotfix is forbidden for demo and production')
 group=adapter['targets'].get(environment);name=requested or (group or {}).get('default')
 if not isinstance(group,dict) or not isinstance(name,str) or name not in group.get('items',{}):raise ContractError('hotfix logical target is not allowlisted')
 target=group['items'][name]
 if target.get('mode')!='active' or target.get('provider')!='dokploy':raise ContractError('hotfix target mode or provider is unsupported')
 return name,target
def _assignments(values,owned_keys):
 result={}
 if not isinstance(values,list) or not values:raise ContractError('hotfix build returned no image assignments')
 for value in values:
  if not isinstance(value,str) or '=' not in value:raise ContractError('hotfix image assignment is malformed')
  key,image=value.split('=',1)
  if not KEY.fullmatch(key) or key not in owned_keys or not image or key in result:raise ContractError('hotfix image assignment is not an adapter-declared image key')
  result[key]=image
 return result
def _transfer_images(plan:TransferPlan,built:dict[str,str])->dict[str,str]:
 if plan.transport=='registry':
  immutable=transfer(list(built.values()));return {key:immutable[value] for key,value in built.items()}
 transfer_ssh(plan,list(built.values()));return dict(built)
def _binding(adapter,target,profile_root):
 binding=adapter['providers']['dokploy']['bindings'][target['provider_binding']];endpoint,credential=profile_credentials(profile_root);resolved=discover_binding(DokployClient(endpoint,credential),ProviderNames(binding['project'],binding['environment'],binding['resource'],binding['child_binding']));return endpoint,credential,resolved.resource_id,binding['child_binding']
def _deploy(endpoint,credential,resource_id):
 return _deploy_correlated(endpoint,credential,resource_id)
def _runtime_proof(repo,adapter,environment,target,images,phase,provider_env):
 operation=adapter['hooks']['operations'].get('adw:validate-deployment')
 if not isinstance(operation,dict) or operation.get('result_keys')!=['images']:raise ContractError('deployment validation hook must return exact images')
 expected=[f'{key}={value}' for key,value in sorted(images.items())];response=invoke(repo,adapter,'adw:validate-deployment',request('adw:validate-deployment',environment=environment,target=target,phase=phase,expected_images=expected),extra_env=provider_env)
 if response['result'].get('images')!=expected:raise ContractError('runtime image digest proof differs')
def _wait_runtime_proof(repo,adapter,environment,target,images,phase,provider_env):
 last=None
 for attempt in range(24):
  try:_runtime_proof(repo,adapter,environment,target,images,phase,provider_env);_trace('runtime-proof','passed',attempt=attempt+1,phase=phase);return
  except HookFailure as failure:
   if failure.status!='blocked' or failure.reason_code not in TRANSIENT_RUNTIME_REASONS:raise
   last=failure
   _trace('runtime-proof','blocked',attempt=attempt+1,phase=phase,reason=_safe_failure('runtime-proof',failure))
  if attempt+1<24:time.sleep(5)
 if last is not None:raise last
 raise ContractError('runtime proof did not produce a result')
def apply(repo:Path,adapter:dict,*,environment:str,requested_target:str|None,approval_path:Path,profile_root:Path,run_id:str,transport:str='registry',ssh_alias:str|None=None)->dict:
 capability='adw:hotfix:apply';cap=adapter['capabilities'][capability]
 if cap['status']!='supported' or environment not in cap['environments'] or environment not in adapter['hotfix']['supported_environments']:raise ContractError('hotfix is unsupported for environment')
 source=prove_source(repo,adapter);name,target=_target(adapter,environment,requested_target);approve(approval_path,capability=capability,environment=environment,target=name,source_sha=source,exclusive_target=True);_trace('approval','passed')
 if prove_upstream_head(repo)!=source:raise ContractError('approved source differs after upstream proof')
 plan=authorize(adapter['hotfix'],environment=environment,target=name,source_sha=source,transport=transport,ssh_alias=ssh_alias);operation=adapter['hooks']['operations'].get(capability)
 if not isinstance(operation,dict) or operation.get('result_keys')!=['images']:raise ContractError('hotfix build hook must return only images')
 owned_keys={key for kind in adapter['release_kinds'].values() for key in kind['compose_variables']}
 _trace('build','started');built=_assignments(invoke(repo,adapter,capability,request(capability,environment=environment,target=name,phase='build'))['result']['images'],owned_keys);verify_build(list(built.values()),source,'https://github.com/'+adapter['repository']['id']);_trace('build','passed',images=len(built))
 _trace('transfer','started',images=len(built),transport=plan.transport);updates=_transfer_images(plan,built);_trace('transfer','passed',images=len(updates),transport=plan.transport)
 endpoint,credential,resource_id,child_binding=_binding(adapter,target,profile_root);provider_env={'DOKPLOY_URL':endpoint,'DOKPLOY_TOKEN':credential,child_binding:resource_id};backend=HotfixBackend(endpoint,credential,resource_id);_trace('state-apply','started');artifact,document,_=apply_state(repo,name,backend,updates,environment=environment,source_sha=source,run_id=run_id,require_digest=plan.transport=='registry');_trace('state-apply','passed')
 try:
  _trace('deploy','started',phase='hotfix');_deploy(endpoint,credential,resource_id);_trace('deploy','passed',phase='hotfix')
 except Exception as failure:primary=_safe_failure('deploy',failure);_trace('deploy','failed',phase='hotfix',reason=primary)
 else:
  try:_wait_runtime_proof(repo,adapter,environment,name,updates,'hotfix',provider_env)
  except Exception as failure:primary=_safe_failure('runtime-proof',failure);_trace('runtime-proof','failed',phase='hotfix',reason=primary)
  else:return {'status':'ok','source_sha':source,'environment':environment,'target':name,'images':len(updates),'restore_artifact':str(artifact.relative_to(repo))}
 try:_trace('restore-state','started');prior=restore_state(repo,name,backend,document,environment=environment,source_sha=source);_trace('restore-state','passed')
 except Exception as restore_failure:reason=_safe_failure('restore-state',restore_failure);_trace('restore-state','failed',reason=reason);raise ContractError(primary+'; '+reason) from restore_failure
 try:_trace('deploy','started',phase='automatic-restore');_deploy(endpoint,credential,resource_id);_trace('deploy','passed',phase='automatic-restore')
 except Exception as restore_failure:reason=_safe_failure('restore-deploy',restore_failure);_trace('deploy','failed',phase='automatic-restore',reason=reason);raise ContractError(primary+'; '+reason) from restore_failure
 try:_wait_runtime_proof(repo,adapter,environment,name,prior,'automatic-restore',provider_env)
 except Exception as restore_failure:reason=_safe_failure('restore-runtime-proof',restore_failure);_trace('runtime-proof','failed',phase='automatic-restore',reason=reason);raise ContractError(primary+'; '+reason) from restore_failure
 raise ContractError(primary+'; prior digests restored and redeployed')
def _read_private(path:Path)->bytes:
 flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0);fd=os.open(path,flags)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077:raise ContractError('restore artifact is not a private regular file')
  chunks=[]
  while True:
   value=os.read(fd,65536)
   if not value:break
   chunks.append(value)
  return b''.join(chunks)
 finally:os.close(fd)
def restore(repo:Path,adapter:dict,*,environment:str,requested_target:str|None,approval_path:Path,profile_root:Path,artifact_path:Path)->dict:
 capability=adapter['capabilities']['adw:hotfix:restore']
 if capability['status']!='supported' or environment not in capability['environments'] or environment not in adapter['hotfix']['supported_environments']:raise ContractError('hotfix restore is unsupported for environment')
 source=prove_source(repo,adapter);name,target=_target(adapter,environment,requested_target);artifact=ensure_contained(repo,str(artifact_path));document=_read_private(artifact);digest='sha256:'+hashlib.sha256(document).hexdigest();approve(approval_path,capability='adw:hotfix:restore',environment=environment,target=name,source_sha=source,operation_digest=digest,exclusive_target=True)
 try:artifact_source=json.loads(document).get('source_sha')
 except (json.JSONDecodeError,AttributeError) as exc:raise ContractError('restore artifact source identity is malformed') from exc
 endpoint,credential,resource_id,child_binding=_binding(adapter,target,profile_root);provider_env={'DOKPLOY_URL':endpoint,'DOKPLOY_TOKEN':credential,child_binding:resource_id};backend=HotfixBackend(endpoint,credential,resource_id);prior=restore_state(repo,name,backend,document,environment=environment,source_sha=artifact_source);_deploy(endpoint,credential,resource_id);_wait_runtime_proof(repo,adapter,environment,name,prior,'manual-restore',provider_env);return {'status':'ok','source_sha':source,'environment':environment,'target':name,'restored':True}

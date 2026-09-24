"""Approved shared Dokploy deploy followed by credential-free semantic proof."""
from __future__ import annotations
import json,secrets,time
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request,urlopen
from urllib.error import HTTPError,URLError
from .approval import validate as approve
from .common import ContractError,FULL_SHA,git_common_state
from .dokploy_preflight import DokployClient,ProviderNames,discover_binding,profile_credentials
from .hooks import HookFailure,invoke,prove_source,request
from .runtime_proof import parse_environment,prove as prove_runtime
from .release_manifest import release_kind,validate as validate_manifest
from .oras_registry import OrasRegistry
from .target_pointers import pointer_set,promote
from .remote_config import ComposeBackend
from .dokploy_transaction import Snapshot,apply as apply_transaction,replace_environment
class DeployClient:
 def __init__(self,url,token):self.url=url.rstrip('/');self.token=token
 def request(self,method,path,payload=None):
  data=None if payload is None else json.dumps(payload).encode();req=Request(self.url+path,data=data,method=method,headers={'x-api-key':self.token,'Accept':'application/json','Content-Type':'application/json'})
  try:
   with urlopen(req,timeout=20) as response:raw=response.read(1024*1024)
  except (HTTPError,URLError,TimeoutError) as exc:raise ContractError('Dokploy deploy operation failed') from exc
  try:return json.loads(raw) if raw else {}
  except json.JSONDecodeError as exc:raise ContractError('Dokploy deploy response malformed') from exc
def _release_updates(adapter:dict,release_kind_name:str,manifest_path:Path,control_source_sha:str,artifact_source_sha:str|None=None)->dict[str,str]:
 artifact_source_sha=artifact_source_sha or control_source_sha
 if not FULL_SHA.fullmatch(control_source_sha) or not FULL_SHA.fullmatch(artifact_source_sha):raise ContractError('control or artifact source SHA is invalid')
 try:manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
 except (OSError,json.JSONDecodeError) as exc:raise ContractError('release manifest is unavailable or malformed') from exc
 validate_manifest(manifest,adapter,release_kind_name)
 if manifest['source_sha']!=artifact_source_sha:raise ContractError('release manifest artifact source differs')
 kind=release_kind(adapter,release_kind_name)
 return {variable:manifest['images'][component] for variable,component in kind['compose_variables'].items()}
def _deploy(endpoint:str,credential:str,resource_id:str)->None:
 client=DeployClient(endpoint,credential);initial=client.request('GET','/api/compose.one?'+urlencode({'composeId':resource_id}))
 if not isinstance(initial,dict):raise ContractError('pre-deploy status is malformed')
 route='/api/deployment.allByCompose?'+urlencode({'composeId':resource_id});before=client.request('GET',route)
 if not isinstance(before,list) or any(not isinstance(row,dict) or not isinstance(row.get('deploymentId'),str) or not row['deploymentId'] for row in before):raise ContractError('pre-deploy history is malformed')
 existing={row['deploymentId'] for row in before};operation='operation-'+secrets.token_hex(16);title='ADW '+operation;description='pzagent-adw-context '+operation
 client.request('GET','/api/compose.loadServices?'+urlencode({'composeId':resource_id,'type':'fetch'}));ack=client.request('POST','/api/compose.deploy',{'composeId':resource_id,'title':title,'description':description})
 if not (isinstance(ack,dict) and set(ack)=={'success','composeId','message'} and ack.get('success') is True and ack.get('composeId')==resource_id and isinstance(ack.get('message'),str) and 0<len(ack['message'])<=512):raise ContractError('deployment acknowledgement is malformed')
 deployment_id=None
 for _ in range(60):
  rows=client.request('GET',route)
  if not isinstance(rows,list) or any(not isinstance(row,dict) for row in rows):raise ContractError('deployment history is malformed')
  if deployment_id is None:
   candidates=[row for row in rows if row.get('deploymentId') not in existing and row.get('title')==title]
   if len(candidates)>1:raise ContractError('deployment correlation is ambiguous')
   if candidates:
    deployment_id=candidates[0].get('deploymentId')
    if not isinstance(deployment_id,str) or not deployment_id:raise ContractError('deployment correlation identity is malformed')
  row=next((item for item in rows if item.get('deploymentId')==deployment_id),None) if deployment_id else None
  status=row.get('status') if isinstance(row,dict) else None
  if status=='done':return
  if status in {'error','failed','cancelled'}:raise ContractError('deployment reached terminal failure')
  time.sleep(5)
 raise ContractError('deployment did not expose a correlated ready transition')
TRANSIENT_RUNTIME_REASONS={'runtime-container-cardinality-differs','runtime-container-discovery-failed','runtime-container-inspection-failed','runtime-image-identity-or-health-mismatch','runtime-health-endpoint-failed','runtime-readiness-endpoint-failed'}
def _wait_runtime_proof(repo,adapter,environment,target,expected_images,provider_env,phase='normal-release'):
 last=None
 for attempt in range(24):
  try:proof=invoke(repo,adapter,'adw:validate-deployment',request('adw:validate-deployment',environment=environment,target=target,phase=phase,expected_images=expected_images),extra_env=provider_env)
  except HookFailure as failure:
   if failure.status!='blocked' or failure.reason_code not in TRANSIENT_RUNTIME_REASONS:raise
   last=failure
  else:
   if proof['result'].get('images')!=expected_images:raise ContractError('runtime image proof differs from deployed release')
   return proof
  if attempt+1<24:time.sleep(5)
 if last is not None:raise last
 raise ContractError('runtime proof did not produce a result')
def deploy(repo:Path,adapter:dict,*,environment:str,requested_target:str|None,approval_path:Path,profile_root:Path,release_kind:str,release_source_sha:str,manifest_path:Path,manifest_reference:str,expected_pointers_path:Path)->dict:
 capability='adw:deploy:apply';cap=adapter['capabilities'][capability]
 if cap['status']!='supported' or environment not in cap['environments']:raise ContractError('deploy is unsupported for environment')
 source=prove_source(repo,adapter);group=adapter['targets'].get(environment)
 if not group:raise ContractError('environment has no target inventory')
 name=requested_target or group['default']
 if name not in group['items']:raise ContractError('logical target is not allowlisted')
 target=group['items'][name]
 if target['mode']!='active' or target['provider']!='dokploy':raise ContractError('target mode or provider is unsupported')
 approve(approval_path,source_sha=source,capability=capability,environment=environment,target=name)
 binding=adapter['providers']['dokploy']['bindings'][target['provider_binding']];url,token=profile_credentials(profile_root);resolved=discover_binding(DokployClient(url,token),ProviderNames(binding['project'],binding['environment'],binding['resource'],binding['child_binding']));provider_env={'DOKPLOY_URL':url,'DOKPLOY_TOKEN':token,binding['child_binding']:resolved.resource_id};backend=ComposeBackend(url,token,resolved.resource_id)
 before=Snapshot(backend.read_compose(),backend.read_environment());updates=_release_updates(adapter,release_kind,manifest_path,source,release_source_sha);desired=Snapshot(before.compose,replace_environment(before.environment,updates));apply_transaction(repo,name,backend,desired,set(updates));runtime_proven=False;deploy_attempted=False
 try:
  prove_runtime(adapter=adapter,release_kind_name=release_kind,manifest_path=manifest_path,manifest_reference=manifest_reference,source_sha=release_source_sha,raw_environment=desired.environment.decode())
  deploy_attempted=True;_deploy(url,token,resolved.resource_id)
  after_environment=backend.read_environment();identity=prove_runtime(adapter=adapter,release_kind_name=release_kind,manifest_path=manifest_path,manifest_reference=manifest_reference,source_sha=release_source_sha,raw_environment=after_environment.decode())
  expected_images=[f'{key}={value}' for key,value in sorted(updates.items())]
  proof=_wait_runtime_proof(repo,adapter,environment,name,expected_images,provider_env)
  runtime_proven=True
 except Exception as failure:
  if not runtime_proven:
   apply_transaction(repo,name,backend,before,set(updates))
   if deploy_attempted:
    try:
     _deploy(url,token,resolved.resource_id);prior=parse_environment(before.environment.decode());prior_images=[f'{key}={prior[key]}' for key in sorted(updates)];_wait_runtime_proof(repo,adapter,environment,name,prior_images,provider_env,'automatic-restore')
    except Exception as recovery:raise ContractError('deployment failed; prior configuration restored but runtime recovery failed') from recovery
  raise
 try:expected_doc=json.loads(expected_pointers_path.read_text(encoding='utf-8'))
 except (OSError,json.JSONDecodeError) as exc:raise ContractError('expected pointer snapshot is unavailable or malformed') from exc
 if not isinstance(expected_doc,dict) or set(expected_doc)!={'schema_version','target','release_kind','current'} or expected_doc.get('schema_version')!='1.0.0' or expected_doc.get('target')!=name or expected_doc.get('release_kind')!=release_kind or not isinstance(expected_doc.get('current'),dict):raise ContractError('expected pointer snapshot identity is invalid')
 tags=identity['pointer_tags'];pointers=[pointer_set(adapter['release_kinds'][release_kind]['manifest_package'],name,release_kind,manifest_reference,current_template=tags['current'],rollback_template=tags['rollback'])]
 for component,reference in identity['images'].items():pointers.append(pointer_set(adapter['release_kinds'][release_kind]['components'][component]['package'],name,release_kind,reference,current_template=tags['current'],rollback_template=tags['rollback']))
 repositories={pointer.repository for pointer in pointers}
 if set(expected_doc['current'])!=repositories:raise ContractError('expected pointer snapshot repository set differs')
 expected={pointer.current:expected_doc['current'][pointer.repository] for pointer in pointers}
 promote(OrasRegistry(),pointers,expected,lock_dir=git_common_state(repo,'pointer-locks'),runtime_proven=True)
 return {'status':'ok','source_sha':source,'artifact_source_sha':release_source_sha,'environment':environment,'target':name,'release_kind':identity['release_kind'],'manifest_reference':identity['manifest_reference'],'pointers_promoted':True,'runtime_proof':proof['result']}

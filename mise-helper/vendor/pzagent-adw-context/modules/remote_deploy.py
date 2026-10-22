"""Approved release orchestration over the deployment-provider protocol."""
from __future__ import annotations
import hashlib,json,re,secrets,time
from pathlib import Path
from .approval import validate as approve
from .common import ContractError,FULL_SHA,git_common_state
from .providers import DeploymentState, DeploymentTerminalFailure, bind, binding_for, require as require_provider
from .hooks import HookFailure,invoke,prove_source,request
from .runtime_proof import parse_environment,prove as prove_runtime
from .release_manifest import image_variables,release_kind,validate as validate_manifest
from .execution import human
from .operator_state import write as write_state,read as read_state
from .oras_registry import OrasRegistry
from .target_pointers import pointer_set,promote,reconcile
def _release_updates(adapter:dict,release_kind_name:str,manifest_path:Path,control_source_sha:str,artifact_source_sha:str|None=None)->dict[str,str]:
 artifact_source_sha=artifact_source_sha or control_source_sha
 if not FULL_SHA.fullmatch(control_source_sha) or not FULL_SHA.fullmatch(artifact_source_sha):raise ContractError('control or artifact source SHA is invalid')
 try:manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
 except (OSError,json.JSONDecodeError) as exc:raise ContractError('release manifest is unavailable or malformed') from exc
 validate_manifest(manifest,adapter,release_kind_name)
 if manifest['source_sha']!=artifact_source_sha:raise ContractError('release manifest artifact source differs')
 kind=release_kind(adapter,release_kind_name)
 return {variable:manifest['images'][component] for variable,component in kind['image_variables'].items()}
TRANSIENT_RUNTIME_REASONS={'runtime-container-cardinality-differs','runtime-container-discovery-failed','runtime-container-inspection-failed','runtime-image-identity-or-health-mismatch','runtime-health-endpoint-failed','runtime-readiness-endpoint-failed','kubernetes-runtime-not-ready','kubernetes-runtime-cardinality-differs','kubernetes-runtime-image-mismatch'}
def _empty_runtime_proof(provider,snapshot):
 reader=getattr(provider,'empty_runtime_proof',None)
 if not callable(reader):return None
 proof=reader(snapshot)
 if proof is None:return None
 if (not isinstance(proof,dict) or set(proof)!={'state','scope_sha256','snapshot_sha256','retained_pvc_count'}
     or proof.get('state')!='empty' or type(proof.get('retained_pvc_count')) is not int
     or proof['retained_pvc_count']<0
     or not isinstance(proof.get('scope_sha256'),str) or not re.fullmatch(r'[0-9a-f]{64}',proof['scope_sha256'])
     or proof.get('snapshot_sha256')!=hashlib.sha256(snapshot.definition).hexdigest()
     or not callable(getattr(provider,'restore_empty_runtime',None))
     or not callable(getattr(provider,'validate_empty_runtime_proof',None))):
  raise ContractError('provider empty-runtime proof is invalid')
 provider.validate_empty_runtime_proof(proof)
 return proof
def _validate_empty_scope(provider,state):
 validate=getattr(provider,'validate_empty_runtime_proof',None)
 if not callable(validate):raise ContractError('empty runtime scope validation is unavailable')
 validate(state.get('empty_runtime_proof'))
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
def deploy(repo:Path,adapter:dict,*,environment:str,requested_target:str|None,
           approval_path:Path|None,profile_root:Path|None,release_kind:str,
           release_source_sha:str,manifest_path:Path,manifest_reference:str,
           expected_pointers_path:Path|None=None,state_path:Path|None=None,
           restore_compose_path:Path|None=None,reconcile_pointers:bool=False,on_failure:str='stop')->dict:
 if on_failure not in {'stop','restore'}:raise ContractError('invalid failure policy')
 if (reconcile_pointers or on_failure=='restore') and not human():raise ContractError('operator recovery options require human mode')
 capability='adw:deploy:apply';cap=adapter['capabilities'][capability]
 if cap['status']!='supported' or environment not in cap['environments']:
  raise ContractError('deploy is unsupported for environment')
 source=prove_source(repo,adapter);group=adapter['targets'].get(environment)
 if not group:raise ContractError('environment has no target inventory')
 name=requested_target or group['default']
 if name not in group['items']:raise ContractError('logical target is not allowlisted')
 target=group['items'][name]
 if target['mode']!='active':raise ContractError('target mode or provider is unsupported')
 require_provider(target['provider'])
 approve(approval_path,source_sha=source,capability=capability,environment=environment,target=name)
 updates=_release_updates(adapter,release_kind,manifest_path,source,release_source_sha)
 kind=adapter['release_kinds'][release_kind];tags=kind['pointer_tags']
 manifest=json.loads(manifest_path.read_text())
 if human():
  invoke(repo,adapter,'adw:validate-deployment',request('adw:validate-deployment',environment=environment,target=name,
         phase='operator-preflight',expected_images=[f'{key}={value}' for key,value in sorted(updates.items())]))
 pointers=[pointer_set(kind['manifest_package'],name,release_kind,manifest_reference,current_template=tags['current'],rollback_template=tags['rollback'])]
 for component,reference in manifest['images'].items():
  pointers.append(pointer_set(kind['components'][component]['package'],name,release_kind,reference,current_template=tags['current'],rollback_template=tags['rollback']))
 registry=OrasRegistry()
 # All input and pointer validation precedes provider writes.
 for pointer in pointers:
  if registry.resolve(pointer.source)!=pointer.source.split('@',1)[1]:
   raise ContractError('selected release or component is unavailable')
 state=read_state(state_path) if state_path and state_path.exists() else None
 selection={'environment':environment,'target':name,'release_kind':release_kind,'manifest_reference':manifest_reference,'source_sha':release_source_sha}
 if state is not None and state.get('selection')!=selection:
  raise ContractError('resume selection differs from recorded deployment')
 restore_compose=None;restore_digest=None
 if restore_compose_path is not None:
  if restore_compose_path.is_symlink() or not restore_compose_path.is_file():raise ContractError('recorded Compose snapshot is unavailable')
  restore_compose=restore_compose_path.read_bytes();restore_digest=hashlib.sha256(restore_compose).hexdigest()
  if not restore_compose:raise ContractError('recorded Compose snapshot is empty')
 if state is not None:
  recorded=state.get('restore_compose_sha256')
  if (recorded is None)!=(restore_digest is None) or (recorded is not None and recorded!=restore_digest):
   raise ContractError('recorded Compose snapshot identity differs')
 if state is None:
  current={p.repository:registry.resolve(p.current) for p in pointers}
  if expected_pointers_path is not None:
   try:expected_doc=json.loads(expected_pointers_path.read_text())
   except (OSError,json.JSONDecodeError) as exc:raise ContractError('expected pointer snapshot unavailable') from exc
   if (not isinstance(expected_doc,dict) or set(expected_doc)!={'schema_version','target','release_kind','current'} or
       expected_doc.get('schema_version')!='1.0.0' or expected_doc.get('target')!=name or
       expected_doc.get('release_kind')!=release_kind or expected_doc.get('current')!=current):
    raise ContractError('expected pointer snapshot differs from registry state')
  elif not human():raise ContractError('CI requires an expected pointer snapshot')
  state={'schema_version':'1.0.0','selection':selection,'phase':'selected','previous':current,
         'prior_rollback':{p.repository:registry.resolve(p.rollback) for p in pointers},
         'deployment_operation':'operation-'+secrets.token_hex(16)}
  if restore_digest is not None:state['restore_compose_sha256']=restore_digest
 def save(phase):
  state['phase']=phase
  if state_path:write_state(state_path,state)
 provider=bind(repo,adapter,name,target,profile_root)
 provider.discover(binding_for(adapter,target))
 if state.get('previous_runtime')=='empty':_validate_empty_scope(provider,state)
 provider_env=provider.probe(capability)
 before=provider.snapshot()
 rollback_compose=restore_compose if restore_compose is not None else before.definition
 desired=provider.plan(updates,current=before)
 identity=prove_runtime(adapter=adapter,release_kind_name=release_kind,manifest_path=manifest_path,
                       manifest_reference=manifest_reference,source_sha=release_source_sha,
                       observed_images=provider.readback(desired))
 expected_images=[f'{key}={value}' for key,value in sorted(updates.items())]
 phase=state['phase']
 def restore_previous_runtime():
  if state.get('previous_runtime')=='empty':
   if {p.repository:registry.resolve(p.current) for p in pointers}!=state['previous']:
    raise ContractError('deployment pointers changed; inspect before restoring runtime')
   restore=getattr(provider,'restore_empty_runtime',None)
   if not callable(restore) or not isinstance(state.get('empty_runtime_proof'),dict):
    raise ContractError('empty runtime restoration is unavailable')
   save('restore-empty-requested')
   state['empty_restore_proof']=restore(state['empty_runtime_proof'])
   restored_proof=state['empty_restore_proof']
   if (not isinstance(restored_proof,dict) or restored_proof.get('state')!='empty'
       or restored_proof.get('scope_sha256')!=state['empty_runtime_proof']['scope_sha256']):
    raise ContractError('empty runtime restoration is unproven')
   state['restored_runtime']='empty'
   save('restored')
   return
  prior=state.get('previous_images')
  if not prior or set(prior)!=set(updates):raise ContractError('prior runtime snapshot unavailable; explicit recovery required')
  if {p.repository:registry.resolve(p.current) for p in pointers}!=state['previous']:
   raise ContractError('deployment pointers changed; inspect before restoring runtime')
  if state['phase'] not in {'restore-configured','restore-runtime-requested','restore-runtime-confirmed'}:
   state['restore_operation']='operation-'+secrets.token_hex(16)
   save('restore-configured')
  if state['phase']=='restore-runtime-requested':
   try:
    state['restore_deployment_id']=provider.wait(provider.apply({},operation=state['restore_operation'],submit=False))
    save('restore-runtime-confirmed')
   except DeploymentTerminalFailure as failure:
    state.setdefault('restore_attempts',[]).append({'operation':state['restore_operation'],
      'deployment_id':failure.deployment_id,'status':failure.status})
    state['restore_operation']='operation-'+secrets.token_hex(16);state.pop('restore_deployment_id',None)
    save('restore-configured')
  if state['phase']=='restore-configured':
   restored=provider.plan(prior,definition=rollback_compose)
   provider.config_apply(restored,set(updates))
   save('restore-runtime-requested')
   state['restore_deployment_id']=provider.wait(provider.apply({},operation=state['restore_operation']))
   save('restore-runtime-confirmed')
  actual=provider.readback()
  if any(actual.get(key)!=value for key,value in prior.items()):raise ContractError('restoration Environment readback differs')
  _wait_runtime_proof(repo,adapter,environment,name,[f'{key}={prior[key]}' for key in sorted(prior)],provider_env,'automatic-restore')
  save('restored')
 if human() and phase in {'restore-configured','restore-runtime-requested','restore-runtime-confirmed','restore-empty-requested'}:
  restore_previous_runtime()
  raise ContractError('previous runtime was restored; start a new deployment operation')
 if phase=='restored':raise ContractError('previous runtime was restored; start a new deployment operation')
 if phase not in {'selected','configured','runtime-requested','runtime-confirmed','pointers','complete'}:
  raise ContractError('unknown deployment recovery phase')
 if phase in {'selected','configured'}:
  live={p.repository:registry.resolve(p.current) for p in pointers}
  if live!=state['previous']:raise ContractError('deployment pointers changed before runtime mutation')
  # Restoring the complete registered current release may discard a temporary
  # hotfix in human mode. Pointer history remains unchanged for this operation.
  restoring_current=human() and state['previous']=={p.repository:p.source.split('@',1)[1] for p in pointers}
  # A different release must retain an accurately described previous runtime.
  previous_values=provider.readback(before)
  if phase=='selected' and 'previous_images' not in state:
   missing=set(updates)-set(previous_values)
   empty_proof=_empty_runtime_proof(provider,before) if missing else None
   if missing and any(value is not None for value in state['previous'].values()) and empty_proof is None:
    raise ContractError('previous runtime image inputs are incomplete')
   state['previous_images']={key:previous_values[key] for key in updates if key in previous_values}
   if empty_proof is not None:
    state['previous_runtime']='empty';state['empty_runtime_proof']=empty_proof
    prior_manifest=state['previous'].get(kind['manifest_package'])
    if prior_manifest is None and any(value is not None for value in state['previous'].values()):
     raise ContractError('previous current manifest is unavailable for empty runtime')
    state['previous_release_reference']=kind['manifest_package']+'@'+prior_manifest if prior_manifest else None
  if state.get('previous_runtime')=='empty':
   _validate_empty_scope(provider,state)
  for component,item in kind['components'].items():
   digest=state['previous'][item['package']]
   variable=next(key for key,value in image_variables(kind).items() if value==component)
   if digest and previous_values.get(variable)!=item['package']+'@'+digest and phase=='selected' and not restoring_current and state.get('previous_runtime')!='empty':
    raise ContractError('runtime and current pointers differ; reconcile before replacing the runtime')
  if phase=='selected':save('selected')
  try:provider.config_apply(desired,set(updates));save('configured')
  except Exception:
   if state.get('previous_runtime')=='empty' and (not human() or on_failure=='restore'):
    restore_previous_runtime()
   raise
 deploy_attempted=False
 try:
  if phase in {'selected','configured','runtime-requested'}:
   submit=phase!='runtime-requested'
   save('runtime-requested');deploy_attempted=True
   state['deployment_id']=provider.wait(provider.apply({},operation=state['deployment_operation'],submit=submit))
  # Recovery reads current runtime, even if it previously passed.
  prove_runtime(adapter=adapter,release_kind_name=release_kind,manifest_path=manifest_path,
                manifest_reference=manifest_reference,source_sha=release_source_sha,
                observed_images=provider.readback())
  proof=_wait_runtime_proof(repo,adapter,environment,name,expected_images,provider_env,
                           'operator-release' if human() else 'normal-release')
  save('runtime-confirmed')
 except Exception:
  # Human invocation stops with durable progress; no implicit redeploy/restore.
  if human() and on_failure=='restore' and phase in {'selected','configured','runtime-requested'}:
   restore_previous_runtime()
  elif not human():
   if state.get('previous_runtime')=='empty':
    restore_previous_runtime()
    raise
   prior=provider.readback(before)
   if not prior:raise ContractError('prior runtime snapshot unavailable; explicit recovery required')
   provider.restore(DeploymentState(rollback_compose,before.settings),set(updates))
   if deploy_attempted:
    provider.wait(provider.apply({}))
    _wait_runtime_proof(repo,adapter,environment,name,[f'{key}={prior[key]}' for key in sorted(updates)],provider_env,'automatic-restore')
  raise
 desired_current={p.repository:p.source.split('@',1)[1] for p in pointers}
 current={p.repository:registry.resolve(p.current) for p in pointers}
 # Same-release retries preserve the saved rollback; a new release retains the
 # replaced current image, including components shared by the two releases.
 same_release=state['previous']==desired_current
 desired_rollback={p.repository:(state.get('prior_rollback',{}).get(p.repository)
                    if same_release or state['previous'][p.repository] is None else state['previous'][p.repository]) for p in pointers}
 rollback_now={p.repository:registry.resolve(p.rollback) for p in pointers}
 needs_pointer_update=current!=desired_current or ('prior_rollback' in state and rollback_now!=desired_rollback)
 if needs_pointer_update:
  save('pointers')
  if current!=state['previous'] or current==desired_current:
   if not reconcile_pointers or 'prior_rollback' not in state:raise ContractError('partial/conflicting pointer state; explicit reconciliation with recorded rollback snapshot required')
   reconcile(registry,pointers,state['previous'],state['prior_rollback'],lock_dir=git_common_state(repo,'pointer-locks'))
  else:
   promote(registry,pointers,{p.current:state['previous'][p.repository] for p in pointers},
           lock_dir=git_common_state(repo,'pointer-locks'),runtime_proven=True)
  if ({p.repository:registry.resolve(p.current) for p in pointers}!=desired_current or
      ('prior_rollback' in state and {p.repository:registry.resolve(p.rollback) for p in pointers}!=desired_rollback)):
   raise ContractError('pointer finalization readback differs; explicit reconciliation required')
 save('complete')
 result={'status':'ok','source_sha':source,'artifact_source_sha':release_source_sha,
         'environment':environment,'target':name,'release_kind':identity['release_kind'],
         'manifest_reference':manifest_reference,'deployment_id':state.get('deployment_id'),
         'pointers_promoted':needs_pointer_update,'runtime_proof':proof['result']}
 if state.get('previous_runtime')=='empty':
  result.update(previous_runtime='empty',previous_release_reference=state.get('previous_release_reference'),
                empty_runtime_proof=state['empty_runtime_proof'])
 return result

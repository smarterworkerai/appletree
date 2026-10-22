"""Approved deployment validation and project-semantic E2E orchestration."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from .approval import validate as approve
from .common import ContractError
from .hooks import invoke,prove_source,request
from .remote_probe import run as run_probe


def _target(adapter:dict[str,Any],environment:str,requested_target:str|None)->str:
 group=adapter.get('targets',{}).get(environment)
 if requested_target is not None:return requested_target
 if not isinstance(group,dict) or not isinstance(group.get('default'),str):raise ContractError('environment has no default logical target')
 return group['default']


def _supported(adapter:dict[str,Any],capability:str,environment:str)->bool:
 value=adapter.get('capabilities',{}).get(capability)
 return isinstance(value,dict) and value.get('status')=='supported' and environment in value.get('environments',[])


def _invoke_e2e(repo:Path,adapter:dict[str,Any],capability:str,environment:str,target:str)->dict[str,Any]:
 result=invoke(repo,adapter,capability,request(capability,environment=environment,target=target))['result']
 if (set(result)!={'status','selected','executed','skipped'} or result['status']!='passed'
     or result['selected']<1 or result['executed']<1
     or result['executed']+result['skipped']!=result['selected']):
  raise ContractError('project E2E hook lacks nonempty suite execution proof')
 return result


def run_e2e(repo:Path,adapter:dict[str,Any],*,capability:str,environment:str,requested_target:str|None,approval_path:Path)->dict[str,Any]:
 if capability not in {'adw:test:e2e:fast','adw:test:e2e:full'} or not _supported(adapter,capability,environment):raise ContractError('E2E is unsupported for environment')
 source=prove_source(repo,adapter);target=_target(adapter,environment,requested_target)
 approve(approval_path,source_sha=source,capability=capability,environment=environment,target=target)
 result=_invoke_e2e(repo,adapter,capability,environment,target)
 return {'status':'ok','source_sha':source,'environment':environment,'target':target,'suite':capability,'selected':result['selected'],'executed':result['executed'],'skipped':result['skipped']}


def validate_deployment(repo:Path,adapter:dict[str,Any],*,environment:str,requested_target:str|None,approval_path:Path,profile_root:Path)->dict[str,Any]:
 if not _supported(adapter,'adw:validate-deployment',environment):raise ContractError('deployment validation is unsupported for environment')
 source=prove_source(repo,adapter);target=_target(adapter,environment,requested_target)
 approve(approval_path,source_sha=source,capability='adw:validate-deployment',environment=environment,target=target)
 for capability in ('adw:deploy:status','adw:health','adw:readiness'):
  run_probe(repo,adapter,capability=capability,environment=environment,requested_target=target,profile_root=profile_root)
 return {'status':'ok','source_sha':source,'environment':environment,'target':target,'status_probe':'passed','health':'passed','readiness':'passed'}

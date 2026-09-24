"""Read-only authorization for immutable publication identity."""
from __future__ import annotations
from typing import Any
from .common import ContractError,FULL_SHA
def authorize(*,source_sha:str,repository:str,pull:Any,run:Any,actor_permission:str,
              protected_targets:tuple[str,...],diagnostic:bool=False,
              marker_at_sha:bool=False,diagnostic_publish:bool=False)->dict[str,Any]:
    if not FULL_SHA.fullmatch(source_sha): raise ContractError('publication source must be a full SHA')
    if actor_permission not in ('admin','maintain'): raise ContractError('publication actor is not authorized')
    if (not isinstance(pull,dict) or pull.get('head_sha')!=source_sha
        or pull.get('repository')!=repository or pull.get('same_repository') is not True
        or pull.get('state')!='closed' or pull.get('merged') is not True
        or pull.get('merge_sha')!=source_sha
        or pull.get('target_branch') not in protected_targets):
        raise ContractError('exact merged protected-destination PR identity is unproven')
    if diagnostic:
        if not marker_at_sha or not diagnostic_publish: raise ContractError('diagnostic publication is not explicitly authorized')
    if (not isinstance(run,dict) or run.get('sha')!=source_sha
        or run.get('target_branch')!=pull.get('target_branch')
        or run.get('conclusion')!='success' or run.get('event')!='push'
        or type(run.get('run_id')) is not int or run['run_id']<1
        or type(run.get('attempt')) is not int or run['attempt']<1
        or run.get('required_job') is not True):
        raise ContractError('exact-SHA required CI evidence is invalid')
    return {'source_sha':source_sha,'repository':repository,
            'target_branch':pull['target_branch'],'run_id':run['run_id'],
            'run_attempt':run['attempt'],'quality_evidence':'exact-sha-destination-push',
            'authorized':True}

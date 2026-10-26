"""Read-only merged-work-branch proof with content-safe outcomes."""
from __future__ import annotations
import json,re,subprocess
from dataclasses import dataclass
from typing import Any,Callable
from .common import ContractError,FULL_SHA
SAFE_BRANCH=re.compile(r'^(?![.-])(?!.*(?:\.\.|//|@\{|\\|[ ~^:?*\[]))(?!.*(?:/|\.)$)[A-Za-z0-9._/-]+$')
@dataclass(frozen=True)
class ProofInput:
    repository:str; pr_number:int; source_branch:str; target_branch:str
def validate_input(value:ProofInput,protected:set[str]=frozenset({'main','demo'}),targets:set[str]=frozenset({'main','demo'}))->None:
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',value.repository) or value.pr_number<1: raise ContractError('repository or PR identity is invalid')
    if value.target_branch not in targets: raise ContractError('target branch is not allowlisted')
    if value.source_branch in protected: raise ContractError('protected branch cannot be a cleanup source')
    if not SAFE_BRANCH.fullmatch(value.source_branch): raise ContractError('source branch is not a safe Git ref')
    checked=subprocess.run(['git','check-ref-format','--branch',value.source_branch],text=True,capture_output=True,check=False)
    if checked.returncode or checked.stdout.removesuffix('\n')!=value.source_branch: raise ContractError('source branch is not a valid Git branch')
def prove(value:ProofInput,pull:Any,live_ref:Callable[[str],str],is_ancestor:Callable[[str,str],bool],tree:Callable[[str],str],*,protected:frozenset[str]=frozenset({'main','demo'}))->dict[str,Any]:
    validate_input(value,protected,protected)
    if not isinstance(pull,dict) or pull.get('state')!='closed' or not pull.get('merged_at'): raise ContractError('pr_not_merged')
    head_raw=pull.get('head'); head=head_raw if isinstance(head_raw,dict) else {}; base=pull.get('base'); source=head.get('sha'); merge=pull.get('merge_commit_sha')
    if not isinstance(base,dict) or base.get('ref')!=value.target_branch: raise ContractError('pr_target_branch_mismatch')
    head_repo=head.get('repo') if isinstance(head,dict) else None
    if head.get('ref')!=value.source_branch or not isinstance(head_repo,dict) or head_repo.get('full_name')!=value.repository: raise ContractError('pr_source_identity_mismatch')
    if not isinstance(source,str) or not FULL_SHA.fullmatch(source) or not isinstance(merge,str) or not FULL_SHA.fullmatch(merge): raise ContractError('pr_revision_identity_invalid')
    remote_source=live_ref(value.source_branch); target=live_ref(value.target_branch)
    if source!=remote_source: raise ContractError('stale_remote_source_head')
    if not is_ancestor(merge,target): raise ContractError('merge_commit_not_on_live_target')
    source_tree,merge_tree=tree(source),tree(merge)
    if is_ancestor(source,target): mode='ancestor'
    elif source_tree==merge_tree: mode='equivalent-merged-result'
    else: raise ContractError('source_not_ancestor_and_trees_unequal')
    return {'repository':value.repository,'pr_number':value.pr_number,'source_branch':value.source_branch,'target_branch':value.target_branch,'source_head':source,'remote_source_head':remote_source,'target_head':target,'merge_commit':merge,'source_tree':source_tree,'merge_tree':merge_tree,'proof_mode':mode}

def _github(endpoint:str,reason:str,*,missing:str|None=None,invalid:str|None=None)->dict[str,Any]:
    fetched=subprocess.run(['gh','api','--method','GET',endpoint],text=True,capture_output=True,check=False)
    if fetched.returncode:
        if missing and 'HTTP 404' in fetched.stderr: raise ContractError(missing)
        raise ContractError(reason)
    try: value=json.loads(fetched.stdout)
    except json.JSONDecodeError: raise ContractError(invalid or reason) from None
    if not isinstance(value,dict): raise ContractError(invalid or reason)
    return value
def operator_prove(repo,adapter:dict,*,pr_number:int,source_branch:str,target_branch:str,remote:str='origin')->dict[str,Any]:
    """Read-only proof through the live GitHub REST API only, so it needs no Git credentials
    (HTTPS, SSH and token-only setups alike); never deletes or pushes a ref. `repo` and
    `remote` are accepted for compatibility and no longer read."""
    repository=adapter['repository']['id']; protected=frozenset(adapter['repository']['protected_branches'])
    value=ProofInput(repository,pr_number,source_branch,target_branch)
    validate_input(value,protected,protected)
    pull=_github(f'repos/{repository}/pulls/{pr_number}','github_pr_lookup_failed',invalid='github_pr_metadata_invalid')
    def live_ref(branch:str)->str:
        ref=_github(f'repos/{repository}/git/ref/heads/{branch}','github_ref_lookup_failed',missing='remote_branch_missing')
        target=ref.get('object')
        sha=target.get('sha') if isinstance(target,dict) and target.get('type')=='commit' else None
        if ref.get('ref')!=f'refs/heads/{branch}' or not isinstance(sha,str) or not FULL_SHA.fullmatch(sha): raise ContractError('remote_branch_missing')
        return sha
    def is_ancestor(ancestor:str,descendant:str)->bool:
        status=_github(f'repos/{repository}/compare/{descendant}...{ancestor}','github_compare_failed').get('status')
        if status not in {'ahead','behind','identical','diverged'}: raise ContractError('github_compare_failed')
        return status in {'behind','identical'}
    def tree(commit:str)->str:
        found=_github(f'repos/{repository}/git/commits/{commit}','github_commit_lookup_failed').get('tree')
        sha=found.get('sha') if isinstance(found,dict) else None
        if not isinstance(sha,str) or not FULL_SHA.fullmatch(sha): raise ContractError('github_commit_lookup_failed')
        return sha
    return prove(value,pull,live_ref,is_ancestor,tree,protected=protected)

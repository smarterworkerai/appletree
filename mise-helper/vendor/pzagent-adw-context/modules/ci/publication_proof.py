"""Post-merge destination and publisher authorization share one exact quality proof."""
from __future__ import annotations
from dataclasses import replace
from .contract import contract_ref
from .ci_only import require_ci_only
from .evidence import job_evidence
from .github_api import ApiError, GitHub
from .provenance import trusted_source
from .quality_proof import Pull, ProofError, Revision, prove_destination
from .reuse import _utc, prior_gate


def _candidate_matches(record: object, *, repository: str, source_sha: str,
                       target: str, source: str | None = None) -> bool:
    if not isinstance(record,dict):
        return False
    head=record.get('head');base=record.get('base')
    return (record.get('state')=='closed' and isinstance(record.get('merged_at'),str)
            and record.get('merge_commit_sha')==source_sha
            and isinstance(head,dict) and head.get('sha')==source_sha
            and isinstance(head.get('repo'),dict)
            and head['repo'].get('full_name')==repository
            and (source is None or head.get('ref')==source)
            and isinstance(base,dict) and base.get('ref')==target
            and isinstance(base.get('repo'),dict)
            and base['repo'].get('full_name')==repository)


def _candidate_lookup_error(exc: ApiError) -> ProofError:
    reason=str(exc)
    if reason in {'response_too_large','response_malformed','pagination_limit'}:
        return ProofError(f'destination_candidate_{reason}')
    return ProofError('destination_candidate_lookup_failed')


def destination_gate(api: GitHub, *, source_sha: str, adapter: dict,
                     target: str | None=None, run_id: int | None=None,
                     attempt: int | None=None) -> dict:
    if (not isinstance(source_sha,str) or len(source_sha)!=40
        or any(ch not in '0123456789abcdef' for ch in source_sha)
        or (run_id is not None and (type(run_id) is not int or run_id<1))
        or (attempt is not None and (type(attempt) is not int or attempt<1))
        or ((run_id is None) != (attempt is None))):
        raise ProofError('destination_identity_invalid')
    targets=adapter['repository']['protected_branches']
    if target is not None:
        if target not in targets:
            raise ProofError('destination_not_protected')
        targets=[target]
    ref=contract_ref(api,source_sha)
    require_ci_only(api,source_sha,adapter['ci']['ci_only_checks'])
    source_tree=api.get(f'git/commits/{source_sha}')['tree']['sha']
    try:
        associated=api.associated_pulls(source_sha)
    except ApiError as exc:
        reason=str(exc)
        if reason in {'response_too_large','pagination_limit','association_lookup_failed'}:
            raise ProofError(f'destination_association_{reason}') from None
        raise ProofError('destination_association_lookup_failed') from None
    candidates=[]
    for branch in targets:
        if api.get(f'git/ref/heads/{branch}')['object']['sha']!=source_sha:
            continue
        discovered:dict[int,str | None]={}
        for record in associated:
            if _candidate_matches(record,repository=api.repository,
                                  source_sha=source_sha,target=branch):
                number=record.get('number')
                if type(number) is int:
                    discovered[number]=None
        if not discovered:
            pairs=[pair for pair in adapter['delivery']['promotion_pairs']
                   if pair['target']==branch]
            try:
                for pair in pairs:
                    for record in api.promotion_pulls(source=pair['source'],target=branch):
                        if _candidate_matches(record,repository=api.repository,
                                              source_sha=source_sha,target=branch,
                                              source=pair['source']):
                            number=record.get('number')
                            if type(number) is int:
                                discovered.setdefault(number,pair['source'])
            except ApiError:
                raise ProofError('destination_promotion_lookup_failed') from None
        if len(discovered)>100:
            raise ProofError('destination_candidate_limit')
        for number,required_source in sorted(discovered.items()):
            try:
                p=api.get(f'pulls/{number}')
            except ApiError as exc:
                raise _candidate_lookup_error(exc) from None
            if not isinstance(p,dict) or p.get('number')!=number:
                raise ProofError('destination_candidate_identity_mismatch')
            if not _candidate_matches(p,repository=api.repository,source_sha=source_sha,
                                      target=branch,source=required_source):
                continue
            pr=Pull(number=p['number'],repository=api.repository,state='closed',merged=True,
                    source_branch=p['head']['ref'],target_branch=branch,head_sha=source_sha,
                    base_sha=p['base']['sha'],merge_sha=source_sha,same_repository=True,
                    approved_head_sha=None)
            trusted_source(api,pr)
            base_tree=api.get(f'git/commits/{pr.base_sha}')['tree']['sha']
            rev=Revision(source_sha=source_sha,source_tree=source_tree,
                         base_sha=pr.base_sha,base_tree=base_tree,
                         checkout_sha=source_sha,checkout_tree=source_tree,
                         contract_ref=ref,live_source_sha=source_sha,live_target_sha=source_sha,
                         ff=True,merge_tree=source_tree)
            for gate in job_evidence(api,pr,rev):
                if ((run_id is not None and (gate.run_id!=run_id or gate.attempt!=attempt))
                    or _utc(gate.completed_at)>=_utc(p['merged_at'])):
                    continue
                parent=None
                current=gate
                if gate.kind=='proof':
                    if {'source':pr.source_branch,'target':branch} not in adapter['delivery']['promotion_pairs']:
                        continue
                    parent=prior_gate(api,pr,rev)
                    current=replace(gate,parent_run_id=parent.run_id,parent_attempt=parent.attempt)
                proof=prove_destination(pr,rev,[current],target=branch,parent=parent)
                if proof['run_id']==gate.run_id and proof['attempt']==gate.attempt:
                    candidates.append((pr,gate))
    if not candidates:
        raise ProofError('destination_exact_gate_missing')
    # A caller requesting a specific run may select it. Without one, different
    # PRs on the same SHA are ambiguous even if their check names match.
    if len({pr.number for pr,_ in candidates})!=1:
        raise ProofError('destination_pr_ambiguous')
    pr,gate=max(candidates,key=lambda item:(item[1].run_id,item[1].attempt))
    return {'status':'proved','proof_kind':gate.kind,'repository':api.repository,
            'source_sha':source_sha,'tested_tree':source_tree,'contract_ref':ref,
            'pr_number':pr.number,'target_branch':pr.target_branch,
            'workflow_path':gate.workflow_path,'run_id':gate.run_id,
            'run_attempt':gate.attempt,'job_id':gate.job_id}


def authorize(api: GitHub, *, source_sha: str, run_id: int, attempt: int,
              actor: str, adapter: dict, diagnostic: bool=False) -> dict:
    if not actor or api.get(f'collaborators/{actor}/permission').get('permission') not in ('admin','maintain'):
        raise ProofError('publication_actor_not_admin')
    if diagnostic:
        api.content('deploy_diag',source_sha)
    result=destination_gate(api,source_sha=source_sha,adapter=adapter,
                            run_id=run_id,attempt=attempt)
    return {'schema_version':'1.0.0','repository':api.repository,'source_sha':source_sha,
            'pr_number':result['pr_number'],'target_branch':result['target_branch'],
            'actor':actor,'workflow_path':result['workflow_path'],
            'run_id':run_id,'run_attempt':attempt,'job_id':result['job_id'],
            'tested_tree':result['tested_tree'],'contract_ref':result['contract_ref'],
            'diagnostic':diagnostic}

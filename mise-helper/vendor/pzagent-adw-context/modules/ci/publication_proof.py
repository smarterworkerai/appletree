"""Post-merge destination and publisher authorization share one exact quality proof."""
from __future__ import annotations
from dataclasses import replace
import time
from .contract import contract_ref
from .ci_only import require_ci_only
from .evidence import job_evidence
from .github_api import ApiError, GitHub
from .live_pr import read_pr
from .provenance import trusted_source
from .quality_proof import Pull, ProofError, Revision, premerge_check, prove_destination
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


# One policy for every read-only proof lookup that GitHub's eventual consistency can
# fail for a few seconds: a hard 60 s ceiling in 5 s polls, the same values as the CI
# gate's appearance grace and the promote read-back. It never wraps a mutation.
TRANSIENT_RETRY_SECONDS = 60
TRANSIENT_POLL_SECONDS = 5
TRANSIENT_REASONS = frozenset({'bootstrap_controller_missing','bootstrap_controller_unusable',
                               'destination_exact_gate_missing','lookup_failed'})
TRANSIENT_PREFIXES = ('destination_association_','destination_candidate_')
TRANSIENT_SUFFIX = '_lookup_failed'


def is_transient(exc: BaseException) -> bool:
    """Only lookups that can succeed on a later poll; a real refusal is never retried."""
    if isinstance(exc,ProofError):
        reason=exc.reason
    elif isinstance(exc,ApiError):
        reason=str(exc)
    else:
        return False
    return (reason in TRANSIENT_REASONS or reason.startswith(TRANSIENT_PREFIXES)
            or reason.endswith(TRANSIENT_SUFFIX))


def with_transient_retry(call, *, ceiling: int = TRANSIENT_RETRY_SECONDS,
                         poll: int = TRANSIENT_POLL_SECONDS, sleep=None):
    """Run a read-only lookup, retrying transient rejections until the ceiling; the last
    error is raised verbatim. Attempt-bounded so a mocked clock can never spin forever."""
    if type(ceiling) is not int or type(poll) is not int or not 0 <= ceiling <= 600 or not 1 <= poll <= 60:
        raise ProofError('transient_retry_invalid')
    attempts=1+ceiling//poll
    for attempt in range(attempts):
        try:
            return call()
        except (ProofError,ApiError) as exc:
            if not is_transient(exc) or attempt+1>=attempts:
                raise
            (sleep or time.sleep)(poll)
    raise AssertionError('unreachable')  # pragma: no cover


def _candidate_lookup_error(exc: ApiError) -> ProofError:
    reason=str(exc)
    if reason in {'response_too_large','response_malformed','pagination_limit'}:
        return ProofError(f'destination_candidate_{reason}')
    return ProofError('destination_candidate_lookup_failed')


def destination_gate(api: GitHub, *, source_sha: str, adapter: dict,
                     target: str | None=None, run_id: int | None=None,
                     attempt: int | None=None, pr_number: int | None=None) -> dict:
    if (not isinstance(source_sha,str) or len(source_sha)!=40
        or any(ch not in '0123456789abcdef' for ch in source_sha)
        or (run_id is not None and (type(run_id) is not int or run_id<1))
        or (attempt is not None and (type(attempt) is not int or attempt<1))
        or ((run_id is None) != (attempt is None))
        or (pr_number is not None and (type(pr_number) is not int or pr_number<1))):
        raise ProofError('destination_identity_invalid')
    targets=adapter['repository']['protected_branches']
    if target is not None:
        if target not in targets:
            raise ProofError('destination_not_protected')
        targets=[target]
    ref=contract_ref(api,source_sha)
    require_ci_only(api,source_sha,adapter['ci']['ci_only_checks'])
    source_tree=api.get(f'git/commits/{source_sha}')['tree']['sha']
    associated:list[dict]=[]
    if pr_number is None:
        # Discover the merged PR through the commit association. A caller that already
        # knows the PR (the promote operator) names it instead: the association list
        # lags pulls/<n> for a short time after a fast-forward and would report "missing".
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
        if pr_number is not None:
            discovered[pr_number]=None
        for record in associated:
            if _candidate_matches(record,repository=api.repository,
                                  source_sha=source_sha,target=branch):
                number=record.get('number')
                if type(number) is int:
                    discovered[number]=None
        if not discovered and pr_number is None:
            pairs=[pair for pair in adapter['delivery']['promotion_pairs']
                   if pair['target']==branch]
            try:
                for pair in pairs:
                    for record in api.promotion_pulls(source=pair['source'],target=branch,head_sha=source_sha):
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
            if (number==pr_number and p['head']['ref'] in adapter['repository']['protected_branches']
                    and {'source':p['head']['ref'],'target':branch} not in adapter['delivery']['promotion_pairs']):
                continue  # a hinted protected-branch source must still be a declared pair
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
            'run_attempt':gate.attempt,'job_id':gate.job_id,
            'quality_producer':{'repository':api.repository,'source_sha':source_sha,
                                'run_id':gate.run_id,'run_attempt':gate.attempt,
                                'event':'pull_request','branch':pr.source_branch,
                                'pr_number':pr.number}}


def pull_request_gate(api: GitHub, *, source_sha: str | None, pr_number: int,
                      adapter: dict, run_id: int | None=None,
                      attempt: int | None=None) -> dict:
    """Prove one live same-repository PR and its latest or selected quality job."""
    if type(pr_number) is not int or pr_number<1:
        raise ProofError('pull_request_identity_invalid')
    if source_sha is None:
        try:
            record=api.get(f'pulls/{pr_number}')
            source_sha=record['head']['sha']
        except (ApiError,KeyError,TypeError):
            raise ProofError('github_lookup_failed') from None
    if (not isinstance(source_sha,str) or len(source_sha)!=40
        or any(ch not in '0123456789abcdef' for ch in source_sha)
        or ((run_id is None)!=(attempt is None))
        or (run_id is not None and (type(run_id) is not int or run_id<1))
        or (attempt is not None and (type(attempt) is not int or attempt<1))):
        raise ProofError('pull_request_identity_invalid')
    ref=contract_ref(api,source_sha)
    pr,rev=read_pr(api,pr_number,contract_ref=ref)
    if pr.head_sha!=source_sha:
        raise ProofError('stale_source_head')
    if pr.target_branch not in adapter['repository']['protected_branches']:
        raise ProofError('destination_not_protected')
    trusted_source(api,pr)
    require_ci_only(api,source_sha,adapter['ci']['ci_only_checks'])
    evidence=job_evidence(api,pr,rev,workflow_path=adapter['ci']['workflow_path'],
                          job_name=adapter['ci']['required_job'])
    parent=None
    if any(item.kind=='proof' for item in evidence):
        if {'source':pr.source_branch,'target':pr.target_branch} not in adapter['delivery']['promotion_pairs']:
            raise ProofError('undeclared_promotion_pair')
        parent=prior_gate(api,pr,rev)
        evidence=[replace(item,parent_run_id=parent.run_id,parent_attempt=parent.attempt)
                  if item.kind=='proof' else item for item in evidence]
    selected=(evidence if run_id is None else
              [item for item in evidence if item.run_id==run_id and item.attempt==attempt])
    if not selected:
        raise ProofError('pull_request_exact_gate_missing')
    proof=premerge_check(pr,rev,selected,target=pr.target_branch,
                         check_name=adapter['ci']['required_job'],
                         workflow_path=adapter['ci']['workflow_path'],parent=parent)
    gates=[item for item in selected
           if item.run_id==proof['run_id'] and item.attempt==proof['attempt']]
    if len(gates)!=1:
        raise ProofError('pull_request_exact_gate_missing')
    gate=gates[0]
    return {'status':'proved','proof_kind':proof['proof_kind'],
            'repository':api.repository,'source_sha':source_sha,
            'tested_tree':rev.source_tree,'contract_ref':ref,
            'pr_number':pr.number,'source_branch':pr.source_branch,
            'target_branch':pr.target_branch,'base_sha':pr.base_sha,
            'workflow_path':gate.workflow_path,'run_id':gate.run_id,
            'run_attempt':gate.attempt,'job_id':gate.job_id,
            'quality_producer':{'repository':api.repository,'source_sha':source_sha,
                                'run_id':gate.run_id,'run_attempt':gate.attempt,
                                'event':'pull_request','branch':pr.source_branch,
                                'pr_number':pr.number}}


def authorize(api: GitHub, *, source_sha: str, run_id: int, attempt: int,
              actor: str, adapter: dict) -> dict:
    if not actor or api.get(f'collaborators/{actor}/permission').get('permission') not in ('admin','maintain'):
        raise ProofError('publication_actor_not_admin')
    result=destination_gate(api,source_sha=source_sha,adapter=adapter,
                            run_id=run_id,attempt=attempt)
    return {'schema_version':'1.1.0','repository':api.repository,'source_sha':source_sha,
            'pr_number':result['pr_number'],'target_branch':result['target_branch'],
            'actor':actor,'workflow_path':result['workflow_path'],
            'run_id':run_id,'run_attempt':attempt,'job_id':result['job_id'],
            'tested_tree':result['tested_tree'],'contract_ref':result['contract_ref']}


def authorize_release(api: GitHub, *, source_sha: str, run_id: int, attempt: int,
                      actor: str, adapter: dict, proof_scope: str,
                      pr_number: int | None, target: str | None,
                      release_kind: str, publication_lane: str,
                      publication_pointer: str | None,
                      expected_pointer_digest: str | None) -> dict:
    """Create the closed receipt consumed and recomputed by public release tasks."""
    if not actor or api.get(f'collaborators/{actor}/permission').get('permission') not in ('admin','maintain'):
        raise ProofError('publication_actor_not_admin')
    if proof_scope=='pull_request':
        if target is not None or pr_number is None:
            raise ProofError('publication_scope_invalid')
        result=pull_request_gate(api,source_sha=source_sha,pr_number=pr_number,
                                 adapter=adapter,run_id=run_id,attempt=attempt)
    elif proof_scope=='destination':
        if not isinstance(target,str):
            raise ProofError('publication_scope_invalid')
        # pr_number is an optional hint naming the promotion PR that produced the
        # destination head; it replaces association discovery, never the proof itself.
        result=destination_gate(api,source_sha=source_sha,adapter=adapter,
                                target=target,run_id=run_id,attempt=attempt,pr_number=pr_number)
    else:
        raise ProofError('publication_scope_invalid')
    if release_kind not in adapter['release_kinds']:
        raise ProofError('publication_release_kind_invalid')
    pointers=adapter['release_kinds'][release_kind].get('publication_pointers',[])
    if ((publication_pointer is None)!=(expected_pointer_digest is None)
        or (publication_pointer is not None and publication_pointer not in pointers)):
        raise ProofError('publication_pointer_invalid')
    if (publication_lane!=release_kind
        or not isinstance(publication_lane,str) or not publication_lane
        or len(publication_lane)>63
        or any(ch not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for ch in publication_lane)):
        raise ProofError('publication_lane_invalid')
    if (expected_pointer_digest is not None and expected_pointer_digest!='absent'
        and (not isinstance(expected_pointer_digest,str)
             or not expected_pointer_digest.startswith('sha256:')
             or len(expected_pointer_digest)!=71
             or any(ch not in '0123456789abcdef' for ch in expected_pointer_digest[7:]))):
        raise ProofError('publication_pointer_expectation_invalid')
    return {'schema_version':'2.2.0','repository':api.repository,
            'source_sha':source_sha,'pr_number':result['pr_number'],
            'target_branch':result['target_branch'],'actor':actor,
            'workflow_path':result['workflow_path'],'run_id':run_id,
            'run_attempt':attempt,'job_id':result['job_id'],
            'tested_tree':result['tested_tree'],'contract_ref':result['contract_ref'],
            'proof_scope':proof_scope,
            'release_kind':release_kind,'publication_lane':publication_lane,
            'publication_pointer':publication_pointer,
            'expected_pointer_digest':expected_pointer_digest,
            'quality_producer':result['quality_producer']}

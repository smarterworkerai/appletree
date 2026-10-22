"""Find a merged, exact-tree full-gate PR feeding a protected branch."""
from __future__ import annotations
from datetime import datetime, timezone
import re
from .github_api import ApiError
from .quality_proof import Pull, Revision, ProofError
from .evidence import executed_evidence
from .provenance import trusted_source


def _utc(value: object) -> datetime:
    if not isinstance(value,str) or not value.endswith('Z'):
        raise ProofError('time_invalid')
    try:
        parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError:
        raise ProofError('time_invalid') from None
    if parsed.tzinfo != timezone.utc:
        raise ProofError('time_invalid')
    return parsed


def _lookup_error(stage: str, exc: ApiError) -> ProofError:
    reason=str(exc)
    safe={'response_too_large','response_malformed','pagination_limit',
          'check_inventory_incomplete','association_lookup_failed'}
    return ProofError(f'prior_{stage}_{reason}' if reason in safe
                      else f'prior_{stage}_lookup_failed')


def _executed_pr_numbers(api, current: Pull) -> set[int]:
    """Resolve prior PRs from exact-SHA required-quality check/run identity."""
    try:
        inventory=api.check_runs(current.head_sha)
    except ApiError as exc:
        raise _lookup_error('check',exc) from None
    checks=[check for check in inventory
            if check.get('name')=='required-quality'
            and check.get('head_sha')==current.head_sha
            and check.get('status')=='completed' and check.get('conclusion')=='success'
            and isinstance(check.get('app'),dict)
            and check['app'].get('slug')=='github-actions']
    if len(checks)>32:
        raise ProofError('prior_check_inventory_limit')
    numbers:set[int]=set()
    details_pattern=(r'https://github\.com/'+re.escape(api.repository)
                     +r'/actions/runs/([1-9][0-9]*)/job/[1-9][0-9]*/?')
    title_pattern=(r'ADW CI pull_request PR#([1-9][0-9]*) to '
                   +re.escape(current.source_branch)+r' head '+current.head_sha)
    for check in checks:
        details=check.get('details_url')
        match=re.fullmatch(details_pattern,details) if isinstance(details,str) else None
        if not match:
            continue
        try:
            run=api.get(f'actions/runs/{match[1]}')
        except ApiError as exc:
            raise _lookup_error('run',exc) from None
        title=run.get('display_title') if isinstance(run,dict) else None
        title_match=re.fullmatch(title_pattern,title) if isinstance(title,str) else None
        if (title_match and run.get('event')=='pull_request'
            and run.get('head_sha')==current.head_sha
            and run.get('status')=='completed' and run.get('conclusion')=='success'
            and isinstance(run.get('path'),str)
            and (run['path']=='.github/workflows/ci.yml'
                 or run['path'].startswith('.github/workflows/ci.yml@'))
            and isinstance(run.get('head_repository'),dict)
            and run['head_repository'].get('full_name')==api.repository):
            numbers.add(int(title_match[1]))
    return numbers


def prior_gate(api, current: Pull, rev: Revision):
    if not rev.ff or rev.merge_tree!=rev.source_tree:
        raise ProofError('merge_tree_requires_branch_sync')
    try:
        associated=api.associated_pulls(current.head_sha)
    except ApiError as exc:
        raise _lookup_error('association',exc) from None
    numbers:set[int]=set()
    for record in associated:
        number=record.get('number') if isinstance(record,dict) else None
        if type(number) is int:
            numbers.add(number)
    numbers.update(_executed_pr_numbers(api,current))
    if len(numbers)>100:
        raise ProofError('prior_pr_inventory_limit')
    candidates=[]
    for number in sorted(numbers):
        if number==current.number:
            continue
        try:
            p=api.get(f'pulls/{number}')
        except ApiError as exc:
            raise _lookup_error('candidate',exc) from None
        if not isinstance(p,dict) or p.get('number')!=number:
            raise ProofError('prior_candidate_identity_mismatch')
        try:
            if (p.get('merged') is not True or p.get('state')!='closed'
                or p.get('merge_commit_sha')!=current.head_sha
                or p.get('head',{}).get('sha')!=current.head_sha
                or p.get('base',{}).get('ref')!=current.source_branch
                or p.get('base',{}).get('repo',{}).get('full_name')!=api.repository
                or p.get('head',{}).get('repo',{}).get('full_name')!=api.repository):
                continue
            prior=Pull(repository=api.repository,number=number,
                       source_branch=p['head']['ref'],target_branch=current.source_branch,
                       head_sha=current.head_sha,base_sha=p['base']['sha'],
                       merge_sha=current.head_sha,state='closed',same_repository=True,
                       approved_head_sha=None,
                       merged=True)
            trusted_source(api,prior)
            merged_at=_utc(p.get('merged_at'))
            for e in executed_evidence(api,prior,rev):
                if _utc(e.completed_at)<merged_at:
                    candidates.append(e)
        except (TypeError,KeyError,AttributeError):
            raise ProofError('prior_pr_invalid') from None
    if len(candidates)>32:
        raise ProofError('prior_evidence_limit')
    if not candidates:
        raise ProofError('prior_gate_missing')
    return max(candidates,key=lambda e:(e.run_id,e.attempt))

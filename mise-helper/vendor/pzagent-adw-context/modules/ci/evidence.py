"""Read a PR-bound executed quality job; no workflow-only success claims."""
from __future__ import annotations
import re
from .github_api import ApiError
from .quality_proof import Evidence, ProofError, Pull, Revision


def run_title(pr: Pull) -> str:
    return f'ADW CI pull_request PR#{pr.number} to {pr.target_branch} head {pr.head_sha}'


def _workflow_path(value: object, expected: str) -> bool:
    if value == expected:
        return True
    if not isinstance(value,str) or not value.startswith(expected+'@'):
        return False
    ref=value[len(expected)+1:]
    return bool(re.fullmatch(r'[A-Za-z0-9._/-]{1,200}',ref) and '..' not in ref and '//' not in ref)


def _job(api, check: dict, pr: Pull, rev: Revision,
              *, workflow_path: str, job_name: str) -> Evidence | None:
    if (check.get('name')!=job_name or check.get('head_sha')!=pr.head_sha
        or check.get('status')!='completed' or check.get('conclusion')!='success'
        or not isinstance(check.get('app'),dict)
        or check['app'].get('slug')!='github-actions'):
        return None
    details=check.get('details_url')
    pattern=(r'https://github\.com/'+re.escape(api.repository)
             +r'/actions/runs/([1-9][0-9]*)/job/([1-9][0-9]*)/?')
    match=re.fullmatch(pattern,details) if isinstance(details,str) else None
    if not match or type(check.get('id')) is not int or check['id']<1:
        return None
    attached=check.get('pull_requests')
    if not isinstance(attached,list):
        return None
    if attached and not any(isinstance(p,dict) and p.get('number')==pr.number
                            and p.get('url')==f'https://api.github.com/repos/{api.repository}/pulls/{pr.number}'
                            and isinstance(p.get('base'),dict)
                            and p['base'].get('ref')==pr.target_branch for p in attached):
        return None
    run_id=int(match[1]);job_id=int(match[2])
    run=api.get(f'actions/runs/{run_id}')
    attempt=run.get('run_attempt') if isinstance(run,dict) else None
    if (type(attempt) is not int or attempt<1 or run.get('event')!='pull_request'
        or not _workflow_path(run.get('path'),workflow_path)
        or run.get('display_title')!=run_title(pr)
        or run.get('head_sha')!=pr.head_sha or run.get('head_branch')!=pr.source_branch
        or run.get('status')!='completed' or run.get('conclusion')!='success'
        or not isinstance(run.get('head_repository'),dict)
        or run['head_repository'].get('full_name')!=api.repository):
        return None
    response=api.get(f'actions/runs/{run_id}/attempts/{attempt}/jobs')
    jobs=response.get('jobs') if isinstance(response,dict) else None
    if (not isinstance(jobs,list) or type(response.get('total_count')) is not int
        or response['total_count']!=len(jobs) or len(jobs)>100):
        raise ProofError('job_inventory_incomplete')
    matches=[j for j in jobs if isinstance(j,dict) and j.get('id')==job_id]
    if len(matches)!=1:
        return None
    job=matches[0]
    if (job.get('name')!=job_name or job.get('run_id')!=run_id
        or job.get('run_attempt')!=attempt or job.get('head_sha')!=pr.head_sha
        or job.get('status')!='completed' or job.get('conclusion')!='success'
        or job.get('check_run_url')!=check.get('url')
        or not isinstance(job.get('completed_at'),str)
        or not job['completed_at'].endswith('Z')):
        return None
    steps=job.get('steps')
    if not isinstance(steps,list) or len(steps)>100:
        return None
    full=[s for s in steps if isinstance(s,dict) and s.get('name')=='Run required full quality graph']
    minimal=[s for s in steps if isinstance(s,dict) and s.get('name')=='Run non-promotable minimal feedback']
    proof=[s for s in steps if isinstance(s,dict) and s.get('name')=='Prove exact prior quality tree']
    if len(full)!=1 or len(minimal)!=1 or len(proof)!=1 or minimal[0].get('conclusion') not in ('skipped',None):
        return None
    if full[0].get('conclusion')=='success' and proof[0].get('conclusion') in ('skipped',None):
        kind='executed'
    elif proof[0].get('conclusion')=='success' and full[0].get('conclusion') in ('skipped',None):
        kind='proof'
    else:
        return None
    return Evidence(kind=kind,repository=api.repository,pr_number=pr.number,
                    target_branch=pr.target_branch,source_sha=pr.head_sha,
                    checkout_sha=pr.head_sha,tested_tree=rev.source_tree,
                    contract_ref=rev.contract_ref,check_name=job_name,
                    run_id=run_id,attempt=attempt,job_id=job_id,
                    completed_at=job['completed_at'],
                    job_conclusion=job['conclusion'],check_conclusion=check['conclusion'],
                    check_status=check['status'],workflow_path=workflow_path)


def job_evidence(api, pr: Pull, rev: Revision, *,
                      workflow_path: str='.github/workflows/ci.yml',
                      job_name: str='required-quality') -> list[Evidence]:
    try:
        checks=api.check_runs(pr.head_sha)
        found=[]
        for check in checks:
            evidence=_job(api,check,pr,rev,workflow_path=workflow_path,job_name=job_name)
            if evidence is not None:
                found.append(evidence)
        if len(found)>32 or len({(e.run_id,e.attempt) for e in found})!=len(found):
            raise ProofError('evidence_ambiguous')
        return found
    except ApiError:
        raise ProofError('github_lookup_failed') from None


def executed_evidence(api,pr,rev,**kwargs):
    return [e for e in job_evidence(api,pr,rev,**kwargs) if e.kind=='executed']


def proof_evidence(api,pr,rev,**kwargs):
    return [e for e in job_evidence(api,pr,rev,**kwargs) if e.kind=='proof']

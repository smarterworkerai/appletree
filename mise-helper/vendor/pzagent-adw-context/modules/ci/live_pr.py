"""Conservative live PR tree readback from documented GitHub REST fields.

A caller-provided contract ref is only a candidate. Authorization must obtain it
from the immutable manifest on this exact source tree before calling read_pr.
"""
from __future__ import annotations
import re
from .github_api import GitHub, ApiError
from .quality_proof import Pull, Revision, ProofError
from ..common import FULL_SHA

BRANCH = re.compile(r'^[A-Za-z0-9._/-]+$')


def _sha(value: object) -> str:
    if not isinstance(value,str) or not FULL_SHA.fullmatch(value):
        raise ProofError('live_revision_invalid')
    return value


def _field(record, *keys):
    try:
        for key in keys:
            record=record[key]
        return record
    except (TypeError,KeyError,IndexError):
        raise ProofError('live_response_invalid') from None


def _approval(api: GitHub, number: int, head: str, author: str) -> str | None:
    reviews=api.list(f'pulls/{number}/reviews')
    effective={}
    for review in reviews:
        actor=_field(review,'user','login')
        state=review.get('state')
        if not isinstance(actor,str) or state not in ('APPROVED','CHANGES_REQUESTED','DISMISSED'):
            continue
        effective[actor]=(state,review.get('commit_id'))
    if any(state=='CHANGES_REQUESTED' for state,commit in effective.values()):
        return None
    if any(actor!=author and state=='APPROVED' and commit==head
           for actor,(state,commit) in effective.items()):
        return head
    return None


def read_pr(api: GitHub, number: int, *, contract_ref: str) -> tuple[Pull, Revision]:
    if type(number) is not int or number<1 or not FULL_SHA.fullmatch(contract_ref):
        raise ProofError('request_invalid')
    try:
        pr=api.get(f'pulls/{number}')
        head=_sha(_field(pr,'head','sha'))
        base=_sha(_field(pr,'base','sha'))
        merge=_sha(pr.get('merge_commit_sha'))
        source=_field(pr,'head','ref')
        target=_field(pr,'base','ref')
        if (not isinstance(source,str) or not BRANCH.fullmatch(source) or '..' in source
            or not isinstance(target,str) or not BRANCH.fullmatch(target) or '..' in target):
            raise ProofError('branch_invalid')
        if (_field(pr,'head','repo','full_name')!=api.repository
            or _field(pr,'base','repo','full_name')!=api.repository):
            raise ProofError('fork_not_trusted')
        live_head=_sha(_field(api.get(f'git/ref/heads/{source}'),'object','sha'))
        live_base=_sha(_field(api.get(f'git/ref/heads/{target}'),'object','sha'))
        source_git=api.get(f'git/commits/{head}')
        base_git=api.get(f'git/commits/{base}')
        merge_git=api.get(f'git/commits/{merge}')
        source_tree=_sha(_field(source_git,'tree','sha'))
        base_tree=_sha(_field(base_git,'tree','sha'))
        merge_tree=_sha(_field(merge_git,'tree','sha'))
        parents=merge_git.get('parents')
        if (not isinstance(parents,list) or len(parents)!=2
            or _sha(_field(parents,0,'sha'))!=base
            or _sha(_field(parents,1,'sha'))!=head):
            raise ProofError('merge_parents_changed')
        comparison=api.get(f'compare/{base}...{head}')
        ff=(comparison.get('status') in ('ahead','identical')
            and comparison.get('behind_by')==0
            and _sha(_field(comparison,'merge_base_commit','sha'))==base)
    except ApiError:
        raise ProofError('github_lookup_failed') from None
    pull=Pull(repository=api.repository,number=number,source_branch=source,
              target_branch=target,head_sha=head,base_sha=base,merge_sha=merge,
              state=pr.get('state'),same_repository=True,approved_head_sha=None,
              merged=pr.get('merged') is True)
    revision=Revision(source_sha=head,source_tree=source_tree,base_sha=base,
                      base_tree=base_tree,checkout_sha=head,checkout_tree=source_tree,
                      merge_tree=merge_tree,contract_ref=contract_ref,
                      live_source_sha=live_head,live_target_sha=live_base,ff=ff)
    return pull,revision

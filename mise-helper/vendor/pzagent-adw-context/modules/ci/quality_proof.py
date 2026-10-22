"""Read-only, content-safe exact-tree quality proof kernel.

The caller must obtain the live PR, refs, checkout tree and check/job readback
from a trusted GitHub adapter. No workflow conclusion alone is a quality gate.
"""
from __future__ import annotations
from dataclasses import dataclass

from ..common import FULL_SHA


class ProofError(ValueError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class Pull:
    repository: str
    number: int
    source_branch: str
    target_branch: str
    head_sha: str
    base_sha: str
    merge_sha: str
    state: str
    same_repository: bool
    approved_head_sha: str | None
    merged: bool = False


@dataclass(frozen=True)
class Revision:
    source_sha: str
    source_tree: str
    base_sha: str
    base_tree: str
    checkout_sha: str
    checkout_tree: str
    merge_tree: str
    contract_ref: str
    live_source_sha: str
    live_target_sha: str
    ff: bool


@dataclass(frozen=True)
class Evidence:
    kind: str
    repository: str
    pr_number: int
    target_branch: str
    source_sha: str
    checkout_sha: str
    tested_tree: str
    contract_ref: str
    check_name: str
    run_id: int
    attempt: int
    job_id: int
    completed_at: str
    job_conclusion: str
    check_conclusion: str
    check_status: str
    workflow_path: str
    parent_run_id: int | None = None
    parent_attempt: int | None = None


def _identity(pr: Pull, rev: Revision, *, target: str, merged: bool) -> None:
    if not pr.same_repository:
        raise ProofError('fork_not_trusted')
    if pr.target_branch != target:
        raise ProofError('target_mismatch')
    if pr.head_sha != rev.source_sha or pr.head_sha != rev.live_source_sha:
        raise ProofError('stale_source_head')
    if pr.base_sha != rev.base_sha:
        raise ProofError('stale_target_head')

    if not all(isinstance(x, str) and FULL_SHA.fullmatch(x) for x in
               (pr.head_sha, pr.base_sha, rev.source_tree, rev.base_tree,
                rev.checkout_sha, rev.checkout_tree, rev.merge_tree, rev.contract_ref)):
        raise ProofError('invalid_revision')
    # CI checks out the explicit PR head SHA, never a historical synthetic ref
    # whose checked-out revision the Actions run API does not expose.
    if rev.checkout_sha != rev.source_sha or rev.checkout_tree != rev.source_tree:
        raise ProofError('checkout_not_source')
    if not rev.ff or rev.merge_tree != rev.source_tree:
        raise ProofError('merge_tree_requires_branch_sync')
    if merged:
        if pr.state != 'closed' or not pr.merged:
            raise ProofError('pr_not_merged')
        if pr.merge_sha != rev.live_target_sha or rev.source_sha != rev.live_target_sha:
            raise ProofError('destination_not_live')
    elif pr.state != 'open' or pr.merged:
        raise ProofError('pr_not_open')
    elif rev.live_target_sha != rev.base_sha:
        raise ProofError('stale_target_head')


def _compatible(e: Evidence, pr: Pull, rev: Revision, *, check_name: str,
                workflow_path: str) -> bool:
    return (e.kind in ('proof', 'executed')
            and e.repository == pr.repository
            and e.pr_number == pr.number and e.target_branch == pr.target_branch
            and e.source_sha == pr.head_sha
            and e.checkout_sha == rev.checkout_sha and e.tested_tree == rev.checkout_tree
            and e.contract_ref == rev.contract_ref and e.check_name == check_name
            and e.workflow_path == workflow_path and e.run_id > 0 and e.attempt > 0
            and type(e.job_id) is int and e.job_id > 0
            and isinstance(e.completed_at,str) and e.completed_at.endswith('Z')
            and e.check_status == 'completed' and e.check_conclusion == 'success'
            and e.job_conclusion == 'success')


def _gate(pr: Pull, rev: Revision, evidence: list[Evidence], *, check_name: str,
          workflow_path: str, parent: Evidence | None = None) -> dict:
    if len(evidence) > 32:
        raise ProofError('evidence_limit')
    candidates = {}
    seen = set()
    for e in evidence:
        identity = (e.run_id, e.attempt)
        if identity in seen:
            raise ProofError('duplicate_evidence')
        seen.add(identity)
        if _compatible(e, pr, rev, check_name=check_name, workflow_path=workflow_path):
            candidates[identity] = e
    starts=set(candidates)
    if parent is not None:
        if (parent.kind!='executed' or parent.repository!=pr.repository
            or parent.target_branch!=pr.source_branch
            or parent.source_sha!=pr.head_sha or parent.checkout_sha!=pr.head_sha
            or parent.tested_tree!=rev.source_tree or parent.contract_ref!=rev.contract_ref
            or parent.check_name!=check_name or parent.workflow_path!=workflow_path
            or parent.check_conclusion!='success' or parent.job_conclusion!='success'
            or parent.check_status!='completed' or parent.run_id<=0 or parent.attempt<=0
            or parent.job_id<=0):
            raise ProofError('prior_gate_incompatible')
        key=(parent.run_id,parent.attempt)
        if key in seen:
            raise ProofError('duplicate_evidence')
        candidates[key]=parent
    if len(candidates) > 32:
        raise ProofError('evidence_limit')
    for key in sorted(starts, reverse=True):
        current = candidates[key]
        seen = set()
        for _ in range(16):
            identity = (current.run_id, current.attempt)
            if identity in seen:
                break
            seen.add(identity)
            if current.kind == 'executed' and current.parent_run_id is None:
                return {'status': 'proved', 'proof_kind': candidates[key].kind,
                        'run_id': candidates[key].run_id,
                        'attempt': candidates[key].attempt,
                        'gate_run_id': current.run_id,
                        'tested_tree': rev.checkout_tree}
            if current.kind != 'proof' or current.parent_run_id is None or current.parent_attempt is None:
                break
            next_identity = (current.parent_run_id, current.parent_attempt)
            current = candidates.get(next_identity)
            if current is None:
                break
    raise ProofError('no_compatible_required_gate')


def prove_pr(pr: Pull, rev: Revision, evidence: list[Evidence], *,
             target: str = 'demo', check_name: str = 'required-quality',
             workflow_path: str = '.github/workflows/ci.yml',
             parent: Evidence | None = None) -> dict:
    _identity(pr, rev, target=target, merged=False)
    return _gate(pr, rev, evidence, check_name=check_name, workflow_path=workflow_path,parent=parent)


def premerge_check(pr: Pull, rev: Revision, evidence: list[Evidence], **kwargs) -> dict:
    return prove_pr(pr, rev, evidence, **kwargs)


def prove_destination(pr: Pull, rev: Revision, evidence: list[Evidence], *,
                      target: str = 'demo', check_name: str = 'required-quality',
                      workflow_path: str = '.github/workflows/ci.yml',
                      parent: Evidence | None = None) -> dict:
    _identity(pr, rev, target=target, merged=True)
    return _gate(pr, rev, evidence, check_name=check_name, workflow_path=workflow_path,parent=parent)

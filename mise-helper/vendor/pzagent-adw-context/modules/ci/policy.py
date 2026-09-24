"""Conservative event routing: proof may be asserted only by the trusted engine."""
from __future__ import annotations
from dataclasses import dataclass
from ..common import ContractError


@dataclass(frozen=True)
class Decision:
    mode: str
    quality_task: str | None
    promotable: bool
    reason: str


def classify(*, event: str, branch: str, protected: tuple[str, ...], marker: bool,
             proof: bool = False, manual_confirm: bool = False) -> Decision:
    if event == 'workflow_dispatch':
        if not manual_confirm:
            raise ContractError('manual quality requires explicit confirmation')
        return Decision('full', 'adw:verify:full', True, 'manual-confirmed')
    if event not in {'pull_request','push'}:
        raise ContractError('unsupported CI event')
    if marker:
        return Decision('suppressed', None, False, 'diagnostic-marker')
    if event == 'push' and branch not in protected:
        return Decision('minimal', 'adw:verify:minimal', False, 'work-branch-feedback')
    if proof:
        return Decision('proof', None, True, 'exact-tree-proof')
    return Decision('full', 'adw:verify:full', True, 'required-gate-fallback')

"""Project-owned CI-only checks are additional obligations, not quality roots."""
from __future__ import annotations
from .quality_proof import ProofError


def require_ci_only(api, sha: str, names: list[str]) -> None:
    if not names:
        return
    checks=api.check_runs(sha)
    for name in names:
        matches=[c for c in checks if c.get('name')==name and c.get('head_sha')==sha
                 and c.get('app',{}).get('slug')=='github-actions']
        if (len(matches)!=1 or matches[0].get('status')!='completed'
            or matches[0].get('conclusion')!='success'):
            raise ProofError('ci_only_check_missing_or_ambiguous')

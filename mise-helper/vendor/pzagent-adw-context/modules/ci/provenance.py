"""Fail closed when the PR edits the trusted CI/proof implementation."""
from __future__ import annotations
from .github_api import ApiError
from .quality_proof import ProofError, Pull

TRUSTED_PATHS = (
    '.github/workflows/ci.yml',
    'mise-helper/vendor/pzagent-adw-context/ci.py',
    'mise-helper/vendor/pzagent-adw-context/templates/github/actions/classify-ci-event/action.yml',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/__init__.py',
    'mise-helper/vendor/pzagent-adw-context/modules/__init__.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/policy.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/github_api.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/live_pr.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/contract.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/evidence.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/quality_proof.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/publication_proof.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/reuse.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/workflow_drift.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/ci_only.py',
    'mise-helper/vendor/pzagent-adw-context/modules/adapter.py',
    'mise-helper/vendor/pzagent-adw-context/modules/common.py',
    'mise-helper/vendor/pzagent-adw-context/modules/bundle.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/provenance.py',
    'mise-helper/vendor/pzagent-adw-context/templates/github/publish-release.yml',
    'mise-helper/vendor/pzagent-adw-context/templates/github/actions/authorize-publication/action.yml',
    'mise-helper/vendor/pzagent-adw-context/templates/github/actions/authorize-publication/authorize.py',
    'mise-helper/vendor/pzagent-adw-context/templates/github/actions/publish-immutable-release/action.yml',
    'mise-helper/vendor/pzagent-adw-context/templates/github/actions/publish-immutable-release/publish.py',
)


def trusted_source(api, pull: Pull) -> None:
    try:
        for path in TRUSTED_PATHS:
            head_blob,_=api.content(path,pull.head_sha)
            base_blob,_=api.content(path,pull.base_sha)
            if head_blob!=base_blob:
                raise ProofError('proof_source_changed')
    except ApiError:
        # A first-time big-bang consumer cutover cannot inherit a trusted v2
        # base. It needs the separate human-reviewed bootstrap gate.
        raise ProofError('trusted_base_missing') from None

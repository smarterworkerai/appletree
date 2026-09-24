"""Ensure the committed GitHub workflow is the exact vendored template."""
from __future__ import annotations
from pathlib import Path
from ..common import ContractError


def validate(root: Path) -> None:
    root=root.resolve()
    template=root/'mise-helper/vendor/pzagent-adw-context/templates/github/ci.yml'
    committed=root/'.github/workflows/ci.yml'
    if template.is_symlink() or committed.is_symlink():
        raise ContractError('workflow_symlink_rejected')
    try:
        if template.read_bytes()!=committed.read_bytes():
            raise ContractError('workflow_template_drift')
    except OSError:
        raise ContractError('workflow_template_missing') from None

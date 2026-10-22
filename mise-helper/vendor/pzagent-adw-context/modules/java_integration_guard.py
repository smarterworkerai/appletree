"""Verify Failsafe class selection and report completeness."""
from __future__ import annotations
from pathlib import Path
from .common import ContractError
def verify(classes:list[str],reports:Path,required_suffixes:tuple[str,...]=('IT','ITCase')) -> None:
    expected={name for name in classes if name.endswith(required_suffixes)}
    if not expected:
        raise ContractError('no declared integration classes matched the configured suffixes')
    actual={p.stem.removeprefix('TEST-') for p in reports.glob('TEST-*.xml')} if reports.is_dir() else set()
    if not actual:
        raise ContractError('Failsafe produced no integration reports')
    missing=sorted(expected-actual)
    if missing: raise ContractError(f'Failsafe reports are incomplete: {missing}')

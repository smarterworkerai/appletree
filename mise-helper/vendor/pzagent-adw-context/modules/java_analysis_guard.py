"""Detect false-green Maven static-analysis configuration and output."""
from __future__ import annotations
from pathlib import Path
from .common import ContractError
def verify(report:Path,required_rulesets:list[str])->None:
    if not report.is_file() or report.stat().st_size==0: raise ContractError('Java analysis report is missing')
    text=report.read_text(encoding='utf-8',errors='replace')
    if any(token not in text for token in required_rulesets): raise ContractError('Java analysis report omits required rulesets')
    lowered=text.lower()
    if 'unable to parse' in lowered or 'analysis skipped' in lowered: raise ContractError('Java analysis contains a false-green parse/skip marker')

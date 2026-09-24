"""Compute fail-closed retention candidates from protected pointer graphs."""
from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Any
from .common import ContractError
@dataclass(frozen=True)
class Version: identifier:str; created_at:float; tags:tuple[str,...]; references:tuple[str,...]
def candidates(versions:list[Version],pointer_roots:set[str],*,now:float|None=None,grace_hours:int=48)->list[str]:
    if grace_hours<1 or grace_hours>720: raise ContractError('retention grace period is outside schema bounds')
    by_id={x.identifier:x for x in versions}
    if len(by_id)!=len(versions) or not pointer_roots<=set(by_id): raise ContractError('protected pointer inventory is incomplete')
    protected=set(); stack=list(pointer_roots)
    while stack:
        item=stack.pop()
        if item in protected: continue
        version=by_id.get(item)
        if version is None: raise ContractError('protected manifest reference is unknown')
        protected.add(item); stack.extend(version.references)
    cutoff=(time.time() if now is None else now)-grace_hours*3600
    return sorted(x.identifier for x in versions if x.identifier not in protected and x.created_at<cutoff)
def recheck(candidate:str,versions:list[Version],pointer_roots:set[str])->bool:
    return candidate in candidates(versions,pointer_roots,now=float('inf'),grace_hours=1)

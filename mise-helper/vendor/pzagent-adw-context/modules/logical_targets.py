"""Resolve one value-free, versioned logical deployment target."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from .common import ContractError,IDENTIFIER
@dataclass(frozen=True)
class LogicalTarget:
    environment:str; name:str; provider:str; mode:str
def parse_inventory(data:Any,environment:str)->dict[str,LogicalTarget]:
    if not IDENTIFIER.fullmatch(environment): raise ContractError('environment must be a bounded logical identifier')
    if not isinstance(data,dict) or set(data)!={'schema_version','environment','targets'} or data.get('schema_version')!='1.0.0' or data.get('environment')!=environment: raise ContractError('logical-target inventory identity is invalid')
    raw=data.get('targets')
    if not isinstance(raw,dict) or not raw: raise ContractError('logical-target inventory is empty')
    targets={}
    for name,value in raw.items():
        if not isinstance(name,str) or not IDENTIFIER.fullmatch(name) or name in targets: raise ContractError('logical-target name is invalid or duplicate')
        if not isinstance(value,dict) or set(value)!={'provider','mode'} or not isinstance(value['provider'],str) or not value['provider'] or value['mode'] not in {'active','shadow'}: raise ContractError('logical-target properties are invalid')
        targets[name]=LogicalTarget(environment,name,value['provider'],value['mode'])
    return targets
def resolve(data:Any,environment:str,requested:str|None=None,*,providers:set[str]|None=None)->LogicalTarget:
    targets=parse_inventory(data,environment)
    if requested is None:
        active=[x for x in targets.values() if x.mode=='active']
        if len(active)!=1: raise ContractError('environment must declare exactly one active logical target')
        target=active[0]
    else:
        if not IDENTIFIER.fullmatch(requested) or requested not in targets: raise ContractError('requested logical target is not allowlisted')
        target=targets[requested]
    if target.mode!='active': raise ContractError('shadow target deployment is not enabled')
    if providers is not None and target.provider not in providers: raise ContractError('selected provider adapter is unsupported')
    return target

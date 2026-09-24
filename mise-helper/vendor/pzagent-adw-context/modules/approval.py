"""Validate an externally issued, exact-operation remote-write approval receipt."""
from __future__ import annotations
import json,os,re,time
from pathlib import Path
from typing import Any
from .common import ContractError,FULL_SHA,IDENTIFIER
NONCE=re.compile(r'^[A-Za-z0-9_-]{32,128}$')
def validate(path:Path,*,source_sha:str,capability:str,environment:str,target:str,operation_digest:str|None=None,exclusive_target:bool=False,now:int|None=None,environ:dict[str,str]|None=None)->dict[str,Any]:
    if not FULL_SHA.fullmatch(source_sha) or not IDENTIFIER.fullmatch(environment) or not IDENTIFIER.fullmatch(target):raise ContractError('approval request identity is invalid')
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:raise ContractError('approval receipt is missing or not private')
    try:data=json.loads(path.read_text(encoding='utf-8'))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError) as exc:raise ContractError('approval receipt is malformed') from exc
    keys={'schema_version','source_sha','capability','environment','target','expires_at','nonce'}
    if operation_digest is not None:keys.add('operation_digest')
    if exclusive_target:keys.add('exclusive_target')
    if not isinstance(data,dict) or set(data)!=keys or data.get('schema_version')!='1.0.0':raise ContractError('approval receipt is not closed')
    expected=(source_sha,capability,environment,target)
    actual=(data['source_sha'],data['capability'],data['environment'],data['target'])
    if actual!=expected:raise ContractError('approval receipt does not name this exact operation')
    if operation_digest is not None and (not re.fullmatch(r'sha256:[0-9a-f]{64}',operation_digest) or data.get('operation_digest')!=operation_digest):raise ContractError('approval receipt operation digest differs')
    if exclusive_target and data.get('exclusive_target') is not True:raise ContractError('approval does not assert exclusive target ownership')
    current=int(time.time()) if now is None else now
    if not isinstance(data['expires_at'],int) or not current<data['expires_at']<=current+900:raise ContractError('approval receipt is expired or exceeds the shared lifetime')
    injected=(os.environ if environ is None else environ).get('PZ_ADW_APPROVAL_NONCE','')
    if not isinstance(data['nonce'],str) or not NONCE.fullmatch(data['nonce']) or data['nonce']!=injected:raise ContractError('approval receipt nonce is absent or differs')
    return {'approved':True,'source_sha':source_sha,'capability':capability,'environment':environment,'target':target,'expires_at':data['expires_at']}

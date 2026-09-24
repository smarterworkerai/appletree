"""Validate the immutable pz runtime bundle and complete non-self inventory."""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any
from .common import ContractError,ensure_contained,load_json,sha256_file
DESCRIPTOR='bundle.json'; VERSION=re.compile(r'^0\.[0-9]+\.[0-9]+$')
def validate_descriptor(data:Any)->dict[str,Any]:
    required={'schema_version','package','version','stability','generic_contract','minimum_mise','task_entrypoint','platforms','runtimes','policy','migration_notes','files'}
    if not isinstance(data,dict) or set(data)!=required: raise ContractError('bundle descriptor is not a closed document')
    if data['schema_version']!='1.0.0' or data['package']!='pzagent-adw-context': raise ContractError('bundle identity is incompatible')
    if not isinstance(data['version'],str) or not VERSION.fullmatch(data['version']) or data['stability']!='experimental': raise ContractError('bundle version or stability is incompatible')
    if data['generic_contract']!='>=2.0.0,<3.0.0' or data['minimum_mise']!='2026.0.0': raise ContractError('bundle tool contract is incompatible')
    if data['platforms']!=['linux','macos','cygwin-wsl'] or data['runtimes']!=['python>=3.11-stdlib']: raise ContractError('bundle runtime assumptions are incompatible')
    for key in ('task_entrypoint','policy','migration_notes'):
        if not isinstance(data[key],str) or not data[key]: raise ContractError(f'bundle {key} is invalid')
    if not isinstance(data['files'],list) or not data['files']: raise ContractError('bundle inventory is empty')
    seen=set()
    for entry in data['files']:
        if not isinstance(entry,dict) or set(entry)!={'path','sha256'}: raise ContractError('bundle inventory entry is invalid')
        path,checksum=entry['path'],entry['sha256']; ensure_contained(Path('.'),path)
        if path==DESCRIPTOR or path in seen: raise ContractError('bundle inventory contains self-reference or duplicate')
        if not isinstance(checksum,str) or not re.fullmatch(r'[0-9a-f]{64}',checksum): raise ContractError('bundle checksum is invalid')
        seen.add(path)
    return data
def validate_bundle(root:Path,*,reject_unexpected:bool=True)->dict[str,Any]:
    root=root.resolve(); descriptor=validate_descriptor(load_json(root/DESCRIPTOR)); expected={x['path']:x['sha256'] for x in descriptor['files']}
    for relative,checksum in expected.items():
        path=ensure_contained(root,relative)
        if not path.is_file() or path.is_symlink(): raise ContractError(f'bundle file missing or unsafe: {relative}')
        if sha256_file(path)!=checksum: raise ContractError(f'bundle checksum drift: {relative}')
    if reject_unexpected:
        actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!=DESCRIPTOR}
        if actual!=set(expected): raise ContractError(f'bundle inventory mismatch (missing={sorted(set(expected)-actual)}, unexpected={sorted(actual-set(expected))})')
    return descriptor

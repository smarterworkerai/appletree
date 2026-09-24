"""Shared closed-contract and content-safe runtime helpers."""
from __future__ import annotations
import hashlib, json, re, subprocess
from pathlib import Path, PurePosixPath
from typing import Any
FULL_SHA=re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER=re.compile(r"^[a-z][a-z0-9-]{0,62}$")
EXIT_OPERATION,EXIT_USAGE,EXIT_CONTRACT=1,20,21
MAX_JSON_BYTES=1024*1024
class ContractError(RuntimeError): pass
class UsageError(RuntimeError): pass
def load_json(path:Path,*,max_bytes:int=MAX_JSON_BYTES)->Any:
    if not path.is_file() or path.is_symlink(): raise ContractError("required JSON document is missing or unsafe")
    data=path.read_bytes()
    if len(data)>max_bytes: raise ContractError("JSON document exceeds the bounded size")
    try: return json.loads(data)
    except (UnicodeDecodeError,json.JSONDecodeError) as exc: raise ContractError("JSON document is malformed") from exc
def closed_object(value:Any,*,required:set[str],allowed:set[str],name:str)->dict[str,Any]:
    if not isinstance(value,dict): raise ContractError(f"{name} must be an object")
    keys=set(value)
    if keys!=required or not keys<=allowed: raise ContractError(f"{name} has invalid fields (missing={sorted(required-keys)}, extra={sorted(keys-allowed)})")
    return value
def sha256_file(path:Path)->str:
    digest=hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda:handle.read(1024*1024),b''): digest.update(chunk)
    return digest.hexdigest()
def safe_relative_path(raw:str)->PurePosixPath:
    if not isinstance(raw,str) or not raw or chr(0) in raw: raise ContractError("bundle path is empty or invalid")
    path=PurePosixPath(raw)
    if path.is_absolute() or any(part in {'','.','..'} for part in path.parts): raise ContractError("bundle path escapes its root")
    return path
def ensure_contained(root:Path,relative:str)->Path:
    rel=safe_relative_path(relative); candidate=root.joinpath(*rel.parts)
    try: candidate.resolve(strict=False).relative_to(root.resolve())
    except ValueError as exc: raise ContractError("bundle path escapes its root") from exc
    return candidate
def git_common_state(repo:Path,namespace:str)->Path:
    result=subprocess.run(['git','rev-parse','--git-common-dir'],cwd=repo,text=True,capture_output=True,check=False)
    if result.returncode: raise ContractError("repository Git common directory is unavailable")
    common=Path(result.stdout.strip()); common=common if common.is_absolute() else (repo/common).resolve()
    path=common/'pzagent-adw-context'/namespace; path.mkdir(parents=True,exist_ok=True,mode=0o700); return path
def json_result(**values:Any)->str:
    payload=json.dumps(values,sort_keys=True,separators=(',',':'))
    if len(payload.encode())>65536: raise ContractError("machine result exceeds bounded stdout")
    return payload

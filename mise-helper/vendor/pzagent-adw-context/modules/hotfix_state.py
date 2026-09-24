"""Operator-serialized Environment hotfix state and restore evidence."""
from __future__ import annotations
import hashlib,json,os,re,tempfile
from pathlib import Path
from .common import ContractError,FULL_SHA,IDENTIFIER,ensure_contained
from .dokploy_transaction import KEY,Snapshot,environment_entries,target_lock
SCHEMA='pzagent.hotfix-restore/v1'
LOCAL_TAG=re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
def _replace(raw:bytes,updates:dict[str,str],expected:dict[str,str]|None=None)->bytes:
 entries=environment_entries(raw)
 if set(updates)-set(entries):raise ContractError('hotfix Environment lacks an owned image key')
 if expected:
  for key,value in expected.items():
   if entries.get(key,b'').split(b'=',1)[-1].rstrip(b'\r\n').decode()!=value:raise ContractError('hotfix restore expected-current differs')
 output=[]
 for line in raw.splitlines(keepends=True):
  stripped=line.strip()
  if not stripped or stripped.startswith(b'#') or b'=' not in line:output.append(line);continue
  key=line.split(b'=',1)[0].strip().decode('ascii');output.append((key+'='+updates[key]+'\n').encode() if key in updates else line)
 return b''.join(output)
def _values(raw:bytes,keys:set[str])->dict[str,str]:
 entries=environment_entries(raw);result={}
 for key in keys:
  if key not in entries:raise ContractError('restore source image key is absent')
  result[key]=entries[key].split(b'=',1)[1].rstrip(b'\r\n').decode()
 return result
def _write_all(fd:int,data:bytes)->None:
 view=memoryview(data)
 while view:
  written=os.write(fd,view)
  if written<=0:raise OSError('short restore evidence write')
  view=view[written:]
def persist(repo:Path,run_id:str,*,environment:str,target:str,source_sha:str,before:bytes,desired:bytes,keys:set[str])->tuple[Path,bytes]:
 if not IDENTIFIER.fullmatch(run_id) or not IDENTIFIER.fullmatch(environment) or not IDENTIFIER.fullmatch(target) or not FULL_SHA.fullmatch(source_sha):raise ContractError('hotfix restore identity is invalid')
 payload={'schema':SCHEMA,'environment':environment,'target':target,'source_sha':source_sha,'prior':_values(before,keys),'hotfix':_values(desired,keys),'before_sha256':hashlib.sha256(before).hexdigest()};encoded=(json.dumps(payload,sort_keys=True)+'\n').encode();digest=hashlib.sha256(encoded).hexdigest();directory=ensure_contained(repo,'.hermes/evidence/'+run_id);directory.mkdir(parents=True,exist_ok=True);final=directory/f'hotfix-restore-{source_sha[:12]}-{digest[:12]}.json'
 if final.exists():raise ContractError('hotfix restore evidence identity already exists')
 fd,name=tempfile.mkstemp(dir=directory,prefix='.hotfix-');temporary=Path(name)
 try:
  os.fchmod(fd,0o600);_write_all(fd,encoded);os.fsync(fd);os.close(fd);os.link(temporary,final);temporary.unlink()
  for item in (directory,directory.parent):
   handle=os.open(item,os.O_RDONLY);os.fsync(handle);os.close(handle)
  return final,encoded
 except Exception:
  try:os.close(fd)
  except OSError:pass
  temporary.unlink(missing_ok=True);raise
def parse(document:bytes,*,environment:str,target:str,source_sha:str)->dict:
 try:value=json.loads(document)
 except (UnicodeDecodeError,json.JSONDecodeError) as exc:raise ContractError('hotfix restore document is malformed') from exc
 if not isinstance(value,dict) or set(value)!={'schema','environment','target','source_sha','prior','hotfix','before_sha256'} or value.get('schema')!=SCHEMA or value.get('environment')!=environment or value.get('target')!=target or value.get('source_sha')!=source_sha or not isinstance(value.get('prior'),dict) or set(value['prior'])!=set(value.get('hotfix',{})):raise ContractError('hotfix restore document identity is invalid')
 for mapping in (value['prior'],value['hotfix']):
  if not mapping or any(not isinstance(k,str) or not KEY.fullmatch(k) or not isinstance(v,str) or not v or '\n' in v or '\r' in v for k,v in mapping.items()):raise ContractError('hotfix restore image mapping is invalid')
 return value
def _write(repo:Path,target:str,backend,desired:bytes,prior:bytes)->None:
 with target_lock(repo,target):
  try:backend.write_environment(desired)
  except Exception as failure:
   live=backend.read_environment()
   if live==desired:return
   if live==prior:raise ContractError('Environment write failed before mutation') from failure
   raise ContractError('ambiguous Environment write requires manual recovery') from failure
  if backend.read_environment()!=desired:raise ContractError('Environment write readback differs; manual recovery required')
def apply(repo:Path,target:str,backend,updates:dict[str,str],*,environment:str,source_sha:str,run_id:str,require_digest:bool=True)->tuple[Path,bytes,dict[str,str]]:
 if not updates or any(not KEY.fullmatch(k) or not isinstance(v,str) or (('@sha256:' not in v) if require_digest else not LOCAL_TAG.fullmatch(v)) for k,v in updates.items()):raise ContractError('hotfix image assignment is invalid')
 before=backend.read_environment();compose=backend.read_compose();desired=_replace(before,updates);artifact,document=persist(repo,run_id,environment=environment,target=target,source_sha=source_sha,before=before,desired=desired,keys=set(updates));_write(repo,target,backend,desired,before)
 if backend.read_compose()!=compose:raise ContractError('Compose changed during operator-serialized hotfix window')
 return artifact,document,updates
def restore(repo:Path,target:str,backend,document:bytes,*,environment:str,source_sha:str)->dict[str,str]:
 value=parse(document,environment=environment,target=target,source_sha=source_sha);live=backend.read_environment();desired=_replace(live,value['prior'],value['hotfix']);compose=backend.read_compose();_write(repo,target,backend,desired,live)
 if backend.read_compose()!=compose:raise ContractError('Compose changed during operator-serialized restore window')
 return value['prior']

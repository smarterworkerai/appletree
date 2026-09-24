"""Locked, read-back, conflict-safe remote configuration transaction."""
from __future__ import annotations
import fcntl,re,time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from .common import ContractError,git_common_state,IDENTIFIER
KEY=re.compile(r'^[A-Z][A-Z0-9_]{0,127}$')
class Backend(Protocol):
    def read_compose(self)->bytes: ...
    def read_environment(self)->bytes: ...
    def write_compose(self,value:bytes)->None: ...
    def write_environment(self,value:bytes)->None: ...
@dataclass(frozen=True)
class Snapshot: compose:bytes; environment:bytes
@dataclass(frozen=True)
class Plan: target:str; compose_changed:bool; environment_changed:bool; environment_keys:tuple[str,...]
def environment_keys(raw:bytes)->set[str]:
    try: text=raw.decode('utf-8')
    except UnicodeDecodeError as exc: raise ContractError('provider Environment is not UTF-8') from exc
    result=set()
    for line in text.splitlines():
        stripped=line.strip()
        if not stripped or stripped.startswith('#'): continue
        if '=' not in line: raise ContractError('provider Environment contains malformed line')
        key=line.split('=',1)[0].strip()
        if not KEY.fullmatch(key) or key in result: raise ContractError('provider Environment contains invalid or duplicate key')
        result.add(key)
    return result
def environment_entries(raw:bytes)->dict[str,bytes]:
    """Return exact key lines so non-owned secret bytes can be compared."""
    environment_keys(raw)
    entries={}
    for line in raw.splitlines(keepends=True):
        stripped=line.strip()
        if not stripped or stripped.startswith(b'#'): continue
        key=line.split(b'=',1)[0].strip().decode('ascii')
        entries[key]=line
    return entries
def replace_environment(raw:bytes,updates:dict[str,str])->bytes:
    entries=environment_entries(raw)
    if not updates or set(updates)-set(entries): raise ContractError('Environment lacks an owned update key')
    if any(not KEY.fullmatch(key) or not isinstance(value,str) or not value or '\n' in value or '\r' in value for key,value in updates.items()): raise ContractError('Environment update mapping is invalid')
    output=[]
    for line in raw.splitlines(keepends=True):
        stripped=line.strip()
        if not stripped or stripped.startswith(b'#') or b'=' not in line: output.append(line); continue
        key=line.split(b'=',1)[0].strip().decode('ascii')
        if key not in updates: output.append(line); continue
        ending=b'\r\n' if line.endswith(b'\r\n') else b'\n' if line.endswith(b'\n') else b''
        output.append(key.encode()+b'='+updates[key].encode()+ending)
    return b''.join(output)
@contextmanager
def target_lock(repo:Path,target:str,wait_seconds:float=5.0):
    if not IDENTIFIER.fullmatch(target): raise ContractError('logical target lock name is invalid')
    path=git_common_state(repo,'locks')/f'{target}.lock'
    with path.open('a+b') as handle:
        deadline=time.monotonic()+wait_seconds
        while True:
            try: fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB); break
            except BlockingIOError:
                if time.monotonic()>=deadline: raise ContractError('logical target transaction lock is busy')
                time.sleep(.05)
        try: yield
        finally: fcntl.flock(handle.fileno(),fcntl.LOCK_UN)
def snapshot(backend:Backend)->Snapshot: return Snapshot(backend.read_compose(),backend.read_environment())
def plan(target:str,current:Snapshot,desired:Snapshot,owned_keys:set[str])->Plan:
    current_keys,desired_keys=environment_keys(current.environment),environment_keys(desired.environment)
    drift=(current_keys^desired_keys)-owned_keys
    if drift: raise ContractError(f'unresolved Environment key drift: {sorted(drift)}')
    if any(not KEY.fullmatch(x) for x in owned_keys): raise ContractError('owned Environment key schema is invalid')
    current_entries=environment_entries(current.environment)
    desired_entries=environment_entries(desired.environment)
    for key in current_keys-owned_keys:
        if current_entries[key] != desired_entries[key]:
            raise ContractError('desired Environment changes non-owned bytes')
    return Plan(target,current.compose!=desired.compose,current.environment!=desired.environment,tuple(sorted(desired_keys)))
def _write_readback(write,read,desired:bytes,label:str)->None:
    try: write(desired)
    except Exception:
        if read()!=desired: raise ContractError(f'ambiguous {label} write did not read back exactly')
        return
    if read()!=desired: raise ContractError(f'{label} write readback differs')
def apply(repo:Path,target:str,backend:Backend,desired:Snapshot,owned_keys:set[str])->Plan:
    with target_lock(repo,target):
        before=snapshot(backend); result=plan(target,before,desired,owned_keys); attempted=[]
        try:
            if result.compose_changed:
                attempted.append(('compose',desired.compose,before.compose))
                _write_readback(backend.write_compose,backend.read_compose,desired.compose,'Compose')
            if result.environment_changed:
                attempted.append(('environment',desired.environment,before.environment))
                _write_readback(backend.write_environment,backend.read_environment,desired.environment,'Environment')
            after=snapshot(backend)
            if after!=desired: raise ContractError('transaction final readback differs')
            return result
        except Exception as failure:
            conflicts=[]
            for name,written,prior in reversed(attempted):
                read=getattr(backend,f'read_{name}'); write=getattr(backend,f'write_{name}')
                live=read()
                if live==prior: continue
                if live!=written: conflicts.append(name); continue
                try: _write_readback(write,read,prior,f'{name} compensation')
                except Exception: conflicts.append(name)
            if conflicts: raise ContractError(f'transaction failed; manual recovery required for {sorted(conflicts)}') from failure
            raise ContractError('transaction failed; prior state restored') from failure

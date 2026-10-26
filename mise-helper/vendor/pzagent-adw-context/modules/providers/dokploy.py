"""Dokploy I/O, configuration transaction and correlated rollout implementation."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
from typing import Any, Mapping, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ..common import ContractError, IDENTIFIER, git_common_state
from ..execution import human
from ..operator_state import private_directory
from . import DeploymentOperation, DeploymentState, ProviderConfiguration, DeploymentTerminalFailure

@dataclass(frozen=True)
class ProviderNames: project:str; environment:str; resource:str; child_binding:str


@dataclass(frozen=True)
class ResolvedBinding: environment_id:str; resource_id:str


class InventoryClient(Protocol):
    def projects(self)->Any: ...


class DokployClient:
    def __init__(self,endpoint:str,credential:str):
        if not endpoint.startswith(('http://','https://')) or not credential: raise ContractError('Dokploy operator inputs are missing or invalid')
        self._endpoint=endpoint.rstrip('/'); self._credential=credential
    def _get(self,path:str)->Any:
        request=Request(self._endpoint+path,headers={'x-api-key':self._credential,'Accept':'application/json'},method='GET')
        try:
            with urlopen(request,timeout=15) as response:
                return json.loads(response.read(1024*1024).decode())
        except (HTTPError,URLError,TimeoutError,UnicodeDecodeError,json.JSONDecodeError) as exc: raise ContractError('Dokploy read-only discovery failed') from exc
    def projects(self)->Any: return self._get('/api/project.all')
    def composes(self,environment_id:str)->Any:
        return self._get('/api/compose.search?'+urlencode({'limit':100,'offset':0,'environmentId':environment_id}))
    @property
    def endpoint(self)->str:return self._endpoint
    @property
    def credential(self)->str:return self._credential


def profile_credentials(profile_root:Path|None)->tuple[str,str]:
    endpoint=os.environ.get('DOKPLOY_URL','')
    credential=os.environ.get('DOKPLOY_TOKEN') or os.environ.get('DOKPLOY_API_KEY','')
    if endpoint and credential:return endpoint,credential
    if endpoint or credential:raise ContractError('Dokploy credentials require both DOKPLOY_URL and DOKPLOY_API_KEY (or DOKPLOY_TOKEN)')
    if profile_root is None:raise ContractError('missing DOKPLOY_URL and DOKPLOY_API_KEY (or DOKPLOY_TOKEN); configure environment, .env.deploy or --profile-root')
    config=profile_root/'config.yaml'
    if not config.is_file() or config.is_symlink():raise ContractError('operator profile config is unavailable')
    values={}; in_env=False
    for raw in config.read_text(encoding='utf-8').splitlines():
        stripped=raw.strip(); current=len(raw)-len(raw.lstrip())
        if not stripped or stripped.startswith('#'):continue
        if current==0:
            in_env=stripped=='env:'
            continue
        if in_env and ':' in stripped:
            key,value=stripped.split(':',1)
            if key in {'DOKPLOY_URL','DOKPLOY_API_KEY'}:values[key]=value.strip().strip('"\'')
    endpoint=values.get('DOKPLOY_URL','');credential=values.get('DOKPLOY_API_KEY','')
    if not endpoint or not credential:raise ContractError('operator profile lacks Dokploy inputs')
    return endpoint,credential


def _single(matches:list,role:str)->Any:
    """An absent role and an ambiguous one need different operator action."""
    if not matches:raise ContractError(f'provider {role} is absent')
    if len(matches)!=1:raise ContractError(f'provider {role} match is not unique')
    return matches[0]


def discover_binding(client:DokployClient,names:ProviderNames)->ResolvedBinding:
    payload=client.projects();items=payload.get('data',payload) if isinstance(payload,dict) else payload
    if not isinstance(items,list):raise ContractError('provider project inventory is malformed')
    project=_single([x for x in items if isinstance(x,dict) and x.get('name')==names.project],'project')
    environments=project.get('environments')
    if not isinstance(environments,list):raise ContractError('provider environment inventory is malformed')
    environment_id=_single([x for x in environments if isinstance(x,dict) and x.get('name')==names.environment and isinstance(x.get('environmentId'),str)],'environment')['environmentId'];payload=client.composes(environment_id)
    records=payload.get('items',payload.get('data',payload)) if isinstance(payload,dict) else payload
    if not isinstance(records,list):raise ContractError('provider resource inventory is malformed')
    resource=_single([x for x in records if isinstance(x,dict) and x.get('name')==names.resource and isinstance(x.get('composeId'),str)],'resource')
    return ResolvedBinding(environment_id,resource['composeId'])


def resolve_inventory(payload:Any,names:ProviderNames)->ResolvedBinding:
    items=payload.get('data',payload) if isinstance(payload,dict) else payload
    if not isinstance(items,list): raise ContractError('provider project inventory is malformed')
    project=_single([x for x in items if isinstance(x,dict) and x.get('name')==names.project],'project')
    environments=project.get('environments')
    if not isinstance(environments,list): raise ContractError('provider environment inventory is malformed')
    environment=_single([x for x in environments if isinstance(x,dict) and x.get('name')==names.environment and isinstance(x.get('environmentId'),str) and x['environmentId']],'environment')
    resources=environment.get('composes',environment.get('resources'))
    if not isinstance(resources,list): raise ContractError('provider resource inventory is malformed')
    resource=_single([x for x in resources if isinstance(x,dict) and x.get('name')==names.resource and isinstance(x.get('composeId'),str) and x['composeId']],'resource')
    return ResolvedBinding(environment['environmentId'],resource['composeId'])


def discover(*,capability:dict[str,Any],environment:str,target_provider:str,names:ProviderNames,client:InventoryClient)->ResolvedBinding:
    if capability.get('status')!='supported' or environment not in capability.get('environments',[]): raise ContractError('capability is unsupported for the requested environment')
    if target_provider!='dokploy': raise ContractError('logical target does not select the Dokploy provider')
    if not IDENTIFIER.fullmatch(environment) or not names.child_binding.isupper(): raise ContractError('provider mapping is invalid')
    return resolve_inventory(client.projects(),names)


def child_environment(parent:dict[str,str],binding_name:str,resource_id:str,*,endpoint:str,credential:str)->dict[str,str]:
    child=parent.copy()
    for key in list(child):
        if key.endswith('_COMPOSE_ID') or key in {'DOKPLOY_URL','DOKPLOY_TOKEN','DOKPLOY_API_KEY'}: child.pop(key,None)
    child[binding_name]=resource_id; child['DOKPLOY_URL']=endpoint; child['DOKPLOY_TOKEN']=credential
    return child


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
    missing=sorted(set(updates)-set(entries))
    if not updates or missing:
        # Key names are not secret; provisioning writes them as empty image slots.
        raise ContractError('Environment lacks owned update keys '+', '.join(missing)+'; restore their empty KEY= image slots' if missing else 'Environment update mapping is empty')
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


_VOLUME_ENTRY = re.compile(r'^  ([A-Za-z0-9_.-]+):(?:\s+.*)?$')


def _named_volume_definitions(raw:bytes)->dict[str,tuple[str,...]]:
 try:text=raw.decode('utf-8')
 except UnicodeDecodeError as exc:raise ContractError('Compose configuration is not UTF-8') from exc
 lines=text.splitlines();start=None
 for index,line in enumerate(lines):
  if line.rstrip()=='volumes:':start=index+1;break
 if start is None:return {}
 result={};name=None;block=[]
 def save():
  if name is not None:
   result[name]=tuple(line.rstrip() for line in block if line.strip() and not line.lstrip().startswith('#'))
 for line in lines[start:]:
  if line and not line[0].isspace():break
  match=_VOLUME_ENTRY.fullmatch(line.rstrip())
  if match:
   save();name=match.group(1);block=[line];continue
  if name is not None:block.append(line)
 save();return result


def validate_persistent_volume_compatibility(current:bytes,desired:bytes)->None:
 """Fail before provider writes if a deployed named-volume contract changes."""
 before,after=_named_volume_definitions(current),_named_volume_definitions(desired)
 changed=sorted(name for name in before if name not in after or before[name]!=after[name])
 if changed:raise ContractError(f'persistent volume definition drift blocks apply: {changed}')


def _capture_compose(path:Path,current:bytes,desired:bytes)->bytes:
 private_directory(path.parent)
 if path.is_symlink():raise ContractError('Compose snapshot must not be a symlink')
 if path.exists():
  if not path.is_file():raise ContractError('Compose snapshot is not a regular file')
  prior=path.read_bytes()
  if current not in {prior,desired}:raise ContractError('remote Compose changed after the recorded snapshot')
  return prior
 fd,temporary=tempfile.mkstemp(prefix='.compose-',dir=path.parent)
 try:
  with os.fdopen(fd,'wb') as output:
   output.write(current);output.flush();os.fsync(output.fileno())
  os.chmod(temporary,0o600);os.replace(temporary,path)
 finally:
  if os.path.exists(temporary):os.unlink(temporary)
 return current


def _key_contract(data):
 if not isinstance(data,dict):raise ContractError('Environment key schema is not closed')
 keys=data.get('keys');optional=data.get('optional_keys',[])
 if set(data) not in ({'keys'},{'keys','optional_keys'}) or not isinstance(keys,list) or not isinstance(optional,list) or len(keys)!=len(set(keys)) or len(optional)!=len(set(optional)) or not set(optional)<=set(keys):raise ContractError('Environment key schema is not closed')
 allowed=set(keys);return allowed-set(optional),allowed


class ComposeBackend:
 def __init__(self,endpoint:str,credential:str,compose_id:str):self.endpoint=endpoint.rstrip('/');self.credential=credential;self.compose_id=compose_id
 def _request(self,method,path,payload=None):
  data=None if payload is None else json.dumps(payload,separators=(',',':')).encode();request=Request(self.endpoint+path,data=data,method=method,headers={'x-api-key':self.credential,'Accept':'application/json','Content-Type':'application/json'})
  try:
   with urlopen(request,timeout=20) as response:raw=response.read(2*1024*1024)
  except (HTTPError,URLError,TimeoutError) as exc:raise ContractError('Dokploy configuration operation failed') from exc
  try:return json.loads(raw) if raw else {}
  except json.JSONDecodeError as exc:raise ContractError('Dokploy configuration response malformed') from exc
 def _state(self):
  value=self._request('GET',f'/api/compose.one?composeId={self.compose_id}')
  if (not isinstance(value,dict) or not isinstance(value.get('composeFile'),str)
      or 'env' not in value or (value['env'] is not None and not isinstance(value['env'],str))):raise ContractError('Dokploy raw configuration readback malformed')
  # Newly created apps return an explicit null for their unset Environment.
  # Missing fields still refuse; existing text is returned byte-for-byte.
  return {**value,'env':value['env'] if value['env'] is not None else ''}
 def read_compose(self):return self._state()['composeFile'].encode()
 def read_environment(self):return self._state()['env'].encode()
 def write_compose(self,value):self._request('POST','/api/compose.update',{'composeId':self.compose_id,'composeFile':value.decode()})
 def write_environment(self,value):self._request('POST','/api/compose.saveEnvironment',{'composeId':self.compose_id,'env':value.decode()})


class DokployNotFound(ContractError):pass


class DeployClient:
 def __init__(self,url,token):self.url=url.rstrip('/');self.token=token
 def request(self,method,path,payload=None):
  data=None if payload is None else json.dumps(payload).encode();req=Request(self.url+path,data=data,method=method,headers={'x-api-key':self.token,'Accept':'application/json','Content-Type':'application/json'})
  try:
   with urlopen(req,timeout=20) as response:raw=response.read(1024*1024)
  except HTTPError as exc:
   if exc.code==404:raise DokployNotFound('Dokploy endpoint is unavailable') from exc
   raise ContractError('Dokploy deploy operation failed') from exc
  except (URLError,TimeoutError) as exc:raise ContractError('Dokploy deploy operation failed') from exc
  try:return json.loads(raw) if raw else {}
  except json.JSONDecodeError as exc:raise ContractError('Dokploy deploy response malformed') from exc


DESTRUCTIVE_CONFIRMATION=re.compile(
 r'data\s+will\s+be\s+lost|(?:recreate|delete|remove).{0,200}\?\s*(?:\[[yYnN/]+\])?',
 re.IGNORECASE|re.DOTALL,
)


def _terminate(client:DeployClient,deployment_id:str,reason:str)->None:
 try:client.request('POST','/api/deployment.killProcess',{'deploymentId':deployment_id})
 except ContractError as exc:raise ContractError(reason+'; provider termination failed') from exc
 raise ContractError(reason)


def _guard_deployment_log(client:DeployClient,deployment_id:str)->None:
 try:
  raw=client.request('GET','/api/deployment.readLogs?'+urlencode(
   {'deploymentId':deployment_id,'tail':200}))
 except DokployNotFound:return
 except ContractError as exc:
  try:_terminate(client,deployment_id,'active deployment log inspection failed')
  except ContractError as terminated:raise terminated from exc
 if not isinstance(raw,str) or len(raw)>1024*1024:
  _terminate(client,deployment_id,'active deployment log response is malformed')
 if DESTRUCTIVE_CONFIRMATION.search(raw):
  _terminate(client,deployment_id,'deployment blocked by destructive confirmation prompt')










def _deploy(endpoint:str,credential:str,resource_id:str,*,operation:str|None=None,submit:bool=True)->str:
 client=DeployClient(endpoint,credential);initial=client.request('GET','/api/compose.one?'+urlencode({'composeId':resource_id}))
 if not isinstance(initial,dict):raise ContractError('pre-deploy status is malformed')
 route='/api/deployment.allByCompose?'+urlencode({'composeId':resource_id});before=client.request('GET',route)
 if not isinstance(before,list) or any(not isinstance(row,dict) or not isinstance(row.get('deploymentId'),str) or not row['deploymentId'] for row in before):raise ContractError('pre-deploy history is malformed')
 existing={row['deploymentId'] for row in before};operation=operation or 'operation-'+secrets.token_hex(16);title='ADW '+operation;description='pzagent-adw-context '+operation
 if submit:
  client.request('GET','/api/compose.loadServices?'+urlencode({'composeId':resource_id,'type':'fetch'}));ack=client.request('POST','/api/compose.deploy',{'composeId':resource_id,'title':title,'description':description})
  if not (isinstance(ack,dict) and set(ack)=={'success','composeId','message'} and ack.get('success') is True and ack.get('composeId')==resource_id and isinstance(ack.get('message'),str) and 0<len(ack['message'])<=512):raise ContractError('deployment acknowledgement is malformed')
 deployment_id=None
 deadline=time.monotonic()+300
 while time.monotonic()<deadline:
  rows=client.request('GET',route)
  if not isinstance(rows,list) or any(not isinstance(row,dict) for row in rows):raise ContractError('deployment history is malformed')
  if deployment_id is None:
   candidates=[row for row in rows if (not submit or row.get('deploymentId') not in existing) and row.get('title')==title]
   if len(candidates)>1:raise ContractError('deployment correlation is ambiguous')
   if candidates:
    deployment_id=candidates[0].get('deploymentId')
    if not isinstance(deployment_id,str) or not deployment_id:raise ContractError('deployment correlation identity is malformed')
  row=next((item for item in rows if item.get('deploymentId')==deployment_id),None) if deployment_id else None
  status=row.get('status') if isinstance(row,dict) else None
  if status=='done':return deployment_id
  if status in {'error','failed','cancelled'}:raise DeploymentTerminalFailure(deployment_id,status)
  if deployment_id is not None:_guard_deployment_log(client,deployment_id)
  remaining=deadline-time.monotonic()
  if remaining>0:time.sleep(min(5,remaining))
 if deployment_id is not None:
  _terminate(client,deployment_id,'deployment exceeded the bounded execution window')
 raise ContractError('deployment did not expose a correlated ready transition')



class HotfixBackend:
    """Raw settings access; deliberately takes no lock and starts no transaction."""

    def __init__(self, backend: ComposeBackend) -> None:
        self.inner = backend

    def read_definition(self) -> bytes:
        return self.inner.read_compose()

    def read_settings(self) -> bytes:
        return self.inner.read_environment()

    def write_settings(self, value: bytes) -> None:
        self.inner._request('POST', '/api/compose.saveEnvironment',
                            {'composeId': self.inner.compose_id, 'env': value.decode()})


PROJECT = re.compile(r'^[a-z0-9][a-z0-9_.-]{0,127}$')
REMOTE_ID = re.compile(r'^[A-Za-z0-9_-]{1,128}$')
CONTAINER_ID = re.compile(r'^[A-Za-z0-9_.-]{1,128}$')
SERVICE = re.compile(r'^  ([A-Za-z0-9][A-Za-z0-9_.-]{0,127}):\s*$')
VARIABLE_IMAGE = re.compile(r'''^    image:\s*["']?\$\{([A-Z][A-Z0-9_]{0,127})(?::[?+-][^}\r\n]*)?\}["']?\s*$''')


def _runtime_blocked(reason: str) -> None:
    raise ContractError(reason)


def _runtime_get(client: DokployClient, route: str, reason: str) -> Any:
    try:
        return client._get(route)
    except ContractError:
        _runtime_blocked(reason)


def runtime_service_variables(definition: bytes, owned: set[str]) -> dict[str, str]:
    return _runtime_services(definition, owned)[0]


def _runtime_services(definition: bytes, owned: set[str]) -> tuple[dict[str, str], set[str]]:
    """Read the explicit service/image mapping subset, rejecting ambiguous ownership."""
    try:
        text = definition.decode('utf-8')
    except UnicodeDecodeError:
        _runtime_blocked('runtime-service-mapping-invalid')
    result: dict[str, str] = {}
    names: set[str] = set()
    active = False
    service: str | None = None
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].rstrip()
        if not line:
            continue
        if line == 'services:':
            if active or names:
                _runtime_blocked('runtime-service-mapping-invalid')
            active = True
            continue
        if not line.startswith(' '):
            active = False
            service = None
        if not active:
            continue
        match = SERVICE.fullmatch(line)
        if match:
            service = match[1]
            if service in names:
                _runtime_blocked('runtime-service-mapping-invalid')
            names.add(service)
            continue
        match = VARIABLE_IMAGE.fullmatch(line)
        if match and match[1] in owned:
            if service is None or service in result or match[1] in result.values():
                _runtime_blocked('runtime-service-mapping-invalid')
            result[service] = match[1]
    if set(result.values()) != owned:
        _runtime_blocked('runtime-service-mapping-invalid')
    return result, names


def observe_runtime(client: DokployClient, resource: str, services: dict[str, str],
                    *, first: dict | None = None,
                    declared: set[str] | None = None) -> dict[str, list[dict]]:
    """Shared read-only Docker observations; no settings leave this boundary."""
    if first is None:
        first = _runtime_get(client, '/api/compose.one?' + urlencode({'composeId': resource}),
                     'runtime-container-discovery-failed')
        if not isinstance(first, dict) or not isinstance(first.get('appName'), str) or not PROJECT.fullmatch(first['appName']):
            _runtime_blocked('runtime-project-identity-absent')
    second = _runtime_get(client, '/api/compose.one?' + urlencode({'composeId': resource}),
                  'runtime-container-discovery-failed')
    if (not isinstance(second, dict) or second.get('appName') != first['appName']
            or not isinstance(second.get('serverId'), str) or not REMOTE_ID.fullmatch(second['serverId'])):
        _runtime_blocked('runtime-project-identity-absent')
    project, server = first['appName'], second['serverId']
    containers = _runtime_get(client, '/api/docker.getContainersByAppLabel?' + urlencode({
        'appName': project, 'serverId': server, 'type': 'standalone'}), 'runtime-container-discovery-failed')
    if not isinstance(containers, list):
        _runtime_blocked('runtime-container-discovery-failed')
    seen: dict[str, list[dict[str, Any]]] = {service: [] for service in services}
    for container in containers:
        if not isinstance(container, dict) or not isinstance(container.get('containerId'), str) or not CONTAINER_ID.fullmatch(container['containerId']):
            _runtime_blocked('runtime-container-discovery-failed')
        metadata = _runtime_get(client, '/api/docker.getConfig?' + urlencode({
            'containerId': container['containerId'], 'serverId': server}), 'runtime-container-inspection-failed')
        if not isinstance(metadata, dict) or not isinstance(metadata.get('Config'), dict):
            _runtime_blocked('runtime-container-inspection-failed')
        labels = metadata['Config'].get('Labels')
        if not isinstance(labels, dict) or labels.get('com.docker.compose.project') != project:
            _runtime_blocked('runtime-image-identity-or-health-mismatch')
        service = labels.get('com.docker.compose.service')
        if service in seen:
            seen[service].append(metadata)
        elif declared is not None:
            # Auxiliary services declared without an owned image are allowed;
            # an unknown service is not part of the tracked deployment scope.
            if not isinstance(service, str) or service not in declared:
                _runtime_blocked('runtime-component-undeclared')
    for service in services:
        if len(seen[service]) != 1:
            _runtime_blocked('runtime-container-cardinality-differs')
    return seen


class DokployProvider:
    """Bound provider observations and writes; shared orchestration owns authority."""

    def __init__(self, repo: Path, target: str, binding: Mapping[str, Any],
                 profile_root: Path | None = None) -> None:
        self.repo = repo
        self.target = target
        self.binding = dict(binding)
        self.profile_root = profile_root
        self.configuration = ProviderConfiguration(
            str(binding.get("compose_path", "")),
            str(binding.get("environment_schema_path", "")),
            volume_definitions=_named_volume_definitions,
        )
        self._backend: ComposeBackend | None = None
        self._endpoint = ""
        self._credential = ""
        self._resource_id = ""

    def discover(self, binding: Mapping[str, Any]) -> None:
        endpoint, credential = profile_credentials(self.profile_root)
        resolved = discover_binding(DokployClient(endpoint, credential), ProviderNames(
            binding["project"], binding["environment"], binding["resource"], binding["child_binding"],
        ))
        self._endpoint, self._credential, self._resource_id = endpoint, credential, resolved.resource_id
        self._backend = ComposeBackend(endpoint, credential, resolved.resource_id)

    @property
    def backend(self) -> ComposeBackend:
        if self._backend is None:
            raise ContractError("provider target has not been discovered")
        return self._backend

    @property
    def settings_backend(self) -> HotfixBackend:
        return HotfixBackend(self.backend)

    def read_state(self) -> DeploymentState:
        return DeploymentState(self.backend.read_compose(), self.backend.read_environment())

    def snapshot(self) -> DeploymentState:
        return self.read_state()

    def plan(self, updates: Mapping[str, str], *, definition: bytes | None = None,
             current: DeploymentState | None = None) -> DeploymentState:
        before = current if current is not None else (self.read_state() if definition is None else DeploymentState(definition, self.backend.read_environment()))
        settings = replace_environment(before.settings, dict(updates)) if updates else before.settings
        return DeploymentState(before.definition if definition is None else definition, settings)

    def config_apply(self, state: DeploymentState, owned_keys: set[str], *,
                     current: DeploymentState | None = None,
                     required: set[str] | None = None, allowed: set[str] | None = None,
                     snapshot_path: Path | None = None) -> dict[str, Any]:
        prior = None
        if required is not None:
            before = current if current is not None else self.read_state()
            actual = environment_keys(before.settings)
            allowed = allowed if allowed is not None else required
            if required - actual or (not human() and actual - allowed):
                raise ContractError(f'Environment key drift blocks apply (missing={sorted(required-actual)}, extra={sorted(actual-allowed)})')
            validate_persistent_volume_compatibility(before.definition, state.definition)
            if snapshot_path is not None:
                prior = _capture_compose(snapshot_path, before.definition, state.definition)
        result = apply(self.repo, self.target, self.backend,
                       Snapshot(state.definition, state.settings), owned_keys)
        output = {"compose_changed": result.compose_changed,
                  "environment_key_count": len(result.environment_keys)}
        if prior is not None:
            output["previous_compose_sha256"] = hashlib.sha256(prior).hexdigest()
        return output

    def restore(self, snapshot: DeploymentState, owned_keys: set[str]) -> None:
        self.config_apply(snapshot, owned_keys)

    def apply(self, updates: Mapping[str, str], *, operation: str | None = None,
              submit: bool = True) -> DeploymentOperation:
        if updates:
            self.config_apply(self.plan(updates), set(updates))
        token = operation or "operation-" + secrets.token_hex(16)
        completed = _deploy(self._endpoint, self._credential, self._resource_id,
                            operation=token, submit=submit)
        return DeploymentOperation(token, completed)

    def wait(self, operation: DeploymentOperation) -> str:
        # Preserve the existing synchronous, bounded Dokploy correlation.
        # apply() may return an already completed operation; never resubmit it.
        return cast(str, operation.context)

    def readback(self, state: DeploymentState | None = None) -> Mapping[str, str]:
        from ..runtime_proof import parse_environment
        raw = self.backend.read_environment() if state is None else state.settings
        return parse_environment(raw.decode())

    def live_image_refs(self) -> Mapping[str, str]:
        # Configured references for retention, including not-yet-running images.
        # The trusted retention caller validates each configured owned image ref
        # before adding it to the protected root set.
        return self.readback()

    def observed_image_refs(self, owned_keys: set[str]) -> Mapping[str, str]:
        from ..common import ensure_contained
        from ..release_manifest import DIGEST_REF
        try:
            definition = ensure_contained(self.repo, self.configuration.definition_path).read_bytes()
            services, declared = _runtime_services(definition, owned_keys)
            observations = observe_runtime(DokployClient(self._endpoint, self._credential),
                                           self._resource_id, services, declared=declared)
            result = {}
            for service, key in services.items():
                metadata = observations[service][0]
                state = metadata.get('State')
                if (not isinstance(state, dict) or state.get('Status') != 'running'
                        or not isinstance(state.get('Health'), dict)
                        or state['Health'].get('Status') != 'healthy'):
                    raise ContractError('runtime_container_not_running')
                image = metadata['Config'].get('Image')
                if not isinstance(image, str) or not DIGEST_REF.fullmatch(image):
                    raise ContractError('runtime_image_not_immutable')
                result[key] = image
            return result
        except ContractError as exc:
            if str(exc).startswith('runtime-'):
                raise ContractError(str(exc).replace('-', '_')) from exc
            raise

    def config_pull(self) -> dict[str, Any]:
        state = self.read_state()
        keys = environment_keys(state.settings)
        return {"compose_sha256": hashlib.sha256(state.definition).hexdigest(),
                "environment_key_count": len(keys), "environment_keys": sorted(keys)}

    def config_plan(self, definition: bytes, required: set[str],
                    allowed: set[str]) -> dict[str, Any]:
        settings = self.backend.read_environment()
        current_definition = self.backend.read_compose()
        state = DeploymentState(current_definition, settings)
        actual = environment_keys(state.settings)
        validate_persistent_volume_compatibility(state.definition, definition)
        return {"expected_key_count": len(required), "missing_keys": sorted(required - actual),
                "dokploy_only_keys": sorted(actual - allowed),
                "compose_changed": state.definition != definition,
                "current_compose_sha256": hashlib.sha256(state.definition).hexdigest(),
                "desired_compose_sha256": hashlib.sha256(definition).hexdigest()}

    def probe(self, kind: str) -> dict[str, str]:
        result = {"DOKPLOY_URL": self._endpoint, "DOKPLOY_TOKEN": self._credential,
                  self.binding["child_binding"]: self._resource_id}
        key = self.binding.get('probes', {}).get('base_url_env')
        if key and key in os.environ:
            result[key] = os.environ[key]
        return result

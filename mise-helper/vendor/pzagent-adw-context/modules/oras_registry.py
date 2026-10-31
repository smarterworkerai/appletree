"""ORAS-backed conditional registry adapter for target pointers."""
from __future__ import annotations
import json,os,re,subprocess
from pathlib import Path
from .common import ContractError
DIGEST=re.compile(r'^sha256:[0-9a-f]{64}$')
ACCESS_DENIED=re.compile(
 r'\b(?:response\s+status(?:\s+code)?|http(?:/\d(?:\.\d)?)?)\s*:?\s*(?:401|403)\b'
 r'|\b(?:401\s+unauthorized|403\s+forbidden)\b'
 r'|(?:^|[\s:])(?:unauthorized|denied|insufficient_scope):',re.I)
def access_denied(stderr)->bool:
 if isinstance(stderr,bytes):stderr=stderr.decode('utf-8',errors='replace')
 return isinstance(stderr,str) and ACCESS_DENIED.search(stderr) is not None
def registry_args(args):
 config=os.environ.get('DOCKER_CONFIG')
 if not config:return args
 path=str(Path(config)/'config.json')
 # Copy has two remote endpoints and separate authentication flags in ORAS 1.2.
 if len(args)>1 and args[1] in {'cp','copy'}:
  return args+['--from-registry-config',path,'--to-registry-config',path]
 return args+['--registry-config',path]
class OrasRegistry:
 def resolve(self,reference:str)->str|None:
  result=subprocess.run(registry_args(['oras','manifest','fetch','--descriptor',reference]),text=True,capture_output=True)
  if result.returncode:
   if access_denied(getattr(result,'stderr',None)):raise ContractError('registry_access_denied')
   if any(marker in result.stderr.lower() for marker in ('manifest unknown','manifest_unknown','404 not found')):return None
   # ORAS 1.2 also normalizes a registry 404 to this reference-specific form.
   # Do not classify missing executables/credential helpers as absent images.
   if 'failed to find "'+reference+'"' in result.stderr and reference+': not found' in result.stderr:return None
   raise ContractError('registry descriptor lookup failed')
  try:value=json.loads(result.stdout).get('digest')
  except json.JSONDecodeError as exc:raise ContractError('registry descriptor is malformed') from exc
  if not isinstance(value,str) or not DIGEST.fullmatch(value):raise ContractError('registry descriptor digest is invalid')
  return value
 def copy_if_unchanged(self,source:str,target:str,expected_target:str|None)->None:
  if self.resolve(target)!=expected_target:raise ContractError('registry pointer changed concurrently')
  source_digest=self.resolve(source)
  if source_digest is None:raise ContractError('registry source is absent')
  result=subprocess.run(registry_args(['oras','cp',source,target]),capture_output=True)
  if result.returncode:
   if access_denied(getattr(result,'stderr',None)):raise ContractError('registry_access_denied')
   raise ContractError('registry pointer copy failed')
  if self.resolve(target)!=source_digest:raise ContractError('registry pointer copy readback differs')
 def delete_if_unchanged(self,target:str,expected_target:str)->None:
  if self.resolve(target)!=expected_target:raise ContractError('registry pointer changed concurrently')
  # ORAS manifest delete removes the manifest, potentially invalidating every
  # tag and immutable release reference to that digest. It is not tag removal.
  # Leave a new pointer for explicit reconciliation rather than delete a release.
  raise ContractError('registry has no verified tag-only deletion; pointer requires explicit reconciliation')

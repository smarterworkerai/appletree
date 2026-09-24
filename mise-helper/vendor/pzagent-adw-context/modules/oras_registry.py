"""ORAS-backed conditional registry adapter for target pointers."""
from __future__ import annotations
import json,re,subprocess
from .common import ContractError
DIGEST=re.compile(r'^sha256:[0-9a-f]{64}$')
class OrasRegistry:
 def resolve(self,reference:str)->str|None:
  result=subprocess.run(['oras','manifest','fetch','--descriptor',reference],text=True,capture_output=True)
  if result.returncode:
   if any(marker in result.stderr.lower() for marker in ('manifest unknown','not found','404')):return None
   raise ContractError('registry descriptor lookup failed')
  try:value=json.loads(result.stdout).get('digest')
  except json.JSONDecodeError as exc:raise ContractError('registry descriptor is malformed') from exc
  if not isinstance(value,str) or not DIGEST.fullmatch(value):raise ContractError('registry descriptor digest is invalid')
  return value
 def copy_if_unchanged(self,source:str,target:str,expected_target:str|None)->None:
  if self.resolve(target)!=expected_target:raise ContractError('registry pointer changed concurrently')
  source_digest=self.resolve(source)
  if source_digest is None:raise ContractError('registry source is absent')
  subprocess.run(['oras','cp',source,target],check=True)
  if self.resolve(target)!=source_digest:raise ContractError('registry pointer copy readback differs')
 def delete_if_unchanged(self,target:str,expected_target:str)->None:
  if self.resolve(target)!=expected_target:raise ContractError('registry pointer changed concurrently')
  subprocess.run(['oras','manifest','delete','--force',target],check=True)
  if self.resolve(target) is not None:raise ContractError('registry pointer delete readback differs')

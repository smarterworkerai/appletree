"""Push source-labelled hotfix images and prove tagged registry digests."""
from __future__ import annotations
import json,re,subprocess
from .common import ContractError
from .oras_registry import OrasRegistry
REF=re.compile(r'^(?P<repo>[a-z0-9][a-z0-9._/-]{1,254})@(?P<digest>sha256:[0-9a-f]{64})$')
def transfer(images:list[str])->dict[str,str]:
 if not images or len(images)!=len(set(images)):raise ContractError('hotfix registry image set is empty or duplicate')
 registry=OrasRegistry();result={}
 for image in images:
  if '/' not in image or ':' not in image.rsplit('/',1)[-1]:raise ContractError('hotfix image must be a fully qualified tagged registry reference')
  if subprocess.run(['docker','image','push',image],text=True,capture_output=True).returncode:raise ContractError('hotfix registry push failed')
  inspected=subprocess.run(['docker','image','inspect',image],text=True,capture_output=True)
  if inspected.returncode:raise ContractError('pushed hotfix image inspection failed')
  try:digests=json.loads(inspected.stdout)[0]['RepoDigests']
  except (json.JSONDecodeError,KeyError,IndexError,TypeError) as exc:raise ContractError('pushed hotfix digest evidence is malformed') from exc
  repository=image.rsplit(':',1)[0];matches=[value for value in digests if isinstance(value,str) and value.startswith(repository+'@') and REF.fullmatch(value)]
  if len(matches)!=1:raise ContractError('pushed hotfix immutable digest is not unique')
  immutable=matches[0];remote=registry.resolve(image)
  if remote!=immutable.rsplit('@',1)[1]:raise ContractError('pushed hotfix tag readback differs')
  result[image]=immutable
 return result

#!/usr/bin/env python3
import hashlib,json,os,re,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from modules.adapter import load as load_adapter
from modules.ci.github_api import ApiError,GitHub
from modules.ci.publication_proof import authorize
from modules.ci.quality_proof import ProofError
from modules.common import ContractError
sha=os.environ.get('SOURCE_SHA',''); repo=os.environ.get('GITHUB_REPOSITORY','')
def blocked(x):print('blocked: '+x,file=sys.stderr);raise SystemExit(21)
def load(path):
 try:return json.loads(Path(path).read_text())
 except (OSError,json.JSONDecodeError):blocked('required JSON document is unavailable')
def digest(ref,absent=False):
 r=subprocess.run(['oras','manifest','fetch','--descriptor',ref],text=True,capture_output=True)
 if r.returncode:
  if absent and any(x in r.stderr.lower() for x in ('not found','manifest unknown','404')):return None
  blocked('registry descriptor lookup failed')
 try:value=json.loads(r.stdout).get('digest')
 except json.JSONDecodeError:blocked('registry descriptor malformed')
 if not isinstance(value,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',value):blocked('registry digest invalid')
 return value
if not re.fullmatch(r'[0-9a-f]{40}',sha):blocked('full source SHA required')
auth=load(os.environ['AUTHORIZATION_PATH'])
auth_keys={'schema_version','repository','source_sha','pr_number','target_branch','actor','workflow_path','run_id','run_attempt','job_id','tested_tree','contract_ref','diagnostic'}
if (not isinstance(auth,dict) or set(auth)!=auth_keys or auth.get('source_sha')!=sha
    or auth.get('repository')!=repo
    or auth.get('actor')!=os.environ.get('GITHUB_ACTOR')
    or type(auth.get('run_id')) is not int or type(auth.get('run_attempt')) is not int
    or type(auth.get('diagnostic')) is not bool):
 blocked('authorization record differs')
try:
 github=GitHub(repo)
 adapter_bytes=github.content('.hermes/pzagent-adapter.json',sha)[1]
 with tempfile.TemporaryDirectory() as temp:
  adapter_path=Path(temp)/'pzagent-adapter.json'
  adapter_path.write_bytes(adapter_bytes)
  adapter=load_adapter(adapter_path)
 if adapter['repository']['id']!=repo or auth['workflow_path']!=adapter['ci']['workflow_path']:
  blocked('authorization adapter differs')
 expected=authorize(github,source_sha=sha,run_id=auth['run_id'],attempt=auth['run_attempt'],
                    actor=auth['actor'],adapter=adapter,diagnostic=auth['diagnostic'])
except (ProofError,ApiError,ContractError,KeyError,OSError,TypeError,ValueError):
 blocked('authorization revalidation failed')
if auth!=expected:blocked('authorization record differs')
root=Path(os.environ['ARTIFACT_PATH']).resolve(); data=load(root/'publication.json')
keys={'source_sha','artifact','sha256','repository','immutable_tag','mutable_tag','expected_previous_digest','media_type'}
if not isinstance(data,dict) or set(data)!=keys or data['source_sha']!=sha:blocked('publication descriptor invalid')
owner=repo.split('/',1)[0]
if not re.fullmatch(rf'ghcr\.io/{re.escape(owner)}/[a-z0-9._/-]+',str(data['repository'])):blocked('registry repository is outside authorized owner')
if data['immutable_tag']!=f'sha-{sha[:12]}' or not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,127}',str(data['mutable_tag'])):blocked('publication tags invalid')
expected=data['expected_previous_digest']
if expected is not None and not re.fullmatch(r'sha256:[0-9a-f]{64}',str(expected)):blocked('expected pointer digest invalid')
artifact=(root/data['artifact']).resolve()
try:artifact.relative_to(root)
except ValueError:blocked('artifact path escapes download root')
if not artifact.is_file() or hashlib.sha256(artifact.read_bytes()).hexdigest()!=data['sha256']:blocked('artifact checksum differs')
subprocess.run(['oras','login','ghcr.io','-u',os.environ.get('GITHUB_ACTOR','github-actions'),'--password-stdin'],input=os.environ['REGISTRY_TOKEN'],text=True,check=True,stdout=subprocess.DEVNULL)
immutable=f"{data['repository']}:{data['immutable_tag']}"; pointer=f"{data['repository']}:{data['mutable_tag']}"
immutable_digest=digest(immutable,True)
if immutable_digest is None:
 subprocess.run(['oras','push',immutable,f"artifact={artifact}:{data['media_type']}"],check=True)
 immutable_digest=digest(immutable)
else:
 with tempfile.TemporaryDirectory() as temp:
  subprocess.run(['oras','pull',immutable,'--output',temp],check=True)
  matches=list(Path(temp).rglob(artifact.name))
  if len(matches)!=1 or hashlib.sha256(matches[0].read_bytes()).hexdigest()!=data['sha256']:blocked('existing immutable artifact is not idempotent')
if digest(pointer,True)!=expected:blocked('mutable pointer compare-and-swap precondition failed')
if digest(pointer,True)!=expected:blocked('mutable pointer changed before update')
subprocess.run(['oras','cp',immutable,pointer],check=True)
if digest(pointer)!=immutable_digest:blocked('mutable pointer readback differs')
print(json.dumps({'published':True,'source_sha':sha,'immutable_digest':immutable_digest},sort_keys=True))

"""Authorize explicit registry or logical-SSH hotfix transfer before side effects."""
from __future__ import annotations
import json,re,subprocess,sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from .common import ContractError,FULL_SHA,IDENTIFIER
from .operator_ssh import command as ssh_command
ALIAS=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$')
BRANCH=re.compile(r'^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$')
SHORT_BRANCH=re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,244}$')
@dataclass(frozen=True)
class TransferPlan: transport:str; environment:str; target:str; source_sha:str; ssh_alias:str|None
def prove_upstream_head(repo:Path)->str:
    def git(*args:str)->str:
        result=subprocess.run(['git','-C',str(repo),*args],text=True,capture_output=True)
        if result.returncode: raise ContractError('hotfix source proof failed')
        return result.stdout.strip()
    if git('status','--porcelain=v1','--untracked-files=all'): raise ContractError('hotfix requires a clean worktree')
    branch=git('symbolic-ref','--quiet','--short','HEAD')
    if not SHORT_BRANCH.fullmatch(branch) or '..' in branch or '@{' in branch or branch.endswith(('/', '.', '.lock')): raise ContractError('hotfix branch identity is invalid')
    remote=git('config','--get',f'branch.{branch}.remote');merge=git('config','--get',f'branch.{branch}.merge')
    if not ALIAS.fullmatch(remote) or not BRANCH.fullmatch(merge): raise ContractError('hotfix upstream is absent or invalid')
    remote_branch=merge.removeprefix('refs/heads/');tracking=f'refs/remotes/{remote}/{remote_branch}'
    git('fetch','--no-tags',remote,f'+{merge}:{tracking}')
    head=git('rev-parse','--verify','HEAD');upstream=git('rev-parse','--verify',tracking)
    if not FULL_SHA.fullmatch(head) or head!=upstream: raise ContractError('local HEAD differs from freshly fetched upstream')
    return head
def authorize(config:Any,*,environment:str,target:str,source_sha:str,transport:str,ssh_alias:str|None=None,provider:str='dokploy')->TransferPlan:
    if not isinstance(config,dict) or set(config)!={'supported_environments','transports','ssh_aliases'}: raise ContractError('hotfix contract is invalid')
    if environment not in config['supported_environments'] or environment in {'production','demo'}: raise ContractError('hotfix is unsupported for requested environment')
    if not IDENTIFIER.fullmatch(target) or not FULL_SHA.fullmatch(source_sha): raise ContractError('hotfix target or source identity is invalid')
    transports=config['transports'].get(provider,[]) if isinstance(config['transports'],dict) else config['transports']
    if provider=='kubernetes' and transport!='registry':raise ContractError('hotfix_provider_transport_invalid')
    if transport not in {'registry','ssh-docker'} or transport not in transports: raise ContractError('hotfix transport is not explicitly supported')
    if transport=='ssh-docker':
        if not isinstance(ssh_alias,str) or not ALIAS.fullmatch(ssh_alias) or ssh_alias not in config['ssh_aliases']: raise ContractError('logical SSH alias is not allowlisted')
    elif ssh_alias is not None: raise ContractError('registry transport must not receive SSH identity')
    return TransferPlan(transport,environment,target,source_sha,ssh_alias)
def verify_runtime(expected_platform:str,actual_platform:str,expected_identity:str,actual_identity:str)->None:
    if expected_platform!=actual_platform: raise ContractError('target runtime platform is incompatible')
    if expected_identity!=actual_identity: raise ContractError('target runtime artifact identity differs')
IMAGE=re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
HOTFIX_IMAGE=re.compile(r'^[a-z0-9][a-z0-9._:-]*(?:/[a-z0-9][a-z0-9._-]*)+:hotfix-(?P<source>[0-9a-f]{12})(?:-[0-9a-f]{12})?$')
def _verify_source_tags(images:list[str],source_sha:str)->None:
    for image in images:
        match=HOTFIX_IMAGE.fullmatch(image) if isinstance(image,str) else None
        if not match or match.group('source')!=source_sha[:12]: raise ContractError('hotfix image must use the exact source-labelled tag')
        authority=image.split('/',1)[0]
        if authority!='localhost' and '.' not in authority and ':' not in authority: raise ContractError('hotfix image must use a fully qualified registry authority')
def _inspect(argv:list[str])->tuple[str,str]:
    result=subprocess.run(argv,text=True,capture_output=True)
    if result.returncode: raise ContractError('hotfix image inspection failed')
    try: value=json.loads(result.stdout)
    except json.JSONDecodeError as exc: raise ContractError('hotfix image inspection output is malformed') from exc
    if not isinstance(value,list) or len(value)!=1 or not isinstance(value[0],dict): raise ContractError('hotfix image inspection output is ambiguous')
    item=value[0];identity=item.get('Id');os_name=item.get('Os');arch=item.get('Architecture')
    if not isinstance(identity,str) or not identity or not isinstance(os_name,str) or not os_name or not isinstance(arch,str) or not arch: raise ContractError('hotfix image identity or platform is absent')
    return identity,f'{os_name}/{arch}'
def _config_identities(images:list[str],ssh_alias:str|None=None)->dict:
    helper=Path(__file__).with_name('image_archive_identity.py')
    argv=ssh_command(ssh_alias,'python3','-c',helper.read_text(),*images) if ssh_alias else [sys.executable,str(helper),*images]
    result=subprocess.run(argv,text=True,capture_output=True)
    if result.returncode:raise ContractError('hotfix image config identity unavailable')
    try:value=json.loads(result.stdout)
    except json.JSONDecodeError as exc:raise ContractError('hotfix image config identity malformed') from exc
    if not isinstance(value,dict) or set(value)!=set(images):raise ContractError('hotfix config image set differs')
    for item in value.values():
        if (not isinstance(item,dict) or set(item)!={'digest','platform'} or
            not isinstance(item['digest'],str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',item['digest']) or
            not isinstance(item['platform'],str)):
            raise ContractError('hotfix image config identity invalid')
    return value
def transfer_ssh(plan:TransferPlan,images:list[str])->dict[str,str]:
    if plan.transport!='ssh-docker' or plan.ssh_alias is None: raise ContractError('SSH transfer requires an authorized SSH plan')
    if not images or len(set(images))!=len(images) or any(not isinstance(image,str) or not IMAGE.fullmatch(image) for image in images): raise ContractError('hotfix image set is invalid')
    _verify_source_tags(images,plan.source_sha)
    local={image:_inspect(['docker','image','inspect',image]) for image in images}
    archive=subprocess.Popen(['docker','image','save',*images],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    try: loaded=subprocess.run(ssh_command(plan.ssh_alias,'docker','image','load'),stdin=archive.stdout,capture_output=True)
    except Exception:
        archive.terminate();archive.wait();raise
    finally:
        if archive.stdout: archive.stdout.close()
    archive_code=archive.wait()
    if archive_code or loaded.returncode: raise ContractError('hotfix image transfer failed')
    proven={};different=[]
    for image in images:
        remote=_inspect(ssh_command(plan.ssh_alias,'docker','image','inspect',image))
        if local[image][1]!=remote[1]:raise ContractError('target runtime platform is incompatible')
        if local[image][0]!=remote[0]:different.append(image)
        proven[image]=remote[0]
    if different:
        # Classic Docker uses the config digest as Id; containerd may expose the
        # manifest digest. Compare exact config bytes (including layer diff IDs),
        # not just labels or a tag, when those identifier domains differ.
        local_configs=_config_identities(different)
        remote_configs=_config_identities(different,plan.ssh_alias)
        for image in different:
            verify_runtime(local[image][1],local_configs[image]['platform'],
                           local_configs[image]['digest'],remote_configs[image]['digest'])
            if remote_configs[image]['platform']!=local[image][1]:raise ContractError('target runtime platform is incompatible')
    return proven
def verify_build(images:list[str],source_sha:str,source_url:str)->None:
    if not FULL_SHA.fullmatch(source_sha) or not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',source_url): raise ContractError('hotfix build source identity is invalid')
    _verify_source_tags(images,source_sha)
    for image in images:
        result=subprocess.run(['docker','image','inspect',image],text=True,capture_output=True)
        if result.returncode: raise ContractError('hotfix build image is absent')
        try: value=json.loads(result.stdout)
        except json.JSONDecodeError as exc: raise ContractError('hotfix build inspection is malformed') from exc
        if not isinstance(value,list) or len(value)!=1 or not isinstance(value[0],dict): raise ContractError('hotfix build inspection is ambiguous')
        labels=value[0].get('Config',{}).get('Labels',{})
        if not isinstance(labels,dict) or labels.get('org.opencontainers.image.revision')!=source_sha or labels.get('org.opencontainers.image.source')!=source_url: raise ContractError('hotfix image OCI source labels differ from exact source')

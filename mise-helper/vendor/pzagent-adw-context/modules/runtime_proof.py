"""Bind live Compose image inputs to one source-bound immutable release."""
from __future__ import annotations
import json,re
from pathlib import Path
from typing import Any
from .common import ContractError,FULL_SHA
from .release_manifest import DIGEST_REF,release_kind,validate
ENV_KEY=re.compile(r'^[A-Z][A-Z0-9_]{0,127}$')
def parse_environment(raw:str)->dict[str,str]:
 values={}
 for line in raw.splitlines():
  stripped=line.strip()
  if not stripped or stripped.startswith('#'):continue
  if '=' not in line:raise ContractError('runtime Environment contains malformed assignment')
  key,value=line.split('=',1);key=key.strip()
  if not ENV_KEY.fullmatch(key) or key in values:raise ContractError('runtime Environment key is invalid or duplicate')
  values[key]=value
 return values
def prove(*,adapter:dict[str,Any],release_kind_name:str,manifest_path:Path,manifest_reference:str,source_sha:str,raw_environment:str)->dict[str,Any]:
 if not FULL_SHA.fullmatch(source_sha):raise ContractError('runtime proof source SHA is invalid')
 try:manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
 except (OSError,json.JSONDecodeError) as exc:raise ContractError('release manifest is unavailable or malformed') from exc
 validate(manifest,adapter,release_kind_name);kind=release_kind(adapter,release_kind_name)
 if manifest['source_sha']!=source_sha:raise ContractError('release manifest source differs from deploy source')
 match=DIGEST_REF.fullmatch(manifest_reference)
 if not match or match.group('repo')!=kind['manifest_package']:raise ContractError('immutable release-manifest reference is invalid')
 values=parse_environment(raw_environment)
 for variable,component in kind['compose_variables'].items():
  if values.get(variable)!=manifest['images'][component]:raise ContractError(f'runtime image input differs for {variable}')
 return {'source_sha':source_sha,'release_kind':release_kind_name,'manifest_reference':manifest_reference,'images':manifest['images'],'pointer_tags':kind['pointer_tags']}

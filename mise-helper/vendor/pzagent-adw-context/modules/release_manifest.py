"""Validate parameterized immutable release manifests."""
from __future__ import annotations
import re
from typing import Any
from .common import ContractError,FULL_SHA,IDENTIFIER
DIGEST_REF=re.compile(r'^(?P<repo>[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+)@sha256:(?P<digest>[0-9a-f]{64})$')
def release_kind(descriptor:Any,name:str)->dict[str,Any]:
    if not isinstance(descriptor,dict) or descriptor.get('schema_version')!='1.0.0' or not isinstance(descriptor.get('release_kinds'),dict): raise ContractError('release-kind descriptor is invalid')
    kinds=descriptor['release_kinds']
    if not isinstance(kinds,dict) or name not in kinds: raise ContractError('release kind is unsupported')
    value=kinds[name]
    if not isinstance(value,dict) or set(value)!={'schema','manifest_package','components','compose_variables','pointer_tags'}: raise ContractError('release-kind entry is not closed')
    components=value['components']; variables=value['compose_variables']
    if not isinstance(components,dict) or not components or not isinstance(variables,dict) or not variables: raise ContractError('release-kind component mapping is empty')
    if set(variables.values())!=set(components): raise ContractError('Compose variable mapping must cover the exact component set')
    for component,entry in components.items():
        if not IDENTIFIER.fullmatch(component) or not isinstance(entry,dict) or set(entry)!={'package'} or not isinstance(entry['package'],str) or not entry['package']: raise ContractError('release component descriptor is invalid')
    return value
def validate(manifest:Any,descriptor:Any,kind_name:str)->dict[str,Any]:
    kind=release_kind(descriptor,kind_name)
    if not isinstance(manifest,dict) or set(manifest)!={'schema','source_sha','source_tag','images'} or manifest.get('schema')!=kind['schema']: raise ContractError('release manifest schema is invalid')
    if not isinstance(manifest.get('source_sha'),str) or not FULL_SHA.fullmatch(manifest['source_sha']): raise ContractError('release source SHA must be full lowercase Git identity')
    if manifest.get('source_tag')!='sha-'+manifest['source_sha'][:12]: raise ContractError('release source tag differs from source SHA')
    images=manifest.get('images')
    if not isinstance(images,dict) or set(images)!=set(kind['components']): raise ContractError('release manifest component set is invalid')
    for name,reference in images.items():
        match=DIGEST_REF.fullmatch(reference) if isinstance(reference,str) else None
        if not match or match.group('repo')!=kind['components'][name]['package']: raise ContractError(f'immutable image reference is invalid for {name}')
    return manifest

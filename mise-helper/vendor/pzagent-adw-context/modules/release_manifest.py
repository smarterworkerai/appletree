"""Validate parameterized immutable release manifests."""
from __future__ import annotations
import re
from typing import Any
from .common import ContractError,FULL_SHA,IDENTIFIER
DIGEST_REF=re.compile(r'^(?P<repo>[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+)@sha256:(?P<digest>[0-9a-f]{64})$')
def image_variables(kind:dict[str,Any])->dict[str,str]:
    """Canonical image map with a strict legacy alias, never two authorities."""
    canonical=kind.get('image_variables');legacy=kind.get('compose_variables')
    if 'image_variables' in kind and 'compose_variables' in kind and canonical!=legacy:
        raise ContractError('image_variable_alias_conflict')
    value=canonical if 'image_variables' in kind else legacy
    if not isinstance(value,dict) or not value:raise ContractError('release-kind component mapping is empty')
    return value

def normalize_image_variables(kind:dict[str,Any])->dict[str,Any]:
    value=dict(kind);value['image_variables']=image_variables(kind);value.pop('compose_variables',None)
    return value

def release_kind(descriptor:Any,name:str)->dict[str,Any]:
    if not isinstance(descriptor,dict) or descriptor.get('schema_version')!='1.0.0' or not isinstance(descriptor.get('release_kinds'),dict): raise ContractError('release-kind descriptor is invalid')
    kinds=descriptor['release_kinds']
    if not isinstance(kinds,dict) or name not in kinds: raise ContractError('release kind is unsupported')
    value=kinds[name]
    required={'schema','manifest_package','components','pointer_tags'}
    if (not isinstance(value,dict) or not required<=set(value)
        or not set(value)<=required|{'publication_pointers','image_variables','compose_variables'}): raise ContractError('release-kind entry is not closed')
    pointers=value.get('publication_pointers',[])
    if (not isinstance(pointers,list) or len(pointers)>16 or len(pointers)!=len(set(pointers))
        or not all(isinstance(tag,str) and IDENTIFIER.fullmatch(tag) for tag in pointers)):
        raise ContractError('publication pointer allowlist is invalid')
    value=normalize_image_variables(value)
    components=value['components']; variables=value['image_variables']
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

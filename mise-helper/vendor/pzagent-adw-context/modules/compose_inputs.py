"""Bind Compose image variables to one verified immutable release."""
from __future__ import annotations
from typing import Any
from .common import ContractError
from .release_manifest import release_kind,validate
def validate_inputs(values:dict[str,str],manifest:Any,descriptor:Any,kind_name:str)->None:
    validated=validate(manifest,descriptor,kind_name); kind=release_kind(descriptor,kind_name)
    expected=set(kind['compose_variables'])
    relevant={k for k in values if k in expected}
    if relevant!=expected: raise ContractError('Compose image variable set is incomplete')
    for variable,component in kind['compose_variables'].items():
        if values[variable]!=validated['images'][component]: raise ContractError(f'Compose image input differs for {variable}')

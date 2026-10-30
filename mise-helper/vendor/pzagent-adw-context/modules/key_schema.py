"""Closed environment key schemas shared by configuration, observation and secrets (#193).

Two shapes are accepted:
- legacy: `{"keys": ["NAME", ...], "optional_keys": [...]}`;
- per key: `{"keys": {"NAME": {"source": ...}, "OTHER": {}}, "optional_keys": [...]}`,
  where each object declares where that key's value comes from (an empty object
  declares no source).
"""
from __future__ import annotations

import re

from .common import ContractError
from .operator_credentials import GENERATE_KINDS, VAULT_ID, VAULT_SCOPE

ENV_KEY = re.compile(r'^[A-Z][A-Z0-9_]{0,127}$')
# Any key a schema may list: environment names and Kubernetes ConfigMap data keys
# (mounted files such as `nginx.conf`); only sourced keys must be environment names.
DATA_KEY = re.compile(r'^[-._A-Za-z0-9]{1,253}$')


def contract(data, reason: str = 'key_schema_invalid') -> tuple[set[str], set[str], dict[str, dict]]:
    """(required, allowed, declared sources) of one key schema document; refuses anything else."""
    if not isinstance(data, dict) or set(data) not in ({'keys'}, {'keys', 'optional_keys'}):
        raise ContractError(reason)
    keys, optional = data.get('keys'), data.get('optional_keys', [])
    if isinstance(keys, dict):
        names, sources = list(keys), {name: entry for name, entry in keys.items() if entry}
        if any(not isinstance(entry, dict) for entry in keys.values()):
            raise ContractError(reason)
    elif isinstance(keys, list):
        names, sources = keys, {}
    else:
        raise ContractError(reason)
    if (not isinstance(optional, list) or len(names) != len(set(names)) or len(optional) != len(set(optional))
            or not set(optional) <= set(names)
            or any(not isinstance(name, str) or not DATA_KEY.fullmatch(name) for name in names)):
        raise ContractError(reason)
    return set(names) - set(optional), set(names), sources


def sources(raw: dict[str, dict], *, project: str, environment: str, images: set[str],
            explicit_ids: bool, reason: str = 'provider_environment_sources_invalid') -> dict[str, dict]:
    """Vault entries of the keys that declare `generate`, `human` or `shared` (#193).

    The same rules hold for Dokploy and Kubernetes, so one environment's targets share
    one collection: `generate` and `human` default to vault ID `<project>.<environment>.<KEY>`
    in vault `shared/<project>-<environment>`; with `explicit_ids` (several targets of one
    platform share the environment) they must name an `id`, so distinct targets never
    alias one value. `shared` names its vault ID; `release` marks an image variable.
    """
    result = {}
    for key, source in raw.items():
        kind = source.get('source')
        if not ENV_KEY.fullmatch(key):
            raise ContractError(reason)               # a sourced value becomes an environment entry
        if kind == 'release':
            if key not in images or set(source) != {'source'}:
                raise ContractError(reason)
            continue
        if key in images or kind not in {'generate', 'human', 'shared'}:
            raise ContractError(reason)
        allowed = {'shared': {'source', 'id'}, 'human': {'source', 'id', 'vault', 'description'},
                   'generate': {'source', 'id', 'vault', 'kind', 'length', 'description'}}[kind]
        if set(source) - allowed or (kind == 'shared' and 'id' not in source):
            raise ContractError(reason)
        if kind != 'shared' and explicit_ids and 'id' not in source:
            raise ContractError(f'provider_environment_source_id_required: {key} (several targets share {environment})')
        entry = {'source': kind, 'id': source.get('id', f'{project}.{environment}.{key}')}
        if kind != 'shared':
            entry['vault'] = source.get('vault', f'shared/{project}-{environment}')
            entry['description'] = str(source.get('description', f'{project} {environment} {key}'))[:200]
            if not isinstance(entry['vault'], str) or not VAULT_SCOPE.fullmatch(entry['vault']):
                raise ContractError(reason)
        if kind == 'generate':
            entry['kind'], entry['length'] = source.get('kind', 'password'), source.get('length')
            if entry['kind'] not in GENERATE_KINDS or (entry['length'] is not None and (
                    not isinstance(entry['length'], int) or isinstance(entry['length'], bool)
                    or not 16 <= entry['length'] <= 256)):
                raise ContractError(reason)
        if not isinstance(entry['id'], str) or not VAULT_ID.fullmatch(entry['id']):
            raise ContractError(reason)
        result[key] = entry
    return result

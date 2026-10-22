"""Resolve one value-free, versioned logical deployment target."""
from __future__ import annotations
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any
from .common import ContractError,IDENTIFIER,ensure_contained
from .providers import require as require_provider
@dataclass(frozen=True)
class LogicalTarget:
    environment:str; name:str; provider:str; mode:str
def parse_inventory(data:Any,environment:str)->dict[str,LogicalTarget]:
    if not IDENTIFIER.fullmatch(environment): raise ContractError('environment must be a bounded logical identifier')
    if not isinstance(data,dict) or set(data)!={'schema_version','environment','targets'} or data.get('schema_version')!='1.0.0' or data.get('environment')!=environment: raise ContractError('logical-target inventory identity is invalid')
    _validate_schema(data, _schema())
    raw=data.get('targets')
    if not isinstance(raw,dict) or not raw: raise ContractError('logical-target inventory is empty')
    targets={}
    for name,value in raw.items():
        if not isinstance(name,str) or not IDENTIFIER.fullmatch(name) or name in targets: raise ContractError('logical-target name is invalid or duplicate')
        if not isinstance(value,dict) or set(value)!={'provider','mode'} or not isinstance(value['provider'],str) or not value['provider'] or value['mode'] not in {'active','shadow'}: raise ContractError('logical-target properties are invalid')
        targets[name]=LogicalTarget(environment,name,value['provider'],value['mode'])
    return targets
def resolve(data:Any,environment:str,requested:str|None=None,*,providers:set[str]|None=None)->LogicalTarget:
    targets=parse_inventory(data,environment)
    if requested is None:
        active=[x for x in targets.values() if x.mode=='active']
        if len(active)!=1: raise ContractError('environment must declare exactly one active logical target')
        target=active[0]
    else:
        if not IDENTIFIER.fullmatch(requested) or requested not in targets: raise ContractError('requested logical target is not allowlisted')
        target=targets[requested]
    if target.mode!='active': raise ContractError('shadow target deployment is not enabled')
    require_provider(target.provider)
    if providers is not None and target.provider not in providers: raise ContractError('provider_unsupported')
    return target


def _schema() -> dict[str, Any]:
    return json.loads((Path(__file__).resolve().parents[1] / 'schemas/logical-targets.schema.json').read_text())


def _validate_schema(value: Any, schema: dict[str, Any]) -> None:
    """Evaluate this inventory schema's small, dependency-free JSON Schema dialect."""
    supported = {'$schema', 'type', 'properties', 'required', 'additionalProperties',
                 'minProperties', 'propertyNames', 'pattern', 'minLength', 'enum', 'const'}
    if set(schema) - supported:
        raise ContractError('logical-target schema uses an unsupported constraint')
    def refuse():
        raise ContractError('logical-target inventory does not satisfy its schema')
    if 'const' in schema and value != schema['const']: refuse()
    if 'enum' in schema and value not in schema['enum']: refuse()
    if schema.get('type') == 'object':
        if not isinstance(value, dict): refuse()
        if not set(schema.get('required', [])) <= set(value): refuse()
        if len(value) < schema.get('minProperties', 0): refuse()
        properties = schema.get('properties', {})
        additional = schema.get('additionalProperties', True)
        for key, child in value.items():
            if not isinstance(key, str): refuse()
            if 'propertyNames' in schema: _validate_schema(key, schema['propertyNames'])
            if key in properties: _validate_schema(child, properties[key])
            elif additional is False: refuse()
            elif isinstance(additional, dict): _validate_schema(child, additional)
    elif schema.get('type') == 'string' and not isinstance(value, str): refuse()
    if 'pattern' in schema and (not isinstance(value, str) or re.search(schema['pattern'], value) is None): refuse()
    if 'minLength' in schema and (not isinstance(value, str) or len(value) < schema['minLength']): refuse()


def _scalar(value: str) -> str:
    value = value.strip()
    if value.startswith(('"', "'")):
        if len(value) < 2 or value[-1] != value[0]:
            raise ContractError('inventory contains unsupported YAML structure')
        value = value[1:-1]
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', value):
        raise ContractError('inventory contains unsupported YAML structure')
    return value


def read_inventory(repo: Path, environment: str) -> dict[str, Any]:
    """Load the versioned closed mapping subset used by logical-target YAML files."""
    if not isinstance(environment, str) or not IDENTIFIER.fullmatch(environment):
        raise ContractError('environment must be a bounded logical identifier')
    path = ensure_contained(repo, 'infra/deployment-targets/' + environment + '.yml')
    if not path.is_file():
        raise ContractError('no versioned deployment target inventory exists for the environment')
    data: dict[str, Any] = {}
    current: str | None = None
    in_targets = False
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.split('#', 1)[0].rstrip()
        if not line: continue
        if '\t' in line: raise ContractError('inventory contains unsupported YAML structure')
        if not line.startswith(' ') and ':' in line:
            key, value = line.split(':', 1)
            if key in data: raise ContractError('inventory contains a duplicate property')
            if key == 'targets' and not value.strip():
                data[key] = {}; in_targets = True; current = None
            elif key in {'schema_version', 'environment'} and value.strip():
                data[key] = _scalar(value); in_targets = False; current = None
            else: raise ContractError('inventory contains unsupported YAML structure')
        elif in_targets and line.startswith('  ') and not line.startswith('   ') and line.endswith(':'):
            current = line.strip()[:-1]
            if not IDENTIFIER.fullmatch(current) or current in data['targets']:
                raise ContractError('inventory contains an invalid or duplicate logical target')
            data['targets'][current] = {}
        elif in_targets and line.startswith('    ') and not line.startswith('     ') and current and ':' in line:
            key, value = line.strip().split(':', 1)
            if key not in {'provider', 'mode'} or key in data['targets'][current] or not value.strip():
                raise ContractError('inventory contains an invalid target property')
            data['targets'][current][key] = _scalar(value)
        else: raise ContractError('inventory contains unsupported YAML structure')
    parse_inventory(data, environment)
    return data


def load(repo: Path, environment: str, requested: str | None = None) -> LogicalTarget:
    return resolve(read_inventory(repo, environment), environment, requested)

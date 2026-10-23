"""Opt-in public-route source identity, independent of container identity and CI authority."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from .common import ContractError, FULL_SHA, project_dir
from .http_probe import ProbeError, fetch

KEY = re.compile(r'^[A-Z][A-Z0-9_]{0,127}$')


def declaration(repo: Path, adapter: dict, target: str) -> dict | None:
    path = project_dir(repo) / 'routed-content.json'
    if not path.exists() and not path.is_symlink():
        return None
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise ValueError()
        value = json.loads(path.read_bytes())
        if (not isinstance(value, dict) or set(value) != {'schema_version', 'targets'}
                or value['schema_version'] != '1.0.0' or not isinstance(value['targets'], dict)):
            raise ValueError()
        targets = {name: item for group in adapter.get('targets', {}).values()
                   for name, item in group['items'].items()}
        for name, probe in value['targets'].items():
            if (name not in targets or not isinstance(probe, dict) or set(probe) != {'path', 'base_url_env'}
                    or not isinstance(probe['path'], str) or not re.fullmatch(r'/[A-Za-z0-9._/-]{1,255}', probe['path'])
                    or probe['path'].startswith('//') or '..' in probe['path'].split('/')
                    or not isinstance(probe['base_url_env'], str) or not KEY.fullmatch(probe['base_url_env'])):
                raise ValueError()
            # Reuse only the already-declared probe input; this file expands no credential allow-list.
            from .providers import binding_for
            binding = binding_for(adapter, targets[name])
            if probe['base_url_env'] != (binding.get('probes', {}).get('base_url_env') or binding.get('ingress_probe_base')):
                raise ValueError()
        return value['targets'].get(target)
    except (OSError, ValueError, KeyError, TypeError):
        raise ContractError('routed_content_contract_invalid') from None


def verify(repo: Path, adapter: dict, target: str, source_sha: str, *, environ=None) -> dict:
    probe = declaration(repo, adapter, target)
    if probe is None:
        return {'status': 'disabled'}
    if not isinstance(source_sha, str) or not FULL_SHA.fullmatch(source_sha):
        raise ContractError('routed_content_source_invalid')
    source = os.environ if environ is None else environ
    base = source.get(probe['base_url_env'], '')
    try:
        parts = urlsplit(base)
        if (parts.scheme not in {'http', 'https'} or not parts.hostname or parts.username or parts.password
                or parts.path not in {'', '/'} or parts.query or parts.fragment):
            raise ValueError()
        response = fetch(base.rstrip('/') + probe['path'], max_bytes=4096)
        if response.status != 200 or response.content_type != 'application/json':
            raise ValueError()
        value = json.loads(response.body)
        if value != {'source_sha': source_sha}:
            raise ValueError()
    except (ProbeError, ValueError, TypeError):
        raise ContractError('routed_content_identity_unproven') from None
    return {'status': 'passed', 'source_sha': source_sha}

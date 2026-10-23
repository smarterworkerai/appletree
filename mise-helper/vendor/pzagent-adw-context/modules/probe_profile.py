"""Load declared runtime probe base URLs from the private operator profile."""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from .common import ContractError
from .operator_credentials import private_profile_path

PROFILE_FILE = 'probes.json'
MAX_BYTES = 65536
MAX_VALUE = 2048
ENV_KEY = re.compile(r'^[A-Z][A-Z0-9_]{0,127}$')


def declared_keys(adapter: Mapping[str, Any]) -> set[str]:
    """Exactly the probe environment keys the adapter bindings declare."""
    keys = set()
    for provider, settings in (adapter.get('providers') or {}).items():
        bindings = settings.get('bindings') if isinstance(settings, Mapping) else None
        for binding in (bindings or {}).values():
            if not isinstance(binding, Mapping):
                continue
            probes = binding.get('probes')
            if isinstance(probes, Mapping):
                keys.update(value for name, value in probes.items() if name.endswith('_env') and isinstance(value, str))
            if provider == 'kubernetes' and isinstance(binding.get('ingress_probe_base'), str):
                keys.add(binding['ingress_probe_base'])
    return {key for key in keys if ENV_KEY.fullmatch(key)}


def load(profile_root: Path, keys: set[str]) -> dict[str, str]:
    """Values of the allowed keys from <profile>/probes.json; values are never reported."""
    if not keys:
        return {}
    try:
        path = private_profile_path(profile_root, profile_root / PROFILE_FILE)
        if not path.exists():
            return {}
        status = path.stat()
        if not path.is_file() or stat.S_IMODE(status.st_mode) & 0o077 or status.st_size > MAX_BYTES:
            raise ContractError('probe_profile_not_private')
        document = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ContractError('probe_profile_invalid') from exc
    if not isinstance(document, dict) or not all(isinstance(key, str) for key in document):
        raise ContractError('probe_profile_invalid')
    selected = {key: document[key] for key in sorted(keys) if key in document}
    if any(not isinstance(value, str) or not value or len(value) > MAX_VALUE or '\x00' in value
           for value in selected.values()):
        raise ContractError('probe_profile_value_invalid')
    return selected


@contextmanager
def probe_environment(adapter: Mapping[str, Any], profile_root: Path | None):
    """Expose profile probe URLs for declared keys the environment does not set; restore afterwards."""
    keys = {key for key in declared_keys(adapter) if not os.environ.get(key)}
    loaded = load(profile_root, keys) if profile_root is not None else {}
    previous = {key: os.environ.get(key) for key in loaded}
    try:
        os.environ.update(loaded)
        yield sorted(loaded)
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

"""Probe base URLs from the provider/environment URL templates in the vault (#193)."""
from __future__ import annotations

from contextlib import contextmanager
import os
from typing import Any, Mapping
from urllib.parse import urlsplit

from .common import ContractError
from .operator_credentials import vault_values, CREDENTIAL_FREE
from .adapter import probe_url_key

MAX_VALUE = 2048


def _origin(template: str, app: str) -> str:
    if not isinstance(template, str) or len(template) > MAX_VALUE:
        raise ContractError('probe_url_template_invalid')
    value = template.replace('{app}', app)
    try:
        parts = urlsplit(value)
        if (len(value) > MAX_VALUE or any(char in value for char in '{}\x00\r\n') or parts.scheme not in {'http', 'https'}
                or not parts.hostname or parts.username or parts.password
                or parts.path not in {'', '/'} or parts.query or parts.fragment):
            raise ValueError()
    except ValueError:
        raise ContractError('probe_url_template_invalid') from None
    return value.rstrip('/')


@contextmanager
def probe_environment(adapter: Mapping[str, Any], *, environment: str | None = None, target: str | None = None,
                      use_templates: bool = True):
    """Expand the selected bindings' provider URL templates (`{app}`) or literal `base_url`.

    An explicit process value of the template key wins; nothing is read from files.
    """
    if os.environ.get(CREDENTIAL_FREE) == '1':
        yield []
        return
    selected = set()
    groups = adapter.get('targets', {})
    for name, group in groups.items():
        if environment is not None and name != environment:
            continue
        for alias, declaration in group.get('items', {}).items():
            if target is not None and alias != target:
                continue
            if environment is not None and target is None and alias != group.get('default'):
                continue
            selected.add((declaration.get('provider'), declaration.get('provider_binding')))
    bindings = []
    for provider, settings in (adapter.get('providers') or {}).items():
        if not isinstance(settings, Mapping):
            continue
        for name, binding in settings.get('bindings', {}).items():
            if (environment is not None or target is not None) and (provider, name) not in selected:
                continue
            probes = binding.get('probes', {})
            key = probes.get('base_url_env') or binding.get('ingress_probe_base')
            if key:
                bindings.append((provider, binding, probes, key))
    app = adapter.get('repository', {}).get('id', '').rsplit('/', 1)[-1]
    requested = set()
    for provider, binding, probes, key in bindings:
        if use_templates and not os.environ.get(key) and not probes.get('base_url') and binding.get('environment'):
            template_key = probe_url_key(provider, binding['environment'])
            if not os.environ.get(template_key):
                requested.add(template_key)
    templates = vault_values(requested, dict(os.environ)) if use_templates else {}
    loaded = {}
    for provider, binding, probes, key in bindings:
        template_key = probe_url_key(provider, binding['environment']) if binding.get('environment') else None
        value = (os.environ.get(key) or probes.get('base_url')
                 or (os.environ.get(template_key) or templates.get(template_key) if template_key else None))
        if value and use_templates:
            expanded = _origin(value, app)
            if os.environ.get(key) != expanded:
                loaded[key] = expanded
            else:
                loaded.pop(key, None)
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

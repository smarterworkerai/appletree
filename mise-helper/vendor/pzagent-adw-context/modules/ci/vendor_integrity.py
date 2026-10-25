"""Trusted CI decision: the vendored provider bundle and generic layer equal their pins.

Only trusted code runs here. `bundle.json` is itself a trusted path, so its inventory,
which also covers the generic pin `generic-release.json`, changes only through an
administrator decision or an exact released-vendor repin. Every other vendored file is
then bound by that inventory, so an edited checker or data file fails before quality runs.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from ..bundle import DESCRIPTOR, validate_bundle
from ..common import ContractError, load_json, project_dir
from .generic_release import GENERIC_PIN, check_generic_layer, validate_generic_pin

VENDOR = Path('mise-helper/vendor/pzagent-adw-context')
LOCK = 'pzagent-context-lock.json'
MANIFEST = 'adw-task-manifest.json'


def check(repo: Path) -> dict[str, Any]:
    vendor = repo / VENDOR
    descriptor = validate_bundle(vendor)
    digest = hashlib.sha256((vendor / DESCRIPTOR).read_bytes()).hexdigest()
    lock = load_json(project_dir(repo) / LOCK)
    if (not isinstance(lock, dict) or lock.get('bundle_sha256') != digest
            or lock.get('package_version') != descriptor['version']):
        raise ContractError('vendor_lock_differs_from_bundle: the context lock does not record the vendored'
                            ' bundle; repin with adw:context:sync')
    pin = validate_generic_pin(load_json(vendor / GENERIC_PIN))
    generic = check_generic_layer(repo, load_json(project_dir(repo) / MANIFEST), pin, descriptor['version'])
    return {'status': 'passed', 'bundle_version': descriptor['version'], 'bundle_sha256': digest,
            'generic': generic}

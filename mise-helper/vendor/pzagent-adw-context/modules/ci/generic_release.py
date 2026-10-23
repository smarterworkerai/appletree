"""The agentic-delivery release a provider release pins (bundle file generic-release.json).

One closed document shared by context sync, the consumer context check and the
released-vendor trust-root decision: release identity plus every runtime file's
SHA-256 and mode.
"""
from __future__ import annotations

import re

from .quality_proof import ProofError

GENERIC = 'smarterworkerai/agentic-delivery'
GENERIC_VENDOR = 'mise-helper/vendor/agentic-delivery/'
GENERIC_PIN = 'generic-release.json'
PIN_KEYS = {'schema_version', 'repository', 'version', 'source_sha', 'snapshot_ref', 'archive_sha256', 'files'}
SHA = re.compile(r'[0-9a-f]{40}')
SHA256 = re.compile(r'[0-9a-f]{64}')
VERSION = re.compile(r'2\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)')


def _require(value, reason):
    if not value:
        raise ProofError(reason)


def _safe_name(value):
    return (isinstance(value, str) and value and not value.startswith('/') and '\\' not in value
            and all(part not in ('', '.', '..') for part in value.split('/')))


def validate_generic_pin(pin):
    _require(isinstance(pin, dict) and set(pin) == PIN_KEYS and pin['schema_version'] == '1.0.0'
             and pin['repository'] == GENERIC, 'generic_pin_invalid')
    _require(isinstance(pin['version'], str) and VERSION.fullmatch(pin['version']), 'generic_pin_version_incompatible')
    _require(all(isinstance(pin[key], str) and SHA.fullmatch(pin[key]) for key in ('source_sha', 'snapshot_ref'))
             and isinstance(pin['archive_sha256'], str) and SHA256.fullmatch(pin['archive_sha256']),
             'generic_pin_identity_invalid')
    files = pin['files']
    _require(isinstance(files, dict) and {'adw_contract.py', 'tasks.toml'} <= set(files) and len(files) <= 256
             and all(_safe_name(name) and isinstance(entry, dict) and set(entry) == {'sha256', 'mode'}
                     and isinstance(entry['sha256'], str) and SHA256.fullmatch(entry['sha256'])
                     and entry['mode'] in ('100644', '100755') for name, entry in files.items()),
             'generic_pin_inventory_invalid')
    return pin


def generic_source(pin):
    """The manifest generic source record of a consumer that vendors the pinned release."""
    return {'layer': 'generic', 'ref': pin['snapshot_ref'], 'path': GENERIC_VENDOR + 'tasks.toml',
            'checksum': 'sha256:' + pin['files']['tasks.toml']['sha256']}

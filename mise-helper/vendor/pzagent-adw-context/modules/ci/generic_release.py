"""The agentic-delivery release a provider release pins (bundle file generic-release.json).

One closed document shared by context sync, the consumer context check and the
released-vendor trust-root decision: release identity plus every runtime file's
SHA-256 and mode.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..common import ContractError, ensure_contained, sha256_file
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


def generic_vendor_matches(repo: Path, pin) -> bool:
    """The vendored generic layer holds exactly the pinned release's runtime files, byte for byte."""
    root = repo / GENERIC_VENDOR
    if not root.is_dir() or root.is_symlink():
        return False
    actual = {path.relative_to(root).as_posix() for path in root.rglob('*')
              if not path.is_dir() and '__pycache__' not in path.parts}
    if actual != set(pin['files']):
        return False
    for name, entry in pin['files'].items():
        path = ensure_contained(root, name)
        if path.is_symlink() or not path.is_file() or sha256_file(path) != entry['sha256']:
            return False
        if ('100755' if path.stat().st_mode & 0o111 else '100644') != entry['mode']:
            return False
    return True


def generic_source_id(manifest) -> str:
    sources = manifest.get('sources') if isinstance(manifest, dict) else None
    ids = [key for key, value in (sources or {}).items() if isinstance(value, dict) and value.get('layer') == 'generic']
    if len(ids) != 1:
        raise ContractError('manifest generic source is missing or ambiguous')
    return ids[0]


def check_generic_layer(repo: Path, manifest, pin, bundle_version: str) -> dict:
    """Generic layer, manifest source and contract version must equal the bundle's pinned release."""
    hint = (f'run `mise run adw:context:sync -- v{bundle_version} <bundle-sha256>` again;'
            ' a 0.15.9 or older updater updates only the context layer on its first run')
    if not generic_vendor_matches(repo, pin):
        raise ContractError(f"generic_layer_differs_from_pin: the vendored agentic-delivery files differ from"
                            f" the pinned v{pin['version']}; {hint}")
    if manifest['sources'][generic_source_id(manifest)] != generic_source(pin) \
            or manifest.get('schema_version') != pin['version'] or manifest['contract'].get('version') != pin['version']:
        raise ContractError(f"generic_manifest_differs_from_pin: the manifest does not record agentic-delivery"
                            f" v{pin['version']}; {hint}")
    return {'status': 'passed', 'version': pin['version'], 'ref': pin['snapshot_ref']}


def generic_source(pin):
    """The manifest generic source record of a consumer that vendors the pinned release."""
    return {'layer': 'generic', 'ref': pin['snapshot_ref'], 'path': GENERIC_VENDOR + 'tasks.toml',
            'checksum': 'sha256:' + pin['files']['tasks.toml']['sha256']}

"""Signed provider release statements (#181).

The release workflow signs one canonical statement per published release: identity,
tag commit, bundle descriptor checksum, the release's trusted-path set and the git blob
SHAs of its release-owned trusted files (so a controller compares blobs from one tree
read instead of downloading files). Consumers
vendor the statement and signature next to the context lock; the default-branch
controller verifies them offline against its own `release_signers`, so no provider
token or provider read is needed.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from .quality_proof import ProofError

NAMESPACE = 'pzagent-release'
IDENTITY = 'pzagent-adw-context-release'
SCHEMA = 'pzagent-release-statement/v1'
REPOSITORY = 'smarterworkerai/pzagent-adw-context'
RECORD = 'pzagent-context-release.json'
SIGNERS = 'modules/ci/release_signers'
STATEMENT_ASSET = 'pzagent-release-statement.json'
SIGNATURE_ASSET = STATEMENT_ASSET + '.sig'
KEYS = {'schema', 'repository', 'version', 'tag', 'commit', 'bundle_sha256', 'trusted_paths', 'blobs'}
VENDOR_PREFIX = 'mise-helper/vendor/pzagent-adw-context/'
WORKFLOW_DIR = '.github/workflows/'
GENERIC_PIN = 'generic-release.json'
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)')
SHA = re.compile(r'[0-9a-f]{40}')
SHA256 = re.compile(r'[0-9a-f]{64}')
ARMOR = re.compile(r'-----BEGIN SSH SIGNATURE-----\n[A-Za-z0-9+/=\n]{1,8192}-----END SSH SIGNATURE-----\n?')
MAX_STATEMENT = 49152


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def _trusted_path(value) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= 512 and not value.startswith('/')
            and '\\' not in value and '..' not in value.split('/') and value.strip() == value)


def blob_paths(trusted_paths) -> set[str]:
    """Bundle-relative files whose git blob SHAs a statement may sign."""
    paths = {GENERIC_PIN}
    for path in trusted_paths:
        if path.startswith(VENDOR_PREFIX):
            paths.add(path.removeprefix(VENDOR_PREFIX))
        elif path.startswith(WORKFLOW_DIR) and '/' not in path.removeprefix(WORKFLOW_DIR):
            paths.add('templates/github/' + path.removeprefix(WORKFLOW_DIR))
    return paths


def release_blobs(snapshot: dict, trusted_paths) -> dict:
    """Select the signed blobs from a {bundle-relative path: blob SHA} map of the tagged tree."""
    wanted = blob_paths(trusted_paths)
    return {path: blob for path, blob in snapshot.items() if path in wanted}


def statement_bytes(*, repository: str, version: str, commit: str, bundle_sha256: str,
                    trusted_paths, blobs) -> bytes:
    """The exact bytes the release workflow signs and consumers vendor."""
    raw = _canonical({'schema': SCHEMA, 'repository': repository, 'version': version,
                      'tag': 'v' + str(version), 'commit': commit, 'bundle_sha256': bundle_sha256,
                      'trusted_paths': list(trusted_paths), 'blobs': dict(blobs)})
    parse_statement(raw)
    return raw


def parse_statement(raw: bytes) -> dict:
    """Strictly validate a statement; only its canonical encoding is accepted."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_STATEMENT:
        raise ProofError('release_statement_invalid')
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProofError('release_statement_invalid') from None
    paths = value.get('trusted_paths') if isinstance(value, dict) else None
    blobs = value.get('blobs') if isinstance(value, dict) else None
    if (not isinstance(value, dict) or set(value) != KEYS or value['schema'] != SCHEMA
            or value['repository'] != REPOSITORY
            or not isinstance(value['version'], str) or not VERSION.fullmatch(value['version'])
            or value['tag'] != 'v' + value['version']
            or not isinstance(value['commit'], str) or not SHA.fullmatch(value['commit'])
            or not isinstance(value['bundle_sha256'], str) or not SHA256.fullmatch(value['bundle_sha256'])
            or not isinstance(paths, list) or not paths or len(paths) > 1024
            or not all(_trusted_path(path) for path in paths) or len(set(paths)) != len(paths)
            or not isinstance(blobs, dict) or not set(blobs) <= blob_paths(paths)
            or not all(isinstance(blob, str) and SHA.fullmatch(blob) for blob in blobs.values())
            or _canonical(value) != raw):
        raise ProofError('release_statement_invalid')
    return value


def _ssh_keygen(args: list[str], data: bytes) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(['ssh-keygen', *args], input=data, capture_output=True,
                              check=False, timeout=30, env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                                                            'LC_ALL': 'C'})
    except (OSError, subprocess.TimeoutExpired):
        raise ProofError('release_signature_unavailable') from None


def sign(raw: bytes, key: Path) -> str:
    """Sign a statement with an OpenSSH private key (release workflow and tests only)."""
    parse_statement(raw)
    result = _ssh_keygen(['-q', '-Y', 'sign', '-n', NAMESPACE, '-f', str(key)], raw)
    signature = result.stdout.decode('ascii', 'replace')
    if result.returncode or not ARMOR.fullmatch(signature):
        raise ProofError('release_signature_failed')
    return signature


def verify(raw: bytes, signature: str, signers: Path) -> dict:
    """Return the statement when a key in `signers` signed exactly these bytes."""
    statement = parse_statement(raw)
    if not isinstance(signature, str) or not ARMOR.fullmatch(signature):
        raise ProofError('release_signature_invalid')
    if not signers.is_file() or signers.is_symlink():
        raise ProofError('release_signers_missing')
    with tempfile.TemporaryDirectory(prefix='.release-signature-') as temporary:
        path = Path(temporary) / 'statement.sig'
        path.write_text(signature, encoding='ascii')
        result = _ssh_keygen(['-Y', 'verify', '-f', str(signers), '-I', IDENTITY, '-n', NAMESPACE,
                              '-s', str(path)], raw)
    if result.returncode:
        raise ProofError('release_signature_invalid')
    return statement


def record(raw: bytes, signature: str) -> dict:
    """The consumer file `<project dir>/pzagent-context-release.json`."""
    parse_statement(raw)
    if not isinstance(signature, str) or not ARMOR.fullmatch(signature):
        raise ProofError('release_signature_invalid')
    return {'schema_version': '1.0.0', 'statement': raw.decode(), 'signature': signature}


def load_record(data: bytes) -> tuple[bytes, str]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        raise ProofError('release_record_invalid') from None
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'statement', 'signature'}
            or value['schema_version'] != '1.0.0' or not isinstance(value['statement'], str)
            or not isinstance(value['signature'], str)):
        raise ProofError('release_record_invalid')
    return value['statement'].encode(), value['signature']

"""Shared, tool-neutral ACME certificate cache: <root>/<domain>/<environment>/.

The same layout as smarterworkerai/devbox#27: certificate.pem (chain), private-key.pem,
account-key.pem (ACME account) and metadata.json, directories 0700 and files 0600 under
${XDG_STATE_HOME:-~/.local/state}/acme-cache. It is keyed by wildcard domain and Let's
Encrypt environment, never by cluster alias, so a renamed cluster reuses it while another
domain or environment can never pick up a foreign certificate. Key material is read and
written only by this process; it is never printed, logged or returned in a receipt, and
reasons never name the domain.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .common import ContractError

SERVERS = {'production': 'https://acme-v02.api.letsencrypt.org/directory',
           'staging': 'https://acme-staging-v02.api.letsencrypt.org/directory'}
FILES = {'certificate.pem', 'private-key.pem', 'account-key.pem', 'metadata.json'}
MINIMUM_DAYS = 30
DOMAIN = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}')


def _state_root() -> Path:
    return Path(os.environ.get('XDG_STATE_HOME') or str(Path.home() / '.local/state'))


def directory(domain: str, environment: str) -> Path:
    if environment not in SERVERS or not isinstance(domain, str) or len(domain) > 253 or not DOMAIN.fullmatch(domain):
        raise ContractError('acme_cache_selection_invalid')
    return _state_root() / 'acme-cache' / domain / environment


def _private_directory(path: Path, *, create: bool) -> bool:
    """A real, owner-only directory (never a link); created 0700 when asked. False if absent."""
    if path.is_symlink():
        raise ContractError('acme_cache_path_unsafe')
    if not path.exists():
        if not create:
            return False
        path.mkdir(mode=0o700)
    status = path.lstat()
    if not path.is_dir() or status.st_uid != os.getuid() or status.st_mode & 0o077:
        raise ContractError('acme_cache_path_unsafe')
    return True


def _chain(domain: str, environment: str, *, create: bool) -> Path | None:
    """Check every component from the cache root down; the state root itself is the user's."""
    target = directory(domain, environment)
    state = _state_root()
    if create:
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state.is_symlink():
        raise ContractError('acme_cache_path_unsafe')
    for path in (state / 'acme-cache', target.parent):
        if not _private_directory(path, create=create):
            return None
    return target


@contextmanager
def _locked(domain_directory: Path, environment: str):
    lock = domain_directory / ('.lock-' + environment)
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _recover(target: Path, environment: str) -> None:
    """Under the entry lock: finish or undo a publication that a crash or kill interrupted.

    The previous entry is moved aside only for the instant before the new one takes its
    place. If the process died in between, the moved-aside entry is restored; if the new
    entry is in place, the leftover is discarded. Stray candidate directories are removed.
    """
    backup = target.parent / ('.previous.' + environment)
    if backup.is_symlink():
        raise ContractError('acme_cache_path_unsafe')
    if backup.exists():
        _private_directory(backup, create=False)
        if _private_directory(target, create=False):
            shutil.rmtree(backup)
        else:
            backup.rename(target)
    # Only this environment's candidates: another environment's export may be in progress.
    for stray in target.parent.glob('.export.' + environment + '.*'):
        if stray.is_dir() and not stray.is_symlink():
            shutil.rmtree(stray)


def _openssl(arguments: list[str], data: bytes) -> subprocess.CompletedProcess:
    return subprocess.run(['openssl', *arguments], input=data, capture_output=True, timeout=30)


def _check(domain: str, environment: str, certificate: bytes, private_key: bytes,
           account_key: bytes | None, minimum_days: int) -> str:
    """Return the certificate's notAfter, or raise with the reason the cache is unusable."""
    if shutil.which('openssl') is None:
        raise ContractError('openssl unavailable')
    if _openssl(['x509', '-noout', '-checkend', str(minimum_days * 86400)], certificate).returncode:
        raise ContractError(f'expires within {minimum_days} days')
    details = _openssl(['x509', '-noout', '-issuer', '-enddate', '-ext', 'subjectAltName'], certificate)
    if details.returncode:
        raise ContractError('certificate unreadable')
    lines = details.stdout.decode(errors='replace').splitlines()
    names = sorted(token.strip()[4:] for line in lines for token in line.split(',') if token.strip().startswith('DNS:'))
    issuer = next((line for line in lines if line.startswith('issuer=')), '')
    if names != ['*.' + domain]:
        raise ContractError('does not cover exactly the profile wildcard')
    if "Let's Encrypt" not in issuer or ('STAGING' in issuer.upper()) != (environment == 'staging'):
        raise ContractError("not issued by Let's Encrypt " + environment)
    public = _openssl(['x509', '-noout', '-pubkey'], certificate).stdout
    if not public or _openssl(['pkey', '-pubout'], private_key).stdout != public:
        raise ContractError('private key does not match the certificate')
    if account_key is not None and _openssl(['pkey', '-noout'], account_key).returncode:
        raise ContractError('account key invalid')
    return next((line.split('=', 1)[1] for line in lines if line.startswith('notAfter=')), '')


def _read(target: Path, domain: str, environment: str, minimum_days: int) -> dict:
    if not _private_directory(target, create=False):
        raise ContractError('no cache')
    entries = {entry.name: entry for entry in target.iterdir()}
    for entry in entries.values():
        if (entry.name not in FILES or entry.is_symlink() or not entry.is_file()
                or entry.lstat().st_mode & 0o077 or entry.lstat().st_uid != os.getuid()):
            raise ContractError('unexpected or unsafe cache entry')
    if not {'certificate.pem', 'private-key.pem', 'metadata.json'} <= set(entries):
        raise ContractError('cache incomplete')
    try:
        metadata = json.loads(entries['metadata.json'].read_text())
    except (ValueError, UnicodeError) as exc:
        raise ContractError('metadata invalid') from exc
    if not isinstance(metadata, dict) or (metadata.get('wildcard'), metadata.get('environment')) != ('*.' + domain, environment):
        raise ContractError('metadata does not match the profile wildcard and environment')
    certificate = entries['certificate.pem'].read_bytes()
    private_key = entries['private-key.pem'].read_bytes()
    account_key = entries['account-key.pem'].read_bytes() if 'account-key.pem' in entries else None
    not_after = _check(domain, environment, certificate, private_key, account_key, minimum_days)
    return {'certificate': certificate, 'private_key': private_key, 'account_key': account_key, 'not_after': not_after}


def load(domain: str, environment: str, *, minimum_days: int = MINIMUM_DAYS,
         recover: bool = True) -> tuple[dict | None, str]:
    """A usable cached certificate for exactly *.<domain> in <environment>, or None and why.

    recover=False is the read-only form for plans: it never repairs an interrupted publication.
    """
    try:
        target = _chain(domain, environment, create=False)
        if target is None:
            return None, 'no cache'
        if not recover:
            return _read(target, domain, environment, minimum_days), 'cache'
        with _locked(target.parent, environment):
            _recover(target, environment)
            return _read(target, domain, environment, minimum_days), 'cache'
    except ContractError as exc:
        return None, str(exc)
    except OSError:
        return None, 'cache unreadable'


def export(domain: str, environment: str, certificate: bytes, private_key: bytes,
           account_key: bytes | None) -> str:
    """Atomically replace the cache entry; the previous entry survives any failure."""
    not_after = _check(domain, environment, certificate, private_key, account_key, 0)
    target = _chain(domain, environment, create=True)
    with _locked(target.parent, environment):
        _recover(target, environment)
        candidate = Path(tempfile.mkdtemp(prefix='.export.' + environment + '.', dir=target.parent))
        backup = target.parent / ('.previous.' + environment)
        try:
            files = {'certificate.pem': certificate, 'private-key.pem': private_key}
            if account_key is not None:
                files['account-key.pem'] = account_key
            files['metadata.json'] = (json.dumps({
                'schema_version': '1.0.0', 'domain': domain, 'wildcard': '*.' + domain, 'environment': environment,
                'acme_server': SERVERS[environment], 'not_after': not_after,
                'exported_by': 'smarterworkerai/pzagent-adw-context',
                'exported_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}, indent=1) + '\n').encode()
            for name, data in files.items():
                with open(os.open(candidate / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as handle:
                    handle.write(data)
            had_previous = _private_directory(target, create=False)
            if had_previous:
                target.rename(backup)
            try:
                candidate.rename(target)
            except OSError:
                if had_previous:
                    backup.rename(target)
                raise
            if had_previous:
                shutil.rmtree(backup)
        finally:
            shutil.rmtree(candidate, ignore_errors=True)
    return not_after


def purge(domain: str, environment: str) -> bool:
    target = _chain(domain, environment, create=False)
    if target is None:
        return False
    with _locked(target.parent, environment):
        _recover(target, environment)
        if not _private_directory(target, create=False):
            return False
        shutil.rmtree(target)
    return True

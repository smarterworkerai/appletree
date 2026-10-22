"""Technology-neutral local build payload identity and integrity checks.

These files describe outputs, never quality or CI authorization. CI callers must
separately establish the producer/run/attempt and its successful required gates.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat

from .common import ContractError
from .operator_state import read, write


def inventory(directory: Path) -> list[dict]:
    if directory.is_symlink() or not directory.is_dir():
        raise ContractError('build payload directory is missing or linked')
    entries = []
    for path in sorted(directory.rglob('*')):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError('build payload must contain regular files, not links or special files')
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        entries.append({'path': path.relative_to(directory).as_posix(),
                        'sha256': digest.hexdigest(), 'size': metadata.st_size,
                        'mode': stat.S_IMODE(metadata.st_mode)})
    if not entries:
        raise ContractError('build payload is empty')
    return entries


def seal(directory: Path, identity: dict) -> dict:
    result = {'schema_version': '1.0.0', 'identity': identity,
              'files': inventory(directory / 'payload')}
    write(directory / 'outputs.json', result)
    return result


def verify(directory: Path, identity: dict) -> dict:
    if (directory.is_symlink() or not directory.is_dir()
            or (directory / 'outputs.json').is_symlink() or not (directory / 'outputs.json').is_file()):
        raise ContractError('build output descriptor must not be linked')
    result = read(directory / 'outputs.json')
    if set(result) != {'schema_version', 'identity', 'files'} or result['identity'] != identity:
        raise ContractError('build output source, role, recipe or platform differs')
    if result['files'] != inventory(directory / 'payload'):
        raise ContractError('build output files, modes or content changed')
    return result

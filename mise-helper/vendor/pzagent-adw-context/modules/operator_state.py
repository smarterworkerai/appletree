"""Private local operation records; atomic writes, no credentials or provider env."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import tempfile
from uuid import uuid4

from .common import ContractError, load_json


def write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ContractError('operation state must not be a symlink')
    fd, temporary = tempfile.mkstemp(prefix='.result-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def new_operation(repo: Path) -> Path:
    path = repo / 'handover' / ('release-' + uuid4().hex)
    path.mkdir(parents=True, mode=0o700)
    return path


@contextmanager
def locked(directory: Path):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / '.lock'
    if path.is_symlink():
        raise ContractError('operation lock must not be a symlink')
    with path.open('a+b') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ContractError('operation is already running') from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def read(path: Path) -> dict:
    value = load_json(path)
    if not isinstance(value, dict) or value.get('schema_version') != '1.0.0':
        raise ContractError('invalid operation record')
    return value

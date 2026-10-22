"""Portable file payload transport; no release or quality authorization."""
import gzip
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile

from .build_outputs import inventory
from .common import ContractError

MAX_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILES = 20000


def pack(directory: Path, destination: Path) -> None:
    files = inventory(directory)
    if destination.exists() or destination.is_symlink():
        raise ContractError('build archive destination already exists')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w|') as archive:
                for item in files:
                    path = directory / item['path']
                    member = tarfile.TarInfo(item['path'])
                    member.size = item['size']; member.mode = item['mode']; member.mtime = 0
                    with path.open('rb') as source:
                        archive.addfile(member, source)


def unpack(archive_path: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise ContractError('build import destination already exists')
    destination.parent.mkdir(parents=True, exist_ok=True)
    total = 0; seen = set()
    with tempfile.TemporaryDirectory(prefix='.build-import-', dir=destination.parent) as temporary:
        staging = Path(temporary)
        try:
            with tarfile.open(archive_path, 'r:gz') as archive:
                for member in archive:
                    relative = PurePosixPath(member.name)
                    if (relative.is_absolute() or '..' in relative.parts or not relative.parts
                            or relative.as_posix() != member.name or '\\' in member.name
                            or not member.isfile() or member.name in seen or member.size < 0):
                        raise ContractError('build archive contains unsupported paths or entries')
                    seen.add(member.name); total += member.size
                    if len(seen) > MAX_FILES or total > MAX_BYTES:
                        raise ContractError('build archive exceeds import limits')
                    target = staging / member.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.extractfile(member) as source, target.open('xb') as output:
                        shutil.copyfileobj(source, output)
                    target.chmod(member.mode & 0o777)
        except (tarfile.TarError, EOFError, OSError) as exc:
            raise ContractError('build archive could not be imported') from exc
        if not seen:
            raise ContractError('build archive is empty')
        staging.rename(destination)

"""Keep consumer workflows byte-identical to the pinned bundle templates."""
from __future__ import annotations
import os
from pathlib import Path
import tempfile
from .common import ContractError

WORKFLOWS = ('ci.yml', 'trust-root-bootstrap.yml', 'publish-release.yml', 'cleanup-retention.yml')


def sync(repo: Path, *, check: bool = False, bundle: Path | None = None) -> dict:
    repo = repo.resolve()
    bundle = bundle or repo / 'mise-helper/vendor/pzagent-adw-context'
    destination = repo / '.github/workflows'
    # Refuse linked ancestors and destinations before any write.
    for path in (repo / '.github', destination):
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise ContractError('workflow_symlink_rejected')
    contents = {}
    drift = []
    for name in WORKFLOWS:
        template = bundle / 'templates/github' / name
        target = destination / name
        if template.is_symlink() or not template.is_file() or target.is_symlink():
            raise ContractError('workflow_template_unsafe')
        data = template.read_bytes()
        contents[name] = data
        if not target.is_file() or target.read_bytes() != data:
            drift.append('.github/workflows/' + name)
    if not check and drift:
        destination.mkdir(parents=True, exist_ok=True)
        for name, data in contents.items():
            if '.github/workflows/' + name not in drift:
                continue
            with tempfile.NamedTemporaryFile(dir=destination, prefix='.workflow-', delete=False) as stream:
                temporary = Path(stream.name)
                try:
                    stream.write(data)
                    stream.flush()
                    os.fchmod(stream.fileno(), 0o644)
                except BaseException:
                    temporary.unlink(missing_ok=True)
                    raise
            try:
                temporary.replace(destination / name)
            finally:
                temporary.unlink(missing_ok=True)
    return {'status': 'blocked' if check and drift else 'ok',
            'reason': 'workflow_template_drift' if check and drift else '',
            'drift': drift, 'written': [] if check else drift}

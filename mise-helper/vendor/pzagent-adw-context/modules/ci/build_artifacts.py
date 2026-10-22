"""Read-only build transport after caller-owned CI release authorization.

This module checks the current quality producer. It does not authorize a lane,
PR, dispatcher or release. Missing/expired optional output returns None; changed
quality identity or corrupt transport raises instead of becoming a cache miss.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import shutil
import stat
import tempfile
import zipfile

from .github_api import ApiError, GitHub, REPO

MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
SHA = re.compile(r'[0-9a-f]{40}')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
COMPONENT = re.compile(r'[a-z0-9][a-z0-9_.-]{0,63}')


@dataclass(frozen=True)
class Producer:
    repository: str
    source_sha: str
    run_id: int
    run_attempt: int
    event: str
    branch: str
    pr_number: int | None = None

    def __post_init__(self):
        if (not isinstance(self.repository, str) or not REPO.fullmatch(self.repository)
                or any(part in {'.', '..'} for part in self.repository.split('/'))
                or not isinstance(self.source_sha, str) or not SHA.fullmatch(self.source_sha)
                or type(self.run_id) is not int or self.run_id <= 0
                or type(self.run_attempt) is not int or self.run_attempt <= 0
                or self.event not in {'push', 'pull_request', 'workflow_dispatch'}
                or not isinstance(self.branch, str) or not re.fullmatch(r'[A-Za-z0-9._/-]+', self.branch)
                or any(part in {'', '.', '..'} for part in self.branch.split('/'))
                or (self.event == 'pull_request' and
                    (type(self.pr_number) is not int or self.pr_number <= 0))):
            raise ApiError('build_producer_invalid')

    def expected(self, contract_sha256: str, context_sha256: str) -> dict:
        if not all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) for value in (contract_sha256, context_sha256)):
            raise ApiError('build_contract_digest_invalid')
        ref = f'refs/pull/{self.pr_number}/merge' if self.event == 'pull_request' else f'refs/heads/{self.branch}'
        return {'kind': 'github-actions', 'source_sha': self.source_sha,
                'contract_sha256': contract_sha256, 'context_sha256': context_sha256,
                'repository': self.repository, 'run_id': str(self.run_id),
                'run_attempt': str(self.run_attempt), 'job': 'required-quality',
                'workflow_ref': f'{self.repository}/.github/workflows/ci.yml@{ref}'}


def _inventory(page, key):
    items = page.get(key) if isinstance(page, dict) else None
    if (not isinstance(items, list) or not all(isinstance(item, dict) for item in items)
            or type(page.get('total_count')) is not int
            or page['total_count'] != len(items) or len(items) > 100):
        raise ApiError('build_inventory_incomplete')
    return items


def _quality(api: GitHub, producer: Producer) -> tuple[int, bool]:
    if api.repository != producer.repository:
        raise ApiError('build_repository_mismatch')
    repository_id = None
    for path in (f'actions/runs/{producer.run_id}',
                 f'actions/runs/{producer.run_id}/attempts/{producer.run_attempt}'):
        run = api.get(path)
        if (not isinstance(run, dict) or run.get('id') != producer.run_id
                or run.get('run_attempt') != producer.run_attempt
                or run.get('head_sha') != producer.source_sha
                or run.get('event') != producer.event or run.get('head_branch') != producer.branch
                or run.get('path') != '.github/workflows/ci.yml'
                or run.get('status') != 'completed' or run.get('conclusion') != 'success'):
            raise ApiError('build_quality_run_changed')
        repository = run.get('repository', {}); head = run.get('head_repository', {})
        if (not isinstance(repository, dict) or not isinstance(head, dict)
                or repository.get('full_name') != producer.repository
                or head.get('full_name') != producer.repository
                or type(repository.get('id')) is not int or repository['id'] <= 0
                or head.get('id') != repository['id']
                or repository_id not in (None, repository['id'])):
            raise ApiError('build_repository_mismatch')
        repository_id = repository['id']
    jobs = _inventory(api.run_jobs(producer.run_id, producer.run_attempt), 'jobs')
    quality = [job for job in jobs if job.get('name') == 'required-quality']
    if len(quality) != 1:
        raise ApiError('build_quality_job_missing')
    job = quality[0]
    if (job.get('run_id') != producer.run_id or job.get('run_attempt') != producer.run_attempt
            or job.get('head_sha') != producer.source_sha
            or job.get('status') != 'completed' or job.get('conclusion') != 'success'
            or not isinstance(job.get('steps'), list)
            or not all(isinstance(step, dict) for step in job['steps'])):
        raise ApiError('build_quality_job_changed')
    full = [step for step in job['steps'] if step.get('name') == 'Run required full quality graph']
    # A successful destination proof may authorize publication but produces no
    # newly compiled files. Its caller must use canonical ADW build instead.
    if not full or (len(full) == 1 and full[0].get('conclusion') == 'skipped'):
        return repository_id, False
    if len(full) != 1 or full[0].get('conclusion') != 'success':
        raise ApiError('build_quality_step_failed')
    uploaded = [step for step in job['steps'] if step.get('name') == 'Archive compiled build outputs']
    return repository_id, len(uploaded) == 1 and uploaded[0].get('conclusion') == 'success'


def artifact_name(producer: Producer, component: str | None = None) -> str:
    if component is not None and (not isinstance(component, str) or not COMPONENT.fullmatch(component)):
        raise ApiError('build_component_invalid')
    name = f'adw-build-{producer.source_sha}-{producer.run_id}-{producer.run_attempt}'
    return name if component is None else name + '-' + component


def select(api: GitHub, producer: Producer, component: str | None = None) -> dict | None:
    name = artifact_name(producer, component)
    repository_id, exported = _quality(api, producer)
    if not exported:
        return None
    matches = [item for item in _inventory(api.run_artifacts(producer.run_id), 'artifacts')
               if item.get('name') == name]
    if not matches:
        return None
    if len(matches) != 1:
        raise ApiError('build_artifact_ambiguous')
    item = matches[0]
    workflow = item.get('workflow_run', {})
    if (type(item.get('id')) is not int or item['id'] <= 0
            or not isinstance(workflow, dict) or workflow.get('id') != producer.run_id
            or workflow.get('head_sha') != producer.source_sha
            or workflow.get('repository_id') != repository_id
            or workflow.get('head_repository_id') != repository_id
            or workflow.get('head_branch') != producer.branch
            or type(item.get('expired')) is not bool):
        raise ApiError('build_artifact_identity_mismatch')
    if item['expired']:
        return None
    # Older artifacts without a recorded server digest cannot be reused.
    if item.get('digest') is None:
        return None
    if (not isinstance(item['digest'], str) or not DIGEST.fullmatch(item['digest'])
            or type(item.get('size_in_bytes')) is not int
            or not 0 < item['size_in_bytes'] <= MAX_ARCHIVE_BYTES):
        raise ApiError('build_artifact_metadata_invalid')
    return item


def extract(archive: Path, destination: Path, metadata: dict) -> None:
    """Validate the server-recorded outer ZIP before exposing the inner payload."""
    if destination.exists() or destination.is_symlink():
        raise ApiError('build_artifact_destination_exists')
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    if (archive.stat().st_size != metadata['size_in_bytes']
            or 'sha256:' + digest.hexdigest() != metadata['digest']):
        raise ApiError('build_artifact_digest_mismatch')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.ci-build-', dir=destination.parent) as temporary:
        payload = Path(temporary) / 'payload'
        try:
            with zipfile.ZipFile(archive) as zipped:
                entries = zipped.infolist()
                if len(entries) != 1:
                    raise ApiError('build_artifact_entries_invalid')
                entry = entries[0]
                kind = stat.S_IFMT(entry.external_attr >> 16)
                if (entry.filename != 'build-output.tar.gz' or entry.is_dir()
                        or kind not in (0, stat.S_IFREG) or entry.flag_bits & 1
                        or not 0 < entry.file_size <= MAX_ARCHIVE_BYTES):
                    raise ApiError('build_artifact_entries_invalid')
                with zipped.open(entry) as source, payload.open('xb') as output:
                    shutil.copyfileobj(source, output)
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError):
            raise ApiError('build_artifact_zip_invalid') from None
        payload.rename(destination)


def fetch(api: GitHub, producer: Producer, destination: Path, component: str | None = None) -> dict | None:
    """Return authenticated transport metadata; package import checks source/files."""
    if destination.exists() or destination.is_symlink():
        raise ApiError('build_artifact_destination_exists')
    metadata = select(api, producer, component)
    if metadata is None:
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.ci-download-', dir=destination.parent) as temporary:
        archive = Path(temporary) / 'artifact.zip'
        api.download_artifact(metadata['id'], archive, max_bytes=MAX_ARCHIVE_BYTES)
        # Recheck the current run attempt and immutable artifact after download.
        if select(api, producer, component) != metadata:
            raise ApiError('build_artifact_changed_during_download')
        extract(archive, destination, metadata)
    return metadata

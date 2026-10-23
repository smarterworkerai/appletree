"""Bounded read-only GitHub REST adapter; never include response bodies in errors."""
from __future__ import annotations
from collections import deque
import copy
import json
import base64
import re
import subprocess
import time
from pathlib import Path
import tempfile
from typing import Any
from urllib.parse import quote
from ..common import project_paths


class ApiError(ValueError):
    def __init__(self, reason: str, *, detail: str | None = None):
        self.detail = lookup_detail(detail)
        super().__init__(reason)


def lookup_detail(value: object) -> str | None:
    """Only fixed diagnostic classes may cross a proof/output boundary."""
    return value if isinstance(value, str) and re.fullmatch(
        r'http_[1-5][0-9]{2}|timeout|os_error|malformed', value) else None


def response_parts(value: str) -> tuple[str, int | None]:
    """Separate gh --include headers without retaining headers or response bodies."""
    status = None
    remaining = value
    consumed = 0
    for _ in range(8):
        if not remaining.startswith('HTTP/'):
            return remaining, status
        headers, separator, body = remaining.partition('\n\n')
        consumed += len(headers.encode('utf-8'))
        match = re.match(r'HTTP/\S+ ([1-5][0-9]{2})(?:[^\n]*)\n?', headers)
        if not separator or not match or consumed > 16384:
            raise ApiError('response_malformed', detail='malformed')
        status = int(match[1])
        remaining = body
    raise ApiError('response_malformed', detail='malformed')


def project_files(api, ref: str, *names: str) -> dict[str, tuple[str, bytes]]:
    """Read one coherent metadata directory at an exact immutable source SHA.

    Only real content_absent responses permit fallback; permission/transport and
    malformed-content failures never mean that the alternate directory wins.
    A mixed or duplicated set refuses instead of combining authorities.
    """
    allowed = {'pzagent-adapter.json', 'adw-task-manifest.json', 'pzagent-context-lock.json'}
    if not names or len(names) != len(set(names)) or not set(names) <= allowed:
        raise ApiError('content_path_forbidden')
    found: dict[str, tuple[str, bytes]] | None = None
    for index in (0, 1):
        values = {}
        for name in names:
            try:
                path = project_paths(name)[index]
                values[name] = (path, api.content(path, ref)[1])
            except ApiError as exc:
                if str(exc) != 'content_absent':
                    raise
        if values:
            if found is not None:
                raise ApiError('project_directory_conflict')
            found = values
    if found is None or set(found) != set(names):
        raise ApiError('content_absent')
    return found


REPO = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
SHA = r'[0-9a-f]{40}'
NUM = r'[1-9][0-9]*'
BRANCH = r'[A-Za-z0-9._/-]+'
PATHS = tuple(re.compile('^' + s + '$') for s in (
    r'',  # Live repository metadata, including the actual default branch.
    rf'pulls/{NUM}', rf'pulls/{NUM}/reviews', rf'pulls/{NUM}/commits',
    rf'commits/{SHA}', rf'git/commits/{SHA}', rf'git/trees/{SHA}\?recursive=1', rf'commits/{SHA}/pulls',
    rf'commits/{SHA}/check-runs', rf'check-runs/{NUM}',
    rf'actions/runs/{NUM}', rf'actions/jobs/{NUM}', rf'actions/runs/{NUM}/attempts/{NUM}',
    rf'actions/runs/{NUM}/attempts/{NUM}/jobs',
    rf'git/ref/heads/{BRANCH}', rf'git/ref/pull/{NUM}/merge',
    r'collaborators/[A-Za-z0-9_.-]+/permission',
    r'pulls',
))
MAX_BYTES = 1_000_000
# Reads addressed by a full commit or tree SHA can never change, so one proof run
# fetches each of them once. Everything else (refs, PRs, checks, runs) stays live.
IMMUTABLE = re.compile(rf'^(?:contents/.+\?ref={SHA}|git/commits/{SHA}|git/trees/{SHA}\?recursive=1)$')


class GitHub:
    def __init__(self, repository: str):
        if (not isinstance(repository, str) or not REPO.fullmatch(repository)
                or any(part in ('.', '..') for part in repository.split('/'))):
            raise ApiError('repository_invalid')
        self.repository = repository
        self._immutable: dict[str, Any] = {}

    def get(self, path: str) -> Any:
        if (not isinstance(path, str) or not any(pattern.fullmatch(path) for pattern in PATHS)
            or any(part in ('.', '..') for part in path.split('/')) or '//' in path):
            raise ApiError('path_not_allowlisted')
        return self._fetch(path)

    def _fetch(self, path: str) -> Any:
        if IMMUTABLE.fullmatch(path) and path in self._immutable:
            return copy.deepcopy(self._immutable[path])
        value = self._fetch_live(path)
        if IMMUTABLE.fullmatch(path):
            self._immutable[path] = copy.deepcopy(value)
        return value

    def _fetch_live(self, path: str) -> Any:
        try:
            result = subprocess.run(['gh', 'api', '--method', 'GET',
                                     '--include',
                                     f'repos/{self.repository}' + ('/' + path if path else '')],
                                    capture_output=True, text=True, timeout=15, check=False)
        except subprocess.TimeoutExpired:
            raise ApiError('lookup_failed', detail='timeout') from None
        except OSError:
            raise ApiError('lookup_failed', detail='os_error') from None
        payload, status = response_parts(result.stdout)
        if result.returncode or (status is not None and status >= 400):
            if status is None:
                match = re.search(r'\bHTTP ([1-5][0-9]{2})\b', result.stderr, re.IGNORECASE)
                status = int(match[1]) if match else None
            detail = f'http_{status}' if status is not None else 'os_error'
            if status is not None and 200 <= status < 300:
                try:
                    json.loads(payload)
                except json.JSONDecodeError:
                    detail = 'malformed'
            if (path.startswith('contents/')
                    and status == 404):
                raise ApiError('content_absent', detail=detail)
            raise ApiError('lookup_failed', detail=detail)
        if len(payload.encode('utf-8')) > MAX_BYTES:
            raise ApiError('response_too_large')
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            raise ApiError('response_malformed', detail='malformed') from None

    def list(self, path: str, *, limit: int = 300) -> list[dict]:
        if path not in {'pulls',} and not re.fullmatch(rf'pulls/{NUM}/reviews|pulls/{NUM}/commits|issues/{NUM}/comments|commits/{SHA}/pulls', path):
            raise ApiError('list_path_not_allowlisted')
        if type(limit) is not int or not 1 <= limit <= 300:
            raise ApiError('pagination_limit')
        result: list[dict] = []
        for page in range(1, 4):
            batch = self._fetch(f'{path}?per_page=100&page={page}')
            if not isinstance(batch, list) or not all(isinstance(x, dict) for x in batch):
                raise ApiError('response_malformed')
            result.extend(batch)
            if len(result) > limit:
                raise ApiError('pagination_limit')
            if len(batch) < 100:
                return result
        raise ApiError('pagination_limit')

    def associated_pulls(self, sha: str, *, attempts: int = 3) -> list[dict]:
        """Read the exact-SHA association with bounded propagation retries."""
        if not isinstance(sha,str) or not re.fullmatch(SHA,sha):
            raise ApiError('sha_invalid')
        if type(attempts) is not int or not 1 <= attempts <= 3:
            raise ApiError('association_attempts_invalid')
        for attempt in range(attempts):
            result=self.list(f'commits/{sha}/pulls',limit=100)
            if result or attempt+1==attempts:
                return result
            time.sleep(attempt+1)
        raise ApiError('association_lookup_failed')  # pragma: no cover

    def is_ancestor(self, ancestor: str, descendant: str, *, limit: int = 256) -> bool:
        """Follow exact commit hashes to prove ancestry without diff inventory."""
        if (not isinstance(ancestor,str) or not re.fullmatch(SHA,ancestor)
            or not isinstance(descendant,str) or not re.fullmatch(SHA,descendant)):
            raise ApiError('sha_invalid')
        if type(limit) is not int or not 1 <= limit <= 1024:
            raise ApiError('ancestry_limit_invalid')
        # Breadth-first traversal reaches a merge commit's direct parents before
        # consuming the bounded budget on either parent's deeper history.
        pending=deque([descendant]);seen=set()
        while pending:
            current=pending.popleft()
            if current==ancestor:
                return True
            if current in seen:
                continue
            if len(seen)>=limit:
                raise ApiError('ancestry_limit')
            seen.add(current)
            record=self.get(f'git/commits/{current}')
            parents=record.get('parents') if isinstance(record,dict) else None
            if (not isinstance(parents,list) or len(parents)>16
                or not all(isinstance(parent,dict)
                           and isinstance(parent.get('sha'),str)
                           and re.fullmatch(SHA,parent['sha']) for parent in parents)):
                raise ApiError('commit_parents_invalid')
            pending.extend(parent['sha'] for parent in parents
                           if parent['sha'] not in seen)
        return False

    def promotion_pulls(self, *, source: str, target: str, head_sha: str) -> list[dict]:
        """Closed PRs from one declared source into one target whose head or merge commit is head_sha.

        The commit association does not list fast-forwarded promotion PRs reliably, so this
        is the normal discovery path for a promoted line. Pages newest-first and stops at the
        first page that holds a match; only 300 records without one count as incomplete.
        """
        for value,label in ((source,'source'),(target,'target')):
            if (not isinstance(value,str) or not re.fullmatch(BRANCH,value)
                or any(part in ('.','..') for part in value.split('/'))):
                raise ApiError(f'{label}_invalid')
        if not isinstance(head_sha,str) or not re.fullmatch(SHA,head_sha):
            raise ApiError('sha_invalid')
        owner=self.repository.split('/',1)[0]
        base=('pulls?state=closed&base='+quote(target,safe='')
              +'&head='+quote(f'{owner}:{source}',safe='')
              +'&sort=updated&direction=desc&per_page=100')
        matches:list[dict]=[]
        for page in range(1,4):
            result=self._fetch(f'{base}&page={page}')
            if (not isinstance(result,list) or not all(isinstance(x,dict) for x in result)):
                raise ApiError('response_malformed')
            matches.extend(record for record in result
                           if record.get('merge_commit_sha')==head_sha
                           or (isinstance(record.get('head'),dict) and record['head'].get('sha')==head_sha))
            if matches or len(result)<100:
                return matches
        raise ApiError('promotion_inventory_limit')

    def controller_runs(self, *, branch: str, head_sha: str) -> list[dict]:
        """List a bounded exact controller-run identity without broad run scans."""
        if (not isinstance(branch,str) or not re.fullmatch(BRANCH,branch)
            or any(part in ('','.','..') for part in branch.split('/'))):
            raise ApiError('branch_invalid')
        if not isinstance(head_sha,str) or not re.fullmatch(SHA,head_sha):
            raise ApiError('sha_invalid')
        path=('actions/workflows/trust-root-bootstrap.yml/runs?event=pull_request_target'
              +'&branch='+quote(branch,safe='')+'&head_sha='+head_sha+'&per_page=20')
        page=self._fetch(path)
        items=page.get('workflow_runs') if isinstance(page,dict) else None
        if (not isinstance(items,list) or not all(isinstance(item,dict) for item in items)
            or type(page.get('total_count')) is not int or page['total_count']!=len(items)
            or len(items)>20):
            raise ApiError('controller_run_inventory_incomplete')
        return items

    def check_runs(self, sha: str) -> list[dict]:
        if not isinstance(sha,str) or not re.fullmatch(SHA,sha):
            raise ApiError('sha_invalid')
        page=self._fetch(f'commits/{sha}/check-runs?per_page=100')
        items=page.get('check_runs') if isinstance(page,dict) else None
        if (not isinstance(items,list) or not all(isinstance(x,dict) for x in items)
            or type(page.get('total_count')) is not int
            or page['total_count']!=len(items) or len(items)>100):
            raise ApiError('check_inventory_incomplete')
        return items

    @staticmethod
    def _positive(value):
        if type(value) is not int or value <= 0:
            raise ApiError('id_invalid')

    def run_jobs(self, run_id: int, attempt: int) -> dict:
        self._positive(run_id); self._positive(attempt)
        return self._fetch(f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')

    def run_artifacts(self, run_id: int) -> dict:
        self._positive(run_id)
        return self._fetch(f'actions/runs/{run_id}/artifacts?per_page=100')

    def download_artifact(self, artifact_id: int, destination: Path, *, max_bytes: int) -> None:
        self._positive(artifact_id); self._positive(max_bytes)
        if destination.exists() or destination.is_symlink():
            raise ApiError('download_destination_exists')
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.artifact-', dir=destination.parent) as temporary:
            archive = Path(temporary) / 'artifact.zip'
            try:
                with archive.open('xb') as output:
                    result = subprocess.run(['gh', 'api', '--method', 'GET',
                                             f'repos/{self.repository}/actions/artifacts/{artifact_id}/zip'],
                                            stdout=output, stderr=subprocess.DEVNULL, timeout=180, check=False)
            except (OSError, subprocess.TimeoutExpired):
                raise ApiError('artifact_download_failed') from None
            if result.returncode or not 0 < archive.stat().st_size <= max_bytes:
                raise ApiError('artifact_download_failed')
            archive.rename(destination)

    def content(self, path: str, ref: str) -> tuple[str, bytes]:
        allowed={'mise-helper/vendor/agentic-delivery/adw_contract.py',
                 'mise-helper/vendor/agentic-delivery/tasks.toml',
                 '.github/workflows/ci.yml','.github/workflows/trust-root-bootstrap.yml'}
        for name in ('adw-task-manifest.json', 'pzagent-context-lock.json', 'pzagent-adapter.json'):
            allowed.update(project_paths(name))
        vendor=r'mise-helper/vendor/pzagent-adw-context/(?:ci\.py|pzagent_context\.py|tasks\.toml|bundle\.json|modules/(?:__init__|ci/[a-z_]+|adapter|common|bundle|operator_publish|operator_retention|pointer_retirement|release_manifest|oras_registry)\.py|templates/github/(?:publish-release\.yml|cleanup-retention\.yml|actions/(?:classify-ci-event/action\.yml|authorize-publication/(?:action\.yml|authorize\.py)|publish-immutable-release/(?:action\.yml|publish\.py))))'
        if path not in allowed and not re.fullmatch(vendor,path):
            raise ApiError('content_path_forbidden')
        if not isinstance(ref,str) or not re.fullmatch(SHA,ref):
            raise ApiError('ref_invalid')
        item=self._fetch(f'contents/{path}?ref={ref}')
        max_size=(131072 if path=='mise-helper/vendor/agentic-delivery/adw_contract.py' else 65536)
        if (not isinstance(item,dict) or item.get('type')!='file'
            or item.get('encoding')!='base64'
            or not isinstance(item.get('sha'),str) or not re.fullmatch(SHA,item['sha'])
            or type(item.get('size')) is not int or not 0 <= item['size'] <= max_size):
            raise ApiError('content_metadata_invalid')
        try:
            data=base64.b64decode(item['content'])
        except (KeyError,ValueError,TypeError):
            raise ApiError('content_invalid') from None
        if len(data)!=item['size']:
            raise ApiError('content_size_mismatch')
        return item['sha'],data

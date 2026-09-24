"""Bounded read-only GitHub REST adapter; never include response bodies in errors."""
from __future__ import annotations
import json
import base64
import re
import subprocess
import time
from typing import Any
from urllib.parse import quote


class ApiError(ValueError):
    pass


REPO = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
SHA = r'[0-9a-f]{40}'
NUM = r'[1-9][0-9]*'
BRANCH = r'[A-Za-z0-9._/-]+'
PATHS = tuple(re.compile('^' + s + '$') for s in (
    rf'pulls/{NUM}', rf'pulls/{NUM}/reviews', rf'pulls/{NUM}/commits',
    rf'commits/{SHA}', rf'git/commits/{SHA}', rf'commits/{SHA}/pulls',
    rf'commits/{SHA}/check-runs', rf'check-runs/{NUM}',
    rf'actions/runs/{NUM}', rf'actions/runs/{NUM}/attempts/{NUM}/jobs',
    rf'git/ref/heads/{BRANCH}', rf'git/ref/pull/{NUM}/merge',
    r'collaborators/[A-Za-z0-9_.-]+/permission',
    rf'compare/{SHA}\.\.\.{SHA}',
    r'pulls',
))
MAX_BYTES = 1_000_000


class GitHub:
    def __init__(self, repository: str):
        if not isinstance(repository, str) or not REPO.fullmatch(repository):
            raise ApiError('repository_invalid')
        self.repository = repository

    def get(self, path: str) -> Any:
        if (not isinstance(path, str) or not any(pattern.fullmatch(path) for pattern in PATHS)
            or any(part in ('.', '..') for part in path.split('/')) or '//' in path):
            raise ApiError('path_not_allowlisted')
        return self._fetch(path)

    def _fetch(self, path: str) -> Any:
        try:
            result = subprocess.run(['gh', 'api', '--method', 'GET',
                                     f'repos/{self.repository}/{path}'],
                                    capture_output=True, text=True, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ApiError('lookup_failed') from None
        if result.returncode:
            raise ApiError('lookup_failed')
        if len(result.stdout.encode('utf-8')) > MAX_BYTES:
            raise ApiError('response_too_large')
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            raise ApiError('response_malformed') from None

    def list(self, path: str, *, limit: int = 300) -> list[dict]:
        if path not in {'pulls',} and not re.fullmatch(rf'pulls/{NUM}/reviews|pulls/{NUM}/commits|commits/{SHA}/pulls', path):
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

    def promotion_pulls(self, *, source: str, target: str) -> list[dict]:
        """Fallback scoped to one adapter-declared source/target identity."""
        for value,label in ((source,'source'),(target,'target')):
            if (not isinstance(value,str) or not re.fullmatch(BRANCH,value)
                or any(part in ('.','..') for part in value.split('/'))):
                raise ApiError(f'{label}_invalid')
        owner=self.repository.split('/',1)[0]
        path=('pulls?state=closed&base='+quote(target,safe='')
              +'&head='+quote(f'{owner}:{source}',safe='')+'&per_page=20')
        result=self._fetch(path)
        if (not isinstance(result,list) or not all(isinstance(x,dict) for x in result)):
            raise ApiError('response_malformed')
        if len(result)>=20:
            raise ApiError('promotion_inventory_limit')
        return result

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

    def content(self, path: str, ref: str) -> tuple[str, bytes]:
        allowed={'deploy_diag','.hermes/adw-task-manifest.json','.hermes/pzagent-context-lock.json',
                 '.hermes/pzagent-adapter.json',
                 '.github/workflows/ci.yml'}
        vendor=r'mise-helper/vendor/pzagent-adw-context/(?:ci\.py|tasks\.toml|bundle\.json|modules/(?:__init__|ci/[a-z_]+|adapter|common|bundle)\.py|templates/github/(?:publish-release\.yml|actions/(?:classify-ci-event/action\.yml|authorize-publication/(?:action\.yml|authorize\.py)|publish-immutable-release/(?:action\.yml|publish\.py))))'
        if path not in allowed and not re.fullmatch(vendor,path):
            raise ApiError('content_path_forbidden')
        if not isinstance(ref,str) or not re.fullmatch(SHA,ref):
            raise ApiError('ref_invalid')
        item=self._fetch(f'contents/{path}?ref={ref}')
        if (not isinstance(item,dict) or item.get('type')!='file'
            or item.get('encoding')!='base64'
            or not isinstance(item.get('sha'),str) or not re.fullmatch(SHA,item['sha'])
            or type(item.get('size')) is not int or not 0 <= item['size'] <= 65536):
            raise ApiError('content_metadata_invalid')
        try:
            data=base64.b64decode(item['content'])
        except (KeyError,ValueError,TypeError):
            raise ApiError('content_invalid') from None
        if len(data)!=item['size']:
            raise ApiError('content_size_mismatch')
        return item['sha'],data

"""Token-scoped GitHub transport for explicit human source/package operations."""
import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .common import ContractError


def api(method, path, body=None):
    token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
    if not token or not path.startswith('/') or path.startswith('//'):
        raise ContractError('GitHub operator credential or path is missing')
    request = Request('https://api.github.com' + path,
                      data=json.dumps(body).encode() if body is not None else None,
                      method=method, headers={'Authorization': 'Bearer ' + token,
                          'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json'})
    try:
        with urlopen(request, timeout=30) as response:
            data = response.read(8 * 1024 * 1024 + 1)
            if len(data) > 8 * 1024 * 1024:
                raise ContractError('GitHub response exceeds inventory bound')
            return json.loads(data) if data else None
    except HTTPError as exc:
        raise ContractError('GitHub operation rejected (HTTP ' + str(exc.code) + ')') from None
    except (URLError, TimeoutError, ValueError):
        raise ContractError('GitHub operation unavailable or response malformed') from None


def pages(path):
    rows = []
    separator = '&' if '?' in path else '?'
    for page in range(1, 101):
        batch = api('GET', path + separator + f'per_page=100&page={page}')
        if not isinstance(batch, list):
            raise ContractError('GitHub paginated inventory malformed')
        rows.extend(batch)
        if len(batch) < 100:
            return rows
    raise ContractError('GitHub inventory exceeds pagination bound')

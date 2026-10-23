"""Public HTTP probe transport for project hooks: the bundled probe identity with bounds.

Project hooks import it from the vendored bundle:

    sys.path.insert(0, 'mise-helper/vendor/pzagent-adw-context')
    from modules.http_probe import fetch

Standard library only; no package-relative imports, so it also loads by path.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

# One identity for every bundled health/readiness probe and for project hooks.
PROBE_USER_AGENT = 'pzagent-health'
PROBE_HEADERS = {'Accept': 'application/json', 'User-Agent': PROBE_USER_AGENT}
DEFAULT_TIMEOUT = 15.0
MAX_TIMEOUT = 60.0
DEFAULT_MAX_BYTES = 65536
MAX_BYTES = 1048576


class ProbeError(RuntimeError):
    """The probe could not produce a bounded same-origin response."""


@dataclass(frozen=True)
class ProbeResponse:
    status: int
    content_type: str
    body: bytes


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    if parts.scheme not in {'http', 'https'} or not parts.hostname or parts.username or parts.password:
        raise ProbeError('probe_url_invalid')
    try:
        port = parts.port or (443 if parts.scheme == 'https' else 80)
    except ValueError as exc:
        raise ProbeError('probe_url_invalid') from exc
    return parts.scheme, parts.hostname.lower(), port


class _SameOriginRedirects(HTTPRedirectHandler):
    max_redirections = 5

    def __init__(self, origin):
        self.origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origin(newurl) != self.origin:
            raise ProbeError('probe_cross_origin_redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _read(response, limit: int) -> bytes:
    body = response.read(limit + 1)
    if len(body) > limit:
        raise ProbeError('probe_body_too_large')
    return body


def fetch(url: str, *, timeout: float = DEFAULT_TIMEOUT, max_bytes: int = DEFAULT_MAX_BYTES) -> ProbeResponse:
    """GET url with the canonical probe headers; HTTP error statuses are returned, not raised."""
    if not 0 < timeout <= MAX_TIMEOUT or not 0 < max_bytes <= MAX_BYTES:
        raise ProbeError('probe_bounds_invalid')
    origin = _origin(url)
    opener = build_opener(_SameOriginRedirects(origin))
    try:
        with opener.open(Request(url, headers=PROBE_HEADERS), timeout=timeout) as response:
            return ProbeResponse(response.status, response.headers.get_content_type(), _read(response, max_bytes))
    except HTTPError as exc:
        with exc:
            return ProbeResponse(exc.code, exc.headers.get_content_type() if exc.headers else '', _read(exc, max_bytes))
    except (URLError, TimeoutError, OSError) as exc:
        raise ProbeError('probe_unreachable') from exc

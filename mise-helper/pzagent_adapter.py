#!/usr/bin/env python3
"""Closed project-semantic hook dispatcher for the shared pzagent runtime."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from html.parser import HTMLParser
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

WIRE = {"schema_version", "capability", "environment", "target", "source_sha", "operation"}
TARGETS = {
    "pr-preview": "pr-preview-dokploy",
    "demo": "demo-dokploy",
    "production": "production-dokploy",
}
ROUTES = {
    "pr-preview": "https://appletree-preview.lan.smarterworker.cc",
    "demo": "https://appletree-demo.smarterworker.cc",
    "production": "https://appletree.smarterworker.cc",
}
OPERATIONS = {
    "config-plan": "adw:deploy:config:plan",
    "deploy-status": "adw:deploy:status",
    "health": "adw:health",
    "readiness": "adw:readiness",
    "e2e-fast": "adw:test:e2e:fast",
    "e2e-full": "adw:test:e2e:full",
}
IMAGE = re.compile(r"^ghcr\.io/smarterworkerai/appletree(?:@sha256:[0-9a-f]{64}|:hotfix-[0-9a-f]{12})$")


class Blocked(RuntimeError):
    pass


class Assets(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.paths: list[str] = []
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        value = values.get("src") if tag == "script" else values.get("href") if tag == "link" else None
        if isinstance(value, str) and value.startswith("/assets/"):
            self.paths.append(value)


def _request_json(path: str) -> dict[str, Any]:
    endpoint = os.environ.get("DOKPLOY_URL", "").rstrip("/")
    token = os.environ.get("DOKPLOY_TOKEN", "")
    compose_id = os.environ.get("APPLETREE_DOKPLOY_COMPOSE_ID", "")
    if not endpoint or not token or not compose_id:
        raise Blocked("provider-input-absent")
    request = Request(
        endpoint + path + "?" + urlencode({"composeId": compose_id}),
        headers={"x-api-key": token, "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=20) as response:  # nosec B310: operator-bound provider URL
            raw = response.read(1024 * 1024)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise Blocked("provider-read-failed") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Blocked("provider-response-invalid") from exc
    if not isinstance(value, dict):
        raise Blocked("provider-response-invalid")
    return value


def _fetch(url: str) -> str:
    request = Request(url, headers={"User-Agent": "appletree-adw-probe/1"})
    try:
        with urlopen(request, timeout=20) as response:  # nosec B310: fixed project route
            body = response.read(2_000_000).decode("utf-8")
            if response.status != 200:
                raise Blocked("http-status-invalid")
            return body
    except (HTTPError, URLError, TimeoutError, UnicodeDecodeError) as exc:
        raise Blocked("http-probe-failed") from exc


def _identity(operation: str, request: dict[str, Any], keys: set[str] = WIRE) -> str:
    if set(request) != keys or request.get("schema_version") != "1.0.0":
        raise ValueError("hook-request-invalid")
    capability = OPERATIONS.get(operation, {"hotfix-build": "adw:hotfix:apply", "runtime-proof": "adw:validate-deployment"}.get(operation))
    environment = request.get("environment")
    if request.get("operation") != operation or request.get("capability") != capability:
        raise ValueError("hook-identity-differs")
    if environment not in TARGETS or request.get("target") != TARGETS[environment]:
        raise ValueError("hook-target-differs")
    if not re.fullmatch(r"[0-9a-f]{40}", str(request.get("source_sha", ""))):
        raise ValueError("hook-source-invalid")
    return str(environment)


def _status() -> dict[str, Any]:
    payload = _request_json("/api/compose.one")
    if payload.get("composeStatus") != "done":
        raise Blocked("deployment-not-ready")
    return payload


def _health(environment: str) -> None:
    body = _fetch(ROUTES[environment] + "/")
    if "<title>Apple Tree</title>" not in body or '<canvas id="scene"></canvas>' not in body:
        raise Blocked("application-semantics-invalid")


def _e2e(environment: str, full: bool) -> dict[str, Any]:
    body = _fetch(ROUTES[environment] + "/")
    if '<canvas id="scene"></canvas>' not in body:
        raise Blocked("application-semantics-invalid")
    selected = 1
    if full:
        parser = Assets()
        parser.feed(body)
        if not parser.paths:
            raise Blocked("application-assets-absent")
        for path in sorted(set(parser.paths)):
            if not _fetch(ROUTES[environment] + path):
                raise Blocked("application-asset-empty")
        selected += len(set(parser.paths))
    return {"status": "passed", "selected": selected, "executed": selected, "skipped": 0}


def _environment_values(raw: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            raise Blocked("runtime-environment-invalid")
        key, value = line.split("=", 1)
        if key.strip() in values:
            raise Blocked("runtime-environment-invalid")
        values[key.strip()] = value
    return values


def _runtime_proof(request: dict[str, Any]) -> dict[str, Any]:
    environment = _identity("runtime-proof", request, WIRE | {"phase", "expected_images"})
    assignments = request.get("expected_images")
    if not isinstance(assignments, list) or len(assignments) != 1 or not assignments[0].startswith("APPLETREE_IMAGE="):
        raise ValueError("runtime-image-set-invalid")
    image = assignments[0].split("=", 1)[1]
    if not IMAGE.fullmatch(image):
        raise ValueError("runtime-image-invalid")
    payload = _status()
    raw = payload.get("env")
    if not isinstance(raw, str) or _environment_values(raw).get("APPLETREE_IMAGE") != image:
        raise Blocked("runtime-image-identity-or-health-mismatch")
    _health(environment)
    return {"images": assignments}


def _hotfix_build(request: dict[str, Any]) -> dict[str, Any]:
    environment = _identity("hotfix-build", request, WIRE | {"phase"})
    if environment != "pr-preview" or request.get("phase") != "build":
        raise ValueError("hotfix-scope-invalid")
    source = request["source_sha"]
    image = f"ghcr.io/smarterworkerai/appletree:hotfix-{source[:12]}"
    subprocess.run([
        "docker", "build", "--tag", image,
        "--label", f"org.opencontainers.image.revision={source}",
        "--label", "org.opencontainers.image.source=https://github.com/smarterworkerai/appletree",
        ".",
    ], check=True, timeout=1200)
    return {"images": [f"APPLETREE_IMAGE={image}"]}


def dispatch(operation: str, request: dict[str, Any]) -> dict[str, Any]:
    if operation == "describe":
        if request not in ({"operation": "describe"}, {"schema_version": "1.0.0", "capability": "adw:describe", "source_sha": request.get("source_sha"), "operation": "describe"}):
            raise ValueError("describe-request-invalid")
        return {"profile": "project-adapter"}
    if operation == "hotfix-build":
        return _hotfix_build(request)
    if operation == "runtime-proof":
        return _runtime_proof(request)
    environment = _identity(operation, request)
    if operation == "config-plan":
        return {"order": "application", "role": "application"}
    if operation == "deploy-status":
        _status()
    elif operation == "health":
        _health(environment)
    elif operation == "readiness":
        _status()
        _health(environment)
    elif operation == "e2e-fast":
        return _e2e(environment, False)
    elif operation == "e2e-full":
        return _e2e(environment, True)
    else:
        raise ValueError("operation-unsupported")
    return {"status": "passed"}


def reason(exc: Exception) -> str:
    value = str(exc)
    return value if re.fullmatch(r"[a-z][a-z0-9-]{0,127}", value) else "project-hook-failure"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        return 2
    try:
        value = json.load(sys.stdin)
        if not isinstance(value, dict):
            raise ValueError("hook-request-invalid")
        result = dispatch(argv[0], value)
    except Blocked as exc:
        response = {"schema_version": "1.0.0", "status": "blocked", "reason_code": reason(exc)}
    except (ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        response = {"schema_version": "1.0.0", "status": "blocked", "reason_code": reason(exc)}
    else:
        response = {"schema_version": "1.0.0", "status": "ok", "result": result}
    json.dump(response, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

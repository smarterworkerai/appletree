#!/usr/bin/env python3
"""Closed project-semantic hook dispatcher for the shared pzagent runtime."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
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
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class Blocked(RuntimeError):
    pass


def _provider_json(path: str, params: dict[str, str]) -> Any:
    endpoint = os.environ.get("DOKPLOY_URL", "").rstrip("/")
    token = os.environ.get("DOKPLOY_TOKEN", "")
    if not endpoint or not token or any(not isinstance(value, str) or not value for value in params.values()):
        raise Blocked("provider-input-absent")
    request = Request(
        endpoint + path + "?" + urlencode(params),
        headers={"x-api-key": token, "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=20) as response:  # nosec B310: operator-bound provider URL
            raw = response.read(2 * 1024 * 1024)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise Blocked("provider-read-failed") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Blocked("provider-response-invalid") from exc


def _compose() -> dict[str, Any]:
    compose_id = os.environ.get("APPLETREE_DOKPLOY_COMPOSE_ID", "")
    value = _provider_json("/api/compose.one", {"composeId": compose_id})
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
    payload = _compose()
    if payload.get("composeStatus") != "done":
        raise Blocked("deployment-not-ready")
    return payload


def _health(environment: str) -> None:
    body = _fetch(ROUTES[environment] + "/")
    if "<title>Apple Tree</title>" not in body or '<canvas id="scene"></canvas>' not in body:
        raise Blocked("application-semantics-invalid")


def _browser_e2e(environment: str, full: bool) -> dict[str, Any]:
    command = ["node", "mise-helper/browser_e2e.mjs", ROUTES[environment], "full" if full else "fast"]
    try:
        completed = subprocess.run(command, text=True, capture_output=True, check=True, timeout=60)
        value = json.loads(completed.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError) as exc:
        raise Blocked("browser-e2e-failed") from exc
    expected = {"status", "selected", "executed", "skipped"}
    if set(value) != expected or value.get("status") != "passed" or value.get("selected") != value.get("executed") or value.get("skipped") != 0:
        raise Blocked("browser-e2e-evidence-invalid")
    if value["selected"] != (2 if full else 1):
        raise Blocked("browser-e2e-count-invalid")
    return value


def _environment_values(raw: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            raise Blocked("runtime-environment-invalid")
        key, value = line.split("=", 1)
        key = key.strip()
        if key in values:
            raise Blocked("runtime-environment-invalid")
        values[key] = value
    return values


def _prove_running_container(payload: dict[str, Any], image: str) -> None:
    project, server = payload.get("appName"), payload.get("serverId")
    if not isinstance(project, str) or not IDENTIFIER.fullmatch(project):
        raise Blocked("runtime-project-identity-absent")
    if server is not None and (not isinstance(server, str) or not IDENTIFIER.fullmatch(server)):
        raise Blocked("runtime-project-identity-absent")
    discovery: dict[str, str] = {"appName": project, "appType": "docker-compose"}
    if server is not None:
        discovery["serverId"] = server
    containers = _provider_json("/api/docker.getContainersByAppNameMatch", discovery)
    if not isinstance(containers, list):
        raise Blocked("runtime-container-discovery-failed")
    matches: list[dict[str, Any]] = []
    for container in containers:
        container_id = container.get("containerId") if isinstance(container, dict) else None
        if not isinstance(container_id, str) or not IDENTIFIER.fullmatch(container_id):
            raise Blocked("runtime-container-discovery-failed")
        inspection = {"containerId": container_id}
        if server is not None:
            inspection["serverId"] = server
        metadata = _provider_json("/api/docker.getConfig", inspection)
        if not isinstance(metadata, dict) or not isinstance(metadata.get("Config"), dict):
            raise Blocked("runtime-container-inspection-failed")
        labels = metadata["Config"].get("Labels")
        if not isinstance(labels, dict) or labels.get("com.docker.compose.project") != project:
            raise Blocked("runtime-image-identity-or-health-mismatch")
        if labels.get("com.docker.compose.service") == "appletree":
            matches.append(metadata)
    if len(matches) != 1:
        raise Blocked("runtime-container-cardinality-differs")
    metadata = matches[0]
    state = metadata.get("State")
    if (metadata["Config"].get("Image") != image or not isinstance(state, dict) or state.get("Status") != "running"
            or not isinstance(state.get("Health"), dict) or state["Health"].get("Status") != "healthy"):
        raise Blocked("runtime-image-identity-or-health-mismatch")


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
    _prove_running_container(payload, image)
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
        return _browser_e2e(environment, False)
    elif operation == "e2e-full":
        return _browser_e2e(environment, True)
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

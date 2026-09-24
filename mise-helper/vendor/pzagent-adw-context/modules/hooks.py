"""Invoke exact-HEAD project hooks through a bounded, redacted JSON ABI."""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from .common import ContractError, IDENTIFIER, ensure_contained, git_common_state

MAX_OUTPUT = 1024 * 1024
IMAGE_ASSIGNMENT = re.compile(
    r"^[A-Z][A-Z0-9_]{1,127}=ghcr\.io/[a-z0-9._/-]+"
    r"(?::hotfix-[0-9a-f]{12}|@sha256:[0-9a-f]{64})$"
)
SECRET_KEY = re.compile(r"(?i)(secret|token|password|credential|endpoint|environment|compose.?id|api.?key)")
SAFE_RESULT_KEYS = {"images", "order", "profile", "role", "status", "selected", "executed", "skipped"}
ROLE_VALUE = re.compile(r"^[a-z]{3,32}$")
ORDER_VALUE = re.compile(r"^[a-z]+(?: [a-z]+)*(?:; [a-z]+(?: [a-z]+)*){0,3}$")
REASON_CODE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+){0,15}$")
_MISSING = object()


class HookFailure(RuntimeError):
    def __init__(self, status: str, reason: str, reason_code: str = "project-hook-failure"):
        super().__init__(reason)
        self.status = status
        self.reason_code = reason_code


def request(
    capability: str,
    *,
    environment: object = _MISSING,
    target: object = _MISSING,
    **fields: Any,
) -> dict[str, Any]:
    """Build the schema-bound project-hook request independent of package provenance."""
    payload: dict[str, Any] = {"schema_version": "1.0.0", "capability": capability}
    if environment is not _MISSING:
        payload["environment"] = environment
    if target is not _MISSING:
        payload["target"] = target
    if set(payload) & set(fields):
        raise ContractError("project-hook request field overrides protocol identity")
    return {**payload, **fields}


def _diagnostic_event(repo: Path, capability: str, operation: str, status: str, reason_code: str | None = None) -> None:
    run_id = os.environ.get("ADW_RUN_ID", f"adhoc-{os.getpid()}")
    if not IDENTIFIER.fullmatch(run_id):
        run_id = f"adhoc-{os.getpid()}"
    payload: dict[str, Any] = {
        "event": "pzagent-hook",
        "capability": capability,
        "operation": operation,
        "status": status,
    }
    if reason_code is not None:
        if not REASON_CODE.fullmatch(reason_code):
            reason_code = "project-hook-failure"
        payload["reason_code"] = reason_code
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path = git_common_state(repo, "diagnostics") / f"{run_id}.jsonl"
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True, check=False,
    )
    if result.returncode:
        raise ContractError("hook source identity could not be proven")
    return result.stdout.strip()


def prove_source(repo: Path, adapter: dict[str, Any]) -> str:
    head = _git(repo, "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ContractError("hook source HEAD is invalid")
    remote = _git(repo, "remote", "get-url", "origin")
    expected = adapter["repository"]["id"]
    normalized = remote.removesuffix(".git").replace("git@github.com:", "https://github.com/")
    if not normalized.endswith("github.com/" + expected):
        raise ContractError("hook repository identity differs from adapter")
    watched = [".hermes/pzagent-adapter.json"]
    dispatcher = adapter["hooks"]["dispatcher"]["argv"]
    watched.extend(arg for arg in dispatcher if "/" in arg and not arg.startswith("-"))
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--", *watched], cwd=repo,
        text=True, capture_output=True, check=False,
    )
    if dirty.returncode or dirty.stdout.strip():
        raise ContractError("hook adapter or executable differs from exact HEAD")
    return head


def _argv(repo: Path, adapter: dict[str, Any], capability: str) -> tuple[list[str], dict[str, Any]]:
    operation = adapter["hooks"]["operations"].get(capability)
    if operation is None:
        raise ContractError("supported project capability has no hook operation")
    dispatcher = adapter["hooks"]["dispatcher"]
    raw = dispatcher["argv"]
    executable = raw[0]
    if "/" in executable:
        executable = str(ensure_contained(repo, executable))
        if not Path(executable).is_file():
            raise ContractError("hook executable is missing")
    elif executable not in dispatcher["path_tools"]:
        raise ContractError("hook executable is not PATH-allowlisted")
    argv = [executable]
    for argument in raw[1:]:
        if "/" in argument and not argument.startswith("-"):
            path = ensure_contained(repo, argument)
            if not path.is_file():
                raise ContractError("hook argv path is missing")
            argv.append(str(path))
        else:
            argv.append(argument)
    argv.append(operation["operation"])
    return argv, operation


def _redact_stderr(raw: str) -> str:
    # Project hooks may invoke provider CLIs whose progress/error output can
    # contain credentials, private endpoints, resource IDs, or payload values.
    # Keyword filtering cannot make arbitrary child stderr content-safe, so the
    # shared boundary exposes only the fact that progress was emitted.
    return "[redacted hook progress]" if raw else ""


def _safe_result(value: Any, keys: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ContractError("hook result fields differ from the declared closed schema")
    if not set(keys) <= SAFE_RESULT_KEYS:
        raise ContractError("hook result schema contains a prohibited evidence field")
    for key, item in value.items():
        if SECRET_KEY.search(key):
            raise ContractError("hook result contains a prohibited evidence field")
        valid = (
            (key == "images" and isinstance(item, list) and len(item) <= 100 and all(
                isinstance(entry, str) and IMAGE_ASSIGNMENT.fullmatch(entry) for entry in item
            ))
            or (key == "status" and item == "passed")
            or (key in {"selected", "executed", "skipped"} and type(item) is int and 0 <= item <= 10000)
            or (key == "profile" and item == "project-adapter")
            or (key == "role" and isinstance(item, str) and ROLE_VALUE.fullmatch(item))
            or (key == "order" and isinstance(item, str) and ORDER_VALUE.fullmatch(item))
        )
        if not valid:
            raise ContractError("hook result contains an unsafe or unbounded value")
    return value


def _decode_response(raw: str, result_keys: list[str]) -> dict[str, Any]:
    try:
        response = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ContractError("project hook stdout is not one JSON document") from exc
    if not isinstance(response, dict) or response.get("schema_version") != "1.0.0":
        raise ContractError("project hook response identity is invalid")
    status = response.get("status")
    if status == "ok":
        if set(response) != {"schema_version", "status", "result"}:
            raise ContractError("project hook success response is not closed")
        return {"status": "ok", "result": _safe_result(response["result"], result_keys)}
    if status in {"blocked", "failed"}:
        if set(response) != {"schema_version", "status", "reason_code"}:
            raise ContractError("project hook failure response is not closed")
        reason_code = response["reason_code"]
        if not isinstance(reason_code, str) or len(reason_code) > 128 or not REASON_CODE.fullmatch(reason_code):
            raise ContractError("project hook failure reason code is invalid")
        raise HookFailure(status, f"project hook {status}: {reason_code}", reason_code)
    raise ContractError("project hook response identity is invalid")


def invoke(
    repo: Path,
    adapter: dict[str, Any],
    capability: str,
    request: dict[str, Any],
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    source_sha = prove_source(repo, adapter)
    argv, operation = _argv(repo, adapter, capability)
    _diagnostic_event(repo, capability, operation["operation"], "started")
    closed_request = {
        **request,
        "source_sha": source_sha,
        "operation": operation["operation"],
    }
    payload = json.dumps(closed_request, sort_keys=True, separators=(",", ":")) + "\n"
    child_env=os.environ.copy()
    if extra_env:
        child_env.update(extra_env)
    process = subprocess.Popen(
        argv, cwd=repo, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=child_env,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(payload, timeout=operation["timeout_seconds"])
    except subprocess.TimeoutExpired as exc:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        _diagnostic_event(repo, capability, operation["operation"], "failed", "project-hook-timeout")
        raise ContractError("project hook process tree timed out and was terminated") from exc
    progress = _redact_stderr(stderr)
    if progress:
        print(progress, file=sys.stderr)
    if len(stdout.encode()) > MAX_OUTPUT:
        raise ContractError("project hook stdout exceeds the shared bound")
    if process.returncode:
        _diagnostic_event(repo, capability, operation["operation"], "failed", "project-hook-process-failed")
        raise HookFailure("failed", "project hook process reported failure", "project-hook-process-failed")
    try:
        decoded = _decode_response(stdout, operation["result_keys"])
    except HookFailure as failure:
        _diagnostic_event(repo, capability, operation["operation"], failure.status, failure.reason_code)
        raise
    except ContractError:
        _diagnostic_event(repo, capability, operation["operation"], "failed", "project-hook-response-invalid")
        raise
    _diagnostic_event(repo, capability, operation["operation"], "passed")
    return {"status": "ok", "source_sha": source_sha, "result": decoded["result"]}

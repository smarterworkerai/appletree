#!/usr/bin/env python3
"""Reference validator and evidence writer for ADW mise tasks."""
from __future__ import annotations

import argparse
from collections import namedtuple
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid
from typing import Any, Iterable
import urllib.request


CONTRACT_NAME = "adw-mise-task-contract"
CONTRACT_VERSION = "2.0.0"
SCHEMA_VERSION = "2.0.0"
EXIT_FAILED = 1
EXIT_BLOCKED = 20
EXIT_CONTRACT_ERROR = 21

STATUSES = {
    "passed",
    "failed",
    "skipped",
    "unsupported",
    "blocked",
    "contract-error",
}
SIDE_EFFECTS = {"read-only", "local-write", "remote-write", "destructive"}
SOURCE_LAYERS = {"generic", "context", "project"}
SOURCE_FIELDS = {"layer", "ref", "checksum", "path"}
CAPABILITY_FIELDS = {"status", "side_effect", "environments", "source"}
TOP_LEVEL_FIELDS = {
    "schema_version",
    "contract",
    "project",
    "evidence",
    "environments",
    "sources",
    "capabilities",
    "verification",
    "required_secret_env",
    "context_freshness",
}
CANONICAL_TASKS = {
    "adw:describe",
    "adw:check",
    "adw:install",
    "adw:build",
    "adw:lint",
    "adw:static-analysis",
    "adw:test:unit",
    "adw:test:integration:fast",
    "adw:test:integration:full",
    "adw:verify:minimal",
    "adw:verify:full",
    "adw:deploy:config:pull",
    "adw:deploy:config:plan",
    "adw:deploy:config:apply",
    "adw:deploy:apply",
    "adw:deploy:status",
    "adw:health",
    "adw:readiness",
    "adw:test:e2e:fast",
    "adw:test:e2e:full",
    "adw:validate-deployment",
    "adw:hotfix:apply",
    "adw:hotfix:restore",
    "adw:context:check",
    "adw:context:sync",
}
TASK_SIDE_EFFECTS = {
    "adw:describe": "read-only",
    "adw:check": "read-only",
    "adw:install": "local-write",
    "adw:build": "local-write",
    "adw:lint": "local-write",
    "adw:static-analysis": "local-write",
    "adw:test:unit": "local-write",
    "adw:test:integration:fast": "local-write",
    "adw:test:integration:full": "local-write",
    "adw:verify:minimal": "local-write",
    "adw:verify:full": "local-write",
    "adw:deploy:config:pull": "local-write",
    "adw:deploy:config:plan": "read-only",
    "adw:deploy:config:apply": "remote-write",
    "adw:deploy:apply": "remote-write",
    "adw:deploy:status": "read-only",
    "adw:health": "read-only",
    "adw:readiness": "read-only",
    "adw:test:e2e:fast": "remote-write",
    "adw:test:e2e:full": "remote-write",
    "adw:validate-deployment": "remote-write",
    "adw:hotfix:apply": "remote-write",
    "adw:hotfix:restore": "remote-write",
    "adw:context:check": "read-only",
    "adw:context:sync": "local-write",
}
ENVIRONMENT_TASKS = {
    "adw:deploy:config:pull",
    "adw:deploy:config:plan",
    "adw:deploy:config:apply",
    "adw:deploy:apply",
    "adw:deploy:status",
    "adw:health",
    "adw:readiness",
    "adw:test:e2e:fast",
    "adw:test:e2e:full",
    "adw:validate-deployment",
    "adw:hotfix:apply",
    "adw:hotfix:restore",
}
CORE_TASKS = {"adw:describe", "adw:check"}
LOCAL_QUALITY_TASKS = {
    "adw:build",
    "adw:lint",
    "adw:static-analysis",
    "adw:test:unit",
    "adw:test:integration:fast",
}
MINIMAL_SMOKE_TASKS = {"adw:build", "adw:test:unit", "adw:test:integration:fast"}
SECRET_KEY_PATTERN = re.compile(r"(?:password|token|secret|credential|private[_-]?key)", re.I)
ALLOWED_SECRET_METADATA_KEYS = {"required_secret_env"}
CHECKSUM_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
COMPATIBILITY_PATTERN = re.compile(r"^>=(\d+)\.(\d+)\.(\d+),<(\d+)\.(\d+)\.(\d+)$")
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
LOGICAL_TARGET_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
TOP_LEVEL_FIELDS = {
    "schema_version",
    "contract",
    "project",
    "evidence",
    "environments",
    "sources",
    "capabilities",
    "verification",
    "required_secret_env",
    "context_freshness",
}
SOURCE_FIELDS = {"layer", "ref", "checksum", "path"}
CAPABILITY_FIELDS = {"status", "side_effect", "environments", "source"}

Result = namedtuple("Result", "exit_code evidence payload")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _run_id(explicit: str | None) -> str:
    candidate = explicit or os.environ.get("ADW_RUN_ID") or f"adw-{uuid.uuid4()}"
    if not RUN_ID_PATTERN.fullmatch(candidate):
        raise ValueError("run ID must be a safe 1-128 character identifier")
    return candidate


def _new_run_id() -> str:
    return f"adw-{uuid.uuid4()}"


def _manifest_path(project_root: Path) -> Path:
    return project_root / ".hermes" / "adw-task-manifest.json"


def _load_manifest(project_root: Path) -> dict[str, Any]:
    path = _manifest_path(project_root)
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("manifest root must be an object")
    return value


def _source_revision(project_root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return completed.stdout.strip() or None
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def _safe_task_filename(task: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", task).strip("_") or "task"


def _evidence_root(project_root: Path, manifest: dict[str, Any] | None) -> Path:
    configured = ".hermes/evidence"
    if manifest:
        evidence = manifest.get("evidence")
        if isinstance(evidence, dict) and isinstance(evidence.get("root"), str):
            configured = evidence["root"]
    root = (project_root / configured).resolve()
    project = project_root.resolve()
    if root != project and project not in root.parents:
        raise ValueError("evidence.root must remain inside the project")
    return root


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _finding(code: str, message: str, severity: str = "error") -> dict[str, str]:
    return {"code": code, "severity": severity, "message": message}


def _arguments(environment: str | None = None, target: str | None = None) -> dict[str, str]:
    value = {"environment": environment} if environment else {}
    if target:
        value["target"] = target
    return value


def _safe_effective_source(manifest: dict[str, Any] | None, task: str) -> dict[str, str] | None:
    if not manifest or not isinstance(manifest.get("capabilities"), dict):
        return None
    capability = manifest["capabilities"].get(task)
    if not isinstance(capability, dict):
        return None
    source = capability.get("source")
    if not isinstance(source, dict) or _validate_source(source, f"capabilities.{task}.source"):
        return None
    return {field: source[field] for field in SOURCE_FIELDS}


def _build_evidence(
    project_root: Path,
    manifest: dict[str, Any] | None,
    *,
    task: str,
    status: str,
    exit_code: int,
    run_id: str | None,
    findings: list[dict[str, str]] | None = None,
    arguments: dict[str, Any] | None = None,
    children: Iterable[str] | None = None,
    freshness: dict[str, Any] | None = None,
    started_at: str | None = None,
) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError(f"invalid evidence status: {status}")
    return {
        "schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "run_id": _run_id(run_id),
        "task": task,
        "status": status,
        "exit_code": exit_code,
        "started_at": started_at or _now(),
        "finished_at": _now(),
        "source_revision": _source_revision(project_root),
        "effective_source": _safe_effective_source(manifest, task),
        "arguments": arguments or {},
        "findings": findings or [],
        "children": list(children or []),
        **({"freshness": freshness} if freshness is not None else {}),
    }


def _persist(project_root: Path, manifest: dict[str, Any] | None, evidence: dict[str, Any]) -> Path:
    try:
        root = _evidence_root(project_root, manifest)
    except ValueError:
        root = project_root.resolve() / ".hermes" / "evidence"
    directory = (root / evidence["run_id"]).resolve()
    if directory != root and root not in directory.parents:
        raise ValueError("evidence run directory must remain inside evidence.root")
    path = directory / f"{_safe_task_filename(evidence['task'])}.json"
    _atomic_write_json(path, evidence)
    return path


def _result(
    project_root: Path,
    manifest: dict[str, Any] | None,
    *,
    task: str,
    status: str,
    exit_code: int,
    run_id: str | None,
    findings: list[dict[str, str]] | None = None,
    arguments: dict[str, Any] | None = None,
    children: Iterable[str] | None = None,
    payload: dict[str, Any] | None = None,
    freshness: dict[str, Any] | None = None,
    started_at: str | None = None,
) -> Result:
    try:
        resolved_run_id = _run_id(run_id)
    except ValueError:
        resolved_run_id = _new_run_id()
        status = "contract-error"
        exit_code = EXIT_CONTRACT_ERROR
        findings = [_finding("evidence.run_id", "run ID contains unsafe characters")] + list(findings or [])
    evidence = _build_evidence(
        project_root,
        manifest,
        task=task,
        status=status,
        exit_code=exit_code,
        run_id=resolved_run_id,
        findings=findings,
        arguments=arguments,
        children=children,
        freshness=freshness,
        started_at=started_at,
    )
    _persist(project_root, manifest, evidence)
    return Result(exit_code, evidence, payload or {})


def _validate_source(source: Any, location: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not isinstance(source, dict):
        return [_finding("source.type", f"{location} must be an object")]
    extra_fields = sorted(set(source) - SOURCE_FIELDS)
    if extra_fields:
        findings.append(_finding("source.additional", f"{location} contains unknown fields: {', '.join(extra_fields)}"))
    layer = source.get("layer")
    if layer not in SOURCE_LAYERS:
        findings.append(_finding("source.layer", f"{location}.layer must be one of {sorted(SOURCE_LAYERS)}"))
    source_ref = source.get("ref")
    if not isinstance(source_ref, str) or not source_ref:
        findings.append(_finding("source.ref", f"{location}.ref must be a non-empty string"))
    elif layer in {"generic", "context"} and not GIT_COMMIT_PATTERN.fullmatch(source_ref):
        findings.append(_finding("source.ref", f"{location}.ref must be an immutable 40-character Git commit SHA for {layer} sources"))
    elif layer == "project" and source_ref != "HEAD" and not GIT_COMMIT_PATTERN.fullmatch(source_ref):
        findings.append(_finding("source.ref", f"{location}.ref must be HEAD or an exact 40-character Git commit SHA for project sources"))
    checksum = source.get("checksum")
    if not isinstance(checksum, str) or not CHECKSUM_PATTERN.fullmatch(checksum):
        findings.append(_finding("source.checksum", f"{location}.checksum must be sha256:<64 lowercase hex>"))
    source_path = source.get("path")
    if not isinstance(source_path, str) or not source_path:
        findings.append(_finding("source.path", f"{location}.path must be a non-empty project-relative path"))
    else:
        parsed_path = Path(source_path)
        if parsed_path.is_absolute() or ".." in parsed_path.parts:
            findings.append(_finding("source.path", f"{location}.path must be a non-escaping project-relative path"))
    return findings


def _find_secret_bearing_fields(value: Any, path: str = "$") -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if SECRET_KEY_PATTERN.search(str(key)) and key not in ALLOWED_SECRET_METADATA_KEYS:
                findings.append(_finding("secret.field", f"secret-bearing field is forbidden at {child_path}"))
                continue
            findings.extend(_find_secret_bearing_fields(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(_find_secret_bearing_fields(child, f"{path}[{index}]"))
    return findings


def validate_manifest(manifest: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    extra_fields = sorted(set(manifest) - TOP_LEVEL_FIELDS)
    if extra_fields:
        findings.append(_finding("schema.additional", f"manifest contains unknown fields: {', '.join(extra_fields)}"))
    if manifest.get("schema_version") != SCHEMA_VERSION:
        findings.append(_finding("schema.version", f"schema_version must equal {SCHEMA_VERSION}"))
    contract = manifest.get("contract")
    if not isinstance(contract, dict):
        findings.append(_finding("contract.type", "contract must be an object"))
    else:
        extra_contract = sorted(set(contract) - {"name", "version", "compatible"})
        if extra_contract:
            findings.append(_finding("contract.additional", f"contract contains unknown fields: {', '.join(extra_contract)}"))
        if contract.get("name") != CONTRACT_NAME:
            findings.append(_finding("contract.name", f"contract.name must equal {CONTRACT_NAME}"))
        version = contract.get("version")
        if version != CONTRACT_VERSION:
            findings.append(_finding("contract.version", f"contract.version must equal consumed version {CONTRACT_VERSION}"))
        compatible = contract.get("compatible")
        match = COMPATIBILITY_PATTERN.fullmatch(compatible) if isinstance(compatible, str) else None
        if match is None:
            findings.append(_finding("contract.compatible", "contract.compatible must use >=x.y.z,<x.y.z syntax"))
        else:
            parts = tuple(int(value) for value in match.groups())
            lower, upper = parts[:3], parts[3:]
            current = tuple(int(value) for value in CONTRACT_VERSION.split("."))
            if not lower <= current < upper:
                findings.append(_finding("contract.compatible", f"contract.compatible does not accept {CONTRACT_VERSION}"))
    project = manifest.get("project")
    if isinstance(project, dict) and set(project) - {"id"}:
        findings.append(_finding("project.additional", "project contains unknown fields"))
    if not isinstance(project, dict) or not isinstance(project.get("id"), str) or not project["id"]:
        findings.append(_finding("project.id", "project.id must be a non-empty string"))
    evidence = manifest.get("evidence")
    if isinstance(evidence, dict) and set(evidence) - {"root"}:
        findings.append(_finding("evidence.additional", "evidence contains unknown fields"))
    if not isinstance(evidence, dict) or not isinstance(evidence.get("root"), str) or not evidence["root"]:
        findings.append(_finding("evidence.root", "evidence.root must be a non-empty string"))
    else:
        evidence_path = Path(evidence["root"])
        if evidence_path.is_absolute() or ".." in evidence_path.parts:
            findings.append(_finding("evidence.root", "evidence.root must be a project-relative non-escaping path"))
    environments = manifest.get("environments")
    if not isinstance(environments, list) or any(not isinstance(item, str) or not item for item in environments):
        findings.append(_finding("environments.type", "environments must be an array of non-empty strings"))
        environments_set: set[str] = set()
    else:
        environments_set = set(environments)
        if len(environments_set) != len(environments):
            findings.append(_finding("environments.unique", "environments must contain unique values"))
    sources = manifest.get("sources")
    registered_sources: set[str] = set()
    if not isinstance(sources, list) or not sources:
        findings.append(_finding("sources.type", "sources must be a non-empty array"))
    else:
        for index, source in enumerate(sources):
            findings.extend(_validate_source(source, f"sources[{index}]"))
            if isinstance(source, dict):
                registered_sources.add(json.dumps(source, sort_keys=True, separators=(",", ":")))
    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, dict):
        findings.append(_finding("capabilities.type", "capabilities must be an object"))
        capabilities = {}
    for core_task in sorted(CORE_TASKS):
        capability = capabilities.get(core_task)
        if not isinstance(capability, dict) or capability.get("status") != "supported":
            findings.append(_finding("capabilities.core", f"{core_task} must be declared supported"))
    for missing_task in sorted(CANONICAL_TASKS - set(capabilities)):
        findings.append(_finding("capabilities.missing", f"canonical capability must be declared supported or unsupported: {missing_task}"))
    for task, capability in capabilities.items():
        if task not in CANONICAL_TASKS:
            findings.append(_finding("capabilities.name", f"unknown canonical task {task}"))
        if not isinstance(capability, dict):
            findings.append(_finding("capabilities.type", f"capability {task} must be an object"))
            continue
        extra_capability = sorted(set(capability) - CAPABILITY_FIELDS)
        if extra_capability:
            findings.append(_finding("capability.additional", f"{task} contains unknown fields: {', '.join(extra_capability)}"))
        if capability.get("status") not in {"supported", "unsupported"}:
            findings.append(_finding("capabilities.status", f"{task}.status must be supported or unsupported"))
        side_effect = capability.get("side_effect")
        if side_effect not in SIDE_EFFECTS:
            findings.append(_finding("capabilities.side_effect", f"{task}.side_effect is invalid"))
        elif task in TASK_SIDE_EFFECTS and side_effect != TASK_SIDE_EFFECTS[task]:
            findings.append(
                _finding(
                    "capability.side_effect",
                    f"{task}.side_effect must be {TASK_SIDE_EFFECTS[task]}",
                )
            )
        task_environments = capability.get("environments")
        if not isinstance(task_environments, list):
            findings.append(_finding("capabilities.environments", f"{task}.environments must be an array"))
        else:
            if len(set(task_environments)) != len(task_environments):
                findings.append(_finding("capabilities.environments", f"{task}.environments must contain unique values"))
            unknown = sorted(set(task_environments) - environments_set)
            if unknown:
                findings.append(_finding("capabilities.environments", f"{task} references unknown environments: {', '.join(unknown)}"))
            if capability.get("status") == "supported" and task in ENVIRONMENT_TASKS and not task_environments:
                findings.append(
                    _finding("capabilities.environments", f"supported environment-aware task {task} requires an environment scope")
                )
        capability_source = capability.get("source")
        findings.extend(_validate_source(capability_source, f"capabilities.{task}.source"))
        if isinstance(capability_source, dict):
            source_key = json.dumps(capability_source, sort_keys=True, separators=(",", ":"))
            if source_key not in registered_sources:
                findings.append(
                    _finding("source.registry", f"capability source for {task} is missing from the sources registry")
                )
    verification = manifest.get("verification")
    if not isinstance(verification, dict):
        findings.append(_finding("verification.type", "verification must be an object"))
    else:
        extra_verification = sorted(set(verification) - {"minimal", "full"})
        if extra_verification:
            findings.append(_finding("verification.additional", f"verification contains unknown fields: {', '.join(extra_verification)}"))
        for name in ("minimal", "full"):
            children = verification.get(name)
            if not isinstance(children, list) or not children:
                findings.append(_finding("verification.children", f"verification.{name} must be a non-empty array"))
                continue
            if len(set(children)) != len(children):
                findings.append(_finding("verification.unique", f"verification.{name} must contain unique tasks"))
            for child in children:
                if child not in LOCAL_QUALITY_TASKS:
                    findings.append(_finding("verification.child", f"verification.{name} may contain only local quality tasks, not {child}"))
                capability = capabilities.get(child)
                if not isinstance(capability, dict):
                    findings.append(_finding("verification.capability", f"verification.{name} references undeclared task {child}"))
                elif capability.get("status") != "supported":
                    findings.append(_finding("verification.unsupported", f"verification.{name} references unsupported task {child}"))
        minimal_children = verification.get("minimal")
        if isinstance(minimal_children, list) and not (set(minimal_children) & MINIMAL_SMOKE_TASKS):
            findings.append(
                _finding("verification.minimal", "verification.minimal must include a supported build or test smoke capability")
            )
        full_children = verification.get("full")
        if isinstance(full_children, list):
            supported_quality = {
                task
                for task in LOCAL_QUALITY_TASKS
                if isinstance(capabilities.get(task), dict)
                and capabilities[task].get("status") == "supported"
            }
            missing_quality = sorted(supported_quality - set(full_children))
            if missing_quality:
                findings.append(
                    _finding(
                        "verification.full",
                        f"verification.full omits supported local quality tasks: {', '.join(missing_quality)}",
                    )
                )
    required_secret_env = manifest.get("required_secret_env", [])
    context_freshness = manifest.get("context_freshness")
    if context_freshness is not None:
        if not isinstance(sources, list) or sum(
            isinstance(source, dict) and source.get("layer") == "generic" for source in sources
        ) != 1:
            findings.append(_finding("freshness.source", "context_freshness requires exactly one generic source"))
        upstream = context_freshness.get("upstream") if isinstance(context_freshness, dict) else None
        if not isinstance(context_freshness, dict) or set(context_freshness) != {"policy", "upstream"} or context_freshness.get("policy") not in {"advisory", "require-current-compatible"} or not isinstance(upstream, dict) or set(upstream) != {"repository", "branch", "index_path"} or upstream.get("repository") != "smarterworkerai/agentic-delivery" or upstream.get("branch") != "main" or not isinstance(upstream.get("index_path"), str) or Path(upstream["index_path"]).is_absolute() or ".." in Path(upstream["index_path"]).parts:
            findings.append(_finding("freshness.config", "context_freshness requires trusted smarterworkerai/agentic-delivery main upstream"))
    required_secret_env = manifest.get("required_secret_env", [])
    if not isinstance(required_secret_env, list) or any(
        not isinstance(item, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", item)
        for item in required_secret_env
    ):
        findings.append(_finding("secret.names", "required_secret_env must contain environment-variable names only"))
    elif len(set(required_secret_env)) != len(required_secret_env):
        findings.append(_finding("secret.unique", "required_secret_env must contain unique values"))
    findings.extend(_find_secret_bearing_fields(manifest))
    return findings


def _validate_source_files(project_root: Path, manifest: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    sources = manifest.get("sources")
    if not isinstance(sources, list):
        return findings
    project = project_root.resolve()
    for source in sources:
        if not isinstance(source, dict):
            continue
        source_path = source.get("path")
        checksum = source.get("checksum")
        if not isinstance(source_path, str) or not isinstance(checksum, str):
            continue
        source_key = (source_path, checksum)
        if source_key in seen:
            continue
        seen.add(source_key)
        candidate = (project / source_path).resolve()
        if candidate != project and project not in candidate.parents:
            findings.append(_finding("source.path", f"declared source escapes project root: {source_path}"))
            continue
        if not candidate.is_file():
            findings.append(_finding("source.missing", f"declared source file is missing: {source_path}"))
            continue
        actual_checksum = "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
        if actual_checksum != checksum:
            findings.append(
                _finding(
                    "source.checksum",
                    f"source checksum mismatch for {source_path}: expected {checksum}, got {actual_checksum}",
                )
            )
    return findings


def _version(value: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", value)
    return tuple(int(part) for part in match.groups()) if match else None


def _resolve_freshness(root: Path, manifest: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[dict[str, str]]]:
    config = manifest.get("context_freshness")
    if not isinstance(config, dict) or config.get("policy") not in {"advisory", "require-current-compatible"}:
        return None, None, [_finding("freshness.config", "context_freshness requires a valid policy")]
    upstream = config.get("upstream")
    if isinstance(upstream, dict):
        repository, branch, path = upstream.get("repository"), upstream.get("branch"), upstream.get("index_path")
        if set(config) != {"policy", "upstream"} or repository != "smarterworkerai/agentic-delivery" or branch != "main" or not isinstance(path, str) or Path(path).is_absolute() or ".." in Path(path).parts:
            return config, None, [_finding("freshness.config", "trusted upstream must be smarterworkerai/agentic-delivery main with a safe index path")]
        url = f"https://raw.githubusercontent.com/{repository}/{branch}/{path}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url), timeout=10) as response:
                raw = response.read()
            index = json.loads(raw)
        except Exception as exc:
            return config, None, [_finding("freshness.lookup", f"trusted upstream index unavailable ({type(exc).__name__})")]
        config = {**config, "lookup_source": url}
    else:
        return config, None, [_finding("freshness.config", "context_freshness requires trusted upstream")]
    if not isinstance(index, dict) or index.get("schema_version") != "1.0.0" or not isinstance(index.get("releases"), list):
        return config, None, [_finding("freshness.index", "trusted index has an invalid shape")]
    match = COMPATIBILITY_PATTERN.fullmatch(manifest["contract"]["compatible"])
    lower, upper = tuple(int(value) for value in match.groups()[:3]), tuple(int(value) for value in match.groups()[3:])
    compatible: list[dict[str, Any]] = []
    for release in index["releases"]:
        if not isinstance(release, dict) or set(release) - {"version", "ref", "checksum", "snapshot_path", "required"}:
            return config, None, [_finding("freshness.release", "trusted index contains an invalid release")]
        version = release.get("version")
        snapshot_path = release.get("snapshot_path")
        if not isinstance(version, str) or _version(version) is None or not isinstance(release.get("ref"), str) or not GIT_COMMIT_PATTERN.fullmatch(release["ref"]):
            return config, None, [_finding("freshness.release.ref", "trusted releases require SemVer and immutable 40-character refs")]
        if not isinstance(release.get("checksum"), str) or not CHECKSUM_PATTERN.fullmatch(release["checksum"]) or not isinstance(snapshot_path, str) or Path(snapshot_path).is_absolute() or ".." in Path(snapshot_path).parts:
            return config, None, [_finding("freshness.release", "trusted release checksum or snapshot path is invalid")]
        if lower <= _version(version) < upper:
            if snapshot_path != "skills/adw/adw-core/assets/mise/v2":
                return config, None, [_finding("freshness.release", "compatible release must point to the v2 snapshot") ]
            compatible.append(release)
    return config, max(compatible, key=lambda item: _version(item["version"])) if compatible else None, []


def _fetch_release_snapshot(release: dict[str, Any], destination: Path) -> list[dict[str, str]]:
    """Download one immutable upstream archive and safely materialize its declared subtree."""
    repository, ref, snapshot_path = "smarterworkerai/agentic-delivery", release["ref"], release["snapshot_path"]
    url = f"https://codeload.github.com/{repository}/tar.gz/{ref}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url), timeout=30) as response:
            archive_bytes = response.read()
        archive = tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz")
    except Exception as exc:
        return [_finding("freshness.snapshot", f"trusted snapshot unavailable ({type(exc).__name__})")]
    prefix_parts = tuple(Path(snapshot_path).parts)
    extracted = 0
    try:
        with archive:
            for member in archive.getmembers():
                parts = tuple(Path(member.name).parts)
                if len(parts) <= len(prefix_parts) or parts[1:1 + len(prefix_parts)] != prefix_parts:
                    continue
                relative_parts = parts[1 + len(prefix_parts):]
                if not relative_parts:
                    if member.isdir():
                        continue
                    return [_finding("freshness.snapshot", "trusted snapshot archive contains an unsafe entry")]
                relative = Path(*relative_parts)
                if member.isdir():
                    continue
                if relative.is_absolute() or ".." in relative.parts or not member.isfile():
                    return [_finding("freshness.snapshot", "trusted snapshot archive contains an unsafe entry")]
                source = archive.extractfile(member)
                if source is None:
                    return [_finding("freshness.snapshot", "trusted snapshot archive cannot be read")]
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                extracted += 1
    except (OSError, tarfile.TarError) as exc:
        return [_finding("freshness.snapshot", f"trusted snapshot extraction failed ({type(exc).__name__})")]
    return [] if extracted else [_finding("freshness.snapshot", "trusted snapshot does not contain the declared path")]


def context_check(project_root: Path | str, run_id: str | None = None) -> Result:
    root = Path(project_root)
    started = _now()
    try:
        manifest = _load_manifest(root)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        return _result(root, None, task="adw:context:check", status="blocked", exit_code=EXIT_BLOCKED, run_id=run_id, findings=[_finding("manifest.missing", f"ADW task manifest unavailable ({type(exc).__name__})")], started_at=started)
    findings = validate_manifest(manifest)
    capability = manifest.get("capabilities", {}).get("adw:context:check")
    if not findings and (not isinstance(capability, dict) or capability.get("status") != "supported"):
        return _result(root, manifest, task="adw:context:check", status="unsupported", exit_code=0, run_id=run_id, findings=[_finding("capability.unsupported", "adw:context:check is unsupported by this project", "info")], started_at=started)
    config, latest, lookup_findings = _resolve_freshness(root, manifest) if not findings else (None, None, [])
    findings.extend(lookup_findings)
    if findings:
        return _result(root, manifest, task="adw:context:check", status="blocked" if any(item["code"] == "freshness.lookup" for item in findings) else "contract-error", exit_code=EXIT_BLOCKED if any(item["code"] == "freshness.lookup" for item in findings) else EXIT_CONTRACT_ERROR, run_id=run_id, findings=findings, freshness={"verdict": "lookup-unavailable", "lookup_source": config.get("lookup_source") if config else None}, started_at=started)
    generic = next(source for source in manifest["sources"] if source.get("layer") == "generic")
    if latest is not None and generic["ref"] == latest["ref"] and generic["checksum"] != latest["checksum"]:
        return _result(root, manifest, task="adw:context:check", status="contract-error", exit_code=EXIT_CONTRACT_ERROR,
                       run_id=run_id, findings=[_finding("freshness.checksum", "pinned generic ref and release checksum disagree")],
                       freshness={"verdict": "pin-mismatch", "lookup_source": config.get("lookup_source") if config else None}, started_at=started)
    verdict = "incompatible-major" if latest is None else "current" if generic["ref"] == latest["ref"] else "update-required" if latest.get("required") else "update-available"
    freshness = {"verdict": verdict, "lookup_source": config["lookup_source"], "pin": {"ref": generic["ref"], "checksum": generic["checksum"]}, "latest": {key: latest[key] for key in ("version", "ref", "checksum")} if latest else None}
    strict = config["policy"] == "require-current-compatible" and verdict in {"update-available", "update-required", "lookup-unavailable"}
    return _result(root, manifest, task="adw:context:check", status="blocked" if strict else "passed", exit_code=EXIT_BLOCKED if strict else 0, run_id=run_id, findings=[_finding("freshness.verdict", verdict, "warning" if verdict != "current" else "info")], freshness=freshness, payload=freshness, started_at=started)


def context_sync(project_root: Path | str, run_id: str | None = None) -> Result:
    root = Path(project_root)
    check_result = context_check(root, run_id=run_id)
    latest = check_result.evidence.get("freshness", {}).get("latest")
    if check_result.evidence["status"] == "contract-error" or not latest:
        return check_result
    manifest = _load_manifest(root)
    sync_capability = manifest.get("capabilities", {}).get("adw:context:sync")
    if not isinstance(sync_capability, dict) or sync_capability.get("status") != "supported":
        return _result(root, manifest, task="adw:context:sync", status="blocked", exit_code=EXIT_BLOCKED, run_id=run_id, findings=[_finding("capability.required", "adw:context:sync is unsupported by this project")])
    _, release, findings = _resolve_freshness(root, manifest)
    if release is None:
        return _result(root, manifest, task="adw:context:sync", status="contract-error", exit_code=EXIT_CONTRACT_ERROR, run_id=run_id, findings=findings or [_finding("freshness.release", "no compatible trusted release is available")])
    generic = next(source for source in manifest["sources"] if source.get("layer") == "generic")
    source_path = Path(generic["path"])
    destination = root / source_path.parent
    staging = destination.parent / f".{destination.name}.adw-sync-{uuid.uuid4().hex}"
    backup = destination.parent / f".{destination.name}.adw-backup-{uuid.uuid4().hex}"
    try:
        staging.mkdir(parents=True)
        findings = findings or _fetch_release_snapshot(release, staging)
        replacement = staging / source_path.name
        if findings or not replacement.is_file() or "sha256:" + hashlib.sha256(replacement.read_bytes()).hexdigest() != release["checksum"]:
            return _result(root, manifest, task="adw:context:sync", status="contract-error", exit_code=EXIT_CONTRACT_ERROR, run_id=run_id, findings=findings or [_finding("freshness.snapshot", "trusted snapshot checksum mismatched")])
        for source in manifest["sources"]:
            if source.get("layer") == "generic":
                source["ref"], source["checksum"] = latest["ref"], latest["checksum"]
        for capability in manifest["capabilities"].values():
            if capability["source"].get("layer") == "generic":
                capability["source"]["ref"], capability["source"]["checksum"] = latest["ref"], latest["checksum"]
        if destination.exists():
            os.replace(destination, backup)
        os.replace(staging, destination)
        try:
            _atomic_write_json(_manifest_path(root), manifest)
        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            if backup.exists():
                os.replace(backup, destination)
            raise
    except OSError as exc:
        return _result(root, manifest, task="adw:context:sync", status="contract-error", exit_code=EXIT_CONTRACT_ERROR, run_id=run_id, findings=[_finding("freshness.snapshot", f"local snapshot update failed ({type(exc).__name__})")])
    finally:
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(backup, ignore_errors=True)
    return _result(root, manifest, task="adw:context:sync", status="passed", exit_code=0, run_id=run_id, freshness=check_result.evidence["freshness"], payload=check_result.evidence["freshness"])


def describe(project_root: Path | str, run_id: str | None = None) -> Result:
    root = Path(project_root)
    started = _now()
    try:
        manifest = _load_manifest(root)
    except FileNotFoundError:
        return _result(
            root,
            None,
            task="adw:describe",
            status="blocked",
            exit_code=EXIT_BLOCKED,
            run_id=run_id,
            findings=[_finding("manifest.missing", "ADW task manifest is missing")],
            started_at=started,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        return _result(
            root,
            None,
            task="adw:describe",
            status="contract-error",
            exit_code=EXIT_CONTRACT_ERROR,
            run_id=run_id,
            findings=[_finding("manifest.invalid", f"ADW task manifest is invalid: {exc}")],
            started_at=started,
        )
    findings = validate_manifest(manifest)
    if findings:
        return _result(
            root,
            manifest,
            task="adw:describe",
            status="contract-error",
            exit_code=EXIT_CONTRACT_ERROR,
            run_id=run_id,
            findings=findings,
            started_at=started,
        )
    payload = {
        "project": manifest["project"]["id"],
        "contract": manifest["contract"],
        "environments": manifest["environments"],
        "capabilities": manifest["capabilities"],
        "sources": manifest["sources"],
    }
    return _result(
        root,
        manifest,
        task="adw:describe",
        status="passed",
        exit_code=0,
        run_id=run_id,
        payload=payload,
        started_at=started,
    )


def _discover_mise_tasks(project_root: Path) -> tuple[set[str], dict[str, str], dict[str, str]]:
    completed = subprocess.run(
        ["mise", "tasks", "--json"],
        cwd=project_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    payload = json.loads(completed.stdout)
    names: set[str] = set()
    sources: dict[str, str] = {}
    usages: dict[str, str] = {}
    if isinstance(payload, dict):
        names = set(payload)
        items = ((name, item) for name, item in payload.items() if isinstance(item, dict))
    elif isinstance(payload, list):
        items = (
            (item["name"], item)
            for item in payload
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        )
        names.update(item for item in payload if isinstance(item, str))
    else:
        raise ValueError("mise tasks --json returned an unsupported shape")
    for name, item in items:
        names.add(name)
        if isinstance(item.get("source"), str):
            sources[name] = item["source"]
        if isinstance(item.get("usage"), str):
            usages[name] = item["usage"]
    return names, sources, usages


def check(
    project_root: Path | str,
    task_names: Iterable[str] | None = None,
    task_sources: dict[str, str] | None = None,
    task_usages: dict[str, str] | None = None,
    run_id: str | None = None,
) -> Result:
    root = Path(project_root)
    started = _now()
    try:
        manifest = _load_manifest(root)
    except FileNotFoundError:
        return _result(
            root,
            None,
            task="adw:check",
            status="blocked",
            exit_code=EXIT_BLOCKED,
            run_id=run_id,
            findings=[_finding("manifest.missing", "ADW task manifest is missing")],
            started_at=started,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        return _result(
            root,
            None,
            task="adw:check",
            status="contract-error",
            exit_code=EXIT_CONTRACT_ERROR,
            run_id=run_id,
            findings=[_finding("manifest.invalid", f"ADW task manifest is invalid: {exc}")],
            started_at=started,
        )
    findings = validate_manifest(manifest)
    findings.extend(_validate_source_files(root, manifest))
    sources = dict(task_sources or {})
    usages = dict(task_usages or {})
    injected_catalog = task_names is not None
    if not injected_catalog:
        try:
            names, sources, usages = _discover_mise_tasks(root)
        except (FileNotFoundError, subprocess.CalledProcessError, json.JSONDecodeError, ValueError) as exc:
            findings.append(_finding("mise.tasks", f"cannot inspect mise task catalog: {exc}"))
            names = set()
            sources = {}
            usages = {}
    else:
        names = set(task_names)
    # A retired v1 name must not remain as a runnable alias in a v2 catalog.
    for retired in sorted({"adw:test:integration", "adw:e2e"} & names):
        findings.append(_finding("task.retired", f"v1 task is forbidden in the v2 catalog: {retired}"))
    capabilities = manifest.get("capabilities", {})
    if isinstance(capabilities, dict):
        for undeclared in sorted(name for name in names if name.startswith("adw:") and name not in capabilities):
            findings.append(_finding("task.undeclared", f"mise ADW task is absent from the manifest: {undeclared}"))
        for task in sorted(capabilities):
            if task not in names:
                findings.append(_finding("task.missing", f"declared canonical task is missing from mise catalog: {task}"))
                continue
            if task in ENVIRONMENT_TASKS and not re.fullmatch(
                r'\s*arg\s+"<environment>"(?:\s+help="[^"]*")?(?:\s*\n\s*flag\s+"--target <target>"(?:\s+help="[^"]*")?)?\s*', usages.get(task, "")
            ):
                findings.append(
                    _finding("task.signature", f"task {task} must declare a required <environment> input")
                )
            actual_source = sources.get(task)
            expected_source = capabilities[task].get("source", {}).get("path")
            if actual_source is None:
                findings.append(_finding("task.source", f"mise catalog omits source metadata for {task}"))
                continue
            actual_path = Path(actual_source)
            if actual_path.is_absolute():
                try:
                    actual_source = actual_path.resolve().relative_to(root.resolve()).as_posix()
                except ValueError:
                    actual_source = actual_path.resolve().as_posix()
            if actual_source != expected_source:
                findings.append(
                    _finding(
                        "task.source",
                        f"task source mismatch for {task}: expected {expected_source!r}, got {actual_source!r}",
                    )
                )
    status = "contract-error" if findings else "passed"
    exit_code = EXIT_CONTRACT_ERROR if findings else 0
    return _result(
        root,
        manifest,
        task="adw:check",
        status=status,
        exit_code=exit_code,
        run_id=run_id,
        findings=findings,
        started_at=started,
    )


def unsupported(
    project_root: Path | str,
    task: str,
    run_id: str | None = None,
    environment: str | None = None,
    target: str | None = None,
) -> Result:
    root = Path(project_root)
    if target is not None and (task not in ENVIRONMENT_TASKS or not LOGICAL_TARGET_PATTERN.fullmatch(target)):
        return _result(root, None, task=task, status="contract-error", exit_code=EXIT_CONTRACT_ERROR, run_id=run_id, findings=[_finding("target.invalid", "target must be a bounded logical identifier for an environment-scoped task")], arguments=_arguments(environment))
    try:
        manifest = _load_manifest(root)
    except FileNotFoundError:
        return _result(
            root,
            None,
            task=task,
            status="blocked",
            exit_code=EXIT_BLOCKED,
            run_id=run_id,
            findings=[_finding("manifest.missing", "ADW task manifest is missing")],
        )
    except (json.JSONDecodeError, ValueError) as exc:
        return _result(
            root,
            None,
            task=task,
            status="contract-error",
            exit_code=EXIT_CONTRACT_ERROR,
            run_id=run_id,
            findings=[_finding("manifest.invalid", f"ADW task manifest is invalid: {exc}")],
        )
    findings = validate_manifest(manifest)
    findings.extend(_validate_source_files(root, manifest))
    if task not in CANONICAL_TASKS:
        findings.append(_finding("capability.name", "unsupported stub task must be canonical"))
    capability = manifest.get("capabilities", {}).get(task)
    if not isinstance(capability, dict) or capability.get("status") != "unsupported":
        findings.append(_finding("capability.stub", f"{task} is not declared unsupported"))
    if findings:
        return _result(
            root,
            manifest,
            task=task,
            status="contract-error",
            exit_code=EXIT_CONTRACT_ERROR,
            run_id=run_id,
            findings=findings,
            arguments=_arguments(environment, target),
        )
    return _result(
        root,
        manifest,
        task=task,
        status="unsupported",
        exit_code=0,
        run_id=run_id,
        findings=[_finding("capability.unsupported", f"{task} is unsupported by this project", "info")],
        arguments=_arguments(environment, target),
    )


def require(
    project_root: Path | str,
    task: str,
    environment: str | None = None,
    run_id: str | None = None,
    _persist_pass: bool = True,
) -> Result:
    root = Path(project_root)
    try:
        manifest = _load_manifest(root)
    except FileNotFoundError:
        return _result(
            root,
            None,
            task=task,
            status="blocked",
            exit_code=EXIT_BLOCKED,
            run_id=run_id,
            findings=[_finding("manifest.missing", "ADW task manifest is missing")],
        )
    except (json.JSONDecodeError, ValueError) as exc:
        return _result(
            root,
            None,
            task=task,
            status="contract-error",
            exit_code=EXIT_CONTRACT_ERROR,
            run_id=run_id,
            findings=[_finding("manifest.invalid", f"ADW task manifest is invalid: {exc}")],
        )
    findings = validate_manifest(manifest)
    findings.extend(_validate_source_files(root, manifest))
    if task not in CANONICAL_TASKS:
        findings.append(_finding("capability.name", "required task must be canonical"))
    if findings:
        return _result(
            root,
            manifest,
            task=task,
            status="contract-error",
            exit_code=EXIT_CONTRACT_ERROR,
            run_id=run_id,
            findings=findings,
            arguments={"environment": environment} if environment else {},
        )
    capability = manifest.get("capabilities", {}).get(task)
    if not isinstance(capability, dict) or capability.get("status") != "supported":
        return _result(
            root,
            manifest,
            task=task,
            status="blocked",
            exit_code=EXIT_BLOCKED,
            run_id=run_id,
            findings=[_finding("capability.required", f"required capability is unsupported: {task}")],
            arguments={"environment": environment} if environment else {},
        )
    if task in ENVIRONMENT_TASKS and environment is None:
        return _result(
            root,
            manifest,
            task=task,
            status="blocked",
            exit_code=EXIT_BLOCKED,
            run_id=run_id,
            findings=[_finding("environment.required", f"environment is required for {task}")],
        )
    supported_environments = capability.get("environments", [])
    if environment is not None and environment not in supported_environments:
        return _result(
            root,
            manifest,
            task=task,
            status="blocked",
            exit_code=EXIT_BLOCKED,
            run_id=run_id,
            findings=[_finding("environment.unsupported", f"environment {environment!r} is unsupported for {task}")],
            arguments={"environment": environment},
        )
    if _persist_pass:
        return _result(
            root,
            manifest,
            task=task,
            status="passed",
            exit_code=0,
            run_id=run_id,
            arguments={"environment": environment} if environment else {},
        )
    evidence = _build_evidence(
        root,
        manifest,
        task=task,
        status="passed",
        exit_code=0,
        run_id=run_id,
        arguments={"environment": environment} if environment else {},
    )
    return Result(0, evidence, {})


def _validate_child_evidence(
    root: Path,
    manifest: dict[str, Any],
    run_id: str,
    child_tasks: list[str],
    aggregate_started_at: str,
) -> tuple[str, int, list[dict[str, str]]]:
    findings: list[dict[str, str]] = []
    child_statuses: list[str] = []
    expected_revision = _source_revision(root)
    window_start = datetime.fromisoformat(aggregate_started_at)
    window_end = datetime.now(timezone.utc)
    expected_exits = {"passed": 0, "unsupported": 0, "failed": 1, "blocked": 20, "contract-error": 21}
    evidence_root = _evidence_root(root, manifest)
    for child in child_tasks:
        path = evidence_root / run_id / f"{_safe_task_filename(child)}.json"
        try:
            evidence = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            findings.append(_finding("evidence.child_missing", f"missing or invalid child evidence for {child}"))
            continue
        status = evidence.get("status")
        if evidence.get("run_id") != run_id or evidence.get("task") != child:
            findings.append(_finding("evidence.child_identity", f"child evidence identity mismatch for {child}"))
            continue
        if status not in expected_exits or evidence.get("exit_code") != expected_exits[status]:
            findings.append(_finding("evidence.child_status", f"child evidence status/exit mismatch for {child}"))
            continue
        try:
            child_start = datetime.fromisoformat(evidence["started_at"])
            child_finish = datetime.fromisoformat(evidence["finished_at"])
            valid_window = (child_start.tzinfo is not None and child_finish.tzinfo is not None
                            and window_start <= child_start <= child_finish <= window_end)
        except (KeyError, TypeError, ValueError):
            valid_window = False
        if (not valid_window or evidence.get("source_revision") != expected_revision
                or evidence.get("effective_source") != manifest["capabilities"][child]["source"]
                or evidence.get("contract_version") != CONTRACT_VERSION
                or evidence.get("schema_version") != SCHEMA_VERSION
                or evidence.get("children") != []):
            findings.append(_finding("evidence.child_provenance", f"child evidence provenance mismatch for {child}"))
            continue
        child_statuses.append(status)
    if findings:
        return "contract-error", EXIT_CONTRACT_ERROR, findings
    if any(status == "contract-error" for status in child_statuses):
        return "contract-error", EXIT_CONTRACT_ERROR, [_finding("evidence.child", "child contract error")]
    if any(status in {"unsupported", "blocked", "skipped"} for status in child_statuses):
        return "blocked", EXIT_BLOCKED, [_finding("evidence.child", "child capability did not complete")]
    if any(status == "failed" for status in child_statuses):
        return "failed", EXIT_FAILED, [_finding("evidence.child", "child capability failed")]
    return "passed", 0, []


def run_command(
    project_root: Path | str,
    task: str,
    command: list[str],
    environment: str | None = None,
    target: str | None = None,
    run_id: str | None = None,
    children: Iterable[str] | None = None,
) -> Result:
    root = Path(project_root)
    started = _now()
    if target is not None and (task not in ENVIRONMENT_TASKS or not LOGICAL_TARGET_PATTERN.fullmatch(target)):
        return _result(
            root, None, task=task, status="contract-error", exit_code=EXIT_CONTRACT_ERROR, run_id=run_id,
            findings=[_finding("target.invalid", "target must be a bounded logical identifier for an environment-scoped task")],
            arguments=_arguments(environment), started_at=started,
        )
    try:
        resolved_run_id = _run_id(run_id)
    except ValueError:
        return _result(
            root,
            None,
            task=task,
            status="contract-error",
            exit_code=EXIT_CONTRACT_ERROR,
            run_id=_new_run_id(),
            findings=[_finding("evidence.run_id", "run ID contains unsafe characters")],
            arguments={"environment": environment} if environment else {},
            started_at=started,
        )
    preflight = require(root, task, environment=environment, run_id=resolved_run_id, _persist_pass=False)
    if preflight.exit_code != 0:
        return preflight
    manifest = _load_manifest(root)
    child_tasks = list(children or [])
    aggregate_tasks = {"adw:verify:minimal", "adw:verify:full", "adw:validate-deployment", "adw:hotfix:apply"}
    invalid_children = sorted(set(child_tasks) - CANONICAL_TASKS)
    forbidden_optional = {"adw:test:integration:full", "adw:test:e2e:fast", "adw:test:e2e:full"}
    child_error = None
    if set(child_tasks) & forbidden_optional:
        child_error = "optional full integration and E2E suites cannot be aggregate children"
    elif child_tasks and task not in aggregate_tasks:
        child_error = f"{task} is not an aggregate task and cannot declare child evidence"
    elif task in child_tasks:
        child_error = f"{task} cannot declare itself as child evidence"
    elif len(set(child_tasks)) != len(child_tasks):
        child_error = "child evidence task names must be unique"
    elif invalid_children:
        child_error = f"unknown child evidence tasks: {', '.join(invalid_children)}"
    elif task in {"adw:verify:minimal", "adw:verify:full"}:
        graph_name = task.rsplit(":", 1)[-1]
        expected_children = manifest.get("verification", {}).get(graph_name, [])
        if child_tasks != expected_children:
            child_error = f"{task} children must exactly match verification.{graph_name}"
    if child_error:
        return _result(
            root,
            manifest,
            task=task,
            status="contract-error",
            exit_code=EXIT_CONTRACT_ERROR,
            run_id=resolved_run_id,
            findings=[_finding("evidence.children", child_error)],
            arguments={"environment": environment} if environment else {},
            started_at=started,
        )
    if not command:
        return _result(
            root,
            manifest,
            task=task,
            status="contract-error",
            exit_code=EXIT_CONTRACT_ERROR,
            run_id=resolved_run_id,
            findings=[_finding("command.missing", "project task command is missing")],
            arguments={"environment": environment} if environment else {},
            started_at=started,
        )
    child_environment = dict(os.environ)
    child_environment["ADW_RUN_ID"] = resolved_run_id
    launch_finding: dict[str, str] | None = None
    try:
        completed = subprocess.run(command, cwd=root, check=False, env=child_environment)
        child_exit = completed.returncode
    except FileNotFoundError:
        child_exit = 127
    except OSError as exc:
        child_exit = 126
        launch_finding = _finding("command.launch", f"project task command could not start ({type(exc).__name__})")
    normalized_child_exit = child_exit if child_exit >= 0 else 128 + abs(child_exit)
    exit_code = 0 if normalized_child_exit == 0 else EXIT_FAILED
    status = "passed" if exit_code == 0 else "failed"
    severity = "info" if exit_code == 0 else "error"
    findings = [launch_finding] if launch_finding else [
        _finding("command.exit", f"project task command exited with code {normalized_child_exit}", severity)
    ]
    if exit_code == 0 and child_tasks:
        status, exit_code, child_findings = _validate_child_evidence(root, manifest, resolved_run_id, child_tasks, started)
        findings.extend(child_findings)
    return _result(
        root,
        manifest,
        task=task,
        status=status,
        exit_code=exit_code,
        run_id=resolved_run_id,
        findings=findings,
        arguments=_arguments(environment, target),
        children=child_tasks,
        started_at=started,
    )


def _print_result(result: Result) -> None:
    print(f"{result.evidence['task']}: {result.evidence['status']}")
    for finding in result.evidence["findings"]:
        print(f"- {finding['severity']}: {finding['message']}")
    if result.payload:
        print(json.dumps(result.payload, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--run-id")
    subparsers = parser.add_subparsers(dest="command", required=True)
    describe_parser = subparsers.add_parser("describe")
    describe_parser.set_defaults(command_name="describe")
    subparsers.add_parser("check")
    subparsers.add_parser("context-check")
    subparsers.add_parser("context-sync")
    unsupported_parser = subparsers.add_parser("unsupported")
    unsupported_parser.add_argument("--task", required=True)
    unsupported_parser.add_argument("--environment")
    unsupported_parser.add_argument("--target")
    require_parser = subparsers.add_parser("require")
    require_parser.add_argument("--task", required=True)
    require_parser.add_argument("--environment")
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--task", required=True)
    run_parser.add_argument("--environment")
    run_parser.add_argument("--target")
    run_parser.add_argument("--child", action="append", choices=sorted(CANONICAL_TASKS), default=[])
    run_parser.add_argument("command_args", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.project_root)
    if args.command == "describe":
        result = describe(root, run_id=args.run_id)
    elif args.command == "check":
        result = check(root, run_id=args.run_id)
    elif args.command == "context-check":
        result = context_check(root, run_id=args.run_id)
    elif args.command == "context-sync":
        result = context_sync(root, run_id=args.run_id)
    elif args.command == "unsupported":
        result = unsupported(root, args.task, run_id=args.run_id, environment=args.environment, target=args.target)
    elif args.command == "require":
        result = require(root, args.task, environment=args.environment, run_id=args.run_id)
    else:
        command = args.command_args[1:] if args.command_args[:1] == ["--"] else args.command_args
        result = run_command(
            root,
            args.task,
            command,
            environment=args.environment,
            target=args.target,
            run_id=args.run_id,
            children=args.child,
        )
    _print_result(result)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())

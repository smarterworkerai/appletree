"""Generic ADW evidence records for context-owned remote tasks.

Remote tasks keep their own exit classes and single-JSON stdout, so they are not
wrapped by `adw_contract.py run`. This module writes the same closed record shape
as the consumer's pinned generic `adw-task-evidence.schema.json` under
`<evidence.root>/<run-id>/`. `schema_version` and `contract_version` follow the
generic contract version the manifest declares, so records stay valid for the
generic snapshot the project actually vendors.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import project_dir
from .common import ContractError, load_json

CONTRACT_NAME = "adw-mise-task-contract"
CONTRACT_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TARGET = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
SOURCE_FIELDS = ("layer", "ref", "checksum", "path")
# Map the pz result status onto the canonical evidence statuses.
STATUS = {"ok": "passed", "failed": "failed", "blocked": "blocked", "unsupported": "unsupported"}
# The generic evidence schema binds each status to one exit class (0 passed/unsupported,
# 1 failed, 20 blocked, 21 contract-error). pz guards refuse with exit 21 while reporting
# `blocked`, so the exit class decides the canonical status and the pz label is kept as a finding.
CANONICAL_STATUS = {0: "passed", 1: "failed", 20: "blocked", 21: "contract-error"}
MAX_MESSAGE = 240


def record_operator(directory: Path, result: dict[str, Any]) -> Path:
    """Value-free pz receipt, never a generic ADW quality or CI authorization proof."""
    from .operator_state import write
    identifier = run_id()
    if result.get('task') not in {'pz:provider:servers', 'pz:provider:provision', 'pz:provider:deprovision', 'pz:provider:examine',
                                   'pz:provider:claim', 'pz:release:pointers:retire', 'pz:release:pointers:orphans'}:
        raise ContractError('operator evidence task invalid')
    value = {'schema_version': '1.0.0', 'workflow': 'operator-receipt',
             'run_id': identifier, **result}
    path = directory / 'receipt.json'
    write(path, value)
    return path


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_id() -> str:
    """Resolve ADW_RUN_ID like the generic adapter: inherit, else generate; reject unsafe values."""
    candidate = os.environ.get("ADW_RUN_ID") or f"adw-{uuid.uuid4()}"
    if not RUN_ID.fullmatch(candidate):
        raise ContractError("ADW_RUN_ID must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    return candidate


def _source_revision(repo: Path) -> str | None:
    try:
        value = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, text=True,
                               capture_output=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return value if re.fullmatch(r"[0-9a-f]{40}", value) else "unknown"


def _effective_source(manifest: dict[str, Any], task: str) -> dict[str, str] | None:
    capability = (manifest.get("capabilities") or {}).get(task)
    source_id = capability.get("source") if isinstance(capability, dict) else None
    source = (manifest.get("sources") or {}).get(source_id) if isinstance(source_id, str) else None
    if not isinstance(source, dict) or not all(isinstance(source.get(field), str) for field in SOURCE_FIELDS):
        return None
    return {field: source[field] for field in SOURCE_FIELDS}


def _contract_version(manifest: dict[str, Any]) -> str:
    """The generic contract version the consumer declares; evidence records carry exactly that."""
    contract = manifest.get("contract")
    version = contract.get("version") if isinstance(contract, dict) else None
    if (not isinstance(contract, dict) or contract.get("name") != CONTRACT_NAME
            or not isinstance(version, str) or not CONTRACT_VERSION_PATTERN.fullmatch(version)):
        raise ContractError("generic ADW contract identity is missing")
    return version


def _evidence_root(repo: Path, manifest: dict[str, Any]) -> Path:
    configured = (manifest.get("evidence") or {}).get("root", str(project_dir(repo).relative_to(repo) / "evidence"))
    root = (repo / configured).resolve()
    if root != repo.resolve() and repo.resolve() not in root.parents:
        raise ContractError("evidence.root must remain inside the project")
    return root


def record(repo: Path, *, task: str, identifier: str, started_at: str, exit_code: int,
           result: dict[str, Any] | None, environment: str | None, target: str | None) -> Path:
    """Persist one redacted record; only status, bounded reason and logical arguments are kept."""
    manifest = load_json(project_dir(repo) / 'adw-task-manifest.json')
    version = _contract_version(manifest)
    reported = (result or {}).get("status", "")
    status = CANONICAL_STATUS.get(exit_code, "failed")
    if exit_code == 0 and STATUS.get(reported) == "unsupported":
        status = "unsupported"
    reason = (result or {}).get("reason")
    findings = []
    if isinstance(reported, str) and reported and STATUS.get(reported) != status:
        findings.append({"code": "task.status", "severity": "info",
                         "message": f"task reported status {reported[:MAX_MESSAGE]}"})
    if isinstance(reason, str) and reason:
        findings.append({"code": "task.reason", "severity": "info" if exit_code == 0 else "error",
                         "message": reason[:MAX_MESSAGE]})
    findings.append({"code": "task.exit", "severity": "info" if exit_code == 0 else "error",
                     "message": f"task exited with code {exit_code}"})
    arguments: dict[str, str] = {}
    if environment:
        arguments["environment"] = environment
    if target and TARGET.fullmatch(target):
        arguments["target"] = target
    evidence = {
        "schema_version": version, "contract_version": version,
        "run_id": identifier, "task": task, "status": status, "exit_code": exit_code,
        "started_at": started_at, "finished_at": now(),
        "source_revision": _source_revision(repo), "effective_source": _effective_source(manifest, task),
        "arguments": arguments, "findings": findings, "children": [],
    }
    root = _evidence_root(repo, manifest)
    directory = (root / identifier).resolve()
    if root not in directory.parents:
        raise ContractError("evidence run directory must remain inside evidence.root")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (re.sub(r"[^A-Za-z0-9._-]+", "_", task).strip("_") + ".json")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(evidence, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return path

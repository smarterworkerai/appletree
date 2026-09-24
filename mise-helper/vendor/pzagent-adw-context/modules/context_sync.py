"""Read-only integrity check and explicit staged consumer synchronization."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Callable

from .bundle import validate_bundle
from .common import ContractError, FULL_SHA, ensure_contained, load_json, sha256_file

REPOSITORY = "smarterworkerai/pzagent-adw-context"
TAG = re.compile(r"^v0\.[0-9]+\.[0-9]+$")
VERSION = re.compile(r"(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)")
VENDOR = Path("mise-helper/vendor/pzagent-adw-context")
MANIFEST = Path(".hermes/adw-task-manifest.json")
LOCK = Path(".hermes/pzagent-context-lock.json")


def current_branch(repo: Path) -> str:
    result = subprocess.run(
        ["git", "branch", "--show-current"], cwd=repo, text=True,
        capture_output=True, check=False,
    )
    if result.returncode or not result.stdout.strip():
        raise ContractError("sync requires a named work branch")
    return result.stdout.strip()


def managed_clean(repo: Path) -> None:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--", str(VENDOR), str(MANIFEST), str(LOCK)],
        cwd=repo, text=True, capture_output=True, check=False,
    )
    if result.returncode or result.stdout.strip():
        raise ContractError("sync managed paths must be clean")


def _mise_file(repo: Path) -> Path:
    candidates = [repo / "mise.toml", repo / ".mise.toml"]
    path = next((item for item in candidates if item.is_file()), None)
    if path is None:
        raise ContractError("mise include configuration is missing")
    return path


def check_precedence(repo: Path) -> None:
    try:
        value = tomllib.loads(_mise_file(repo).read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ContractError("mise include configuration is malformed") from exc
    includes = value.get("task_config", {}).get("includes")
    expected = [
        "mise-helper/vendor/agentic-delivery/tasks.toml",
        "mise-helper/vendor/pzagent-adw-context/tasks.toml",
        "mise-helper/tasks.toml",
    ]
    if includes != expected:
        raise ContractError("mise task precedence must be exactly generic, context, project")


def _version(raw: str, label: str) -> tuple[int, int, int]:
    match = VERSION.search(raw)
    if not match:
        raise ContractError(f"{label} version is unavailable")
    return (int(match.group("major")), int(match.group("minor")), int(match.group("patch")))


def _check_compatibility(manifest: dict[str, Any], mise_version: str | None) -> None:
    contract = manifest.get("contract")
    if not isinstance(contract, dict) or contract.get("name") != "adw-mise-task-contract":
        raise ContractError("generic ADW contract identity is missing")
    if not (2, 0, 0) <= _version(str(contract.get("version", "")), "generic ADW") < (3, 0, 0):
        raise ContractError("generic ADW contract is incompatible")
    raw_mise = mise_version
    if raw_mise is None:
        result = subprocess.run(
            ["mise", "--version"], text=True, capture_output=True, check=False,
        )
        if result.returncode:
            raise ContractError("mise is unavailable")
        raw_mise = result.stdout or result.stderr
    if _version(raw_mise, "mise") < (2026, 0, 0):
        raise ContractError("mise version is incompatible")


def check_consumer(
    repo: Path,
    *,
    freshness_lookup: Callable[[dict[str, Any]], str | None] | None = None,
    strict_freshness: bool = False,
    mise_version: str | None = None,
) -> dict[str, Any]:
    bundle = validate_bundle(repo / VENDOR)
    manifest = load_json(repo / MANIFEST)
    lock = load_json(repo / LOCK)
    project_adw = repo / ".hermes/ADW.md"
    if project_adw.exists():
        if not project_adw.is_file() or project_adw.is_symlink():
            raise ContractError("project ADW.md is missing or unsafe")
        try:
            project_adw_text = project_adw.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError("project ADW.md is not UTF-8") from exc
        if re.search(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])", project_adw_text):
            raise ContractError("ADW.md must not duplicate exact Git provenance")
    required_lock = {"schema_version", "source_ref", "package_version", "bundle_sha256"}
    if not isinstance(lock, dict) or set(lock) != required_lock or lock["schema_version"] != "1.0.0":
        raise ContractError("context lock is invalid")
    if not FULL_SHA.fullmatch(str(lock["source_ref"])) or lock["package_version"] != bundle["version"]:
        raise ContractError("context lock identity differs")
    descriptor_checksum = sha256_file(repo / VENDOR / "bundle.json")
    if lock["bundle_sha256"] != descriptor_checksum:
        raise ContractError("bundle descriptor differs from the trusted context lock")

    sources = manifest.get("sources") if isinstance(manifest, dict) else None
    matches = [
        item for item in sources or []
        if isinstance(item, dict) and item.get("layer") == "context"
    ]
    if len(matches) != 1 or set(matches[0]) != {"layer", "ref", "checksum", "path"}:
        raise ContractError("manifest context source is missing or ambiguous")
    source = matches[0]
    if (
        source["ref"] != lock["source_ref"]
        or source["path"] != f"{VENDOR.as_posix()}/tasks.toml"
        or source["checksum"] != "sha256:" + sha256_file(repo / VENDOR / "tasks.toml")
    ):
        raise ContractError("manifest context provenance differs")
    capabilities = manifest.get("capabilities")
    if capabilities is not None:
        if not isinstance(capabilities, dict):
            raise ContractError("consumer manifest capabilities are malformed")
        for capability in capabilities.values():
            if not isinstance(capability, dict):
                raise ContractError("consumer manifest capability is malformed")
            capability_source = capability.get("source")
            if isinstance(capability_source, dict) and capability_source.get("layer") == "context":
                if capability_source != source:
                    raise ContractError("context capability provenance differs")
    _check_compatibility(manifest, mise_version)
    check_precedence(repo)

    verdict = "current"
    warning = None
    if freshness_lookup is not None:
        try:
            latest = freshness_lookup(bundle)
            if latest and latest != bundle["version"]:
                verdict = "update-available"
        except Exception:
            if strict_freshness:
                raise ContractError("trusted freshness lookup is unavailable")
            warning = "lookup-unavailable"
    elif strict_freshness:
        raise ContractError("strict freshness requires a trusted lookup")
    return {
        "verdict": verdict,
        "warning": warning,
        "version": bundle["version"],
        "source_ref": source["ref"],
        "bundle_sha256": descriptor_checksum,
    }


def _resolve_ref(source: str) -> str:
    if FULL_SHA.fullmatch(source):
        return source
    if not TAG.fullmatch(source):
        raise ContractError("sync source must be an exact SHA or protected 0.x tag")
    result = subprocess.run(
        ["gh", "api", f"repos/{REPOSITORY}/commits/{source}", "--jq", ".sha"],
        text=True, capture_output=True, check=False,
    )
    sha = result.stdout.strip()
    if result.returncode or not FULL_SHA.fullmatch(sha):
        raise ContractError("protected release ref could not be resolved")
    return sha


def trusted_freshness(bundle: dict[str, Any]) -> str | None:
    result = subprocess.run(
        ["gh", "release", "list", "--repo", REPOSITORY, "--limit", "100", "--json", "tagName,isDraft,isPrerelease"],
        text=True, capture_output=True, check=False,
    )
    if result.returncode:
        raise ContractError("trusted release freshness lookup failed")
    try:
        releases = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ContractError("trusted release freshness response is malformed") from exc
    versions = [
        item["tagName"].removeprefix("v") for item in releases
        if isinstance(item, dict) and not item.get("isDraft") and not item.get("isPrerelease")
        and isinstance(item.get("tagName"), str) and TAG.fullmatch(item["tagName"])
    ]
    return max(versions, key=lambda value: _version(value, "release"), default=None)


def _archive(ref: str, target: Path) -> None:
    with target.open("wb") as handle:
        result = subprocess.run(
            ["gh", "api", f"repos/{REPOSITORY}/tarball/{ref}"], stdout=handle,
            stderr=subprocess.DEVNULL, check=False,
        )
    if result.returncode:
        raise ContractError("immutable archive fetch failed")


def safe_extract(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:*") as tar:
        members = tar.getmembers()
        if not members:
            raise ContractError("release archive is empty")
        roots = {member.name.split("/", 1)[0] for member in members}
        if len(roots) != 1:
            raise ContractError("release archive has ambiguous root")
        for member in members:
            relative = member.name.split("/", 1)[1] if "/" in member.name else ""
            if not relative:
                continue
            ensure_contained(destination, relative)
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise ContractError("release archive contains unsafe link or entry")
            member.name = relative
        tar.extractall(destination, members=members, filter="data")
    return destination / "skills/pzagent/pzagent-adw-context/assets/mise/v2"


def _stage_consumer(
    repo: Path, staged: Path, bundle_root: Path, manifest: dict[str, Any],
    lock: dict[str, Any],
) -> None:
    shutil.copytree(bundle_root, staged / VENDOR)
    (staged / MANIFEST).parent.mkdir(parents=True, exist_ok=True)
    (staged / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (staged / LOCK).write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    shutil.copy2(_mise_file(repo), staged / _mise_file(repo).name)


def sync(
    repo: Path,
    source: str,
    *,
    bundle_sha256: str | None = None,
    allow_downgrade: bool = False,
    archive_path: Path | None = None,
    mise_version: str | None = None,
) -> dict[str, Any]:
    repo = repo.resolve()
    branch = current_branch(repo)
    if branch in {"main", "demo"}:
        raise ContractError("sync is forbidden on protected branches")
    managed_clean(repo)
    ref = _resolve_ref(source) if archive_path is None else source
    if not FULL_SHA.fullmatch(ref):
        raise ContractError("resolved sync ref is not an exact SHA")
    if not isinstance(bundle_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", bundle_sha256):
        raise ContractError("sync requires a trusted bundle descriptor SHA-256")

    with tempfile.TemporaryDirectory(prefix="pzagent-context-sync-") as raw:
        temp = Path(raw)
        archive = archive_path or temp / "source.tar.gz"
        if archive_path is None:
            _archive(ref, archive)
        bundle_root = safe_extract(archive, temp / "extract")
        descriptor = validate_bundle(bundle_root)
        if sha256_file(bundle_root / "bundle.json") != bundle_sha256:
            raise ContractError("release bundle checksum differs from trusted metadata")
        current = None
        if (repo / VENDOR / "bundle.json").is_file():
            current = validate_bundle(repo / VENDOR)["version"]
        if current and _version(descriptor["version"], "bundle") < _version(current, "current bundle") and not allow_downgrade:
            raise ContractError("bundle downgrade requires --allow-downgrade")

        manifest = load_json(repo / MANIFEST)
        sources = manifest.get("sources")
        if not isinstance(sources, list):
            raise ContractError("consumer manifest sources are missing")
        source_record = {
            "layer": "context", "ref": ref,
            "checksum": "sha256:" + sha256_file(bundle_root / "tasks.toml"),
            "path": f"{VENDOR.as_posix()}/tasks.toml",
        }
        manifest["sources"] = [
            item for item in sources
            if not (isinstance(item, dict) and item.get("layer") == "context")
        ] + [source_record]
        capabilities = manifest.get("capabilities")
        if capabilities is not None:
            if not isinstance(capabilities, dict):
                raise ContractError("consumer manifest capabilities are malformed")
            for value in capabilities.values():
                if not isinstance(value, dict):
                    raise ContractError("consumer manifest capability is malformed")
                capability_source = value.get("source")
                if isinstance(capability_source, dict) and capability_source.get("layer") == "context":
                    value["source"] = dict(source_record)
        lock = {
            "schema_version": "1.0.0", "source_ref": ref,
            "package_version": descriptor["version"],
            "bundle_sha256": bundle_sha256,
        }
        staged = temp / "consumer"
        _stage_consumer(repo, staged, bundle_root, manifest, lock)
        check_consumer(staged, mise_version=mise_version)

        if (repo / VENDOR).exists():
            shutil.rmtree(repo / VENDOR)
        (repo / VENDOR).parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(staged / VENDOR, repo / VENDOR)
        shutil.copy2(staged / MANIFEST, repo / MANIFEST)
        shutil.copy2(staged / LOCK, repo / LOCK)
    return check_consumer(repo, mise_version=mise_version)

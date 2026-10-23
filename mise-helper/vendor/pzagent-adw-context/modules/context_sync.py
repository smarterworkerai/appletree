"""Read-only integrity check and explicit staged consumer synchronization."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Callable

from .bundle import validate_bundle
from .common import ContractError, FULL_SHA, project_dir, ensure_contained, load_json, sha256_file

REPOSITORY = "smarterworkerai/pzagent-adw-context"
TAG = re.compile(r"^v(0|[1-9][0-9]*)\.[0-9]+\.[0-9]+$")
VERSION = re.compile(r"(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)")
VENDOR = Path("mise-helper/vendor/pzagent-adw-context")
GENERIC_ENGINE = Path("mise-helper/vendor/agentic-delivery/adw_contract.py")
ENGINE_VERSION = re.compile(r'^CONTRACT_VERSION\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', re.MULTILINE)
MAX_ENGINE_BYTES = 1_048_576
MANIFEST = Path("adw-task-manifest.json")
LOCK = Path("pzagent-context-lock.json")


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
        ["git", "status", "--porcelain", "--", str(VENDOR), str(project_dir(repo).relative_to(repo) / MANIFEST), str(project_dir(repo).relative_to(repo) / LOCK)],
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


def check_context_task_overrides(repo: Path) -> None:
    """Context wrapper provenance must agree with the task mise actually selects."""
    try:
        inline = tomllib.loads(_mise_file(repo).read_text(encoding='utf-8')).get('tasks', {})
        project_path = repo / 'mise-helper/tasks.toml'
        project = tomllib.loads(project_path.read_text(encoding='utf-8')) if project_path.exists() else {}
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        raise ContractError('context_project_tasks_invalid') from None
    if not isinstance(inline, dict) or not isinstance(project, dict):
        raise ContractError('context_project_tasks_invalid')
    for tasks in (inline, project):
        if {'adw:verify:full', 'adw:describe'}.intersection(tasks):
            raise ContractError('context_task_override_requires_removal')


def _version(raw: str, label: str) -> tuple[int, int, int]:
    match = VERSION.search(raw)
    if not match:
        raise ContractError(f"{label} version is unavailable")
    return (int(match.group("major")), int(match.group("minor")), int(match.group("patch")))


def _check_compatibility(manifest: dict[str, Any], mise_version: str | None, *, minimum_mise: str) -> None:
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
    # The bundle declares the floor it was validated on; never accept an older mise.
    if _version(raw_mise, "mise") < _version(minimum_mise, "bundle minimum mise"):
        raise ContractError("mise version is incompatible")


def _check_generic_engine(repo: Path, manifest: dict[str, Any]) -> None:
    """The vendored generic engine must implement the contract version the manifest declares.

    `adw:check` verifies the generic source checksum, but that covers `tasks.toml`, which is
    byte-identical across several generic releases. Reading the engine's own version
    constant keeps a stale manifest declaration from passing unnoticed.
    """
    path = repo / GENERIC_ENGINE
    if not path.is_file() or path.is_symlink():
        raise ContractError("vendored generic ADW engine is missing")
    if path.stat().st_size > MAX_ENGINE_BYTES:
        raise ContractError("vendored generic ADW engine is unexpectedly large")
    match = ENGINE_VERSION.search(path.read_text(encoding="utf-8", errors="replace"))
    declared = str(manifest["contract"].get("version", ""))
    if match is None or match.group(1) != declared:
        raise ContractError("vendored generic ADW engine version differs from the manifest contract")


MAX_TOOL_CONFIG_BYTES = 1_048_576


def _private_toml(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_TOOL_CONFIG_BYTES:
        raise ContractError(label + " is unsafe")
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ContractError(label + " is malformed") from exc
    return value


def _pinned_versions(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict) and isinstance(value.get("version"), str):
        return [value["version"]]
    if isinstance(value, list):
        return [version for item in value for version in _pinned_versions(item)]
    raise ContractError("mise.toml tool pin is malformed")


def tool_lock_gaps(repo: Path) -> list[str] | None:
    """Pins of a lockfile-enabled mise.toml that mise.lock does not cover; None when not enforced.

    Parses the lock only; never invokes mise.
    """
    config_path = repo / "mise.toml"
    if not config_path.exists():
        return None
    config = _private_toml(config_path, "mise.toml")
    if (config.get("settings") or {}).get("lockfile") is not True:
        return None
    tools = config.get("tools") or {}
    if not isinstance(tools, dict):
        raise ContractError("mise.toml tools are malformed")
    pins = {(name, version) for name, value in tools.items() for version in _pinned_versions(value)}
    if not pins:
        return None
    lock_path = repo / "mise.lock"
    if not lock_path.exists() and not lock_path.is_symlink():
        return sorted(name + "@" + version for name, version in pins)
    locked = _private_toml(lock_path, "mise.lock").get("tools")
    if not isinstance(locked, dict):
        locked = {}

    def covered(name: str, version: str) -> bool:
        entries = locked.get(name)
        entries = entries if isinstance(entries, list) else [entries]
        return any(isinstance(entry, dict) and (
            entry.get("version") == version
            or version in (entry.get("specifiers") if isinstance(entry.get("specifiers"), list) else ()))
            for entry in entries)

    return sorted(name + "@" + version for name, version in pins if not covered(name, version))


def check_tool_lock(repo: Path) -> dict:
    gaps = tool_lock_gaps(repo)
    if gaps:
        lock = repo / "mise.lock"
        state = "missing" if not lock.exists() else "does not cover " + ", ".join(gaps)
        raise ContractError("mise.lock " + state + "; run `mise lock` and commit mise.lock")
    return {'status': 'skipped', 'reason': 'lockfile_disabled_or_no_tool_pins'} if gaps is None else {'status': 'passed'}


RELEASE_BUILD = "mise-helper/vendor/pzagent-adw-context/modules/release_build.py"


def check_release_handover(repo: Path, adapter: dict[str, Any]) -> dict:
    """Release kinds need an adw:build that hands outputs to pz:release:package via PZ_ADW_BUILD_DIR."""
    kinds = sorted(name for name, kind in (adapter.get("release_kinds") or {}).items()
                   if isinstance(kind, dict) and kind.get("components"))
    commands_path = repo / "mise-helper/project-commands.toml"
    if not kinds:
        return {'status': 'skipped', 'reason': 'no_release_components'}
    if not commands_path.exists() and not commands_path.is_symlink():
        return {'status': 'skipped', 'reason': 'legacy_project_tasks_without_command_file'}
    declared = _private_toml(commands_path, "project-commands.toml")
    task = (declared.get("tasks") or {}).get("adw:build")
    if not isinstance(task, dict) or task.get("implemented") is not True:
        raise ContractError('release build handover requires an implemented adw:build')
    if task.get("release_commands"):
        return {'status': 'passed'}
    commands = task.get("commands") if isinstance(task.get("commands"), list) else []
    if any(isinstance(command, dict) and isinstance(command.get("argv"), list) and RELEASE_BUILD in command["argv"]
           for command in commands):
        return {'status': 'passed'}
    raise ContractError("release kind " + ", ".join(kinds) + " has no release build handover: adw:build declares"
                        " neither release_commands nor the bundled release_build.py producer for PZ_ADW_BUILD_DIR")


def check_consumer(
    repo: Path,
    *,
    freshness_lookup: Callable[[dict[str, Any]], str | None] | None = None,
    strict_freshness: bool = False,
    mise_version: str | None = None,
    development: bool = False,
    simulation: bool = False,
) -> dict[str, Any]:
    candidate_path = project_dir(repo) / 'pzagent-context-development.json'
    candidate = load_json(candidate_path) if candidate_path.exists() else None
    local_simulation = (simulation and os.environ.get('ACT', '').lower() == 'true'
                        and bool(os.environ.get('LAB_RUN')))
    if candidate is not None and (not development or (os.environ.get('GITHUB_ACTIONS') == 'true'
                                                      and not local_simulation)):
        raise ContractError('local development candidate is not an upstream release; use --development locally')
    bundle = validate_bundle(repo / VENDOR)
    manifest = load_json(project_dir(repo) / MANIFEST)
    lock = load_json(project_dir(repo) / LOCK)
    project_adw = project_dir(repo) / "ADW.md"
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
    if candidate is not None:
        if (candidate.get('schema_version') != '1.0.0' or candidate.get('kind') != 'local-development'
                or candidate.get('source_ref') != lock['source_ref']
                or candidate.get('bundle_sha256') != descriptor_checksum
                or not isinstance(candidate.get('baseline'), dict)):
            raise ContractError('development candidate identity differs')
        generic_root = repo / 'mise-helper/vendor/agentic-delivery'
        generic_files = candidate.get('generic_files')
        if (not isinstance(generic_files, dict) or not generic_files
                or any(sha256_file(ensure_contained(generic_root, name)) != checksum
                       for name, checksum in generic_files.items())):
            raise ContractError('generic development candidate checksum differs')

    sources = manifest.get("sources") if isinstance(manifest, dict) else None
    if not isinstance(sources, dict):
        raise ContractError("manifest source registry is missing")
    matches = [
        (source_id, item) for source_id, item in sources.items()
        if isinstance(source_id, str) and isinstance(item, dict) and item.get("layer") == "context"
    ]
    if len(matches) != 1 or set(matches[0][1]) != {"layer", "ref", "checksum", "path"}:
        raise ContractError("manifest context source is missing or ambiguous")
    context_source_id, source = matches[0]
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
            if not isinstance(capability_source, str) or capability_source not in sources:
                raise ContractError("consumer manifest capability source is unresolved")
            if sources[capability_source].get("layer") == "context" and capability_source != context_source_id:
                raise ContractError("context capability provenance differs")
    _check_compatibility(manifest, mise_version, minimum_mise=bundle["minimum_mise"])
    _check_generic_engine(repo, manifest)
    check_precedence(repo)
    check_context_task_overrides(repo)
    tool_lock = check_tool_lock(repo)
    handover = {'status': 'skipped', 'reason': 'no_project_adapter'}

    adapter_path = project_dir(repo) / 'pzagent-adapter.json'
    if adapter_path.exists():
        from .adapter import load as load_adapter
        from .hooks import check_commands
        adapter = load_adapter(adapter_path)
        check_commands(repo, adapter)
        handover = check_release_handover(repo, adapter)

    verdict = "local-development" if candidate is not None else "current"
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
        "tool_lock": tool_lock,
        "release_handover": handover,
    }


def check_version_transition(current: str, new: str, *, allow_downgrade: bool) -> None:
    old_version, new_version = _version(current, "current bundle"), _version(new, "bundle")
    if new_version < old_version and not allow_downgrade:
        raise ContractError("bundle downgrade requires --allow-downgrade")
    # SemVer promise: from 1.0 on, a new major version is a reviewed migration, not a sync.
    if old_version[0] >= 1 and new_version[0] != old_version[0]:
        raise ContractError("stable bundle major version change requires an explicit migration")


def _resolve_ref(source: str) -> str:
    if FULL_SHA.fullmatch(source):
        return source
    if not TAG.fullmatch(source):
        raise ContractError("sync source must be an exact SHA or protected release tag")
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
        try:
            tar.extractall(destination, members=members, filter="data")
        except TypeError:  # Python 3.11; members were validated above.
            tar.extractall(destination, members=members)
    return destination / "skills/pzagent/pzagent-adw-context/assets/mise/v2"


def _stage_consumer(
    repo: Path, staged: Path, bundle_root: Path, manifest: dict[str, Any],
    lock: dict[str, Any],
) -> None:
    shutil.copytree(bundle_root, staged / VENDOR)
    # The generic layer is untouched by a context sync, but the staged check needs it.
    generic = repo / GENERIC_ENGINE.parent
    if generic.is_dir() and not generic.is_symlink():
        shutil.copytree(generic, staged / GENERIC_ENGINE.parent, symlinks=False)
    (staged / project_dir(repo).name).mkdir(parents=True, exist_ok=True)
    (project_dir(staged) / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (project_dir(staged) / LOCK).write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    shutil.copy2(_mise_file(repo), staged / _mise_file(repo).name)
    tool_lock = repo / "mise.lock"
    if tool_lock.exists() or tool_lock.is_symlink():
        if (tool_lock.is_symlink() or not tool_lock.is_file()
                or tool_lock.stat().st_size > MAX_TOOL_CONFIG_BYTES):
            raise ContractError("mise.lock is unsafe")
        shutil.copy2(tool_lock, staged / "mise.lock")


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
        if current:
            check_version_transition(current, descriptor["version"], allow_downgrade=allow_downgrade)

        manifest = load_json(project_dir(repo) / MANIFEST)
        sources = manifest.get("sources")
        if not isinstance(sources, dict):
            raise ContractError("consumer manifest source registry is missing")
        context_ids = [
            source_id for source_id, value in sources.items()
            if isinstance(value, dict) and value.get("layer") == "context"
        ]
        if len(context_ids) != 1:
            raise ContractError("manifest context source is missing or ambiguous")
        context_source_id = context_ids[0]
        # Refuse before replacing vendor, lock, manifest or committed workflows.
        check_context_task_overrides(repo)
        source_record = {
            "layer": "context", "ref": ref,
            "checksum": "sha256:" + sha256_file(bundle_root / "tasks.toml"),
            "path": f"{VENDOR.as_posix()}/tasks.toml",
        }
        manifest["sources"][context_source_id] = source_record
        capabilities = manifest.get("capabilities")
        if capabilities is not None:
            if not isinstance(capabilities, dict):
                raise ContractError("consumer manifest capabilities are malformed")
            for value in capabilities.values():
                if not isinstance(value, dict):
                    raise ContractError("consumer manifest capability is malformed")
                capability_source = value.get("source")
                if not isinstance(capability_source, str) or capability_source not in sources:
                    raise ContractError("consumer manifest capability source is unresolved")
        if capabilities is not None:
            for task in ('adw:verify:full', 'adw:describe'):
                if task in capabilities:
                    capabilities[task]['source'] = context_source_id
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
        shutil.copy2(project_dir(staged) / MANIFEST, project_dir(repo) / MANIFEST)
        shutil.copy2(project_dir(staged) / LOCK, project_dir(repo) / LOCK)
    result = check_consumer(repo, mise_version=mise_version)
    from .workflows_sync import sync as sync_workflows
    sync_workflows(repo)
    return result

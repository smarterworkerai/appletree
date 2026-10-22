"""Bounded local ADW cleanup with an explicit host-wide mode."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

from .common import ContractError, UsageError, ensure_contained
from .providers import get

PREFIX = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
VOLUME_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
OWNER_LABEL = "com.smarterworkerai.adw.owner"
Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def _docker(runner: Runner, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(["docker", *arguments])
    except OSError as exc:
        raise ContractError("Docker is unavailable for local cleanup") from exc
    if result.returncode:
        raise ContractError("Docker local cleanup command failed")
    return result


def _tmp_size(path: Path) -> int:
    try:
        if path.is_symlink() or path.is_file():
            return path.lstat().st_size
        return sum(item.lstat().st_size for item in path.rglob("*") if not item.is_symlink())
    except OSError:
        return 0


def _remove(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _tmp_candidates(root: Path, prefix: str | None, aggressive: bool) -> list[Path]:
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        raise ContractError("temporary directory is unavailable") from exc
    if aggressive:
        return entries
    assert prefix is not None
    return [
        entry for entry in entries
        if entry.name == prefix or entry.name.startswith(prefix + "-")
    ]


def protected_volumes(repo: Path, adapter: dict) -> set[str]:
    """Protect the named volumes observed in every declared provider definition."""
    result: set[str] = set()
    for kind, declared in adapter.get("providers", {}).items():
        factory = get(kind)
        for name, binding in declared["bindings"].items():
            configuration = factory(repo, name, binding, None).configuration
            parser = configuration.volume_definitions
            if parser is None:
                if configuration.no_persistent_volumes:
                    continue
                raise ContractError("provider_capability_unsupported")
            definition_path = ensure_contained(repo, configuration.definition_path)
            if not definition_path.is_file():
                raise ContractError("declared deployment Compose is missing")
            for logical, definition in parser(definition_path.read_bytes()).items():
                result.add(logical)
                for line in definition[1:]:
                    stripped = line.strip()
                    if not stripped.startswith("name:"):
                        continue
                    explicit = stripped.split(":", 1)[1].strip().strip("'\"")
                    if VOLUME_NAME.fullmatch(explicit):
                        result.add(explicit)
    return result


def _volume_names(
    runner: Runner, label: list[str], protected: set[str],
) -> list[str]:
    output = _docker(
        runner, ["volume", "ls", "--quiet", "--filter", "dangling=true", *label],
    ).stdout
    names = {line.strip() for line in output.splitlines() if line.strip()}
    if not all(VOLUME_NAME.fullmatch(name) for name in names):
        raise ContractError("Docker returned an invalid volume name")
    if len(names) > 1000:
        raise ContractError("Docker volume candidate inventory exceeds safe bound")
    return sorted(name for name in names if not any(
        name == item or name.endswith("_" + item) or name.endswith("-" + item)
        for item in protected
    ))


def _listed(runner: Runner, arguments: list[str]) -> int:
    output = _docker(runner, arguments).stdout
    return len({line.strip() for line in output.splitlines() if line.strip()})


def _docker_candidates(
    runner: Runner, prefix: str | None, aggressive: bool, volumes: list[str],
) -> dict[str, int]:
    label = [] if aggressive else ["--filter", f"label={OWNER_LABEL}={prefix}"]
    return {
        "containers": _listed(runner, ["container", "ls", "--all", "--quiet", *label]),
        "images": _listed(runner, ["image", "ls", "--quiet", *label]),
        "volumes": len(volumes),
        "networks": _listed(runner, ["network", "ls", "--quiet", *label]),
    }


def _prune(
    runner: Runner, prefix: str | None, aggressive: bool, volumes: list[str],
) -> None:
    label = [] if aggressive else ["--filter", f"label={OWNER_LABEL}={prefix}"]
    if aggressive:
        commands = [
            ["container", "prune", "--force"],
            ["image", "prune", "--all", "--force"],
        ]
    else:
        commands = [
            ["container", "prune", "--force", *label],
            ["image", "prune", "--all", "--force", *label],
        ]
    for command in commands:
        _docker(runner, command)
    if volumes:
        _docker(runner, ["volume", "rm", "--", *volumes])
    _docker(runner, ["network", "prune", "--force", *label])
    if aggressive:
        _docker(runner, ["builder", "prune", "--all", "--force"])


def clean(
    *, prefix: str | None, dry_run: bool, aggressive: bool, yes: bool,
    tmp_root: Path = Path("/tmp"), runner: Runner = _run,
    interactive: bool | None = None, protected: set[str] | None = None,
) -> dict:
    protected = protected or set()
    if aggressive:
        if prefix is not None:
            raise UsageError("--prefix is not accepted with --aggressive")
        if not dry_run and not yes:
            raise UsageError("--aggressive requires --yes")
        if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
            raise ContractError("aggressive cleanup is forbidden in CI")
        if not dry_run and not (sys.stdin.isatty() if interactive is None else interactive):
            raise ContractError("aggressive cleanup requires an interactive local terminal")
    else:
        if prefix is None or not PREFIX.fullmatch(prefix):
            raise UsageError("normal cleanup requires a safe --prefix slug")
        if yes:
            raise UsageError("--yes is reserved for --aggressive mode")

    _docker(runner, ["version", "--format", "{{.Server.Version}}"])
    temporary = _tmp_candidates(tmp_root, prefix, aggressive)
    label = [] if aggressive else ["--filter", f"label={OWNER_LABEL}={prefix}"]
    effective_protected = set() if aggressive else protected
    volumes = _volume_names(runner, label, effective_protected)
    docker = _docker_candidates(runner, prefix, aggressive, volumes)
    temporary_bytes = sum(_tmp_size(path) for path in temporary)
    if not dry_run:
        if aggressive:
            print("WARNING: clearing /tmp can invalidate SSH-agent sockets, IDE/lab state and other processes", file=sys.stderr)
            for volume in volumes:
                print(f"WARNING: deleting unused Docker volume: {volume}", file=sys.stderr)
        for path in temporary:
            _remove(path)
        _prune(runner, prefix, aggressive, volumes)
    return {
        "status": "dry-run" if dry_run else "cleaned",
        "mode": "aggressive" if aggressive else "scoped",
        "temporary_entries": len(temporary),
        "temporary_bytes": temporary_bytes,
        "docker_candidates": docker,
        "docker_volume_candidates": volumes,
        "protected_volumes": len(effective_protected),
    }

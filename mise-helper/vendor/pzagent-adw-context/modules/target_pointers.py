"""Locked, conditional current/rollback target pointer promotion."""
from __future__ import annotations

import fcntl
import re
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .common import ContractError, IDENTIFIER

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMMUTABLE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")


class Registry(Protocol):
    def resolve(self, reference: str) -> str | None: ...
    def copy_if_unchanged(
        self, source: str, target: str, expected_target: str | None,
    ) -> None: ...
    def delete_if_unchanged(self, target: str, expected_target: str) -> None: ...


@dataclass(frozen=True)
class PointerSet:
    repository: str
    target: str
    release_kind: str
    source: str
    current: str
    rollback: str


def pointer_set(
    repository: str, target: str, release_kind: str, source: str,
    *, current_template: str = "target-{target}-current",
    rollback_template: str = "target-{target}-rollback",
) -> PointerSet:
    if (
        not repository
        or not IDENTIFIER.fullmatch(target)
        or not IDENTIFIER.fullmatch(release_kind)
        or not IMMUTABLE.fullmatch(source)
        or "{target}" not in current_template
        or "{target}" not in rollback_template
    ):
        raise ContractError("pointer declaration is invalid")
    return PointerSet(
        repository, target, release_kind, source,
        f"{repository}:{current_template.format(target=target)}",
        f"{repository}:{rollback_template.format(target=target)}",
    )


@contextmanager
def _lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("a+b") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ContractError("target pointer promotion lock is busy") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _copy(
    registry: Registry, source: str, target: str, source_digest: str,
    expected_target: str | None,
) -> None:
    registry.copy_if_unchanged(source, target, expected_target)
    if registry.resolve(target) != source_digest:
        raise ContractError("pointer descriptor readback differs")


def promote(
    registry: Registry,
    pointers: list[PointerSet],
    expected_current: dict[str, str | None],
    *,
    lock_dir: Path,
    runtime_proven: bool,
) -> None:
    if not pointers or not runtime_proven:
        raise ContractError("pointer promotion requires runtime proof")
    identities = {(item.target, item.release_kind) for item in pointers}
    if len(identities) != 1:
        raise ContractError("pointer promotion must isolate one target and release kind")
    target, release_kind = next(iter(identities))
    with _lock(lock_dir / f"{target}-{release_kind}.lock"):
        prior: list[tuple[PointerSet, str | None, str | None, str]] = []
        attempts: list[tuple[str, str, str | None]] = []
        try:
            for pointer in pointers:
                source_digest = registry.resolve(pointer.source)
                if source_digest is None or not DIGEST.fullmatch(source_digest):
                    raise ContractError("immutable release input is absent or invalid")
                current = registry.resolve(pointer.current)
                rollback = registry.resolve(pointer.rollback)
                if expected_current.get(pointer.current) != current:
                    raise ContractError("current pointer compare-and-swap precondition failed")
                prior.append((pointer, current, rollback, source_digest))
            for pointer, current, rollback, source_digest in prior:
                if current is not None:
                    attempts.append((pointer.rollback, current, rollback))
                    _copy(
                        registry, f"{pointer.repository}@{current}", pointer.rollback,
                        current, rollback,
                    )
                attempts.append((pointer.current, source_digest, current))
                _copy(registry, pointer.source, pointer.current, source_digest, current)
        except Exception as failure:
            conflicts: list[str] = []
            for reference, written, old in reversed(attempts):
                live = registry.resolve(reference)
                if live == old:
                    continue
                if live != written:
                    conflicts.append(reference)
                    continue
                try:
                    if old is None:
                        registry.delete_if_unchanged(reference, written)
                        if registry.resolve(reference) is not None:
                            raise ContractError("pointer delete readback differs")
                    else:
                        repository = reference.split(":target-", 1)[0]
                        _copy(
                            registry, f"{repository}@{old}", reference, old, written,
                        )
                except Exception:
                    conflicts.append(reference)
            if conflicts:
                raise ContractError(
                    "pointer promotion failed; manual recovery required"
                ) from failure
            raise ContractError(
                "pointer promotion failed; prior pointers restored"
            ) from failure


def reconcile(registry, pointers, previous, prior_rollback, *, lock_dir):
    """Explicitly finish this operation's partial promotion after runtime proof."""
    target, kind = pointers[0].target, pointers[0].release_kind
    same_release = all(previous[p.repository] == p.source.split('@', 1)[1] for p in pointers)
    with _lock(lock_dir / f'{target}-{kind}.lock'):
        observed = []
        for pointer in pointers:
            desired = pointer.source.split('@', 1)[1]
            current = registry.resolve(pointer.current)
            rollback = registry.resolve(pointer.rollback)
            old = previous[pointer.repository]
            if current not in {old, desired} or rollback not in {prior_rollback[pointer.repository], old}:
                raise ContractError('pointer reconciliation found an unrelated writer; no writes performed')
            if registry.resolve(pointer.source) != desired:
                raise ContractError('reconciliation release descriptor is unavailable')
            observed.append((pointer, current, rollback, old, desired))
        for pointer, current, rollback, old, desired in observed:
            retained = prior_rollback[pointer.repository] if same_release or old is None else old
            if rollback != retained:
                if retained is None:
                    registry.delete_if_unchanged(pointer.rollback, rollback)
                else:
                    _copy(registry, pointer.repository + '@' + retained, pointer.rollback, retained, rollback)
            if current != desired:
                _copy(registry, pointer.source, pointer.current, desired, current)

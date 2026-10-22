"""Deployment-provider protocol and the explicit registered-provider decision."""
from __future__ import annotations

from dataclasses import dataclass, field
import importlib
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, cast, runtime_checkable

from ..common import ContractError


@dataclass(frozen=True)
class DeploymentState:
    definition: bytes = field(repr=False)
    settings: bytes = field(repr=False)


@dataclass(frozen=True)
class DeploymentOperation:
    token: str
    context: Any = field(repr=False)


@dataclass(frozen=True)
class ProviderConfiguration:
    definition_path: str
    settings_schema_path: str
    volume_definitions: Callable[[bytes], Mapping[str, list[str]]] | None = None
    no_persistent_volumes: bool = False
    render_definition: Callable[[Path], bytes] | None = None


class DeploymentTerminalFailure(ContractError):
 def __init__(self,deployment_id:str,status:str):
  super().__init__('deployment reached terminal failure')
  self.deployment_id=deployment_id;self.status=status



class SettingsBackend(Protocol):
    """Optional byte access; shared hotfix state owns locking and recovery."""

    def read_definition(self) -> bytes: ...
    def read_settings(self) -> bytes: ...
    def write_settings(self, value: bytes) -> None: ...


@runtime_checkable
class DeploymentProvider(Protocol):
    """The operations in ADR 0004; observations are validated by their callers."""

    configuration: ProviderConfiguration

    @property
    def settings_backend(self) -> SettingsBackend:
        """Raise provider_capability_unsupported when this capability is absent."""
        ...

    def discover(self, binding: Mapping[str, Any]) -> None: ...
    def read_state(self) -> DeploymentState: ...
    def plan(self, updates: Mapping[str, str], *, definition: bytes | None = None,
             current: DeploymentState | None = None) -> DeploymentState: ...
    def apply(self, updates: Mapping[str, str], *, operation: str | None = None,
              submit: bool = True) -> DeploymentOperation: ...
    def wait(self, operation: DeploymentOperation) -> str: ...
    def readback(self, state: DeploymentState | None = None) -> Mapping[str, str]: ...
    def snapshot(self) -> DeploymentState: ...
    def restore(self, snapshot: DeploymentState, owned_keys: set[str]) -> None: ...
    def config_pull(self) -> dict[str, Any]: ...
    def config_plan(self, definition: bytes, required: set[str],
                    allowed: set[str]) -> dict[str, Any]: ...
    def config_apply(self, state: DeploymentState, owned_keys: set[str], *,
                     current: DeploymentState | None = None,
                     required: set[str] | None = None, allowed: set[str] | None = None,
                     snapshot_path: Path | None = None) -> dict[str, Any]: ...
    def probe(self, kind: str) -> dict[str, str]: ...
    def live_image_refs(self) -> Mapping[str, str]: ...
    def observed_image_refs(self, owned_keys: set[str]) -> Mapping[str, str]:
        """Unique declared runtime images, digest-pinned; never configured settings."""
        ...


# Only this declaration decides which provider kinds the adapter may accept.
# New implementations require an explicit registry and trust-boundary review.
_REGISTERED = {
    "dokploy": ("modules.providers.dokploy", "DokployProvider"),
    "kubernetes": ("modules.providers.kubernetes", "KubernetesProvider"),
}


def require(kind: str) -> None:
    """Validate a provider kind without importing or executing its implementation."""
    if not isinstance(kind, str) or kind not in _REGISTERED:
        raise ContractError("provider_unsupported")


ProviderFactory = Callable[[Path, str, Mapping[str, Any], Path | None], DeploymentProvider]


def get(kind: str) -> ProviderFactory:
    require(kind)
    module, name = _REGISTERED[kind]
    return cast(ProviderFactory, getattr(importlib.import_module(module), name))


def binding_for(adapter: Mapping[str, Any], target: Mapping[str, Any]) -> Mapping[str, Any]:
    require(target["provider"])
    return cast(Mapping[str, Any], adapter["providers"][target["provider"]]["bindings"][target["provider_binding"]])


def bind(repo: Path, adapter: Mapping[str, Any], name: str, target: Mapping[str, Any],
         profile_root: Path | None = None) -> DeploymentProvider:
    return get(target["provider"])(repo, name, binding_for(adapter, target), profile_root)


def hook_command(kind: str, repo: Path | None = None) -> list[str]:
    require(kind)
    # Provider registration owns this exact path, never project-controlled code.
    directory = (repo / 'mise-helper/vendor/pzagent-adw-context/modules/providers'
                 if repo is not None else Path(__file__).parent)
    path = directory / (kind + '_hooks.py')
    if not path.is_file():
        raise ContractError('provider_capability_unsupported')
    return [sys.executable, str(path)]

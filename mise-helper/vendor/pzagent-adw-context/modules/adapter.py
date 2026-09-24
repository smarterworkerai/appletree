"""Validate the closed project adapter and canonical declarations."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .common import ContractError, IDENTIFIER, load_json, safe_relative_path

CANONICAL = (
    "adw:build", "adw:check", "adw:context:check", "adw:context:sync",
    "adw:deploy:apply", "adw:deploy:config:apply", "adw:deploy:config:plan",
    "adw:deploy:config:pull", "adw:deploy:status", "adw:describe",
    "adw:test:e2e:fast", "adw:test:e2e:full",
    "adw:health", "adw:hotfix:apply", "adw:hotfix:restore", "adw:install", "adw:lint",
    "adw:readiness", "adw:static-analysis", "adw:test:integration:fast",
    "adw:test:integration:full",
    "adw:test:unit", "adw:validate-deployment", "adw:verify:full",
    "adw:verify:minimal",
)
SIDE_EFFECT = {
    "adw:build": "local-write", "adw:check": "read-only",
    "adw:context:check": "read-only", "adw:context:sync": "local-write",
    "adw:deploy:apply": "remote-write", "adw:deploy:config:apply": "remote-write",
    "adw:deploy:config:plan": "read-only", "adw:deploy:config:pull": "local-write",
    "adw:deploy:status": "read-only", "adw:describe": "read-only",
    "adw:test:e2e:fast": "remote-write", "adw:test:e2e:full": "remote-write",
    "adw:health": "read-only",
    "adw:hotfix:apply": "remote-write", "adw:hotfix:restore": "remote-write", "adw:install": "local-write",
    "adw:lint": "local-write", "adw:readiness": "read-only",
    "adw:static-analysis": "local-write", "adw:test:integration:fast": "local-write",
    "adw:test:integration:full": "local-write",
    "adw:test:unit": "local-write", "adw:validate-deployment": "remote-write",
    "adw:verify:full": "local-write", "adw:verify:minimal": "local-write",
}
TOP = {
    "schema_version", "repository", "environments", "capabilities", "targets",
    "providers", "release_kinds", "hooks", "retention", "diagnostics", "hotfix",
    "ci", "delivery",
}
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
OPERATION = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
PACKAGE = re.compile(r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+$")


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ContractError(f"{label} is not a closed object")
    return value


def _strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) != len(set(value)) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ContractError(f"{label} must be unique non-empty strings")
    return value


def validate(data: Any) -> dict[str, Any]:
    root = _exact(data, TOP, "project adapter")
    if root["schema_version"] != "1.0.0":
        raise ContractError("project adapter schema version is incompatible")

    repository = _exact(root["repository"], {"id", "protected_branches"}, "repository")
    if not isinstance(repository["id"], str) or not REPOSITORY.fullmatch(repository["id"]):
        raise ContractError("repository identity is invalid")
    protected = _strings(repository["protected_branches"], "protected branches")
    if not protected or not all(IDENTIFIER.fullmatch(branch) for branch in protected):
        raise ContractError("protected branches are invalid")
    ci = _exact(root["ci"], {"workflow_path", "required_job", "full_task", "minimal_task",
                             "diagnostic_marker", "ci_only_checks"}, "CI adapter")
    if (ci["workflow_path"] != ".github/workflows/ci.yml"
        or ci["required_job"] != "required-quality"
        or ci["full_task"] != "adw:verify:full"
        or ci["minimal_task"] != "adw:verify:minimal"
        or ci["diagnostic_marker"] != "deploy_diag"):
        raise ContractError("CI contract differs")
    checks=_strings(ci["ci_only_checks"], "CI-only checks")
    if len(checks)>20 or not all(len(item)<=100 for item in checks):
        raise ContractError("CI-only checks are invalid")
    delivery=_exact(root["delivery"], {"promotion_pairs"}, "delivery adapter")
    pairs=delivery["promotion_pairs"]
    if not isinstance(pairs,list) or len(pairs)>8:
        raise ContractError("promotion pairs are invalid")
    seen_pairs=set()
    for pair in pairs:
        value=_exact(pair,{"source","target"},"promotion pair")
        key=(value["source"],value["target"])
        if (key[0] not in protected or key[1] not in protected
            or key[0]==key[1] or key in seen_pairs):
            raise ContractError("promotion pair is invalid")
        seen_pairs.add(key)

    environments = _strings(root["environments"], "environments")
    if not all(IDENTIFIER.fullmatch(item) for item in environments):
        raise ContractError("environment identifier is invalid")

    capabilities = root["capabilities"]
    if not isinstance(capabilities, dict) or set(capabilities) != set(CANONICAL):
        raise ContractError("every canonical capability must be declared exactly once")
    for name, value in capabilities.items():
        capability = _exact(value, {"status", "environments", "side_effect"}, f"capability {name}")
        supported = capability["status"] in {"supported", "unsupported"}
        subset = _strings(capability["environments"], f"capability environments {name}")
        if not supported or not set(subset) <= set(environments) or capability["side_effect"] != SIDE_EFFECT[name]:
            raise ContractError(f"capability contract is invalid: {name}")
        if capability["status"] == "unsupported" and subset:
            raise ContractError(f"unsupported capability declares environments: {name}")

    targets = root["targets"]
    if not isinstance(targets, dict) or not set(targets) <= set(environments):
        raise ContractError("target environments are invalid")
    binding_refs: set[tuple[str, str]] = set()
    for environment, raw in targets.items():
        group = _exact(raw, {"default", "items"}, f"targets {environment}")
        items = group["items"]
        if not isinstance(items, dict) or not items:
            raise ContractError("target group is empty")
        for name, raw_target in items.items():
            if not IDENTIFIER.fullmatch(name):
                raise ContractError("logical target name is invalid")
            target = _exact(raw_target, {"mode", "provider", "provider_binding"}, f"target {name}")
            if target["mode"] not in {"active", "shadow"} or not all(
                isinstance(target[key], str) and IDENTIFIER.fullmatch(target[key])
                for key in ("provider", "provider_binding")
            ):
                raise ContractError("logical target declaration is invalid")
            binding_refs.add((target["provider"], target["provider_binding"]))
        default = group["default"]
        if default is not None and (default not in items or items[default]["mode"] != "active"):
            raise ContractError("default logical target must name an active item")
        active = [name for name, value in items.items() if value["mode"] == "active"]
        if default is None and len(active) == 1:
            raise ContractError("single active target must be declared as default")

    providers = root["providers"]
    if not isinstance(providers, dict) or set(providers) - {"dokploy"}:
        raise ContractError("provider adapters are invalid")
    known_bindings: set[tuple[str, str]] = set()
    if "dokploy" in providers:
        dokploy = _exact(providers["dokploy"], {"profile_handle", "bindings"}, "Dokploy provider")
        if not isinstance(dokploy["profile_handle"], str) or not dokploy["profile_handle"]:
            raise ContractError("Dokploy profile handle is invalid")
        if not isinstance(dokploy["bindings"], dict):
            raise ContractError("Dokploy bindings must be an object")
        for name, raw in dokploy["bindings"].items():
            if not IDENTIFIER.fullmatch(name):
                raise ContractError("provider binding name is invalid")
            binding = _exact(raw, {"project", "environment", "resource", "child_binding", "compose_path", "environment_schema_path"}, f"Dokploy binding {name}")
            if not all(isinstance(binding[key], str) and binding[key] for key in ("project", "environment", "resource")):
                raise ContractError("provider logical names are invalid")
            if not isinstance(binding["child_binding"], str) or not ENV_KEY.fullmatch(binding["child_binding"]):
                raise ContractError("provider child binding is invalid")
            if binding["child_binding"] in {"DOKPLOY_URL", "DOKPLOY_TOKEN"}:
                raise ContractError("provider child binding uses a reserved credential name")
            safe_relative_path(binding["compose_path"])
            safe_relative_path(binding["environment_schema_path"])
            known_bindings.add(("dokploy", name))
    if not binding_refs <= known_bindings:
        raise ContractError("logical target references an unknown provider binding")

    release_kinds = root["release_kinds"]
    if not isinstance(release_kinds, dict):
        raise ContractError("release kinds must be an object")
    for name, raw in release_kinds.items():
        if not IDENTIFIER.fullmatch(name):
            raise ContractError("release kind name is invalid")
        kind = _exact(raw, {"schema", "manifest_package", "components", "compose_variables", "pointer_tags"}, f"release kind {name}")
        if not isinstance(kind["schema"], str) or not kind["schema"] or not isinstance(kind["manifest_package"], str) or not PACKAGE.fullmatch(kind["manifest_package"]):
            raise ContractError("release kind identity is invalid")
        components = kind["components"]
        if not isinstance(components, dict) or not components:
            raise ContractError("release kind component set is empty")
        for component, raw_component in components.items():
            entry = _exact(raw_component, {"package"}, f"release component {component}")
            if not IDENTIFIER.fullmatch(component) or not isinstance(entry["package"], str) or not PACKAGE.fullmatch(entry["package"]):
                raise ContractError("release component is invalid")
        variables = kind["compose_variables"]
        if not isinstance(variables, dict) or set(variables.values()) != set(components) or not all(ENV_KEY.fullmatch(key) for key in variables):
            raise ContractError("release Compose variable mapping is invalid")
        tags = _exact(kind["pointer_tags"], {"current", "rollback"}, "pointer tags")
        if not all(isinstance(tags[key], str) and "{target}" in tags[key] for key in tags):
            raise ContractError("pointer tag template is invalid")

    hooks = _exact(root["hooks"], {"dispatcher", "operations"}, "hooks")
    dispatcher = _exact(hooks["dispatcher"], {"argv", "path_tools"}, "hook dispatcher")
    argv = dispatcher["argv"]
    path_tools = _strings(dispatcher["path_tools"], "hook PATH allowlist")
    if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) and 0 < len(arg) <= 4096 for arg in argv):
        raise ContractError("hook dispatcher argv is invalid")
    if "/" not in argv[0] and argv[0] not in path_tools:
        raise ContractError("hook dispatcher executable is not PATH-allowlisted")
    operations = hooks["operations"]
    if not isinstance(operations, dict):
        raise ContractError("hook operations must be an object")
    for capability, raw in operations.items():
        if capability not in CANONICAL or capabilities[capability]["status"] != "supported":
            raise ContractError("hook operation references an unsupported capability")
        operation = _exact(raw, {"operation", "timeout_seconds", "result_keys"}, f"hook operation {capability}")
        if not isinstance(operation["operation"], str) or not OPERATION.fullmatch(operation["operation"]):
            raise ContractError("hook operation identifier is invalid")
        if not isinstance(operation["timeout_seconds"], int) or not 1 <= operation["timeout_seconds"] <= 3600:
            raise ContractError("hook timeout is outside the shared bound")
        keys = _strings(operation["result_keys"], "hook result keys")
        if not all(OPERATION.fullmatch(key) for key in keys):
            raise ContractError("hook result key is invalid")
        if not set(keys) <= {"images", "order", "profile", "role", "status", "selected", "executed", "skipped"}:
            raise ContractError("hook result key is not content-safe")
        if capability in {"adw:test:e2e:fast", "adw:test:e2e:full"} and set(keys) != {"status", "selected", "executed", "skipped"}:
            raise ContractError("E2E hook must declare exact suite counts")

    retention = _exact(root["retention"], {"grace_hours", "diagnostic_days", "managed_release_kinds"}, "retention")
    if not isinstance(retention["grace_hours"], int) or not 1 <= retention["grace_hours"] <= 720:
        raise ContractError("retention grace period is invalid")
    if not isinstance(retention["diagnostic_days"], int) or not 1 <= retention["diagnostic_days"] <= 90:
        raise ContractError("diagnostic retention is invalid")
    if not set(_strings(retention["managed_release_kinds"], "managed release kinds")) <= set(release_kinds):
        raise ContractError("retention references an unknown release kind")

    diagnostics = _exact(root["diagnostics"], {"marker"}, "diagnostics")
    safe_relative_path(diagnostics["marker"])

    hotfix = _exact(root["hotfix"], {"supported_environments", "transports", "ssh_aliases"}, "hotfix")
    if not set(_strings(hotfix["supported_environments"], "hotfix environments")) <= set(environments):
        raise ContractError("hotfix environment is unknown")
    if not set(_strings(hotfix["transports"], "hotfix transports")) <= {"registry", "ssh-docker"}:
        raise ContractError("hotfix transport is invalid")
    _strings(hotfix["ssh_aliases"], "hotfix SSH aliases")
    return root


def load(path: Path) -> dict[str, Any]:
    return validate(load_json(path))

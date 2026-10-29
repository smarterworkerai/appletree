"""Validate the closed project adapter and canonical declarations."""
from __future__ import annotations

import copy
import re
import sys
from pathlib import Path
from typing import Any

from .common import ContractError, IDENTIFIER, load_json, safe_relative_path
from .providers import require as require_provider
from .release_manifest import normalize_image_variables

CANONICAL = (
    "adw:build", "adw:check", "adw:context:check", "adw:context:sync",
    "adw:deploy:apply", "adw:deploy:config:apply", "adw:deploy:config:plan",
    "adw:deploy:config:pull", "adw:deploy:status", "adw:describe",
    "adw:test:e2e:fast", "adw:test:e2e:full",
    "adw:health", "adw:hotfix:apply", "adw:hotfix:restore", "adw:install", "adw:lint",
    "adw:local:clean", "adw:readiness", "adw:static-analysis", "adw:test:integration:fast",
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
    "adw:lint": "local-write", "adw:local:clean": "local-write",
    "adw:readiness": "read-only",
    "adw:static-analysis": "local-write", "adw:test:integration:fast": "local-write",
    "adw:test:integration:full": "local-write",
    "adw:test:unit": "local-write", "adw:validate-deployment": "remote-write",
    "adw:verify:full": "local-write", "adw:verify:minimal": "local-write",
}
NORMALIZED_TOP = {
    "schema_version", "repository", "environments", "capabilities", "targets",
    "providers", "release_kinds", "hooks", "retention", "hotfix",
    "ci", "delivery",
}
V11_REQUIRED_TOP = {
    "schema_version", "repository", "targets", "providers", "release_kinds",
    "hooks", "retention", "hotfix", "delivery",
}
CI_DEFAULTS = {
    "workflow_path": ".github/workflows/ci.yml",
    "required_job": "required-quality",
    "ci_only_checks": [],
}
DISPATCHER_DEFAULT = {
    "argv": ["python3", "mise-helper/pzagent_adapter.py"],
    "path_tools": ["python3"],
}
POINTER_DEFAULT = {
    "current": "target-{target}-current",
    "rollback": "target-{target}-rollback",
}
FORCED_RESULT_KEYS = {
    "adw:test:e2e:fast": ["status", "selected", "executed", "skipped"],
    "adw:test:e2e:full": ["status", "selected", "executed", "skipped"],
    "adw:validate-deployment": ["images"],
}
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
OPERATION = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
PACKAGE = re.compile(r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+$")
KUBE_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _validate_hook_command(command: Any) -> None:
    if not isinstance(command, str) or not command:
        raise ContractError('hook command is invalid')
    if command == 'bundle:provider':
        return
    if command.startswith('bundle:'):
        require_provider(command.removeprefix('bundle:'))
    else:
        if re.match(r'^(?:python(?:[0-9]+(?:\.[0-9]+)*)?|node|bash|sh|env)\s+', command):
            raise ContractError('hook command must name a file without an interpreter prefix')
        safe_relative_path(command)


SERVICE_NAME = re.compile(r'^[a-z0-9][a-z0-9_-]{0,62}$')
ROUTE_PATH = re.compile(r'^/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?$')
ENV_FILE = re.compile(r'^\.env\.[a-z0-9][a-z0-9.-]{0,62}$')


def dokploy_routes(binding) -> list[dict]:
    """Validated optional `routes` of a Dokploy binding (#187); absent means unmanaged."""
    value = binding.get('routes')
    if value is None:
        return []
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise ContractError('provider_routes_invalid')
    result, seen = [], set()
    for route in value:
        if not isinstance(route, dict) or not {'service', 'port'} <= set(route) or set(route) - {'service', 'port', 'path'}:
            raise ContractError('provider_routes_invalid')
        path = route.get('path', '/')
        if (not isinstance(route['service'], str) or not SERVICE_NAME.fullmatch(route['service'])
                or type(route['port']) is not int or not 1 <= route['port'] <= 65535
                or not isinstance(path, str) or not ROUTE_PATH.fullmatch(path) or path in seen):
            raise ContractError('provider_routes_invalid')
        seen.add(path)
        result.append({'service': route['service'], 'port': route['port'], 'path': path})
    return result


def _dokploy_operator_fields(binding):
    """Optional operator declarations (#187): routed domains, private file name, data-import hook."""
    dokploy_routes(binding)
    if 'env_file' in binding and (not isinstance(binding['env_file'], str) or not ENV_FILE.fullmatch(binding['env_file'])
                                  or binding['env_file'].endswith('.example')):
        raise ContractError('provider env_file must be .env.<name> in the repository root')
    if 'data_import' in binding:
        spec = _exact(binding['data_import'], {'service', 'script'}, 'provider data_import')
        if not isinstance(spec['service'], str) or not SERVICE_NAME.fullmatch(spec['service']):
            raise ContractError('provider data_import service is invalid')
        safe_relative_path(spec['script'])


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


def _manifest_contract(manifest: Any) -> tuple[list[str], dict[str, dict[str, Any]]]:
    if not isinstance(manifest, dict):
        raise ContractError("task manifest is required to load the adapter")
    try:
        environments = _strings(manifest["environments"], "manifest environments")
        raw_capabilities = manifest["capabilities"]
    except (KeyError, TypeError, ContractError) as exc:
        raise ContractError("task manifest is required to load the adapter") from exc
    if (not all(IDENTIFIER.fullmatch(item) for item in environments)
            or not isinstance(raw_capabilities, dict)
            or set(raw_capabilities) != set(CANONICAL)):
        raise ContractError("task manifest is required to load the adapter")
    capabilities: dict[str, dict[str, Any]] = {}
    for name, raw in raw_capabilities.items():
        if not isinstance(raw, dict) or set(raw) != {"status", "environments", "side_effect", "source"}:
            raise ContractError("task manifest is required to load the adapter")
        if not isinstance(raw["source"], str) or not raw["source"]:
            raise ContractError("task manifest is required to load the adapter")
        capabilities[name] = {
            "status": raw["status"],
            "environments": copy.deepcopy(raw["environments"]),
            "side_effect": raw["side_effect"],
        }
    return copy.deepcopy(environments), capabilities


def expand(data: Any, manifest: Any) -> dict[str, Any]:
    """Expand closed project facts into the backwards-compatible runtime shape."""
    if not isinstance(data, dict) or data.get("schema_version") not in {"1.1.0", "1.2.0"}:
        raise ContractError("project adapter schema version is incompatible")
    if not V11_REQUIRED_TOP <= set(data) or set(data) - (V11_REQUIRED_TOP | {"ci"}):
        raise ContractError("project adapter is not a closed object")
    environments, capabilities = _manifest_contract(manifest)
    raw = copy.deepcopy(data)

    raw_ci = raw.get("ci", {})
    if not isinstance(raw_ci, dict) or set(raw_ci) - {"ci_only_checks"}:
        raise ContractError("CI adapter is not a closed object")
    ci = {**copy.deepcopy(CI_DEFAULTS), "ci_only_checks": copy.deepcopy(raw_ci.get("ci_only_checks", []))}

    raw_providers = raw["providers"]
    if not isinstance(raw_providers, dict):
        raise ContractError("provider adapters are invalid")
    for kind in raw_providers:
        require_provider(kind)
    if "kubernetes" in raw_providers and data["schema_version"] != "1.2.0":
        raise ContractError("kubernetes_adapter_version_required")
    providers: dict[str, Any] = {}
    if "kubernetes" in raw_providers:
        providers["kubernetes"] = copy.deepcopy(raw_providers["kubernetes"])
    if "dokploy" in raw_providers:
        raw_dokploy = raw_providers["dokploy"]
        if not isinstance(raw_dokploy, dict) or "bindings" not in raw_dokploy or set(raw_dokploy) - {"project", "bindings"}:
            raise ContractError("Dokploy provider is not a closed object")
        project = raw_dokploy.get("project")
        if project is not None and (not isinstance(project, str) or not project):
            raise ContractError("provider logical names are invalid")
        bindings = raw_dokploy["bindings"]
        if not isinstance(bindings, dict):
            raise ContractError("Dokploy bindings must be an object")
        expanded_bindings: dict[str, Any] = {}
        binding_keys = {"project", "environment", "resource", "child_binding", "compose_path", "environment_schema_path"}
        optional_binding_keys = {"probes", "plan", "placement", "routes", "env_file", "data_import"}
        for name, binding in bindings.items():
            if not isinstance(binding, dict) or set(binding) - (binding_keys | optional_binding_keys) or not (binding_keys - {"project"}) <= set(binding):
                raise ContractError(f"Dokploy binding {name} is not a closed object")
            resolved_project = binding.get("project", project)
            if not isinstance(resolved_project, str) or not resolved_project:
                raise ContractError("provider binding project is required")
            expanded_bindings[name] = {**copy.deepcopy(binding), "project": resolved_project}
        providers["dokploy"] = {"bindings": expanded_bindings}

    targets: dict[str, Any] = {}
    if not isinstance(raw["targets"], dict):
        raise ContractError("target environments are invalid")
    for environment, target in raw["targets"].items():
        if isinstance(target, str):
            logical_name = f"{environment}-dokploy"
            targets[environment] = {
                "default": logical_name,
                "items": {
                    logical_name: {
                        "mode": "active", "provider": "dokploy", "provider_binding": target,
                    }
                },
            }
        else:
            targets[environment] = copy.deepcopy(target)

    release_kinds: dict[str, Any] = {}
    if not isinstance(raw["release_kinds"], dict):
        raise ContractError("release kinds must be an object")
    for name, kind in raw["release_kinds"].items():
        if not isinstance(kind, dict):
            raise ContractError(f"release kind {name} has invalid fields")
        release_kinds[name] = copy.deepcopy(kind)
        release_kinds[name].setdefault("pointer_tags", copy.deepcopy(POINTER_DEFAULT))

    raw_hooks = raw["hooks"]
    if not isinstance(raw_hooks, dict) or "operations" not in raw_hooks or set(raw_hooks) - {"dispatcher", "operations"}:
        raise ContractError("hooks is not a closed object")
    operations = raw_hooks["operations"]
    if not isinstance(operations, dict):
        raise ContractError("hook operations must be an object")
    expanded_operations: dict[str, Any] = {}
    for capability, operation in operations.items():
        if not isinstance(operation, dict):
            raise ContractError(f"hook operation {capability} is not a closed object")
        allowed = {"operation", "timeout_seconds", "result_keys", "command"}
        required = {"operation", "timeout_seconds"}
        if set(operation) - allowed or not required <= set(operation):
            raise ContractError(f"hook operation {capability} is not a closed object")
        value = copy.deepcopy(operation)
        if "result_keys" not in value:
            if capability not in FORCED_RESULT_KEYS:
                raise ContractError(f"hook operation {capability} requires result_keys")
            value["result_keys"] = copy.deepcopy(FORCED_RESULT_KEYS[capability])
        expanded_operations[capability] = value
    hooks = {
        "dispatcher": copy.deepcopy(raw_hooks.get("dispatcher", DISPATCHER_DEFAULT)),
        "operations": expanded_operations,
    }

    hotfix_raw = raw["hotfix"]
    if not isinstance(hotfix_raw, dict) or set(hotfix_raw) != {"transports", "ssh_aliases"}:
        raise ContractError("hotfix is not a closed object")
    apply_environments = set(capabilities["adw:hotfix:apply"]["environments"])
    restore_environments = set(capabilities["adw:hotfix:restore"]["environments"])
    supported_environments = [
        environment for environment in environments
        if environment in apply_environments and environment in restore_environments
    ]
    hotfix = {"supported_environments": supported_environments, **copy.deepcopy(hotfix_raw)}

    retention_raw = raw["retention"]
    if not isinstance(retention_raw, dict) or set(retention_raw) != {"grace_hours"}:
        raise ContractError("retention is not a closed object")

    normalized = {
        "schema_version": "1.0.0",
        "repository": copy.deepcopy(raw["repository"]),
        "environments": environments,
        "capabilities": capabilities,
        "targets": targets,
        "providers": providers,
        "release_kinds": release_kinds,
        "hooks": hooks,
        "retention": copy.deepcopy(retention_raw),
        "hotfix": hotfix,
        "ci": ci,
        "delivery": copy.deepcopy(raw["delivery"]),
    }
    return validate(normalized)


def _kubernetes_bindings(provider: Any, environments: list[str]) -> set[tuple[str, str]]:
    """Validate facts only; never import the driver or read an operator profile."""
    provider = _exact(provider, {"bindings"}, "Kubernetes provider")
    bindings = provider["bindings"]
    if not isinstance(bindings, dict):
        raise ContractError("kubernetes_bindings_invalid")
    required = {"environment", "context_alias", "namespace", "release",
                "image_variables", "config_schema_path", "ingress_probe_base"}
    result = set()
    for name, binding in bindings.items():
        if (not isinstance(name, str) or not IDENTIFIER.fullmatch(name)
                or not isinstance(binding, dict) or not required <= set(binding)
                or set(binding) - (required | {"probes", "plan"})):
            raise ContractError("kubernetes_binding_invalid")
        if (binding["environment"] not in environments
                or not isinstance(binding["context_alias"], str)
                or not IDENTIFIER.fullmatch(binding["context_alias"])
                or not isinstance(binding["namespace"], str)
                or not KUBE_NAME.fullmatch(binding["namespace"])):
            raise ContractError("kubernetes_binding_identity_invalid")
        release = _exact(binding["release"], {"kind", "path"}, "Kubernetes release")
        if release["kind"] not in {"kustomize", "helm"}:
            raise ContractError("kubernetes_release_kind_invalid")
        safe_relative_path(release["path"])
        safe_relative_path(binding["config_schema_path"])
        key = binding["ingress_probe_base"]
        if not isinstance(key, str) or not ENV_KEY.fullmatch(key):
            raise ContractError("kubernetes_probe_key_invalid")
        variables = binding["image_variables"]
        if not isinstance(variables, dict) or not variables:
            raise ContractError("kubernetes_image_mapping_invalid")
        seen = set()
        for variable, raw in variables.items():
            entry = _exact(raw, {"kind", "name", "container"}, "Kubernetes image mapping")
            if (not isinstance(variable, str) or not ENV_KEY.fullmatch(variable)
                    or entry["kind"] not in {"Deployment", "StatefulSet", "DaemonSet"}
                    or not all(isinstance(entry[k], str) and KUBE_NAME.fullmatch(entry[k])
                               for k in ("name", "container"))):
                raise ContractError("kubernetes_image_mapping_invalid")
            identity = (entry["kind"], entry["name"], entry["container"])
            if identity in seen:
                raise ContractError("kubernetes_image_mapping_ambiguous")
            seen.add(identity)
        if "probes" in binding:
            probes = _exact(binding["probes"], {"base_url_env", "health_path", "readiness_path"}, "provider probes")
            if probes["base_url_env"] != key:
                raise ContractError("kubernetes_probe_key_conflict")
            for field in ("health_path", "readiness_path"):
                if (not isinstance(probes[field], str)
                        or not re.fullmatch(r'/[A-Za-z0-9/_-]{0,255}', probes[field])
                        or "//" in probes[field] or ".." in probes[field]):
                    raise ContractError("provider probe path is invalid")
        if "plan" in binding:
            plan = _exact(binding["plan"], {"role", "order"}, "provider plan")
            if (not isinstance(plan["role"], str) or not re.fullmatch(r'[a-z]{3,32}', plan["role"])
                    or not isinstance(plan["order"], str)
                    or not re.fullmatch(r'[a-z]+(?: [a-z]+)*(?:; [a-z]+(?: [a-z]+)*){0,3}', plan["order"])):
                raise ContractError("provider plan semantics are invalid")
        result.add(("kubernetes", name))
    return result


def validate(data: Any) -> dict[str, Any]:
    root = copy.deepcopy(_exact(data, NORMALIZED_TOP, "project adapter"))
    if root["schema_version"] != "1.0.0":
        raise ContractError("project adapter schema version is incompatible")

    repository = _exact(root["repository"], {"id", "protected_branches"}, "repository")
    if not isinstance(repository["id"], str) or not REPOSITORY.fullmatch(repository["id"]):
        raise ContractError("repository identity is invalid")
    protected = _strings(repository["protected_branches"], "protected branches")
    if not protected or not all(IDENTIFIER.fullmatch(branch) for branch in protected):
        raise ContractError("protected branches are invalid")
    ci = root["ci"]
    normalized_ci_keys = {"workflow_path", "required_job", "ci_only_checks"}
    legacy_ci_keys = normalized_ci_keys | {"full_task", "minimal_task"}
    if not isinstance(ci, dict) or frozenset(ci) not in {frozenset(normalized_ci_keys), frozenset(legacy_ci_keys)}:
        raise ContractError("CI adapter is not a closed object")
    if (ci["workflow_path"] != ".github/workflows/ci.yml"
        or ci["required_job"] != "required-quality"):
        raise ContractError("CI contract differs")
    if set(ci) == legacy_ci_keys:
        if ci["full_task"] != "adw:verify:full" or ci["minimal_task"] != "adw:verify:minimal":
            raise ContractError("CI contract differs")
        del ci["full_task"]
        del ci["minimal_task"]
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
            require_provider(target["provider"])
            binding_refs.add((target["provider"], target["provider_binding"]))
        default = group["default"]
        if default is not None and (default not in items or items[default]["mode"] != "active"):
            raise ContractError("default logical target must name an active item")
        active = [name for name, value in items.items() if value["mode"] == "active"]
        if default is None and len(active) == 1:
            raise ContractError("single active target must be declared as default")

    providers = root["providers"]
    if not isinstance(providers, dict):
        raise ContractError("provider adapters are invalid")
    for kind in providers:
        require_provider(kind)
    known_bindings: set[tuple[str, str]] = set()
    if "dokploy" in providers:
        dokploy = providers["dokploy"]
        if not isinstance(dokploy, dict) or set(dokploy) not in ({"bindings"}, {"profile_handle", "bindings"}):
            raise ContractError("Dokploy provider is not a closed object")
        if "profile_handle" in dokploy:
            if not isinstance(dokploy["profile_handle"], str) or not dokploy["profile_handle"]:
                raise ContractError("Dokploy profile handle is invalid")
            del dokploy["profile_handle"]
        if not isinstance(dokploy["bindings"], dict):
            raise ContractError("Dokploy bindings must be an object")
        for name, raw in dokploy["bindings"].items():
            if not IDENTIFIER.fullmatch(name):
                raise ContractError("provider binding name is invalid")
            required_binding = {"project", "environment", "resource", "child_binding", "compose_path", "environment_schema_path"}
            if not isinstance(raw, dict) or not required_binding <= set(raw) or set(raw) - (required_binding | {'probes', 'plan', 'placement', 'routes', 'env_file', 'data_import'}):
                raise ContractError(f'Dokploy binding {name} is not a closed object')
            binding = raw
            if 'placement' in binding and (not isinstance(binding['placement'], str)
                                            or binding['placement'] not in {'local', 'remote'}):
                raise ContractError('provider_placement_invalid')
            if 'probes' in binding:
                probes = _exact(binding['probes'], {'base_url_env', 'health_path', 'readiness_path'}, 'provider probes')
                if not isinstance(probes['base_url_env'], str) or not ENV_KEY.fullmatch(probes['base_url_env']):
                    raise ContractError('provider probe base URL key is invalid')
                for field in ('health_path', 'readiness_path'):
                    if not isinstance(probes[field], str) or not re.fullmatch(r'/[A-Za-z0-9/_-]{0,255}', probes[field]) or '//' in probes[field] or '..' in probes[field]:
                        raise ContractError('provider probe path is invalid')
            if 'plan' in binding:
                plan = _exact(binding['plan'], {'role', 'order'}, 'provider plan')
                if not isinstance(plan['role'], str) or not re.fullmatch(r'[a-z]{3,32}', plan['role']) or not isinstance(plan['order'], str) or not re.fullmatch(r'[a-z]+(?: [a-z]+)*(?:; [a-z]+(?: [a-z]+)*){0,3}', plan['order']):
                    raise ContractError('provider plan semantics are invalid')
            if not all(isinstance(binding[key], str) and binding[key] for key in ("project", "environment", "resource")):
                raise ContractError("provider logical names are invalid")
            if not isinstance(binding["child_binding"], str) or not ENV_KEY.fullmatch(binding["child_binding"]):
                raise ContractError("provider child binding is invalid")
            if binding["child_binding"] in {"DOKPLOY_URL", "DOKPLOY_TOKEN"}:
                raise ContractError("provider child binding uses a reserved credential name")
            safe_relative_path(binding["compose_path"])
            safe_relative_path(binding["environment_schema_path"])
            _dokploy_operator_fields(binding)
            known_bindings.add(("dokploy", name))
    if "kubernetes" in providers:
        known_bindings |= _kubernetes_bindings(providers["kubernetes"], environments)
        for environment, group in targets.items():
            for target in group["items"].values():
                if (target["provider"] == "kubernetes"
                        and ("kubernetes", target["provider_binding"]) in known_bindings
                        and providers["kubernetes"]["bindings"][target["provider_binding"]]["environment"] != environment):
                    raise ContractError("kubernetes_binding_environment_mismatch")
    if not binding_refs <= known_bindings:
        raise ContractError("logical target references an unknown provider binding")

    release_kinds = root["release_kinds"]
    if not isinstance(release_kinds, dict):
        raise ContractError("release kinds must be an object")
    for name, raw in release_kinds.items():
        if not IDENTIFIER.fullmatch(name):
            raise ContractError("release kind name is invalid")
        required_kind = {"schema", "manifest_package", "components", "pointer_tags"}
        if not isinstance(raw, dict) or not required_kind <= set(raw) or not set(raw) <= required_kind | {"publication_pointers", "image_variables", "compose_variables"}:
            raise ContractError(f"release kind {name} has invalid fields")
        kind = normalize_image_variables(raw)
        release_kinds[name] = kind
        if not isinstance(kind["schema"], str) or not kind["schema"] or not isinstance(kind["manifest_package"], str) or not PACKAGE.fullmatch(kind["manifest_package"]):
            raise ContractError("release kind identity is invalid")
        components = kind["components"]
        if not isinstance(components, dict) or not components:
            raise ContractError("release kind component set is empty")
        for component, raw_component in components.items():
            entry = _exact(raw_component, {"package"}, f"release component {component}")
            if not IDENTIFIER.fullmatch(component) or not isinstance(entry["package"], str) or not PACKAGE.fullmatch(entry["package"]):
                raise ContractError("release component is invalid")
        variables = kind["image_variables"]
        if not isinstance(variables, dict) or set(variables.values()) != set(components) or not all(ENV_KEY.fullmatch(key) for key in variables):
            raise ContractError("release Compose variable mapping is invalid")
        tags = _exact(kind["pointer_tags"], {"current", "rollback"}, "pointer tags")
        if not all(isinstance(tags[key], str) and "{target}" in tags[key] for key in tags):
            raise ContractError("pointer tag template is invalid")
        publication_pointers = kind.get("publication_pointers", [])
        if (not isinstance(publication_pointers, list)
                or len(publication_pointers) > 16
                or len(publication_pointers) != len(set(publication_pointers))
                or not all(isinstance(tag, str) and IDENTIFIER.fullmatch(tag)
                           for tag in publication_pointers)):
            raise ContractError("publication pointer allowlist is invalid")

    hooks = _exact(root["hooks"], {"dispatcher", "operations"}, "hooks")
    dispatcher = hooks['dispatcher']
    if isinstance(dispatcher, dict) and set(dispatcher) == {'command'}:
        _validate_hook_command(dispatcher['command'])
    else:
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
        required_operation = {'operation', 'timeout_seconds', 'result_keys'}
        if not isinstance(raw, dict) or not required_operation <= set(raw) or set(raw) - (required_operation | {'command'}):
            raise ContractError(f'hook operation {capability} is not a closed object')
        operation = raw
        if 'command' in operation:
            _validate_hook_command(operation['command'])
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
        if capability == "adw:validate-deployment" and keys != ["images"]:
            raise ContractError("deployment validation hook must declare exact images result")

    retention = root["retention"]
    if not isinstance(retention, dict) or set(retention) not in ({"grace_hours"}, {"grace_hours", "managed_release_kinds"}):
        raise ContractError("retention is not a closed object")
    if not isinstance(retention["grace_hours"], int) or not 1 <= retention["grace_hours"] <= 720:
        raise ContractError("retention grace period is invalid")
    if "managed_release_kinds" in retention:
        if not set(_strings(retention["managed_release_kinds"], "managed release kinds")) <= set(release_kinds):
            raise ContractError("retention references an unknown release kind")
        del retention["managed_release_kinds"]

    hotfix = _exact(root["hotfix"], {"supported_environments", "transports", "ssh_aliases"}, "hotfix")
    if not set(_strings(hotfix["supported_environments"], "hotfix environments")) <= set(environments):
        raise ContractError("hotfix environment is unknown")
    transports = hotfix["transports"]
    if isinstance(transports, dict):
        if set(transports) - set(providers):
            raise ContractError("hotfix_provider_unknown")
        for provider, values in transports.items():
            allowed = {"registry"} if provider == "kubernetes" else {"registry", "ssh-docker"}
            if not set(_strings(values, "hotfix transports")) <= allowed:
                raise ContractError("hotfix_provider_transport_invalid")
    elif not set(_strings(transports, "hotfix transports")) <= {"registry", "ssh-docker"}:
        raise ContractError("hotfix transport is invalid")
    _strings(hotfix["ssh_aliases"], "hotfix SSH aliases")
    return root


def _validate_legacy_shape(data: dict[str, Any]) -> None:
    """Keep persisted schema 1.0.0 files under their original closed constraints."""
    ci = data.get("ci")
    if (not isinstance(ci, dict)
            or set(ci) != {"workflow_path", "required_job", "full_task", "minimal_task", "ci_only_checks"}
            or ci.get("full_task") != "adw:verify:full"
            or ci.get("minimal_task") != "adw:verify:minimal"):
        raise ContractError("CI adapter is not a closed object")
    providers = data.get("providers")
    if not isinstance(providers, dict):
        raise ContractError("provider adapters are invalid")
    dokploy = providers.get("dokploy")
    if dokploy is not None and (
        not isinstance(dokploy, dict)
        or set(dokploy) != {"profile_handle", "bindings"}
        or not isinstance(dokploy.get("profile_handle"), str)
        or not dokploy["profile_handle"]
    ):
        raise ContractError("Dokploy provider is not a closed object")
    retention = data.get("retention")
    if not isinstance(retention, dict) or set(retention) != {"grace_hours", "managed_release_kinds"}:
        raise ContractError("retention is not a closed object")


def load(path: Path, manifest_path: Path | None = None) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        raise ContractError("project adapter is not a closed object")
    manifest_path = manifest_path or path.parent / "adw-task-manifest.json"
    if data.get("schema_version") in {"1.1.0", "1.2.0"}:
        try:
            manifest = load_json(manifest_path)
        except (ContractError, OSError, ValueError) as exc:
            raise ContractError("task manifest is required to load the adapter") from exc
        return expand(data, manifest)

    _validate_legacy_shape(data)
    normalized = validate(data)
    if not manifest_path.is_file():
        print(
            "deprecated: adapter schema 1.0.0 without a task manifest is accepted only until 0.7.0",
            file=sys.stderr,
        )
        return normalized
    try:
        environments, capabilities = _manifest_contract(load_json(manifest_path))
    except (ContractError, OSError, ValueError) as exc:
        raise ContractError("task manifest is required to load the adapter") from exc
    if normalized["environments"] != environments or normalized["capabilities"] != capabilities:
        raise ContractError("adapter capabilities differ from the task manifest")
    return normalized

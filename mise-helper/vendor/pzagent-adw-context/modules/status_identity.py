"""Read-only release identity for a single declared logical target."""
from __future__ import annotations

import json
from collections.abc import Mapping
from contextlib import nullcontext
from pathlib import Path

from .common import project_dir
from .common import ContractError
from .operator_registry import inspect
from .oras_registry import DIGEST, OrasRegistry
from .release_manifest import DIGEST_REF, image_variables, release_kind


def read(repo: Path, adapter: dict, environment: str, target: str, provider,
         registry_auth=nullcontext) -> dict:
    """Never infer a release from tags or expose transport exception contents."""
    result = {'status': 'blocked'}
    try:
        config = json.loads((project_dir(repo) / 'pz-release.json').read_text())
        names = [name for name, environments in config['kind_environments'].items()
                 if environment in environments and name in adapter['release_kinds']]
        if len(names) != 1:
            return result | {'reason': 'release_kind_ambiguous'}
        kind_name = names[0]
        kind = release_kind(adapter, kind_name)
        mapping = image_variables(kind)
        with registry_auth():
            registry = OrasRegistry()
            pointers = {}
            for which in ('current', 'rollback'):
                reference = kind['manifest_package'] + ':' + kind['pointer_tags'][which].format(target=target)
                value = registry.resolve(reference)
                if value is not None and (not isinstance(value, str) or not DIGEST.fullmatch(value)):
                    return result | {'reason': 'release_pointer_invalid'}
                pointers[which] = value or 'absent'
            result['pointers'] = pointers
            if pointers['current'] == 'absent':
                return result | {'reason': 'release_current_absent'}
            immutable = kind['manifest_package'] + '@' + pointers['current']
            try:
                inspected = inspect(adapter, kind_name, release_reference=immutable)
            except ContractError:
                return result | {'reason': 'release_manifest_unproven'}
            if not inspected['available']:
                return result | {'reason': 'release_manifest_unavailable'}
            manifest = inspected['manifest']
            # inspect validates bytes, declared kind, source and exact components.
            # Compare its resolved reference too: an immutable lookup must not drift.
            manifest_current = inspected['release_reference'] == immutable
            result.update(manifest_digest=inspected['release_reference'].split('@', 1)[1],
                          source_sha=manifest['source_sha'],
                          components={name: reference.split('@', 1)[1]
                                      for name, reference in manifest['images'].items()},
                          parity={'manifest_current': manifest_current})
            try:
                observed = provider.observed_image_refs(set(mapping))
            except ContractError as exc:
                # Only fixed observation refusals can leave this boundary.
                safe = {'runtime_image_not_immutable', 'runtime_component_undeclared',
                        'runtime_container_not_running',
                        'runtime_container_cardinality_differs', 'runtime_service_mapping_invalid',
                        'runtime_project_identity_absent', 'runtime_container_discovery_failed',
                        'runtime_container_inspection_failed', 'runtime_image_identity_or_health_mismatch',
                        'provider_capability_unsupported'}
                return result | {'reason': str(exc) if str(exc) in safe else 'release_runtime_unproven'}
            if not isinstance(observed, Mapping) or set(observed) != set(mapping):
                return result | {'reason': 'release_runtime_scope_differs'}
            for image in observed.values():
                if not isinstance(image, str) or not DIGEST_REF.fullmatch(image):
                    return result | {'reason': 'runtime_image_not_immutable'}
            runtime_manifest = all(observed[key] == manifest['images'][component]
                                   for key, component in mapping.items())
            result['parity']['runtime_manifest'] = runtime_manifest
            if not manifest_current:
                return result | {'reason': 'release_manifest_current_differs'}
            if not runtime_manifest:
                return result | {'reason': 'release_runtime_manifest_differs'}
            # Detect a concurrent pointer update rather than reporting stale parity.
            current = registry.resolve(kind['manifest_package'] + ':' +
                                       kind['pointer_tags']['current'].format(target=target))
            if current != pointers['current']:
                result['parity']['manifest_current'] = False
                return result | {'reason': 'release_current_changed'}
            return result | {'status': 'ok'}
    except (ContractError, OSError, ValueError, KeyError, TypeError, AttributeError):
        return result | {'reason': 'release_identity_unavailable'}

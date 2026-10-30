"""Explicit-context Kubernetes observations and bounded server-side operations.

The CLI transports data only. Generic release orchestration retains approval,
source, pointer and runtime-proof decisions. Tool output never becomes a reason.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
from typing import Any, Mapping

from ..adapter import probe_url_key
from ..common import ContractError, ensure_contained
from ..operator_credentials import bootstrap_keys, clean_environment
from ..runtime_proof import parse_environment
from ..operator_state import private_directory
from . import DeploymentOperation, DeploymentState, ProviderConfiguration

MAX_BYTES = 8 * 1024 * 1024


class KubernetesCommandError(ContractError):
    """A closed public reason with transient private inputs for the operator journal.

    stderr and command values stay in memory until an operator lifecycle records
    a sanitized diagnostic. str(error), receipts and evidence contain only reason.
    """
    def __init__(self, reason, arguments, stderr, *, sensitive=(), data=None, kubeconfig=None,
                 operation_id=None, stage='selection'):
        super().__init__(reason)
        self.arguments = tuple(arguments)
        self.stderr = stderr if isinstance(stderr, bytes) else b''
        self.sensitive, self.data, self.kubeconfig = sensitive, data, kubeconfig
        self.operation_id, self.stage = operation_id, stage


MANAGER = 'adw'
MANAGED = 'app.kubernetes.io/managed-by'
TARGET = 'adw.pzagent.io/target'
WORKLOADS = {'Deployment', 'StatefulSet', 'DaemonSet'}
KINDS = WORKLOADS | {'Service', 'Ingress', 'ConfigMap', 'PersistentVolumeClaim'}
RESOURCES = 'deployments,statefulsets,daemonsets,services,ingresses,configmaps,persistentvolumeclaims'
NAME = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
RUNTIME_PATHS = {'Deployment': ('/apis/apps/v1', 'deployments'), 'StatefulSet': ('/apis/apps/v1', 'statefulsets'),
                 'DaemonSet': ('/apis/apps/v1', 'daemonsets'), 'ReplicaSet': ('/apis/apps/v1', 'replicasets'),
                 'Service': ('/api/v1', 'services'), 'Ingress': ('/apis/networking.k8s.io/v1', 'ingresses'),
                 'ConfigMap': ('/api/v1', 'configmaps'), 'PersistentVolumeClaim': ('/api/v1', 'persistentvolumeclaims'),
                 'Pod': ('/api/v1', 'pods')}
DIGEST = re.compile(r'^.+@sha256:[0-9a-f]{64}$')


def _encoded(items: list[dict]) -> bytes:
    return (json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items},
                       sort_keys=True, separators=(',', ':')) + '\n').encode()


def _objects(raw: bytes) -> list[dict]:
    try:
        if len(raw) > MAX_BYTES:
            raise ValueError()
        # kubectl may emit one JSON object per YAML document, rather than a List.
        remaining = raw.decode().strip()
        objects = []
        while remaining:
            value, end = json.JSONDecoder().raw_decode(remaining)
            if not isinstance(value, dict):
                raise ValueError()
            if isinstance(value.get('kind'), str) and value['kind'].endswith('List'):
                if not isinstance(value.get('items'), list):
                    raise ValueError()
                objects.extend(value['items'])
            else:
                objects.append(value)
            remaining = remaining[end:].lstrip()
        if any(not isinstance(item, dict) for item in objects):
            raise ValueError()
        return objects
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ContractError('kubernetes_objects_invalid') from exc


def _identity(item: dict) -> tuple[str, str]:
    metadata = item.get('metadata')
    if (not isinstance(metadata, dict) or not isinstance(item.get('kind'), str) or item['kind'] not in KINDS
            or not isinstance(metadata.get('name'), str)
            or not NAME.fullmatch(metadata['name'])):
        raise ContractError('kubernetes_object_identity_invalid')
    return item['kind'], metadata['name']


def _containers(item: dict) -> list[dict]:
    try:
        values = item['spec']['template']['spec']['containers']
        if (not isinstance(values, list) or not values
                or any(not isinstance(v, dict) or not isinstance(v.get('name'), str)
                       or not NAME.fullmatch(v['name']) or not isinstance(v.get('image'), str)
                       for v in values)
                or len({v['name'] for v in values}) != len(values)):
            raise ValueError()
        return values
    except (KeyError, TypeError, ValueError) as exc:
        raise ContractError('kubernetes_workload_invalid') from exc


def _controlled_by(item: dict, kind: str, name: str, uid: str) -> bool:
    owners = item.get('metadata', {}).get('ownerReferences', [])
    controllers = [v for v in owners if isinstance(v, dict) and v.get('controller') is True] if isinstance(owners, list) else []
    return bool(uid) and len(controllers) == 1 and all(
        controllers[0].get(key) == value for key, value in (('kind', kind), ('name', name), ('uid', uid)))


def _declarative(item: dict) -> dict:
    result = copy.deepcopy(item)
    result.pop('status', None)
    metadata = result['metadata']
    for key in ('uid', 'resourceVersion', 'generation', 'creationTimestamp',
                'managedFields', 'selfLink', 'deletionTimestamp'):
        metadata.pop(key, None)
    annotations = metadata.get('annotations', {})
    annotations.pop('kubectl.kubernetes.io/last-applied-configuration', None)
    if result.get('kind') == 'Deployment':
        annotations.pop('deployment.kubernetes.io/revision', None)
    if not annotations:
        metadata.pop('annotations', None)
    return result


class KubernetesProvider:
    def __init__(self, repo: Path, target: str, binding: Mapping[str, Any],
                 profile_root: Path | None = None) -> None:
        self.repo, self.target = repo, target
        self.binding = copy.deepcopy(dict(binding))
        self.profile_root = profile_root
        self.context = ''
        self.namespace = ''
        self.kubeconfig: Path | None = None
        self.image_pull_secret: str | None = None
        self._diagnostic_secrets: tuple[bytes, ...] = ()
        self._diagnostic_state: dict | None = None
        # Observation-only callers redirect kubectl's discovery cache and Helm's
        # homes into private scratch they remove; None keeps the user's defaults.
        self.cache_dir: Path | None = None
        release = self.binding.get('release', {})
        self.configuration = ProviderConfiguration(
            str(release.get('path', '')), str(binding.get('config_schema_path', '')),
            render_definition=self.render,
        )

    def _environment(self) -> dict[str, str]:
        env = clean_environment()
        for key in bootstrap_keys(self.profile_root):
            env.pop(key, None)
        for key in ('SSH_AUTH_SOCK', 'DOCKER_CONFIG', 'DOCKER_AUTH_CONFIG', 'REGISTRY_AUTH_FILE', 'ORAS_CONFIG'):
            env.pop(key, None)
        return env

    def _run(self, arguments: list[str], *, data: bytes | None = None,
             accepted: set[int] | None = None, timeout: int = 45) -> bytes:
        if not self.context or not self.namespace or self.kubeconfig is None:
            raise ContractError('kubernetes_context_not_discovered')
        env = self._environment()
        env['KUBECONFIG'] = str(self.kubeconfig)
        cache = ['--cache-dir', str(self.cache_dir)] if self.cache_dir is not None else []
        command = ['kubectl', '--context', self.context, '--namespace', self.namespace,
                   '--request-timeout=30s', *cache, *arguments]

        def failed(reason, stderr=b''):
            values = (*arguments, self.context, self.namespace, str(self.kubeconfig),
                      *os.environ.values())
            state = self._diagnostic_state or {}
            return KubernetesCommandError(reason, arguments, stderr, data=data, kubeconfig=self.kubeconfig,
                sensitive=tuple(value.encode() for value in values if value) + self._diagnostic_secrets,
                operation_id=state.get('operation_id'), stage=state.get('phase', 'selection'))

        try:
            result = subprocess.run(command, input=data, capture_output=True,
                                    env=env, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise failed('kubernetes_command_unavailable', getattr(exc, 'stderr', b'')) from None
        if result.returncode not in (accepted if accepted is not None else {0}):
            diagnostic = result.stderr[-65536:].lower()
            if b'conflict with' in diagnostic or b'fieldmanagerconflict' in diagnostic:
                raise failed('kubernetes_field_conflict', result.stderr)
            if b'field is immutable' in diagnostic or b'immutable field' in diagnostic:
                raise failed('kubernetes_immutable_field_refused', result.stderr)
            raise failed('kubernetes_command_failed', result.stderr)
        if len(result.stdout) > MAX_BYTES:
            raise ContractError('kubernetes_output_unbounded')
        return result.stdout

    def discover(self, binding: Mapping[str, Any]) -> None:
        self.discover_context(binding)
        try:
            actual_namespace = json.loads(self._run(['get', 'namespace', self.namespace, '-o', 'json']))
            if actual_namespace.get('metadata', {}).get('name') != self.namespace:
                raise ValueError()
        except (ValueError, AttributeError) as exc:
            raise ContractError('kubernetes_namespace_mismatch') from exc

    def discover_context(self, binding: Mapping[str, Any]) -> None:
        """Select the explicit context before namespace provisioning or discovery."""
        if dict(binding) != self.binding:
            raise ContractError('kubernetes_binding_changed')
        root = self.profile_root
        if root is None:
            raw = os.environ.get('PZ_ADW_PROFILE_ROOT')
            root = Path(raw) if raw else None
        if root is None:
            raise ContractError('kubernetes_context_profile_missing')
        path = root / 'kubernetes-contexts.json'
        # Reasons name the file relative to the operator home and the failed check,
        # never the private path, context handle or file contents.
        where = (root.name + '/' if root.name == 'profile' else '') + path.name

        def invalid(check: str) -> ContractError:
            return ContractError(f'kubernetes_context_profile_invalid: {where}: {check}')

        try:
            if path.is_symlink():
                raise invalid('is a symlink')
            if not path.is_file():
                flat = root.name == 'profile' and (root.parent / path.name).exists()
                raise invalid('missing; found in the operator home itself (flat layout before 0.15.5): '
                              'move the profile files into <operator-home>/profile/' if flat
                              else 'missing; expected in <operator-home>/profile/')
            if path.stat().st_mode & 0o077:
                raise invalid('mode must be 0600')
            if path.stat().st_size > 65536:
                raise invalid('larger than 64 KiB')
            try:
                profile = json.loads(path.read_bytes())
            except (UnicodeError, ValueError):
                raise invalid('not valid JSON') from None
            if (not isinstance(profile, dict) or set(profile) != {'schema_version', 'contexts'}
                    or profile['schema_version'] != '1.0.0' or not isinstance(profile['contexts'], dict)):
                raise invalid('schema must be {schema_version: "1.0.0", contexts}')
            selected = profile['contexts'].get(binding['context_alias'])
            if selected is None:
                raise invalid('no entry for the binding\'s context alias ' + str(binding['context_alias']))
            if (not isinstance(selected, dict) or not {'context', 'namespace'} <= set(selected)
                    or set(selected) - {'context', 'namespace', 'image_pull_secret'}):
                raise invalid('context entry needs exactly context, namespace and optional image_pull_secret')
            secret = selected.get('image_pull_secret')
            if secret is not None and secret != 'adw-ghcr-pull':
                raise invalid('image_pull_secret must be adw-ghcr-pull')
            context = selected['context']
            namespace = selected['namespace']
            if not isinstance(context, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}', context):
                raise invalid('context handle is not a valid kubeconfig context name')
            if namespace != binding['namespace']:
                raise invalid('namespace differs from the adapter binding')
            if os.environ.get('PZ_ADW_KUBE_CONTEXT', context) != context:
                raise invalid('PZ_ADW_KUBE_CONTEXT selects a different context')
            config = Path(os.environ.get('KUBECONFIG', str(root / 'kubeconfig')))
            if config.is_symlink() or not config.is_file():
                raise invalid('kubeconfig missing (KUBECONFIG or profile/kubeconfig)')
            if config.stat().st_mode & 0o077:
                raise invalid('kubeconfig mode must be 0600')
            if config.stat().st_size > MAX_BYTES:
                raise invalid('kubeconfig too large')
        except (OSError, TypeError) as exc:
            raise invalid('unreadable') from exc
        self.context, self.namespace, self.kubeconfig = context, namespace, config
        self.image_pull_secret = secret
        actual = self._run(['config', 'get-contexts', context, '-o', 'name']).decode().strip()
        if actual != context:
            raise ContractError('kubernetes_context_mismatch')

    def _validate(self, items: list[dict], *, desired: bool) -> list[dict]:
        result, seen = [], set()
        for raw in items:
            item = copy.deepcopy(raw)
            identity = _identity(item)
            if identity in seen:
                raise ContractError('kubernetes_object_ambiguous')
            seen.add(identity)
            metadata = item['metadata']
            namespace = metadata.get('namespace', self.namespace if desired else None)
            if namespace != self.namespace:
                raise ContractError('kubernetes_namespace_mismatch')
            metadata['namespace'] = self.namespace
            labels = metadata.setdefault('labels', {})
            if not isinstance(labels, dict):
                raise ContractError('kubernetes_object_identity_invalid')
            if desired:
                if labels.get(MANAGED, MANAGER) != MANAGER or labels.get(TARGET, self.target) != self.target:
                    raise ContractError('kubernetes_object_owner_mismatch')
                labels.update({MANAGED: MANAGER, TARGET: self.target})
            elif labels.get(MANAGED) != MANAGER or labels.get(TARGET) != self.target:
                raise ContractError('kubernetes_object_owner_mismatch')
            if identity[0] in WORKLOADS:
                _containers(item)
                if desired:
                    template = item['spec']['template'].setdefault('metadata', {})
                    template.setdefault('labels', {}).update({MANAGED: MANAGER, TARGET: self.target})
                    if self.image_pull_secret:
                        pod = item['spec']['template']['spec']
                        pulls = pod.setdefault('imagePullSecrets', [])
                        if not isinstance(pulls, list) or any(not isinstance(v, dict) or set(v) != {'name'} for v in pulls):
                            raise ContractError('kubernetes_pull_secret_invalid')
                        if {'name': self.image_pull_secret} not in pulls:
                            pulls.append({'name': self.image_pull_secret})
            result.append(item)
        return sorted(result, key=_identity)

    def render(self, path: Path) -> bytes:
        try:
            # config_source may supply an independently verified Git snapshot.
            # Its root differs from the operator checkout, but the declared
            # relative release path and containment contract remain identical.
            parts = Path(self.configuration.definition_path).parts
            root = path
            for _ in parts:
                root = root.parent
            if ensure_contained(root, self.configuration.definition_path) != path.resolve():
                raise ValueError()
            if path.is_symlink() or not path.is_dir():
                raise ValueError()
            for child in (root / parts[0]).rglob('*'):
                if child.is_symlink():
                    raise ValueError()
                if child.name.lower() in {'kustomization.yaml', 'kustomization.yml', 'kustomization'}:
                    if child.stat().st_size > 1024 * 1024 or re.search(r'https?://|git::|git@|github\.com/', child.read_text()):
                        raise ValueError()
        except (OSError, UnicodeError, ValueError) as exc:
            raise ContractError('kubernetes_render_input_invalid') from exc
        if self.binding['release']['kind'] == 'kustomize':
            raw = self._run(['kustomize', str(path), '--load-restrictor=LoadRestrictionsRootOnly'])
        else:
            env = self._environment()
            if self.cache_dir is not None:
                env.update({key: str(self.cache_dir / name) for key, name in (
                    ('HELM_CACHE_HOME', 'helm-cache'), ('HELM_CONFIG_HOME', 'helm-config'),
                    ('HELM_DATA_HOME', 'helm-data'))})
            try:
                run = subprocess.run(['helm', 'template', self.target, str(path), '--namespace', self.namespace],
                                     env=env, capture_output=True, timeout=45)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ContractError('kubernetes_renderer_unavailable') from exc
            if run.returncode or len(run.stdout) > MAX_BYTES:
                raise ContractError('kubernetes_render_failed')
            raw = run.stdout
        converted = self._run(['create', '--dry-run=client', '--validate=false', '-f', '-', '-o', 'json'], data=raw)
        items = self._validate(_objects(converted), desired=True)
        if not items:
            raise ContractError('kubernetes_release_empty')
        self._images(items, require_all=True)
        return _encoded(items)

    def _live(self) -> list[dict]:
        selector = f'{MANAGED}={MANAGER},{TARGET}={self.target}'
        raw = self._run(['get', RESOURCES, '-l', selector, '-o', 'json', '--show-managed-fields=true'])
        return self._validate(_objects(raw), desired=False)

    def read_state(self) -> DeploymentState:
        items = self._live()
        definition = _encoded([_declarative(v) for v in items])
        values = self._images(items, require_all=False)
        return DeploymentState(definition, ''.join(k + '=' + v + '\n' for k, v in sorted(values.items())).encode())

    def snapshot(self) -> DeploymentState:
        return self.read_state()

    def _empty_scope(self) -> str:
        try:
            value = json.loads(self._run(['get', 'namespace', self.namespace, '-o', 'json']))
        except (ValueError, UnicodeError) as exc:
            raise ContractError('kubernetes_empty_runtime_scope_unproven') from exc
        metadata = value.get('metadata') if isinstance(value, dict) else None
        if not isinstance(metadata, dict):
            raise ContractError('kubernetes_empty_runtime_scope_unproven')
        uid = metadata.get('uid')
        if metadata.get('name') != self.namespace or not isinstance(uid, str) or not uid:
            raise ContractError('kubernetes_empty_runtime_scope_unproven')
        return hashlib.sha256('\0'.join((self.context, self.namespace, self.target, uid)).encode()).hexdigest()

    def _runtime_children(self) -> list[dict]:
        selector = f'{MANAGED}={MANAGER},{TARGET}={self.target}'
        items = []
        for resource, kind in (('replicasets', 'ReplicaSet'), ('pods', 'Pod')):
            selected = _objects(self._run(['get', resource, '-l', selector, '-o', 'json']))
            for item in selected:
                metadata = item.get('metadata', {})
                labels = metadata.get('labels') if isinstance(metadata, dict) else None
                if (not isinstance(metadata, dict) or not isinstance(labels, dict)
                        or item.get('kind') != kind or metadata.get('namespace') != self.namespace
                        or not isinstance(metadata.get('name'), str) or not NAME.fullmatch(metadata['name'])
                        or labels.get(MANAGED) != MANAGER or labels.get(TARGET) != self.target):
                    raise ContractError('kubernetes_empty_runtime_readback_ambiguous')
            items.extend(selected)
        return items

    def empty_runtime_proof(self, snapshot: DeploymentState | None = None) -> dict[str, Any] | None:
        """Prove absence of bounded owned runtime; bootstrap Secrets/storage stay outside it."""
        scope = self._empty_scope()
        items = self._live()
        if any(item['kind'] != 'PersistentVolumeClaim' for item in items) or self._runtime_children():
            return None
        definition = _encoded(sorted((_declarative(v) for v in items), key=_identity))
        if snapshot is not None and _encoded(sorted(_objects(snapshot.definition), key=_identity)) != definition:
            raise ContractError('kubernetes_state_changed')
        claims = _objects(self._run(['get', 'persistentvolumeclaims', '-o', 'json']))
        if any(v.get('kind') != 'PersistentVolumeClaim' or not isinstance(v.get('metadata'), dict)
               or v['metadata'].get('namespace') != self.namespace for v in claims):
            raise ContractError('kubernetes_empty_runtime_readback_ambiguous')
        if scope != self._empty_scope():
            raise ContractError('kubernetes_empty_runtime_scope_changed')
        return {'state': 'empty', 'scope_sha256': scope,
                'snapshot_sha256': hashlib.sha256(snapshot.definition if snapshot is not None else definition).hexdigest(),
                'retained_pvc_count': len(claims)}

    def validate_empty_runtime_proof(self, proof: dict[str, Any]) -> None:
        if (not isinstance(proof, dict)
                or set(proof) != {'state', 'scope_sha256', 'snapshot_sha256', 'retained_pvc_count'}
                or proof.get('state') != 'empty' or proof.get('scope_sha256') != self._empty_scope()
                or not isinstance(proof.get('snapshot_sha256'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', proof['snapshot_sha256'])
                or type(proof.get('retained_pvc_count')) is not int or proof['retained_pvc_count'] < 0):
            raise ContractError('kubernetes_empty_runtime_scope_changed')

    def restore_empty_runtime(self, proof: dict[str, Any]) -> dict[str, Any]:
        """Remove only this target's nonpersistent objects; orphan all dependents first."""
        self.validate_empty_runtime_proof(proof)
        from ..dokploy_transaction import target_lock
        with target_lock(self.repo, self.target):
            live = [v for v in self._live() if v['kind'] != 'PersistentVolumeClaim']
            self._guard(live, live)
            # Orphan propagation prevents indirect deletion of PVCs, Secrets or
            # foreign children through owner references. Delete only validated
            # selector-owned ReplicaSets, then Pods, after their parents vanish.
            if live:
                self._run(['delete', '--cascade=orphan', '--ignore-not-found=true', '-f', '-',
                           '--wait=true', '--timeout=300s'], data=_encoded(live), timeout=315)
            for kind in ('ReplicaSet', 'Pod'):
                children = [v for v in self._runtime_children() if v['kind'] == kind]
                if children:
                    self._run(['delete', '--cascade=orphan', '--ignore-not-found=true', '-f', '-',
                               '--wait=true', '--timeout=300s'], data=_encoded(children), timeout=315)
            result = self.empty_runtime_proof()
            if result is None or result['scope_sha256'] != proof['scope_sha256']:
                raise ContractError('kubernetes_empty_runtime_restore_unproven')
            return result

    def runtime_inventory(self, journaled: list[dict] = ()) -> tuple[list[dict], list[dict]]:
        """This target's applied runtime and its persistent claims, with exact identities.

        A claim is owned when the provider applied it (labeled live object), when a live
        owned StatefulSet created it from a claim template (exact `<template>-<set>-<n>`
        name, the set's selector labels, created after the set, no foreign owner), or when
        this operation journaled its UID before an interrupted removal. Every other claim,
        including a same-named replacement of a journaled one, is foreign.
        """
        recorded = {(v['kind'], v['name']): v['uid'] for v in journaled}
        live = self._live() + self._runtime_children()
        for item in live:
            identity = (item['kind'], item['metadata']['name'])
            if identity in recorded and recorded[identity] != item['metadata'].get('uid'):
                raise ContractError('kubernetes_provision_identity_changed')
        workloads = [v for v in live if v['kind'] != 'PersistentVolumeClaim']
        owned = {v['metadata']['name']: v for v in live if v['kind'] == 'PersistentVolumeClaim'}
        templates = {}
        for item in workloads:
            if item['kind'] == 'StatefulSet':
                for template in item.get('spec', {}).get('volumeClaimTemplates', []) or []:
                    name = template.get('metadata', {}).get('name') if isinstance(template, dict) else None
                    if not isinstance(name, str) or not NAME.fullmatch(name):
                        raise ContractError('kubernetes_object_identity_invalid')
                    templates[name + '-' + item['metadata']['name'] + '-'] = item
        for claim in _objects(self._run(['get', 'persistentvolumeclaims', '-o', 'json'])):
            kind, name = _identity(claim)
            metadata = claim['metadata']
            if kind != 'PersistentVolumeClaim' or metadata.get('namespace') != self.namespace:
                raise ContractError('kubernetes_empty_runtime_readback_ambiguous')
            if name in owned:
                continue
            if recorded.get((kind, name)) is not None:
                if recorded[(kind, name)] != metadata.get('uid'):
                    raise ContractError('kubernetes_provision_identity_changed')
                owned[name] = claim
                continue
            sets = [s for prefix, s in templates.items() if re.fullmatch(re.escape(prefix) + r'[0-9]+', name)]
            if len(sets) == 1:
                owner = sets[0]
                selector = owner.get('spec', {}).get('selector', {}).get('matchLabels', {})
                references = metadata.get('ownerReferences', []) or []
                if (isinstance(selector, dict) and selector and isinstance(metadata.get('labels'), dict)
                        and all(metadata['labels'].get(k) == v for k, v in selector.items())
                        and str(metadata.get('creationTimestamp', '')) >= str(owner['metadata'].get('creationTimestamp', '~'))
                        and all(isinstance(r, dict) and r.get('uid') == owner['metadata'].get('uid') for r in references)):
                    owned[name] = claim
        return workloads, [owned[name] for name in sorted(owned)]

    def namespace_inventory(self) -> list[dict]:
        """Every listable namespaced object, for an ownership preflight before runtime removal."""
        resources = self._run(['api-resources', '--verbs=list', '--namespaced=true', '-o', 'name']).decode().splitlines()
        if not resources or len(resources) > 256:
            raise ContractError('kubernetes_provision_inventory_invalid')
        items = []
        for resource in resources:
            if not resource or not all(c.isalnum() or c in '.-' for c in resource):
                raise ContractError('kubernetes_provision_inventory_invalid')
            if resource in {'events', 'events.events.k8s.io'} or resource.endswith('.metrics.k8s.io'):
                # Control-plane telemetry and metrics-server views (PodMetrics) carry no stored state.
                continue
            for item in _objects(self._run(['get', resource, '-o', 'json'])):
                metadata = item.get('metadata')
                if (not isinstance(metadata, dict) or not isinstance(item.get('kind'), str)
                        or not isinstance(metadata.get('name'), str) or metadata.get('namespace') != self.namespace):
                    raise ContractError('kubernetes_provision_inventory_invalid')
                items.append(item)
        return items

    def _current_uid(self, kind: str, name: str) -> str | None:
        resource = RUNTIME_PATHS[kind][1]
        raw = self._run(['get', resource, name, '--ignore-not-found', '-o', 'jsonpath={.metadata.uid}'])
        return raw.decode().strip() or None

    def delete_exact(self, item: dict) -> None:
        """Delete one object only while it still has the observed UID and resourceVersion.

        An object that is already gone (garbage-collected with its owner, or a lost delete
        acknowledgement) is reconciled by absence; a same-named replacement refuses.
        """
        kind, name = item['kind'], item['metadata']['name']
        group, resource = RUNTIME_PATHS[kind]
        uid, version = item['metadata'].get('uid'), item['metadata'].get('resourceVersion')
        if not isinstance(uid, str) or not uid or not isinstance(version, str) or not version:
            raise ContractError('kubernetes_provision_readback_invalid')
        current = self._current_uid(kind, name)
        if current is None:
            return
        if current != uid:
            raise ContractError('kubernetes_provision_identity_changed')
        path = f'{group}/namespaces/{self.namespace}/{resource}/{name}'
        options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'propagationPolicy': 'Background',
                   'preconditions': {'uid': uid, 'resourceVersion': version}}
        try:
            self._run(['delete', '--raw', path, '-f', '-'], data=json.dumps(options).encode())
        except ContractError:
            current = self._current_uid(kind, name)
            if current is None:
                return
            if current != uid:
                raise ContractError('kubernetes_provision_identity_changed') from None
            raise

    def wait_gone(self, items: list[dict]) -> None:
        for item in items:
            self._run(['wait', '--for=delete', item['kind'] + '/' + item['metadata']['name'], '--timeout=300s'],
                      timeout=315)

    def verify_runtime_removed(self, claims: list[dict]) -> None:
        remaining, _ = self.runtime_inventory()
        names = {v['metadata']['name'] for v in claims}
        left = {v['metadata']['name'] for v in _objects(self._run(['get', 'persistentvolumeclaims', '-o', 'json']))}
        if remaining or names & left:
            raise ContractError('kubernetes_deprovision_runtime_unproven')

    def _images(self, items: list[dict], *, require_all: bool) -> dict[str, str]:
        indexed = {_identity(item): item for item in items}
        result = {}
        for variable, entry in self.binding['image_variables'].items():
            item = indexed.get((entry['kind'], entry['name']))
            if item is None and not require_all:
                continue
            matches = [c for c in _containers(item) if c['name'] == entry['container']] if item is not None else []
            if len(matches) != 1:
                raise ContractError('kubernetes_image_mapping_unresolved')
            result[variable] = matches[0]['image']
        return result

    @staticmethod
    def _preserve_claim_defaults(before: list[dict], desired: list[dict]) -> None:
        def spec_defaults(old: dict, new: dict) -> None:
            for key in ('volumeMode', 'storageClassName', 'volumeName'):
                if key not in new and key in old:
                    new[key] = copy.deepcopy(old[key])
        prior = {_identity(item): item for item in before}
        for item in desired:
            old = prior.get(_identity(item))
            if old is None:
                continue
            if item['kind'] == 'PersistentVolumeClaim':
                spec_defaults(old.get('spec', {}), item.setdefault('spec', {}))
            if item['kind'] == 'StatefulSet':
                existing = {v['metadata']['name']: v for v in old.get('spec', {}).get('volumeClaimTemplates', [])}
                for claim in item.get('spec', {}).get('volumeClaimTemplates', []):
                    name = claim['metadata']['name']
                    if name in existing:
                        spec_defaults(existing[name].get('spec', {}), claim.setdefault('spec', {}))

    def _guard(self, before: list[dict], desired: list[dict]) -> None:
        desired_ids = {_identity(item) for item in desired}
        by_id = {_identity(item): item for item in desired}
        for item in before:
            identity = _identity(item)
            if identity[0] == 'PersistentVolumeClaim':
                if identity not in desired_ids or item.get('spec') != by_id[identity].get('spec'):
                    raise ContractError('kubernetes_pvc_change_refused')
            if identity[0] == 'StatefulSet':
                claims = item.get('spec', {}).get('volumeClaimTemplates', [])
                if (claims and identity not in by_id) or (identity in by_id and [_declarative(v) for v in claims] != [_declarative(v) for v in by_id[identity].get('spec', {}).get('volumeClaimTemplates', [])]):
                    raise ContractError('kubernetes_pvc_change_refused')
                if claims and identity in by_id:
                    old_spec, new_spec = item['spec'], by_id[identity].get('spec', {})
                    policy = old_spec.get('persistentVolumeClaimRetentionPolicy', {})
                    new_policy = new_spec.get('persistentVolumeClaimRetentionPolicy', {})
                    if (any(policy.get(key, 'Retain') != new_policy.get(key, 'Retain') for key in ('whenScaled', 'whenDeleted'))
                            or (policy.get('whenScaled', 'Retain') == 'Delete'
                                and new_spec.get('replicas', 1) < old_spec.get('replicas', 1))):
                        raise ContractError('kubernetes_pvc_change_refused')
            fields = item.get('metadata', {}).get('managedFields', [])
            if not isinstance(fields, list):
                raise ContractError('kubernetes_field_owner_invalid')
            for field in fields:
                if (not isinstance(field, dict) or not isinstance(field.get('fieldsV1', {}), dict) or
                        (field.get('subresource') != 'status' and field.get('manager') != MANAGER
                         and any(k in field.get('fieldsV1', {}) for k in ('f:spec', 'f:data', 'f:binaryData')))):
                    raise ContractError('kubernetes_foreign_field_manager')

    def plan(self, updates: Mapping[str, str], *, definition: bytes | None = None,
             current: DeploymentState | None = None) -> DeploymentState:
        before = current if current is not None else self.read_state()
        items = self._validate(_objects(before.definition if definition is None else definition), desired=True)
        if not items and definition is None:
            items = _objects(self.render(ensure_contained(self.repo, self.configuration.definition_path)))
        # An empty image is an initializer placeholder owned by the release
        # pipeline. Configuration sync preserves an existing concrete image;
        # a first deployment must supply the immutable release updates.
        current_images = dict(self.readback(before))
        for variable, entry in self.binding['image_variables'].items():
            matches = [v for v in items if _identity(v) == (entry['kind'], entry['name'])]
            if len(matches) == 1:
                for container in _containers(matches[0]):
                    if container['name'] == entry['container'] and not container['image'] and variable in current_images:
                        container['image'] = current_images[variable]
        if set(updates) - set(self.binding['image_variables']) or any(not isinstance(v, str) or not DIGEST.fullmatch(v) for v in updates.values()):
            raise ContractError('kubernetes_image_update_invalid')
        for variable, image in updates.items():
            entry = self.binding['image_variables'][variable]
            matches = [v for v in items if _identity(v) == (entry['kind'], entry['name'])]
            if len(matches) != 1:
                raise ContractError('kubernetes_image_mapping_unresolved')
            containers = [v for v in _containers(matches[0]) if v['name'] == entry['container']]
            if len(containers) != 1:
                raise ContractError('kubernetes_image_mapping_unresolved')
            containers[0]['image'] = image
        # Still-empty placeholders mean no release image was ever deployed here: a fresh
        # namespace needs the initial deployment before a configuration-only sync.
        for entry in self.binding['image_variables'].values():
            for item in items:
                if _identity(item) == (entry['kind'], entry['name']) and any(
                        v['name'] == entry['container'] and not v['image'] for v in _containers(item)):
                    raise ContractError('kubernetes_initial_deploy_required: deploy the release once without '
                                        'config sync, then sync configuration')
        live = self._live()
        self._preserve_claim_defaults(live, items)
        self._guard(live, items)
        encoded = _encoded(items)
        self._run(['diff', '--server-side', '--field-manager', MANAGER, '-f', '-'], data=encoded, accepted={0, 1})
        images = self._images(items, require_all=bool(items))
        return DeploymentState(encoded, ''.join(k + '=' + v + '\n' for k, v in sorted(images.items())).encode())

    def config_apply(self, state: DeploymentState, owned_keys: set[str], *,
                     current: DeploymentState | None = None,
                     required: set[str] | None = None, allowed: set[str] | None = None,
                     snapshot_path: Path | None = None) -> dict[str, Any]:
        from ..dokploy_transaction import target_lock
        with target_lock(self.repo, self.target):
            return self._config_apply_unlocked(state, owned_keys, current=current,
                required=required, allowed=allowed, snapshot_path=snapshot_path)

    def _config_apply_unlocked(self, state: DeploymentState, owned_keys: set[str], *,
                     current: DeploymentState | None = None,
                     required: set[str] | None = None, allowed: set[str] | None = None,
                     snapshot_path: Path | None = None) -> dict[str, Any]:
        live = self._live()
        desired = self._validate(_objects(state.definition), desired=True)
        self._preserve_claim_defaults(live, desired)
        self._guard(live, desired)
        # Include collisions which lack this target's selector labels.
        # A create/apply must never silently adopt another owner's object.
        if desired:
            existing = self._validate(_objects(self._run(
                ['get', '-f', '-', '--ignore-not-found', '-o', 'json', '--show-managed-fields=true'],
                data=_encoded(desired))), desired=False)
            self._guard(existing, desired)
        actual = _encoded([_declarative(v) for v in live])
        if required is not None:
            keys = self._desired_config_keys(desired)
            if required - keys or keys - (allowed if allowed is not None else required):
                raise ContractError('kubernetes_config_key_drift')
        expected = _encoded([_declarative(v) for v in desired])
        resumed = False
        previous = actual
        if snapshot_path is not None:
            intent_path = snapshot_path.with_name(snapshot_path.name + '.intent.json')
            for path in (snapshot_path, intent_path):
                if path.is_symlink() or (path.exists() and (
                        not path.is_file() or path.stat().st_size > MAX_BYTES
                        or path.stat().st_mode & 0o077)):
                    raise ContractError('kubernetes_snapshot_invalid')
            identity = {'schema_version': '1.0.0', 'target': self.target,
                        'context_sha256': hashlib.sha256(self.context.encode()).hexdigest(),
                        'namespace': self.namespace,
                        'desired_sha256': hashlib.sha256(expected).hexdigest()}
            if snapshot_path.exists():
                previous = snapshot_path.read_bytes()
                identity['previous_sha256'] = hashlib.sha256(previous).hexdigest()
                if intent_path.exists():
                    try:
                        if json.loads(intent_path.read_bytes()) != identity:
                            raise ValueError()
                    except (ValueError, UnicodeError) as exc:
                        raise ContractError('kubernetes_snapshot_conflict') from exc
                    # A lost acknowledgement can be recovered only from an
                    # exact, intent-bound readback. Never blindly resubmit.
                    resumed = actual == expected
                elif previous != actual:
                    raise ContractError('kubernetes_snapshot_conflict')
                if not resumed and previous != actual:
                    raise ContractError('kubernetes_snapshot_conflict')
            else:
                if intent_path.exists():
                    raise ContractError('kubernetes_snapshot_conflict')
                identity['previous_sha256'] = hashlib.sha256(actual).hexdigest()
            if current is not None and actual != current.definition and not resumed:
                raise ContractError('kubernetes_state_changed')
            private_directory(snapshot_path.parent)
            for path, content in ((snapshot_path, previous),
                                  (intent_path, json.dumps(identity, sort_keys=True).encode())):
                if not path.exists():
                    with path.open('xb') as stream:
                        os.chmod(path, 0o600)
                        stream.write(content)
        elif current is not None and actual != current.definition:
            raise ContractError('kubernetes_state_changed')
        if resumed or actual == expected:
            return {'definition_changed': previous != expected,
                    'previous_definition_sha256': hashlib.sha256(previous).hexdigest()}
        if desired:
            self._run(['apply', '--server-side', '--dry-run=server', '--field-manager', MANAGER, '-f', '-'], data=_encoded(desired))
            self._run(['apply', '--server-side', '--field-manager', MANAGER, '-f', '-'], data=_encoded(desired))
        desired_ids = {_identity(item) for item in desired}
        removed = [_declarative(item) for item in live if _identity(item) not in desired_ids]
        if removed:
            self._run(['delete', '-f', '-', '--wait=true', '--timeout=300s'], data=_encoded(removed), timeout=315)
        return {'definition_changed': actual != state.definition,
                'previous_definition_sha256': hashlib.sha256(actual).hexdigest()}

    def restore(self, snapshot: DeploymentState, owned_keys: set[str]) -> None:
        self.config_apply(snapshot, owned_keys)

    def apply(self, updates: Mapping[str, str], *, operation: str | None = None,
              submit: bool = True) -> DeploymentOperation:
        if updates and submit:
            self.config_apply(self.plan(updates), set(updates))
        return DeploymentOperation(operation or 'operation-' + secrets.token_hex(16), None)

    def wait(self, operation: DeploymentOperation) -> str:
        for kind, name in sorted({(v['kind'], v['name']) for v in self.binding['image_variables'].values()}):
            self._run(['rollout', 'status', kind.lower() + '/' + name, '--timeout=300s'], timeout=315)
        return operation.token

    def readback(self, state: DeploymentState | None = None) -> Mapping[str, str]:
        return parse_environment((self.read_state() if state is None else state).settings.decode())

    def live_image_refs(self) -> Mapping[str, str]:
        return self.readback()

    def observed_image_refs(self, owned_keys: set[str]) -> Mapping[str, str]:
        items = self._live()
        images = self._images(items, require_all=True)
        if not owned_keys <= set(images):
            raise ContractError('kubernetes_image_mapping_unresolved')
        workloads = {_identity(item): item for item in items if item['kind'] in WORKLOADS}
        raw = self._run(['get', 'pods', '-l', f'{MANAGED}={MANAGER},{TARGET}={self.target}', '-o', 'json'])
        pods = _objects(raw)
        replica_sets = _objects(self._run(['get', 'replicasets', '-l',
            f'{MANAGED}={MANAGER},{TARGET}={self.target}', '-o', 'json'])) if any(v['kind'] == 'Deployment' for v in workloads.values()) else []
        result = {}
        for key in owned_keys:
            entry = self.binding['image_variables'][key]
            workload = workloads[(entry['kind'], entry['name'])]
            status, spec = workload.get('status', {}), workload['spec']
            desired = status.get('desiredNumberScheduled') if entry['kind'] == 'DaemonSet' else spec.get('replicas', 1)
            ready = status.get('numberReady', 0) if entry['kind'] == 'DaemonSet' else status.get('readyReplicas', 0)
            updated = status.get('updatedNumberScheduled', 0) if entry['kind'] == 'DaemonSet' else status.get('updatedReplicas', 0)
            if (type(desired) is not int or type(ready) is not int or type(updated) is not int
                    or desired < 1 or ready != desired or updated != desired
                    or status.get('observedGeneration', 0) < workload['metadata'].get('generation', 1)):
                raise ContractError('kubernetes_runtime_not_ready')
            selector = spec.get('selector', {}).get('matchLabels')
            if not isinstance(selector, dict) or not selector or spec.get('selector', {}).get('matchExpressions'):
                raise ContractError('kubernetes_runtime_selector_invalid')
            matched = [p for p in pods if all(p.get('metadata', {}).get('labels', {}).get(k) == v for k, v in selector.items())
                       and not p.get('metadata', {}).get('deletionTimestamp')]
            if len(matched) != desired:
                raise ContractError('kubernetes_runtime_cardinality_differs')
            expected = images[key]
            if not DIGEST.fullmatch(expected):
                raise ContractError('kubernetes_runtime_image_not_immutable')
            for pod in matched:
                metadata = workload['metadata']
                uid = metadata.get('uid', '')
                if entry['kind'] == 'Deployment':
                    owners = [v for v in replica_sets if v.get('kind') == 'ReplicaSet'
                        and v.get('metadata', {}).get('namespace') == self.namespace
                        and v.get('metadata', {}).get('labels', {}).get(MANAGED) == MANAGER
                        and v.get('metadata', {}).get('labels', {}).get(TARGET) == self.target
                        and _controlled_by(v, 'Deployment', metadata['name'], uid)
                        and _controlled_by(pod, 'ReplicaSet', v['metadata']['name'], v['metadata'].get('uid', ''))]
                    owned = len(owners) == 1
                else:
                    owned = _controlled_by(pod, entry['kind'], metadata['name'], uid)
                if not owned:
                    raise ContractError('kubernetes_runtime_owner_mismatch')
                if pod.get('metadata', {}).get('namespace') != self.namespace or pod.get('status', {}).get('phase') != 'Running':
                    raise ContractError('kubernetes_runtime_not_ready')
                statuses = pod.get('status', {}).get('containerStatuses', [])
                matches = [s for s in statuses if s.get('name') == entry['container']]
                if len(matches) != 1 or matches[0].get('ready') is not True:
                    raise ContractError('kubernetes_runtime_not_ready')
                image_id = matches[0].get('imageID', '')
                if image_id.removeprefix('docker-pullable://') != expected:
                    raise ContractError('kubernetes_runtime_image_mismatch')
            result[key] = expected
        return result

    def _config_keys(self, *, secrets_only: bool = False) -> set[str]:
        selector = f'{MANAGED}={MANAGER},{TARGET}={self.target}'
        items = _objects(self._run(['get', 'configmaps,secrets', '-l', selector, '-o', 'json']))
        keys = set()
        for item in items:
            metadata = item.get('metadata', {})
            if (item.get('kind') not in {'ConfigMap', 'Secret'} or metadata.get('namespace') != self.namespace
                    or metadata.get('labels', {}).get(MANAGED) != MANAGER
                    or metadata.get('labels', {}).get(TARGET) != self.target):
                raise ContractError('kubernetes_config_observation_invalid')
            if secrets_only and item['kind'] != 'Secret':
                continue
            for field in ('data', 'binaryData', 'stringData'):
                values = item.get(field, {})
                if not isinstance(values, dict):
                    raise ContractError('kubernetes_config_observation_invalid')
                keys.update(values)
        return keys

    def _desired_config_keys(self, items: list[dict]) -> set[str]:
        keys = self._config_keys(secrets_only=True)
        for item in items:
            if item['kind'] == 'ConfigMap':
                for field in ('data', 'binaryData'):
                    values = item.get(field, {})
                    if not isinstance(values, dict):
                        raise ContractError('kubernetes_config_observation_invalid')
                    keys.update(values)
        return keys

    def config_pull(self) -> dict[str, Any]:
        keys = self._config_keys()
        return {'config_key_count': len(keys), 'config_keys': sorted(keys),
                'definition_sha256': hashlib.sha256(self.read_state().definition).hexdigest()}

    def config_plan(self, definition: bytes, required: set[str], allowed: set[str]) -> dict[str, Any]:
        current = self.read_state()
        planned = self.plan({}, definition=definition, current=current)
        keys = self._desired_config_keys(_objects(planned.definition))
        return {'missing_keys': sorted(required - keys), 'provider_only_keys': sorted(keys - allowed),
                'definition_changed': current.definition != planned.definition,
                'desired_definition_sha256': hashlib.sha256(planned.definition).hexdigest()}

    def probe(self, kind: str) -> dict[str, str]:
        if self.kubeconfig is None:
            raise ContractError('kubernetes_context_not_discovered')
        result = {'KUBECONFIG': str(self.kubeconfig), 'PZ_ADW_KUBE_CONTEXT': self.context}
        root = self.profile_root or (Path(os.environ['PZ_ADW_PROFILE_ROOT']) if os.environ.get('PZ_ADW_PROFILE_ROOT') else None)
        if root is not None:
            result['PZ_ADW_PROFILE_ROOT'] = str(root)
        # #193: always the provider/environment template key; the adapter refuses any other.
        key = self.binding.get('ingress_probe_base') or probe_url_key('kubernetes', self.binding['environment'])
        if key in os.environ:
            result[key] = os.environ[key]
        return result

    @property
    def settings_backend(self) -> KubernetesSettings:
        # The shared hotfix helper owns locking and expected-current recovery.
        return KubernetesSettings(self)


class KubernetesSettings:
    def __init__(self, provider: KubernetesProvider) -> None:
        self.provider = provider

    def read_definition(self) -> bytes:
        return self.provider.render(ensure_contained(self.provider.repo, self.provider.configuration.definition_path))

    def read_settings(self) -> bytes:
        return self.provider.read_state().settings

    def capture_restore_state(self) -> dict:
        state = self.provider.read_state()
        return {'kind': 'kubernetes-rendered/v1', 'definition': json.loads(state.definition)}

    def restore_saved_state(self, value: bytes, saved: dict) -> None:
        if (not isinstance(saved, dict) or set(saved) != {'kind', 'definition'}
                or saved['kind'] != 'kubernetes-rendered/v1' or not isinstance(saved['definition'], dict)):
            raise ContractError('kubernetes_hotfix_snapshot_invalid')
        prior = self.provider._validate(_objects(json.dumps(saved['definition']).encode()), desired=False)
        definition = _encoded([_declarative(item) for item in prior])
        prior = _objects(definition)
        wanted = parse_environment(value.decode())
        if self.provider._images(prior, require_all=True) != wanted:
            raise ContractError('kubernetes_hotfix_snapshot_images_differ')
        current = self.provider.read_state()
        live = _objects(current.definition)
        # Only the hotfix's image fields may differ from the saved definition.
        # Foreign config/replica changes are not reverted by a hotfix restore.
        for items in (live, prior):
            for item in items:
                if item['kind'] in WORKLOADS:
                    for container in _containers(item):
                        container['image'] = '<owned-image>' if any(
                            entry['kind'] == item['kind'] and entry['name'] == item['metadata']['name']
                            and entry['container'] == container['name'] for entry in self.provider.binding['image_variables'].values()) else container['image']
        if _encoded(live) != _encoded(prior):
            raise ContractError('kubernetes_hotfix_definition_changed')
        observed = self.provider._live()
        self.provider._guard(observed, observed)
        def image_field(fields):
            return isinstance(fields, dict) and any(key == 'f:image' or image_field(item)
                                                    for key, item in fields.items())
        legacy_image_update = any(field.get('manager') == MANAGER and field.get('operation') == 'Update'
            and image_field(field.get('fieldsV1', {})) for item in observed
            for field in item['metadata'].get('managedFields', []))
        if legacy_image_update:
            # Recover an artifact created by the old image-only Update path.
            # Its complete non-image state was checked above; never force SSA
            # against Update ownership. Change only the recorded image fields,
            # then require exact full-manifest readback before completion.
            self._set_recorded_images(wanted)
            current = self.provider.read_state()
            if current.definition != definition:
                raise ContractError('kubernetes_hotfix_restore_readback_differs')
        self.provider._config_apply_unlocked(DeploymentState(definition, value), set(wanted), current=current)

    def write_settings(self, value: bytes) -> None:
        updates = parse_environment(value.decode())
        if set(updates) != set(self.provider.binding['image_variables']) or any(not DIGEST.fullmatch(v) for v in updates.values()):
            raise ContractError('kubernetes_hotfix_images_invalid')
        current = self.provider.read_state()
        planned = self.provider.plan(updates, current=current)
        self.provider._config_apply_unlocked(planned, set(updates), current=current)

    def _set_recorded_images(self, updates: Mapping[str, str]) -> None:
        # This compatibility recovery is reachable only after the saved full
        # manifest and actual owned Update fields have been validated above.
        if set(updates) != set(self.provider.binding['image_variables']) or any(not DIGEST.fullmatch(v) for v in updates.values()):
            raise ContractError('kubernetes_hotfix_images_invalid')
        grouped: dict[tuple[str, str], list[str]] = {}
        for key, image in updates.items():
            entry = self.provider.binding['image_variables'][key]
            grouped.setdefault((entry['kind'], entry['name']), []).append(entry['container'] + '=' + image)
        live = self.provider._live()
        self.provider._guard(live, live)
        for (kind, name), assignments in sorted(grouped.items()):
            self.provider._run(['set', 'image', kind.lower() + '/' + name, *assignments,
                                '--field-manager', MANAGER])

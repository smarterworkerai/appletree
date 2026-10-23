"""Operator-only provisioning on an explicit local or remote Kubernetes context.

Bootstrap values exist only in memory. Private journals bind resource identity;
public receipts contain counts and hashes, never contexts, UIDs or Secret data.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets

from ..common import ContractError, IDENTIFIER
from ..cluster_bootstrap import Bootstrap, validate, facts, PULL_SECRET
from ..operator_state import locked, read, write
from ..operator_credentials import private_profile_path
from .kubernetes import KubernetesProvider
from .kubernetes_metadata import metadata_api

OPERATION = 'adw.pzagent.io/provision-operation'
NONCE = 'adw.pzagent.io/provision-nonce'
IDENTITY = {'repository': 'adw.pzagent.io/repository', 'environment': 'adw.pzagent.io/environment',
            'target': 'adw.pzagent.io/target'}
PROFILE_FILE = 'kubernetes-provisioning.json'


def ownership_annotations(state):
    """Self-describing ownership: operation, nonce and the selection it belongs to."""
    selection = state['selection']
    return {OPERATION: state['operation_id'], NONCE: state['nonce'],
            **{key: selection[name] for name, key in IDENTITY.items()}}


def owned_by(annotations, state, *, require_identity=False):
    """Legacy objects may lack identity annotations; present ones must all match."""
    expected = ownership_annotations(state)
    if annotations.get(OPERATION) != expected[OPERATION] or annotations.get(NONCE) != expected[NONCE]:
        return False
    present = [key for key in IDENTITY.values() if key in annotations]
    if (require_identity or present) and any(annotations.get(key) != expected[key] for key in IDENTITY.values()):
        return False
    return True


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _private(path, *, root=None):
    try:
        path = private_profile_path(root or path.parent, path)
    except (OSError, ValueError, RuntimeError):
        raise ContractError('kubernetes_provision_profile_invalid') from None
    if (path.is_symlink() or not path.is_file()
            or path.stat().st_mode & 0o077 or path.stat().st_size > 262144):
        raise ContractError('kubernetes_provision_profile_invalid')
    return read(path)


def _state(path, *, root=None):
    value = _private(path, root=root)
    if (set(value) != {'schema_version', 'workflow', 'selection', 'profile', 'operation_id', 'nonce', 'resources', 'phase'}
            or value['schema_version'] != '1.0.0' or value['workflow'] != 'kubernetes-provision'
            or not isinstance(value['operation_id'], str) or not re.fullmatch(r'kube-provision-[0-9a-f]{24}', value['operation_id'])
            or not isinstance(value['nonce'], str) or not re.fullmatch(r'[0-9a-f]{32}', value['nonce'])
            or value['phase'] not in {'planned', 'complete', 'deprovisioning', 'deprovisioned'}
            or not isinstance(value['resources'], dict) or len(value['resources']) > 80):
        raise ContractError('kubernetes_provision_journal_invalid')
    for key, entry in value['resources'].items():
        if (not isinstance(entry, dict) or not {'created', 'kind', 'name', 'namespace'} <= set(entry)
                or set(entry) - {'created', 'kind', 'name', 'namespace', 'apiVersion', 'uid', 'deleted', 'delete_requested'}
                or entry['created'] is not True
                or entry['kind'] not in {'Secret', 'Namespace'}
                or not isinstance(entry['name'], str) or not IDENTIFIER.fullmatch(entry['name'])
                or (entry['namespace'] is not None and (not isinstance(entry['namespace'], str)
                    or not IDENTIFIER.fullmatch(entry['namespace'])))
                or key != '|'.join((entry['kind'], entry['namespace'] or '', entry['name']))
                or (entry['created'] and entry.get('apiVersion') != 'v1')):
            raise ContractError('kubernetes_provision_journal_invalid')
    return value


def _profile(root, provider, binding):
    alias, namespace = binding['context_alias'], binding['namespace']
    path = root / PROFILE_FILE
    if path.exists() or path.is_symlink():
        data = _private(path, root=root)
        if (set(data) != {'schema_version', 'targets'} or data['schema_version'] != '1.0.0'
                or not isinstance(data['targets'], dict) or alias not in data['targets']):
            raise ContractError('kubernetes_provision_profile_invalid')
        selected = data['targets'][alias]
        if not isinstance(selected, dict) or set(selected) - {'tls', 'image_pull', 'app_secrets'}:
            raise ContractError('kubernetes_provision_profile_invalid')
        profile = {'namespaces': [namespace], 'context_aliases': {provider.target: namespace}, **selected}
        digest = _hash({'context': provider.context, 'namespace': namespace, 'profile': profile})
    else:
        profile = {'namespaces': [namespace], 'context_aliases': {provider.target: namespace}}
        digest = _hash({'context': provider.context, 'namespace': namespace, 'profile': profile})
    validate(profile)
    if 'image_pull' in profile and provider.image_pull_secret != PULL_SECRET:
        raise ContractError('kubernetes_provision_pull_profile_mismatch')
    return profile, digest


class TargetBootstrap(Bootstrap):
    def __init__(self, provider, profile, digest, values, state, save, plan=False, metadata=None):
        self.provider, self.profile, self.digest = provider, profile, digest
        self.state, self.save, self.plan = state, save, plan
        self.mutations = 0
        self.metadata = metadata
        super().__init__(self, values)

    def kube(self, arguments, **kw):
        return self.provider._run(arguments, **kw)

    def observed(self, kind, name, namespace):
        if self.metadata is not None:
            return self.metadata.get(kind, name, namespace)
        args = ['get', kind, name, '--ignore-not-found', '-o',
                'jsonpath={.metadata}{"\\n"}{.type}']
        if namespace:
            args += ['--namespace', namespace]
        raw = self.kube(args)
        if not raw.strip():
            return None
        try:
            metadata, _, secret_type = raw.partition(b'\n')
            value = json.loads(metadata)
            if (not isinstance(value, dict) or value.get('name') != name or not value.get('uid')
                    or (namespace is not None and value.get('namespace') != namespace)):
                raise ValueError()
            return {'metadata': value, 'type': secret_type.decode()}
        except (ValueError, TypeError, UnicodeError) as exc:
            raise ContractError('kubernetes_provision_readback_invalid') from exc

    def check(self, value, extra=None):
        labels = value['metadata'].get('labels', {})
        if any(labels.get(k) != v for k, v in (self.labels | (extra or {})).items()):
            raise ContractError('cluster_bootstrap_ownership_unproven')

    def owned(self, kind, name, namespace, extra_labels=None):
        value = self.observed(kind, name, namespace)
        if value is None:
            return False
        self.check(value, extra_labels)
        if kind == 'Secret' and extra_labels and value['type'] != 'Opaque':
            raise ContractError('kubernetes_provision_secret_type_changed')
        key = '|'.join((kind, namespace or '', name))
        entry = self.state['resources'].get(key)
        if entry and entry['created']:
            if (not owned_by(value['metadata'].get('annotations', {}), self.state)
                    or entry.get('uid', value['metadata']['uid']) != value['metadata']['uid']):
                raise ContractError('kubernetes_provision_identity_changed')
            entry['uid'] = value['metadata']['uid']
        else:
            raise ContractError('kubernetes_provision_foreign_resource')
        if not self.plan:
            self.save()
        return True

    def namespace(self, namespace):
        if namespace != self.provider.namespace:
            raise ContractError('kubernetes_provision_namespace_refused')
        self.apply([{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace}}])

    def apply(self, items):
        # Inspect the entire batch before any creation. Existing resources are
        # never patched, relabelled, rotated or acquired for later deletion.
        for item in items:
            meta = item['metadata']
            if not ((item['kind'] == 'Namespace' and meta['name'] == self.provider.namespace
                     and not meta.get('namespace')) or (item['kind'] == 'Secret'
                     and meta.get('namespace') == self.provider.namespace)):
                raise ContractError('kubernetes_provision_resource_scope_refused')
            value = self.observed(item['kind'], meta['name'], meta.get('namespace'))
            if value:
                self.check(value, meta.get('labels', {}))
        for item in items:
            meta = item['metadata']
            kind, name, namespace = item['kind'], meta['name'], meta.get('namespace')
            key = '|'.join((kind, namespace or '', name))
            value = self.observed(kind, name, namespace)
            entry = self.state['resources'].get(key)
            if value:
                self.check(value, meta.get('labels', {}))
                if entry and entry['created']:
                    if (not owned_by(value['metadata'].get('annotations', {}), self.state)
                            or entry.get('uid', value['metadata']['uid']) != value['metadata']['uid']):
                        raise ContractError('kubernetes_provision_identity_changed')
                    entry['uid'] = value['metadata']['uid']
                else:
                    raise ContractError('kubernetes_provision_foreign_resource')
                if not self.plan:
                    self.save()
                continue
            if self.plan:
                continue
            if entry is not None:
                raise ContractError('kubernetes_provision_create_outcome_unproven')
            if entry is None:
                entry = {'created': True, 'apiVersion': item['apiVersion'], 'kind': kind,
                         'name': name, 'namespace': namespace}
                self.state['resources'][key] = entry
                self.save()  # Intent precedes request; a lost acknowledgement is read back.
            meta.setdefault('labels', {}).update(self.labels)
            meta.setdefault('annotations', {}).update(ownership_annotations(self.state))
            self.kube(['create', '-f', '-', '-o', 'name'], data=json.dumps(item).encode())
            self.mutations += 1
            value = self.observed(kind, name, namespace)
            if value is None:
                raise ContractError('kubernetes_provision_create_unproven')
            self.check(value)
            if not owned_by(value['metadata'].get('annotations', {}), self.state, require_identity=True):
                raise ContractError('kubernetes_provision_identity_changed')
            entry['uid'] = value['metadata']['uid']
            self.save()

    def secret(self, name, namespace, values, kind='Opaque', extra_labels=None):
        value = self.observed('Secret', name, namespace)
        if value:
            self.check(value, extra_labels)
            if value['type'] != kind:
                raise ContractError('kubernetes_provision_secret_type_changed')
            keys = self.kube(['get', 'Secret', name, '--namespace', namespace,
                             '-o', 'go-template={{range $key, $value := .data}}{{$key}}{{"\\n"}}{{end}}'])
            if set(keys.decode().splitlines()) != set(values):
                raise ContractError('cluster_app_secret_readback_unproven')
            self.apply([{'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {
                'name': name, 'namespace': namespace, 'labels': extra_labels or {}}}])
            return
        super().secret(name, namespace, values, kind, extra_labels)


def _selection(repo, adapter, environment, target, profile_root):
    group = adapter['targets'].get(environment, {})
    target = target or group.get('default')
    declaration = group.get('items', {}).get(target)
    if not declaration or declaration['provider'] != 'kubernetes':
        raise ContractError('provider_target_unsupported')
    binding = adapter['providers']['kubernetes']['bindings'][declaration['provider_binding']]
    if binding['namespace'] in {'default', 'cert-manager', 'kube-system', 'kube-public', 'kube-node-lease'}:
        raise ContractError('kubernetes_provision_namespace_refused')
    provider = KubernetesProvider(repo, target, binding, profile_root)
    provider.discover_context(binding)
    # API identity prevents a journal from following a same-named foreign context.
    raw = provider._run(['get', 'namespace', 'kube-system', '-o', 'jsonpath={.metadata.uid}'])
    if not raw.strip():
        raise ContractError('kubernetes_provision_cluster_identity_missing')
    profile, digest = _profile(profile_root, provider, binding)
    selection = {'repository': adapter['repository']['id'], 'environment': environment, 'target': target,
                 'binding': binding, 'context': provider.context, 'cluster_sha256': hashlib.sha256(raw).hexdigest(),
                 'profile_sha256': digest}
    return provider, profile, digest, selection


def _receipt(operation_dir, state, *, plan, cleanup, mutations, source_sha, bootstrap=None):
    from ..task_evidence import record_operator
    created = [v for v in state['resources'].values() if v['created']]
    result = {'status': 'ok', 'task': 'pz:provider:deprovision' if cleanup else 'pz:provider:provision',
              'phase': 'planned' if plan else 'complete', 'operation': state['operation_id'],
              'source_sha': source_sha,
              'environment': state['selection']['environment'], 'target': state['selection']['target'],
              'provider': 'kubernetes', 'runtime_activated': False, 'mutations_requested': mutations,
              'created_resources': len(created),
              'operation_digest': 'sha256:' + _hash(state['selection'])}
    if bootstrap is not None:
        result['bootstrap'] = bootstrap
    record_operator(operation_dir, result)
    return result


def provision(repo, adapter, *, environment, target, profile_root, operation_dir, source_sha,
              adopt=False, plan=False, server_name_env=None):
    from ..provider_lifecycle import _operator, archive_ownership, ownership_path
    _operator()
    if adopt or server_name_env:
        raise ContractError('kubernetes_provision_selection_invalid')
    provider, profile, digest, selection = _selection(repo, adapter, environment, target, profile_root)
    private = ownership_path(repo, profile_root, selection['repository'], environment, selection['target'])
    target_profile = {key: value for key, value in profile.items() if key != 'tls'}
    values = {} if plan else facts(target_profile)
    if 'tls' in profile:
        _tls_ready(provider, profile['tls'])
    with locked(private.parent), locked(operation_dir):
        if private.exists() and _state(private, root=private.parent)['phase'] == 'deprovisioned':
            archive_ownership(private, _state(private, root=private.parent)['operation_id'])
        state = _state(private, root=private.parent) if private.exists() else {'schema_version': '1.0.0',
            'workflow': 'kubernetes-provision', 'selection': selection, 'profile': profile,
            'operation_id': 'kube-provision-' + secrets.token_hex(12), 'nonce': secrets.token_hex(16),
            'resources': {}, 'phase': 'planned'}
        if state.get('workflow') != 'kubernetes-provision' or state.get('selection') != selection:
            raise ContractError('provider_operation_selection_changed')
        if state['phase'] in {'deprovisioning', 'deprovisioned'}:
            raise ContractError('provider_operation_decommissioned')
        save = lambda: write(private, state)
        save()
        bootstrap = TargetBootstrap(provider, target_profile, digest, values, state, save, plan)
        bootstrap.namespace(provider.namespace)
        if plan:
            if 'image_pull' in profile:
                bootstrap.owned('Secret', PULL_SECRET, provider.namespace)
            for name in profile.get('app_secrets', {}).get(provider.namespace, {}):
                bootstrap.owned('Secret', name, provider.namespace,
                    {'app.kubernetes.io/managed-by': 'adw', 'adw.pzagent.io/target': binding_alias(profile, provider.namespace)})
        report = None if plan else bootstrap.run()
        if report is not None:
            report['tls_ready'] = 'tls' in profile
        state['phase'] = 'planned' if plan else 'complete'
        save()
        return _receipt(operation_dir, state, plan=plan, cleanup=False,
                        mutations=bootstrap.mutations, source_sha=source_sha, bootstrap=report)


def binding_alias(profile, namespace):
    return next(alias for alias, ns in profile['context_aliases'].items() if ns == namespace)


def _tls_ready(provider, tls):
    """Cluster ingress/TLS is a prerequisite; observe only public readiness."""
    try:
        issuer = provider._run(['get', 'ClusterIssuer', 'adw-acme-' + tls['issuer'],
            '-o', 'jsonpath={.status.conditions[?(@.type=="Ready")].status}'])
        certificate = provider._run(['get', 'Certificate', 'adw-wildcard', '--namespace', 'kube-system',
            '-o', 'jsonpath={.status.conditions[?(@.type=="Ready")].status}'])
        store = provider._run(['get', 'TLSStore', 'default', '--namespace', 'kube-system',
            '-o', 'jsonpath={.spec.defaultCertificate.secretName}'])
        if (issuer.strip() != b'True' or certificate.strip() != b'True'
                or store.strip() != b'adw-wildcard-tls'):
            raise ContractError('cluster_tls_not_ready')
    except ContractError as exc:
        raise ContractError('cluster_tls_not_ready') from exc


def _delete_path(bootstrap, entry):
    api = entry['apiVersion']
    base = '/api/v1' if api == 'v1' else '/apis/' + api
    try:
        resources = json.loads(bootstrap.kube(['get', '--raw', base]))['resources']
        matches = [v for v in resources if v.get('kind') == entry['kind'] and '/' not in v.get('name', '')
                   and {'get', 'delete'} <= set(v.get('verbs', []))]
        if len(matches) != 1 or matches[0]['namespaced'] != (entry['namespace'] is not None):
            raise ValueError()
        resource = matches[0]['name']
        if not IDENTIFIER.fullmatch(resource):
            raise ValueError()
    except (ValueError, KeyError, TypeError) as exc:
        raise ContractError('kubernetes_provision_discovery_invalid') from exc
    return base + ('/namespaces/' + entry['namespace'] if entry['namespace'] else '') + '/' + resource + '/' + entry['name']


def _generated_default(bootstrap, namespace, kind, name):
    if (kind, name) not in {('ServiceAccount', 'default'), ('ConfigMap', 'kube-root-ca.crt')}:
        return False
    value = json.loads(bootstrap.kube(['get', kind, name, '--namespace', namespace, '-o', 'json']))
    meta = value.get('metadata', {})
    if (meta.get('name') != name or meta.get('namespace') != namespace or meta.get('labels')
            or meta.get('ownerReferences') or meta.get('finalizers') or meta.get('deletionTimestamp')):
        return False
    annotations = meta.get('annotations', {})
    if kind == 'ServiceAccount':
        return (not annotations and not value.get('secrets') and not value.get('imagePullSecrets')
                and not set(value) - {'apiVersion', 'kind', 'metadata', 'secrets', 'imagePullSecrets'})
    if (set(annotations) - {'kubernetes.io/description'} or set(value) - {'apiVersion', 'kind', 'metadata', 'data'}
            or set(value.get('data', {})) != {'ca.crt'}):
        return False
    # The CA is public cluster trust material, not a Secret. Comparing it also
    # refuses a modified default ConfigMap with an otherwise unchanged shape.
    public_ca = bootstrap.kube(['get', 'ConfigMap', 'kube-root-ca.crt', '--namespace', 'kube-system',
                               '-o', 'jsonpath={.data.ca\\.crt}']).decode()
    return bool(public_ca) and value['data']['ca.crt'] == public_ca


def _namespace_children(bootstrap, namespace, candidates):
    resources = bootstrap.kube(['api-resources', '--verbs=list', '--namespaced=true', '-o', 'name']).decode().splitlines()
    if not resources or len(resources) > 256:
        raise ContractError('kubernetes_provision_inventory_invalid')
    owned = {(v['kind'], v['name']) for v in candidates if v['namespace'] == namespace}
    for resource in resources:
        if not resource or not all(c.isalnum() or c in '.-' for c in resource):
            raise ContractError('kubernetes_provision_inventory_invalid')
        if resource in {'events', 'events.events.k8s.io'}:
            continue  # Control-plane telemetry carries no persistent state.
        raw = bootstrap.kube(['get', resource, '--namespace', namespace, '-o',
            'jsonpath={range .items[*]}{.kind}{" "}{.metadata.name}{"\\n"}{end}'])
        for line in raw.decode().splitlines():
            parts = line.split()
            if len(parts) != 2 or (tuple(parts) not in owned
                    and not _generated_default(bootstrap, namespace, *parts)):
                raise ContractError('provider_foreign_child_present')


def deprovision(repo, adapter, *, private, profile_root, operation_dir, source_sha, plan=False):
    from ..provider_lifecycle import _operator
    _operator()
    with locked(private.parent), locked(operation_dir):
        state = _state(private, root=private.parent)
        if state.get('workflow') != 'kubernetes-provision':
            raise ContractError('provider_operation_selection_changed')
        selected = state['selection']
        provider, profile, digest, selection = _selection(repo, adapter, selected['environment'], selected['target'], profile_root)
        if selection != selected:
            raise ContractError('provider_operation_selection_changed')
        save = lambda: write(private, state)
        bootstrap = TargetBootstrap(provider, profile, digest, {}, state, save, plan)
        candidates = [v for v in state['resources'].values() if v['created']]
        if any(not ((v['kind'] == 'Secret' and v['namespace'] == provider.namespace)
                    or (v['kind'] == 'Namespace' and v['name'] == provider.namespace and v['namespace'] is None))
               for v in candidates):
            raise ContractError('kubernetes_provision_resource_scope_refused')
        candidates.sort(key=lambda v: v['kind'] == 'Namespace')
        observations = []
        # Preflight every candidate before deleting the first object.
        for entry in candidates:
            value = bootstrap.observed(entry['kind'], entry['name'], entry['namespace'])
            if value is None:
                if entry.get('delete_requested') and not entry.get('deleted') and not plan:
                    entry['deleted'] = True
                    save()
                continue
            bootstrap.check(value)
            metadata = value['metadata']
            if (not owned_by(metadata.get('annotations', {}), state)
                    or entry.get('uid', metadata['uid']) != metadata['uid']):
                raise ContractError('kubernetes_provision_identity_changed')
            if entry.get('delete_requested'):
                if not metadata.get('deletionTimestamp'):
                    raise ContractError('kubernetes_provision_delete_outcome_unproven')
                if plan:
                    continue
                args = ['wait', '--for=delete', entry['kind'] + '/' + entry['name'], '--timeout=90s']
                if entry['namespace']:
                    args += ['--namespace', entry['namespace']]
                bootstrap.kube(args, timeout=105)
                if bootstrap.observed(entry['kind'], entry['name'], entry['namespace']) is not None:
                    raise ContractError('kubernetes_provision_delete_unproven')
                entry['deleted'] = True
                save()
                continue
            if entry['kind'] == 'Namespace':
                _namespace_children(bootstrap, entry['name'], candidates)
            if not isinstance(metadata.get('resourceVersion'), str) or not metadata['resourceVersion']:
                raise ContractError('kubernetes_provision_readback_invalid')
            observations.append((entry, metadata['uid'], metadata['resourceVersion']))
        mutations = 0
        for entry, uid, version in observations:
            if plan:
                continue
            path = _delete_path(bootstrap, entry)
            if entry['kind'] == 'Namespace':
                _namespace_children(bootstrap, entry['name'], candidates)
            payload = {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                       'preconditions': {'uid': uid, 'resourceVersion': version}, 'propagationPolicy': 'Orphan'}
            state['phase'] = 'deprovisioning'
            entry['delete_requested'] = True
            save()
            bootstrap.kube(['delete', '--raw', path, '-f', '-'], data=json.dumps(payload).encode())
            mutations += 1
            args = ['wait', '--for=delete', entry['kind'] + '/' + entry['name'], '--timeout=90s']
            if entry['namespace']:
                args += ['--namespace', entry['namespace']]
            bootstrap.kube(args, timeout=105)
            if bootstrap.observed(entry['kind'], entry['name'], entry['namespace']) is not None:
                raise ContractError('kubernetes_provision_delete_unproven')
            entry['deleted'] = True
            save()
        if not plan:
            state['phase'] = 'deprovisioned'
            save()
        return _receipt(operation_dir, state, plan=plan, cleanup=True, mutations=mutations, source_sha=source_sha)


def rebuild_journal(repo, adapter, *, environment, target, profile_root, write_journal=False):
    """Read-only reconstruction or verification of a provisioning journal from the cluster.

    Only object metadata is read (never Secret data). Every owned object must carry
    the same operation, nonce and repository/environment/target identity; anything
    partial, foreign or conflicting refuses. An existing journal is verified, never
    overwritten; a missing one is written only when explicitly requested.
    """
    from ..provider_lifecycle import _operator, ownership_path
    _operator()
    provider, profile, digest, selection = _selection(repo, adapter, environment, target, profile_root)
    private = ownership_path(repo, profile_root, selection['repository'], environment, selection['target'])
    with metadata_api(provider) as metadata:
        return _rebuild_metadata(provider, profile, digest, selection, private, metadata, write_journal)


def _rebuild_metadata(provider, profile, digest, selection, private, metadata, write_journal):
    namespace = provider.namespace
    probe = {'selection': selection, 'operation_id': '', 'nonce': '', 'resources': {}}
    reader = TargetBootstrap(provider, {k: v for k, v in profile.items() if k != 'tls'}, digest, {}, probe,
                             lambda: None, plan=True, metadata=metadata)
    value = reader.observed('Namespace', namespace, None)
    if value is None:
        raise ContractError('kubernetes_rebuild_nothing_owned')
    reader.check(value)
    annotations = value['metadata'].get('annotations', {})
    operation, nonce = annotations.get(OPERATION), annotations.get(NONCE)
    if (not isinstance(operation, str) or not re.fullmatch(r'kube-provision-[0-9a-f]{24}', operation)
            or not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{32}', nonce)):
        raise ContractError('kubernetes_rebuild_marker_invalid')
    state = {'schema_version': '1.0.0', 'workflow': 'kubernetes-provision', 'selection': selection,
             'profile': profile, 'operation_id': operation, 'nonce': nonce, 'resources': {}, 'phase': 'complete'}
    if not owned_by(annotations, state, require_identity=True):
        raise ContractError('kubernetes_rebuild_identity_unproven')
    state['resources']['|'.join(('Namespace', '', namespace))] = {
        'created': True, 'apiVersion': 'v1', 'kind': 'Namespace', 'name': namespace, 'namespace': None,
        'uid': value['metadata']['uid']}
    expected = ([(PULL_SECRET, None)] if 'image_pull' in profile else []) + [
        (name, {'app.kubernetes.io/managed-by': 'adw', 'adw.pzagent.io/target': binding_alias(profile, namespace)})
        for name in profile.get('app_secrets', {}).get(namespace, {})]
    for name, extra in expected:
        secret = reader.observed('Secret', name, namespace)
        if secret is None:
            raise ContractError('kubernetes_rebuild_incomplete')
        reader.check(secret, extra)
        if not owned_by(secret['metadata'].get('annotations', {}), state, require_identity=True):
            raise ContractError('kubernetes_rebuild_identity_unproven')
        state['resources']['|'.join(('Secret', namespace, name))] = {
            'created': True, 'apiVersion': 'v1', 'kind': 'Secret', 'name': name, 'namespace': namespace,
            'uid': secret['metadata']['uid']}
    with locked(private.parent):
        if private.exists() or private.is_symlink():
            current = _state(private, root=private.parent)
            same = (current['selection'] == selection and current['operation_id'] == operation
                    and current['nonce'] == nonce and current['phase'] == 'complete'
                    and {k: (v['kind'], v['name'], v['namespace'], v.get('uid')) for k, v in current['resources'].items()
                         if not v.get('deleted')}
                    == {k: (v['kind'], v['name'], v['namespace'], v['uid']) for k, v in state['resources'].items()})
            if not same:
                raise ContractError('kubernetes_journal_conflict')
            phase, written = 'verified', False
        elif write_journal:
            write(private, state)
            _state(private, root=private.parent)
            phase, written = 'rebuilt', True
        else:
            phase, written = 'planned', False
    return {'status': 'ok', 'task': 'pz:provider:journal-rebuild', 'provider': 'kubernetes', 'phase': phase,
            'operation': operation, 'environment': selection['environment'], 'target': selection['target'],
            'owned_resources': len(state['resources']), 'journal_written': written, 'mutations_requested': 0}


def annotate_identity(repo, adapter, *, environment, target, profile_root, plan=False):
    """One-off migration: add missing identity annotations to journal-owned objects.

    Each object must still match its journal entry (operation, nonce, UID, labels);
    the patch is metadata-only, bound to the observed resourceVersion and read back.
    Secret data is never read.
    """
    from ..provider_lifecycle import _operator, ownership_path
    _operator()
    provider, profile, digest, selection = _selection(repo, adapter, environment, target, profile_root)
    private = ownership_path(repo, profile_root, selection['repository'], environment, selection['target'])
    if not private.exists():
        raise ContractError('kubernetes_migration_journal_required')
    with metadata_api(provider) as metadata:
        return _annotate_metadata(provider, profile, digest, selection, private, metadata, plan)


def _annotate_metadata(provider, profile, digest, selection, private, client, plan):
    with locked(private.parent):
        state = _state(private, root=private.parent)
        if state['selection'] != selection:
            raise ContractError('provider_operation_selection_changed')
        reader = TargetBootstrap(provider, {k: v for k, v in profile.items() if k != 'tls'}, digest, {}, state,
                                 lambda: None, plan=True, metadata=client)
        expected = ownership_annotations(state)
        pending = []
        for entry in state['resources'].values():
            if entry.get('deleted'):
                continue
            value = reader.observed(entry['kind'], entry['name'], entry['namespace'])
            if value is None:
                raise ContractError('kubernetes_migration_resource_absent')
            reader.check(value)
            metadata = value['metadata']
            annotations = metadata.get('annotations', {})
            if not owned_by(annotations, state) or entry.get('uid') != metadata['uid']:
                raise ContractError('kubernetes_provision_identity_changed')
            missing = {key: expected[key] for key in IDENTITY.values() if key not in annotations}
            version = metadata.get('resourceVersion')
            if missing and (not isinstance(version, str) or not version):
                raise ContractError('kubernetes_provision_readback_invalid')
            if missing:
                pending.append((entry, missing, metadata))
        mutations = 0
        for entry, missing, metadata in ([] if plan else pending):
            client.annotate(entry['kind'], entry['name'], entry['namespace'], metadata, missing)
            mutations += 1
            value = reader.observed(entry['kind'], entry['name'], entry['namespace'])
            if (value is None or value['metadata']['uid'] != entry['uid']
                    or not owned_by(value['metadata'].get('annotations', {}), state, require_identity=True)):
                raise ContractError('kubernetes_migration_readback_unproven')
    return {'status': 'ok', 'task': 'pz:provider:journal-migrate', 'provider': 'kubernetes',
            'phase': 'planned' if plan else 'complete', 'operation': state['operation_id'],
            'objects_needing_identity': len(pending), 'mutations_requested': mutations}

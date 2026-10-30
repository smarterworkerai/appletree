"""Operator-only provisioning on an explicit local or remote Kubernetes context.

Bootstrap values exist only in memory. Private journals bind resource identity;
public receipts contain counts and hashes, never contexts, UIDs or Secret data.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from ..common import ContractError, IDENTIFIER, ensure_contained
from ..cluster_bootstrap import Bootstrap, validate, facts, PULL_SECRET
from ..key_schema import contract, sources as resolve_sources
from ..operator_state import locked, private_directory, read, write
from ..operator_credentials import entry_command, private_profile_path, vault_generate, vault_secrets
from .kubernetes import KubernetesCommandError, KubernetesProvider
from .kubernetes_metadata import metadata_api

OPERATION = 'adw.pzagent.io/provision-operation'
NONCE = 'adw.pzagent.io/provision-nonce'
IDENTITY = {'repository': 'adw.pzagent.io/repository', 'environment': 'adw.pzagent.io/environment',
            'target': 'adw.pzagent.io/target'}
PROFILE_FILE = 'kubernetes-provisioning.json'
# A Secret declared as this string takes every sourced key of the binding's key schema (#193).
SCHEMA_SECRET = 'key-schema'
APP_LABEL = 'app.kubernetes.io/managed-by'
COMMAND_FAILURES = {'kubernetes_command_failed', 'kubernetes_command_unavailable',
                    'kubernetes_field_conflict', 'kubernetes_immutable_field_refused'}
PHASES = {'planned', 'complete', 'deprovisioning', 'deprovisioned'}


def _failure_valid(value):
    return (isinstance(value, dict)
            and set(value) in ({'reason', 'stage', 'tool', 'subcommands', 'at'},
                               {'reason', 'stage', 'tool', 'subcommands', 'at', 'diagnostic'})
            and isinstance(value['reason'], str) and value['reason'] in COMMAND_FAILURES
            and isinstance(value['stage'], str) and value['stage'] in PHASES | {'selection'}
            and value['tool'] == 'kubectl' and isinstance(value['subcommands'], list)
            and len(value['subcommands']) <= 2
            and all(isinstance(word, str) and re.fullmatch(r'[a-z][a-z-]{0,31}', word)
                    for word in value['subcommands'])
            and isinstance(value['at'], str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value['at'])
            and ('diagnostic' not in value or (isinstance(value['diagnostic'], str)
                 and re.fullmatch(r'kubectl-failed-[0-9a-f]{24}\.log', value['diagnostic']))))


def _private_values(value):
    if isinstance(value, str):
        return (value.encode(),) if value else ()
    if isinstance(value, dict):
        return tuple(part for child in value.values() for part in _private_values(child))
    if isinstance(value, (list, tuple)):
        return tuple(part for child in value for part in _private_values(child))
    return ()


def _record_command_failure(private, operation_dir, error):
    """Retain a closed stage/reason and a bounded private diagnostic, never raw stderr."""
    from ..cluster_lifecycle import _sanitized
    state = _state(private, root=private.parent) if private.exists() else None
    if state is not None and error.operation_id != state['operation_id']:
        # Provision's failing call releases its lock before this handler takes
        # it again. Never attribute an old failure to a replacement operation.
        state = None
    # Only reviewed command words enter the journal/header; resource names,
    # options, context handles, paths and stdin never do.
    words = []
    allowed = {'get', 'delete', 'wait', 'create', 'apply', 'replace', 'patch', 'api-resources',
               'config', 'rollout', 'auth', 'version'}
    if error.arguments and error.arguments[0] in allowed:
        words.append(error.arguments[0])
        children = {'config': {'get-contexts', 'view', 'current-context'},
                    'rollout': {'status'}, 'auth': {'can-i'}}
        if len(error.arguments) > 1 and error.arguments[1] in children.get(words[0], set()):
            words.append(error.arguments[1])
    failure = {'reason': str(error), 'stage': error.stage,
               'tool': 'kubectl', 'subcommands': words,
               'at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
    sensitive = error.sensitive + _private_values(state)
    printable = bytes(c for c in error.stderr if c in b'\n\t' or 32 <= c < 127)
    # Server-generated UUIDs and diagnostic addresses may not exist in a journal
    # yet. Add their complete normalized forms before the shared union redaction
    # and tail bound, so truncation cannot disclose a suffix.
    for pattern in (rb'\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b',
                    rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                    rb'(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*(?![A-Za-z0-9])',
                    rb'https?://[^\s"\']+',
                    rb'\b(?:[A-Za-z0-9_-]+\.)+[A-Za-z][A-Za-z0-9_-]*\b'):
        sensitive += tuple(re.findall(pattern, printable))
    if error.data:
        try:
            sensitive += _private_values(json.loads(error.data))
        except (ValueError, UnicodeError):
            sensitive += (error.data,)
    storage = private.parent if state else operation_dir
    directory = storage / 'diagnostics'
    try:
        if error.kubeconfig:
            # Config is private YAML or JSON. Redact every lexical value, its
            # encoded forms and URL hostnames without invoking another command.
            raw = error.kubeconfig.read_bytes()
            tokens = re.findall(rb'[A-Za-z0-9_./:@+=-]+', raw)
            sensitive += (raw, *tokens)
            for token in tokens:
                if len(token) >= 16:
                    try:
                        sensitive += (base64.b64decode(token + b'=' * (-len(token) % 4), validate=True),)
                    except ValueError:
                        pass
                if token.startswith((b'https://', b'http://')):
                    host = urlsplit(token.decode('ascii')).hostname
                    if host:
                        sensitive += (host.encode(),)
        if directory.is_symlink():
            raise OSError('linked diagnostic directory')
        private_directory(directory)
        directory.chmod(0o700)
        name = 'kubectl-failed-' + secrets.token_hex(12) + '.log'
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(b'COMMAND ' + ' '.join(['kubectl', *words]).encode() + b'\nSTDERR\n'
                         + _sanitized(error.stderr, sensitive))
        failure['diagnostic'] = name
    except (OSError, ValueError):
        pass  # A diagnostic failure must not replace the original closed reason.
    if state is not None:
        state['last_failure'] = failure
        write(private, state)
    else:
        write(operation_dir / 'last-failure.json', failure)


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
    keys = {'schema_version', 'workflow', 'selection', 'profile', 'operation_id', 'nonce', 'resources', 'phase'}
    if (set(value) - {'runtime', 'last_failure'} != keys
            or ('runtime' in value and not _runtime_record(value['runtime']))
            or ('last_failure' in value and not _failure_valid(value['last_failure']))
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


def _runtime_record(value):
    from ..provider_lifecycle import BACKUP_REFERENCE
    from .kubernetes import RUNTIME_PATHS
    if not isinstance(value, dict) or set(value) != {'objects', 'backup_reference'}:
        return False
    objects = value['objects']
    if (not isinstance(objects, list) or len(objects) > 256
            or any(not isinstance(v, dict) or set(v) != {'kind', 'name', 'uid'} or v['kind'] not in RUNTIME_PATHS
                   or not isinstance(v['name'], str) or not IDENTIFIER.fullmatch(v['name'])
                   or not isinstance(v['uid'], str) or not v['uid'] for v in objects)):
        return False
    if any(v['kind'] == 'PersistentVolumeClaim' for v in objects):
        return isinstance(value['backup_reference'], str) and bool(BACKUP_REFERENCE.fullmatch(value['backup_reference']))
    return value['backup_reference'] is None


def schema_sources(repo, adapter, binding):
    """(vault entries, optional keys) of a Kubernetes binding's key schema (#193).

    The rules and default IDs are Dokploy's, so an environment's Dokploy and Kubernetes
    targets share one collection; explicit IDs are required only when several
    Kubernetes bindings share the environment.
    """
    try:
        document = json.loads(ensure_contained(repo, binding['config_schema_path']).read_text(encoding='utf-8'))
    except (OSError, ValueError, KeyError):
        raise ContractError('kubernetes_key_schema_invalid') from None
    required, keys, raw = contract(document, 'kubernetes_key_schema_invalid')
    environment = binding['environment']
    images = set(binding.get('image_variables') or {}) | {
        key for kind in adapter.get('release_kinds', {}).values() for key in (kind.get('image_variables') or {})}
    shared = sum(other.get('environment') == environment
                 for other in adapter['providers']['kubernetes']['bindings'].values()) > 1
    found = resolve_sources(raw, project=adapter['repository']['id'].rsplit('/', 1)[-1], environment=environment,
                            images=images, explicit_ids=shared, reason='kubernetes_key_schema_invalid')
    return found, keys - required


def _vault_source(entry):
    source = {'vault': entry['id']}
    if entry['source'] == 'generate':
        source.update(generate=entry['kind'], scope=entry['vault'])
        if entry['length'] is not None:
            source['length'] = entry['length']
    return source


def _schema_secrets(repo, adapter, binding, profile):
    """Expand the target's one `"key-schema"` Secret into the key schema's vault sources (#193).

    The private profile only names the Secret, `{namespace: {secret-name: "key-schema"}}`;
    every key with a `generate`, `human` or `shared` source goes into it.
    """
    if 'app_secrets' not in profile:
        return profile
    declared = profile['app_secrets']
    if (not isinstance(declared, dict) or set(declared) != {binding['namespace']}
            or not isinstance(declared[binding['namespace']], dict) or len(declared[binding['namespace']]) != 1
            or list(declared[binding['namespace']].values()) != [SCHEMA_SECRET] or repo is None):
        raise ContractError('kubernetes_provision_profile_invalid')
    found, _ = schema_sources(repo, adapter, binding)
    if not found:
        raise ContractError('kubernetes_key_schema_has_no_sources')
    (name,) = declared[binding['namespace']]
    fields = {key: _vault_source(entry) for key, entry in sorted(found.items())}
    return {**profile, 'app_secrets': {binding['namespace']: {name: fields}}}


def _profile(root, provider, binding, repo=None, adapter=None):
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
        # The digest binds the profile as written; schema keys may grow without a new selection.
        profile = _schema_secrets(repo, adapter, binding, profile)
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
        self.provider._diagnostic_secrets += _private_values(values)
        self.provider._diagnostic_state = state
        super().__init__(self, values)

    def register_secret(self, value):
        self.provider._diagnostic_secrets += _private_values(value)

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
    profile, digest = _profile(profile_root, provider, binding, repo, adapter)
    selection = {'repository': adapter['repository']['id'], 'environment': environment, 'target': target,
                 'binding': binding, 'context': provider.context, 'cluster_sha256': hashlib.sha256(raw).hexdigest(),
                 'profile_sha256': digest}
    return provider, profile, digest, selection


def _receipt(operation_dir, state, *, plan, cleanup, mutations, source_sha, bootstrap=None, runtime=None,
             activation=None):
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
    if runtime is not None:
        result['runtime'] = runtime
    if activation is not None:
        result['activation'] = activation
    record_operator(operation_dir, result)
    return result


def provision(repo, adapter, *, environment, target, profile_root, operation_dir, source_sha,
              adopt=False, plan=False, server=None):
    from ..provider_lifecycle import ownership_path
    try:
        return _provision(repo, adapter, environment=environment, target=target, profile_root=profile_root,
                          operation_dir=operation_dir, source_sha=source_sha, adopt=adopt, plan=plan,
                          server=server)
    except KubernetesCommandError as exc:
        if not plan:
            selected = target or adapter['targets'].get(environment, {}).get('default')
            private = ownership_path(repo, profile_root, adapter['repository']['id'], environment, selected)
            with locked(private.parent):
                _record_command_failure(private, operation_dir, exc)
        raise


def _provision(repo, adapter, *, environment, target, profile_root, operation_dir, source_sha,
               adopt=False, plan=False, server=None):
    from ..provider_lifecycle import _operator, archive_ownership, ownership_path
    _operator()
    if adopt or server:
        raise ContractError('kubernetes_provision_selection_invalid')
    provider, profile, digest, selection = _selection(repo, adapter, environment, target, profile_root)
    private = ownership_path(repo, profile_root, selection['repository'], environment, selection['target'])
    target_profile = {key: value for key, value in profile.items() if key != 'tls'}
    values = {} if plan else facts(target_profile)
    tls = _tls_ready(provider, profile['tls']) if 'tls' in profile else None
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
            report.update(_missing_sources(repo, adapter, selection['binding'], profile, values))
            report['tls_ready'] = 'tls' in profile
            if tls is not None:
                report['tls'] = tls
        state['phase'] = 'planned' if plan else 'complete'
        save()
        from ..provider_lifecycle import activation_patch
        return _receipt(operation_dir, state, plan=plan, cleanup=False,
                        mutations=bootstrap.mutations, source_sha=source_sha, bootstrap=report,
                        activation=activation_patch(repo, environment, state['selection']['target'], adapter))


def _missing_sources(repo, adapter, binding, profile, values):
    """Dokploy's `missing_human` (with the entry command) and `missing_shared` for left-out keys."""
    absent = {slot[2] for slot in values.get('app_secrets_absent', {})}
    if not absent:
        return {}
    found, _ = schema_sources(repo, adapter, binding)
    parent = dict(os.environ)
    return {'missing_human': [{'key': key, 'vault': entry['vault'], 'id': entry['id'],
                               'command': entry_command(entry['vault'], entry['id'], entry['description'], parent)}
                              for key, entry in sorted(found.items()) if key in absent and entry['source'] == 'human'],
            'missing_shared': [{'key': key, 'id': entry['id']}
                               for key, entry in sorted(found.items()) if key in absent and entry['source'] == 'shared']}


def _secret_data(provider, name):
    """The owned Secret's object and decoded values; values only in memory, registered for redaction."""
    raw = provider._run(['get', 'Secret', name, '-o', 'json'])
    try:
        item = json.loads(raw)
        values = {key: base64.b64decode(value, validate=True).decode('utf-8')
                  for key, value in (item.get('data') or {}).items()}
    except (ValueError, TypeError, AttributeError, UnicodeError) as exc:
        raise ContractError('kubernetes_provision_readback_invalid') from exc
    provider._diagnostic_secrets += _private_values(values)
    return item, values


def _proven_data(reader, provider, name, labels):
    """The full Secret, re-proven like `owned()` (labels, profile, ownership annotations, UID).

    A Secret replaced between the metadata proof and this read refuses, so its data is
    never used and its resourceVersion never becomes the replace precondition.
    """
    item, values = _secret_data(provider, name)
    metadata = item.get('metadata') or {}
    entry = reader.state['resources'].get('Secret|' + provider.namespace + '|' + name) or {}
    reader.check({'metadata': metadata}, labels)
    if (not entry.get('created') or metadata.get('uid') != entry.get('uid')
            or not owned_by(metadata.get('annotations') or {}, reader.state)):
        raise ContractError('kubernetes_provision_identity_changed')
    return item, values


def _backup(operation_dir, values):
    """Private mode-0600 copy of the Secret before a write; only path, digest and key count are reported."""
    operation_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if operation_dir.stat().st_mode & 0o077:
        raise ContractError('provider_environment_backup_not_private')
    raw = json.dumps(values, sort_keys=True).encode()
    path = operation_dir / 'secret-backup.json'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as handle:
        handle.write(raw)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'keys': len(values)}


def env_apply(repo, adapter, *, environment, target, profile_root, operation_dir, source_sha,
              replace=(), apply=False):
    """`pz:provider:env:apply` on a Kubernetes target, with Dokploy's semantics (#193).

    Missing schema keys are appended to the target's own `"key-schema"` Secret from the
    vault; only keys named in `replace` are overwritten. A `generate` ID is created only
    when neither the vault nor the Secret has it, a value only in the Secret is reported
    for import, and missing `human` IDs come with the entry command. The write replaces
    the whole Secret at its read resourceVersion through stdin, after a private backup,
    and the readback is compared in memory.
    """
    from ..provider_lifecycle import ownership_path
    from ..dokploy_transaction import target_lock
    if profile_root is None and os.environ.get('PZ_ADW_PROFILE_ROOT'):
        profile_root = Path(os.environ['PZ_ADW_PROFILE_ROOT'])
    if profile_root is None:
        raise ContractError('kubernetes_context_profile_missing')
    provider, profile, digest, selection = _selection(repo, adapter, environment, target, profile_root)
    binding = selection['binding']
    sources, optional = schema_sources(repo, adapter, binding)
    declared = profile.get('app_secrets', {}).get(provider.namespace, {})
    if len(declared) != 1:
        raise ContractError('kubernetes_env_apply_no_app_secret: declare the "key-schema" Secret in kubernetes-provisioning.json')
    (name,) = declared
    for key in replace:
        if key not in sources:
            raise ContractError(f'provider_env_key_not_settable: {key} is not a sourced key of the binding schema')
    private = ownership_path(repo, profile_root, selection['repository'], environment, selection['target'])
    if not private.exists():
        raise ContractError('kubernetes_env_apply_not_provisioned: run pz:provider:provision first')
    parent = dict(os.environ)
    vault, _ = vault_secrets({entry['id'] for entry in sources.values()}, parent)
    with target_lock(repo, selection['target']), locked(private.parent):
        state = _state(private, root=private.parent)
        if state.get('workflow') != 'kubernetes-provision' or state.get('selection') != selection:
            raise ContractError('provider_operation_selection_changed')
        if state['phase'] != 'complete':
            raise ContractError('kubernetes_env_apply_not_provisioned: run pz:provider:provision first')
        bootstrap = TargetBootstrap(provider, profile, digest, {}, state, lambda: write(private, state), plan=not apply)
        labels = {APP_LABEL: 'adw', IDENTITY['target']: binding_alias(profile, provider.namespace)}
        if not bootstrap.owned('Secret', name, provider.namespace, labels):
            raise ContractError('kubernetes_env_apply_not_provisioned: run pz:provider:provision first')
        item, current = _proven_data(bootstrap, provider, name, labels)     # the data read is the proven object
        present = {key for key, value in current.items() if value}
        values, generated, missing_human, missing_shared, import_needed = {}, [], [], [], []
        for key, entry in sorted(sources.items()):
            if entry['id'] in vault:
                values[key] = vault[entry['id']]
            elif key in present:
                import_needed.append(key)            # import the live value; never diverge
            elif entry['source'] == 'generate':
                generated.append(key)
            elif entry['source'] == 'human':
                missing_human.append({'key': key, 'vault': entry['vault'], 'id': entry['id'],
                                      'command': entry_command(entry['vault'], entry['id'], entry['description'], parent)})
            else:
                missing_shared.append({'key': key, 'id': entry['id']})
        if generated and apply:
            for key in generated:
                entry = sources[key]
                vault_generate(entry['vault'], entry['id'], entry['kind'], parent, length=entry['length'],
                               description=entry['description'])
            fresh, still = vault_secrets({sources[key]['id'] for key in generated}, parent)
            if still:
                raise ContractError('vault_generate_readback_failed')
            values.update({key: fresh[sources[key]['id']] for key in generated})
        provider._diagnostic_secrets += _private_values(values)
        add = sorted(key for key in values if values[key] and key not in present)
        if not apply:
            add = sorted(set(add) | {key for key in generated if key not in present})
        replaced = sorted(key for key in replace if key in present and values.get(key))
        result = {'status': 'ok', 'task': 'pz:provider:env:apply', 'provider': 'kubernetes',
                  'environment': environment, 'target': selection['target'], 'secret': name, 'apply': apply,
                  'present': sorted(present), 'append': add, 'replace': replaced,
                  'vault': {'sourced': sorted(sources), 'generated': generated if apply else [],
                            'would_generate': [] if apply else generated,
                            'missing_human': missing_human, 'missing_shared': missing_shared,
                            'missing_in_vault_present_in_target': import_needed,
                            'push_required': bool(generated and apply)},
                  'undeclared': sorted(set(current) - set(sources)),
                  'missing_required': sorted((set(sources) - optional) - present - set(add)),
                  'mutations_requested': 0, 'source_sha': source_sha}
        if apply and (add or replaced):
            desired = {**current, **{key: values[key] for key in add + replaced}}
            result['backup'] = _backup(operation_dir, current)
            metadata = {key: item['metadata'][key] for key in ('name', 'namespace', 'labels', 'annotations',
                                                               'resourceVersion', 'uid') if key in item['metadata']}
            body = {'apiVersion': 'v1', 'kind': 'Secret', 'type': item.get('type', 'Opaque'), 'metadata': metadata,
                    'data': {key: base64.b64encode(value.encode()).decode() for key, value in desired.items()}}
            # The read resourceVersion makes a concurrent change fail instead of being overwritten.
            provider._run(['replace', '-f', '-', '-o', 'name'], data=json.dumps(body).encode())
            result['mutations_requested'] = 1
            _, after = _secret_data(provider, name)
            if after != desired:
                result.update(status='blocked', reason='kubernetes_secret_readback_mismatch')
            result['present'] = sorted(key for key, value in after.items() if value)
    return result


def observe_app_secrets(repo, adapter, *, environment, target, profile_root):
    """Read-only view of one target's application Secrets for `pz:secrets:show` (#193).

    One entry per declared Secret: its name, per-key sources, the key schema's sources
    and optional keys, whether the Secret is this target's own, and its values. Ownership
    is proven like provisioning's (journal operation, nonce, profile label and UID) on
    metadata alone before any value is read, and the read is bound to that UID. Values
    stay in memory, join the failure-diagnostic redaction and are never returned publicly.
    """
    from ..provider_lifecycle import ownership_path
    if profile_root is None and os.environ.get('PZ_ADW_PROFILE_ROOT'):
        profile_root = Path(os.environ['PZ_ADW_PROFILE_ROOT'])
    if profile_root is None:
        raise ContractError('kubernetes_context_profile_missing')
    provider, profile, digest, selection = _selection(repo, adapter, environment, target, profile_root)
    binding = selection['binding']
    schema, optional = schema_sources(repo, adapter, binding)
    labels = {APP_LABEL: 'adw', IDENTITY['target']: binding_alias(profile, provider.namespace)}
    private = ownership_path(repo, profile_root, selection['repository'], environment, selection['target'])
    state = _state(private, root=private.parent) if private.exists() else None
    if state is not None and (state.get('workflow') != 'kubernetes-provision' or state.get('selection') != selection):
        state = None                      # another operation or profile: nothing is provably ours
    # Without a journal nothing is ours: an existing Secret of that name is foreign.
    reader = TargetBootstrap(provider, profile, digest, {}, state or {'resources': {}}, lambda: None, plan=True)
    result = []
    for name, fields in profile.get('app_secrets', {}).get(provider.namespace, {}).items():
        values, owned = None, True
        try:
            present = reader.owned('Secret', name, provider.namespace, labels)    # metadata only
        except ContractError:
            owned = present = False
        if present:
            _item, values = _proven_data(reader, provider, name, labels)
        result.append({'name': name, 'fields': fields, 'schema': schema, 'optional': optional,
                       'owned': owned, 'values': values if owned else None})
    return result


def binding_alias(profile, namespace):
    return next(alias for alias, ns in profile['context_aliases'].items() if ns == namespace)


# A verified existing certificate must stay valid at least this long after provisioning.
VERIFY_EXISTING_MINIMUM = timedelta(days=7)


def _served_certificate(host):
    """The certificate the cluster ingress serves for host: strict TLS, public data only."""
    import socket
    import ssl
    from datetime import datetime, timezone
    context = ssl.create_default_context()  # chain and hostname verification on
    with socket.create_connection((host, 443), timeout=15) as raw, context.wrap_socket(raw, server_hostname=host) as tls:
        peer = tls.getpeercert()
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(peer['notAfter']), timezone.utc)
    return not_after, [value for kind, value in peer.get('subjectAltName', ()) if kind == 'DNS']


def _verify_existing_tls(provider, tls):
    """Existing cluster TLS (verify-existing): read-only, nothing is installed or changed.

    The Traefik default TLSStore must name a Secret in kube-system that exists (read as
    metadata only: no Secret data is requested). If a cert-manager Certificate writes it
    (cert-manager's certificate-name annotation), that Certificate must be Ready with affirmative
    evidence for its current generation, valid for at least seven more days and cover the
    target's ingress host exactly or through a one-level wildcard. An imported certificate that
    no Certificate manages is verified by the certificate the ingress actually serves for the
    host instead: strict TLS chain and hostname verification, at least seven more days.
    """
    from datetime import datetime, timezone

    def refuse(check):
        return ContractError('cluster_tls_not_ready: verify-existing: ' + check)
    host = tls['host']
    try:
        secret = provider._run(['get', 'TLSStore', 'default', '--namespace', 'kube-system',
            '-o', 'jsonpath={.spec.defaultCertificate.secretName}']).decode().strip()
    except ContractError as exc:
        raise refuse('Traefik TLSStore kube-system/default is missing') from exc
    if not secret or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', secret):
        raise refuse('TLSStore kube-system/default names no certificate Secret')
    try:
        with metadata_api(provider, secret=('kube-system', secret)) as client:
            observed = client.get('Secret', secret, 'kube-system')
    except ContractError as exc:
        raise refuse('the TLSStore Secret metadata is unreadable') from exc
    if observed is None:
        raise refuse('the TLSStore Secret is missing')
    writer = (observed['metadata'].get('annotations') or {}).get('cert-manager.io/certificate-name')
    try:
        raw = provider._run(['get', 'certificates.cert-manager.io', '--namespace', 'kube-system', '-o', 'json'])
        certificates = [item for item in json.loads(raw).get('items', [])
                        if isinstance(item, dict) and isinstance(item.get('spec'), dict)
                        and item['spec'].get('secretName') == secret]
    except (ContractError, ValueError, AttributeError):
        certificates = []  # No cert-manager on this cluster.
    if not certificates and writer is None:
        try:
            served_until, served_names = _served_certificate(host)
        except (OSError, ValueError, KeyError) as exc:
            raise refuse('the imported certificate served for the host does not verify') from exc
        wildcard = '*.' + host.split('.', 1)[1] if '.' in host else None
        if host not in served_names and wildcard not in served_names:
            raise refuse('the certificate does not cover the target host')
        if served_until - datetime.now(timezone.utc) < VERIFY_EXISTING_MINIMUM:
            raise refuse('the certificate expires within 7 days')
        return {'mode': 'verify-existing', 'certificate_valid_until': served_until.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'evidence': 'served-certificate'}
    if len(certificates) != 1:
        raise refuse('no single cert-manager Certificate manages the TLSStore Secret')
    certificate = certificates[0]
    metadata = certificate.get('metadata') if isinstance(certificate.get('metadata'), dict) else {}
    if writer != metadata.get('name'):
        raise refuse('the TLSStore Secret was not written by its managing Certificate')
    status = certificate.get('status') if isinstance(certificate.get('status'), dict) else {}
    generation = metadata.get('generation')
    if not isinstance(generation, int) or not any(
            isinstance(c, dict) and c.get('type') == 'Ready' and c.get('status') == 'True'
            and c.get('observedGeneration') == generation for c in status.get('conditions', []) or []):
        raise refuse('the managing Certificate is not Ready for its current generation')
    try:
        not_after = datetime.fromisoformat(str(status.get('notAfter', '')).replace('Z', '+00:00'))
    except ValueError as exc:
        raise refuse('the managing Certificate reports no expiry') from exc
    if not_after.tzinfo is None or not_after - datetime.now(timezone.utc) < VERIFY_EXISTING_MINIMUM:
        raise refuse('the certificate expires within 7 days')
    names = certificate['spec'].get('dnsNames', []) or []
    wildcard = '*.' + host.split('.', 1)[1] if '.' in host else None
    if not isinstance(names, list) or (host not in names and wildcard not in names):
        raise refuse('the certificate does not cover the target host')
    return {'mode': 'verify-existing', 'certificate_valid_until': not_after.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'evidence': 'cert-manager'}


def _tls_ready(provider, tls):
    """Cluster ingress/TLS is a prerequisite; observe only public readiness."""
    if tls.get('mode') == 'verify-existing':
        return _verify_existing_tls(provider, tls)
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
    return {'mode': 'provider-owned'}


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
        if resource in {'events', 'events.events.k8s.io'} or resource.endswith('.metrics.k8s.io'):
            continue  # Control-plane telemetry and metrics-server views carry no persistent state.
        raw = bootstrap.kube(['get', resource, '--namespace', namespace, '-o',
            'jsonpath={range .items[*]}{.kind}{" "}{.metadata.name}{"\\n"}{end}'])
        for line in raw.decode().splitlines():
            parts = line.split()
            if len(parts) != 2 or (tuple(parts) not in owned
                    and not _generated_default(bootstrap, namespace, *parts)):
                raise ContractError('provider_foreign_child_present')


def _settled_children(bootstrap, namespace, candidates, attempts=30):
    """Endpoints and terminating Pods of just-removed runtime vanish asynchronously."""
    for attempt in range(attempts):
        try:
            return _namespace_children(bootstrap, namespace, candidates)
        except ContractError as exc:
            if str(exc) != 'provider_foreign_child_present' or attempt == attempts - 1:
                raise
            time.sleep(2)


# The only controller dependents garbage collection may remove with the runtime.
DEPENDENTS = {'ReplicaSet': {'Deployment'}, 'Pod': {'ReplicaSet', 'StatefulSet', 'DaemonSet'},
              'ControllerRevision': {'StatefulSet', 'DaemonSet'}, 'EndpointSlice': {'Service'}}


def _runtime_preflight(bootstrap, provider, namespace, candidates, runtime):
    """Before the first deletion, every object in the namespace must be provably ours.

    Owned are the journaled Secrets, the controller defaults, the inventoried runtime and,
    transitively, the bounded controller dependents in DEPENDENTS whose controller owner
    reference names an owned UID of the expected parent kind, plus the Endpoints of owned
    Services. Any other kind with such a reference (a Secret, Role or custom resource) stays
    foreign. Then no deletion, including garbage collection, can reach a foreign object.
    """
    journaled = {(v['kind'], v['name']) for v in candidates if v['namespace'] == namespace}
    owned = {v['metadata']['uid']: v['kind'] for v in runtime}
    services = {v['metadata']['name'] for v in runtime if v['kind'] == 'Service'}
    pending = []
    for item in provider.namespace_inventory():
        kind, name = item['kind'], item['metadata']['name']
        if ((kind, name) in journaled or item['metadata'].get('uid') in owned
                or (kind == 'Endpoints' and name in services)):
            continue
        pending.append(item)
    changed = True
    while pending and changed:
        changed = False
        for item in list(pending):
            references = item['metadata'].get('ownerReferences') or []
            parents = DEPENDENTS.get(item['kind'], set())
            if any(isinstance(r, dict) and r.get('controller') is True and owned.get(r.get('uid')) in parents
                   for r in references):
                owned[item['metadata'].get('uid')] = item['kind']
                pending.remove(item)
                changed = True
    for item in pending:
        if not _generated_default(bootstrap, namespace, item['kind'], item['metadata']['name']):
            raise ContractError('provider_foreign_child_present')


def _remove_runtime(bootstrap, provider, state, save, candidates, *, plan, confirm_data_loss, backup_reference):
    """Remove the runtime this provider applied to the target before its namespace goes."""
    from ..provider_lifecycle import BACKUP_REFERENCE
    previous = state.get('runtime', {}).get('objects', [])
    workloads, claims = provider.runtime_inventory(previous)
    persistent = bool(claims) or any(v['kind'] == 'PersistentVolumeClaim' for v in previous)
    if persistent and (confirm_data_loss is not True or not isinstance(backup_reference, str)
                       or not BACKUP_REFERENCE.fullmatch(backup_reference)):
        raise ContractError('kubernetes_deprovision_persistent_data_present')
    _runtime_preflight(bootstrap, provider, provider.namespace, candidates, workloads + claims)
    top = [v for v in workloads if v['kind'] not in {'ReplicaSet', 'Pod'}]
    summary = {'workloads': len(top), 'persistent_claims': len(claims), 'data_loss_confirmed': persistent}
    if plan:
        return {**summary, 'state': 'planned'}
    known = {(v['kind'], v['name']) for v in previous}
    record = previous + [{'kind': v['kind'], 'name': v['metadata']['name'], 'uid': v['metadata']['uid']}
                         for v in workloads + claims if (v['kind'], v['metadata']['name']) not in known]
    state['runtime'] = {'objects': record, 'backup_reference': backup_reference if persistent else None}
    state['phase'] = 'deprovisioning'
    save()
    for item in top:
        provider.delete_exact(item)
    provider.wait_gone(workloads)
    for claim in claims:
        provider.delete_exact(claim)
    provider.wait_gone(claims)
    provider.verify_runtime_removed(claims)
    return {**summary, 'state': 'removed'}


def deprovision(repo, adapter, *, private, profile_root, operation_dir, source_sha, plan=False,
                include_runtime=False, confirm_data_loss=False, backup_reference=None):
    from ..provider_lifecycle import _operator
    from ..dokploy_transaction import target_lock
    _operator()
    with locked(private.parent), locked(operation_dir):
        state = _state(private, root=private.parent)
        target = state.get('selection', {}).get('target') if isinstance(state.get('selection'), dict) else None
        if not isinstance(target, str) or not IDENTIFIER.fullmatch(target):
            raise ContractError('kubernetes_provision_journal_invalid')
        # Deployments and configuration sync hold the same logical target lock, so no apply
        # can interleave with the inventory, the ownership preflight or any deletion.
        with target_lock(repo, target):
            try:
                return _deprovision_locked(repo, adapter, state, private=private, profile_root=profile_root,
                                           operation_dir=operation_dir, source_sha=source_sha, plan=plan,
                                           include_runtime=include_runtime, confirm_data_loss=confirm_data_loss,
                                           backup_reference=backup_reference)
            except KubernetesCommandError as exc:
                if not plan:
                    _record_command_failure(private, operation_dir, exc)
                raise


def _deprovision_locked(repo, adapter, state, *, private, profile_root, operation_dir, source_sha, plan,
                        include_runtime, confirm_data_loss, backup_reference):
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
    runtime = ({'state': 'absent', 'workloads': 0, 'persistent_claims': 0, 'data_loss_confirmed': False}
               if include_runtime else None)
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
        if entry.get('delete_requested') and metadata.get('deletionTimestamp'):
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
        # A present, still-owned object with the same UID and no deletion
        # timestamp proves a requested delete did not land. Use the freshly
        # observed resourceVersion below; never relax ownership or UID checks.
        if entry['kind'] == 'Namespace':
            if not include_runtime:
                _namespace_children(bootstrap, entry['name'], candidates)
            else:
                # Only inside the journal-proven namespace, after every Secret was checked.
                runtime = _remove_runtime(bootstrap, provider, state, save, candidates, plan=plan,
                                          confirm_data_loss=confirm_data_loss, backup_reference=backup_reference)
                if not plan:
                    # Garbage-collected dependents of the removed runtime vanish asynchronously.
                    _settled_children(bootstrap, entry['name'], candidates)
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
    return _receipt(operation_dir, state, plan=plan, cleanup=True, mutations=mutations, source_sha=source_sha,
                    runtime=runtime)


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

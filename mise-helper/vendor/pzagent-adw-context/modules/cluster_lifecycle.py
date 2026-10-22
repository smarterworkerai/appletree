"""Profile-bound local k3d lifecycle; private inputs never enter task output."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import secrets
import subprocess

from .common import ContractError, IDENTIFIER
from .execution import human
from .operator_credentials import clean_environment, bootstrap_keys, cluster_seed, CLUSTER_SEED
from .cluster_bootstrap import Bootstrap, validate as validate_bootstrap, facts as bootstrap_facts, PULL_SECRET
from .operator_state import locked, read, write

OWNER = 'pzagent.owner'
PROFILE = 'pzagent.profile'
MAX_BYTES = 8 * 1024 * 1024


def _failure_reason(stdout: bytes, stderr: bytes) -> str:
    # Read bounded diagnostics as data and emit only reviewed fixed codes.
    # Never persist or echo raw k3d/Docker output, addresses or runtime IDs.
    raw = (stdout[-65536:] + stderr[-65536:]).lower()
    patterns = (
        ('cluster_port_unavailable', (b'port is already allocated', b'address already in use', b'failed to bind host port', b'cannot expose privileged port')),
        ('cluster_disk_full', (b'no space left on device',)),
        ('cluster_memory_unavailable', (b'cannot allocate memory', b'out of memory')),
        ('cluster_docker_api_incompatible', (b'client version', b'minimum supported api version')),
        ('cluster_image_pull_failed', (b'failed to pull image', b'error pulling image', b'pull access denied', b'toomanyrequests')),
        ('cluster_docker_permission_denied', (b'permission denied', b'operation not permitted')),
        ('cluster_registry_config_invalid', (b'failed to read registry', b'failed to parse registry', b'failed to unmarshal')),
        ('cluster_node_filter_invalid', (b'invalid nodefilter', b'invalid node filter')),
        ('cluster_tools_node_failed', (b'failed to ensure tools node',)),
        ('cluster_environment_discovery_failed', (b'failed to gather environment information',)),
        ('cluster_start_failed', (b'failed cluster start',)),
    )
    for reason, markers in patterns:
        if any(marker in raw for marker in markers):
            return reason
    return 'cluster_command_failed'


def _private_json(path: Path) -> dict:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077 or path.stat().st_size > 65536:
            raise ValueError()
        value = json.loads(path.read_bytes())
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (OSError, ValueError) as exc:
        raise ContractError('cluster_profile_invalid') from exc


def _profile(root: Path, alias: str, data: dict | None = None) -> tuple[dict, str, Path]:
    data = _private_json(root / 'k3d-clusters.json') if data is None else data
    try:
        if set(data) != {'schema_version', 'clusters'} or data['schema_version'] != '1.0.0' or not IDENTIFIER.fullmatch(alias):
            raise ValueError()
        profile = data['clusters'][alias]
        required = {'name', 'image', 'bind_address', 'http_port', 'https_port', 'registry',
                    'namespaces', 'context_aliases', 'storage_directory'}
        if (not isinstance(profile, dict) or not required <= set(profile)
                or set(profile) - required - {'tls', 'image_pull', 'app_secrets'} or not IDENTIFIER.fullmatch(profile['name'])):
            raise ValueError()
        if not re.fullmatch(r'(?:docker\.io/)?rancher/k3s:v1\.[0-9]+\.[0-9]+-k3s[0-9]+', profile['image']):
            raise ValueError()
        if ipaddress.ip_address(profile['bind_address']).version != 4:
            raise ValueError()
        for port in ('http_port', 'https_port'):
            if type(profile[port]) is not int or not 1 <= profile[port] <= 65535:
                raise ValueError()
        if profile['http_port'] == profile['https_port']:
            raise ValueError()
        namespaces = profile['namespaces']
        if (not isinstance(namespaces, list) or not namespaces or len(namespaces) > 8
                or len(set(namespaces)) != len(namespaces)
                or any(not isinstance(v, str) or not IDENTIFIER.fullmatch(v) for v in namespaces)):
            raise ValueError()
        aliases = profile['context_aliases']
        if not isinstance(aliases, dict) or not aliases or any(not IDENTIFIER.fullmatch(k) or v not in namespaces for k, v in aliases.items()):
            raise ValueError()
        registry = profile['registry']
        if registry is not None and (not isinstance(registry, dict) or set(registry) != {'name', 'port'}
                or registry['name'] != profile['name'] + '-registry'
                or type(registry['port']) is not int or not 0 <= registry['port'] <= 65535):
            raise ValueError()
        directory = profile['storage_directory']
        if not isinstance(directory, str) or not IDENTIFIER.fullmatch(directory):
            raise ValueError()
        storage = Path.home() / '.local/share' / directory
        if storage.is_symlink() or storage.parent.is_symlink():
            raise ValueError()
        validate_bootstrap(profile)
    except (KeyError, TypeError, ValueError) as exc:
        raise ContractError('cluster_profile_invalid') from exc
    digest = hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return profile, digest, storage


class Lifecycle:
    def __init__(self, root: Path, alias: str, data: dict | None = None) -> None:
        self.root, self.alias = root, alias
        self.profile, self.digest, self.storage = _profile(root, alias, data)
        self.kubeconfig = root / 'kubeconfig'
        self.env = clean_environment()
        for key in bootstrap_keys(root):
            self.env.pop(key, None)
        for key in ('SSH_AUTH_SOCK', 'DOCKER_CONFIG', 'DOCKER_AUTH_CONFIG', 'REGISTRY_AUTH_FILE', 'ORAS_CONFIG'):
            self.env.pop(key, None)
        self.env['KUBECONFIG'] = str(self.kubeconfig)

    def run(self, arguments: list[str], *, data: bytes | None = None, timeout: int = 45) -> bytes:
        diagnostic = None
        if arguments[:3] == ['k3d', 'cluster', 'create']:
            directory = self.storage / 'diagnostics'
            if directory.is_symlink():
                raise ContractError('cluster_diagnostic_path_invalid')
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            diagnostic = directory / ('cluster-create-' + secrets.token_hex(12) + '.log')
        try:
            result = subprocess.run(arguments, input=data, env=self.env, capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ContractError('cluster_command_unavailable') from exc
        if diagnostic is not None:
            # Operator-only raw diagnostic, never evidence/stdout or source.
            # No argv, environment, input or kubeconfig is written here.
            with diagnostic.open('xb') as stream:
                os.chmod(diagnostic, 0o600)
                stream.write(b'STDOUT\n' + result.stdout[-MAX_BYTES:]
                             + b'\nSTDERR\n' + result.stderr[-MAX_BYTES:])
        if result.returncode:
            raise ContractError(_failure_reason(result.stdout, result.stderr))
        if len(result.stdout) > MAX_BYTES:
            raise ContractError('cluster_output_unbounded')
        return result.stdout

    def clusters(self) -> list[dict]:
        try:
            values = json.loads(self.run(['k3d', 'cluster', 'list', '-o', 'json']))
            if not isinstance(values, list) or any(not isinstance(v, dict) or not isinstance(v.get('name'), str) for v in values):
                raise ValueError()
            return values
        except (ValueError, TypeError) as exc:
            raise ContractError('cluster_observation_invalid') from exc

    def foreign_hash(self) -> str:
        values = [v for v in self.clusters() if v['name'] != self.profile['name']]
        return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def local_docker(self) -> None:
        try:
            rows = json.loads(self.run(['docker', 'context', 'inspect']))
            endpoint = rows[0]['Endpoints']['docker']['Host']
            override = os.environ.get('DOCKER_HOST', endpoint)
            if not endpoint.startswith('unix://') or not override.startswith('unix://'):
                raise ValueError()
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            raise ContractError('cluster_local_docker_required') from exc
        try:
            with socket.socket() as listener:
                listener.bind((self.profile['bind_address'], 0))
        except OSError as exc:
            raise ContractError('cluster_bind_address_not_local') from exc

    def owned(self) -> None:
        names = self.run(['docker', 'ps', '-a', '--filter', 'label=k3d.cluster=' + self.profile['name'],
                          '--format', '{{.ID}}']).decode().splitlines()
        if not names:
            raise ContractError('cluster_ownership_unproven')
        try:
            rows = json.loads(self.run(['docker', 'inspect', *names]))
            primary = []
            for node in rows:
                labels = node['Config']['Labels']
                if node.get('Name') == '/k3d-' + self.profile['name'] + '-tools':
                    mounts = node.get('Mounts', [])
                    expected_mounts = {('bind', '/var/run/docker.sock', '/var/run/docker.sock'),
                                       ('volume', 'k3d-' + self.profile['name'] + '-images', '/k3d/images')}
                    actual_mounts = {(v.get('Type'), v.get('Name') if v.get('Type') == 'volume' else v.get('Source'),
                                      v.get('Destination')) for v in mounts}
                    if (labels.get('app') != 'k3d' or labels.get('k3d.cluster') != self.profile['name']
                            or node['Config'].get('Image') != 'ghcr.io/k3d-io/k3d-tools:5.8.3'
                            or actual_mounts != expected_mounts):
                        raise ValueError()
                else:
                    if labels.get(OWNER) != 'adw' or labels.get(PROFILE) != self.digest:
                        raise ValueError()
                    primary.append(node)
            if not primary:
                raise ValueError()
        except (ValueError, KeyError, TypeError) as exc:
            raise ContractError('cluster_ownership_unproven') from exc

    def kube(self, arguments: list[str], *, data: bytes | None = None, timeout: int = 45) -> bytes:
        override = os.environ.get('PZ_ADW_KUBE_CONTEXT')
        if override is not None and override != 'k3d-' + self.profile['name']:
            raise ContractError('cluster_context_mismatch')
        return self.run(['kubectl', '--kubeconfig', str(self.kubeconfig), '--context',
                         'k3d-' + self.profile['name'], '--request-timeout=30s', *arguments], data=data, timeout=timeout)

    def kubeconfig_owned(self) -> None:
        if not self.kubeconfig.exists():
            return
        if self.kubeconfig.is_symlink() or self.kubeconfig.stat().st_mode & 0o077:
            raise ContractError('cluster_kubeconfig_path_invalid')
        try:
            value = json.loads(self.run(['kubectl', '--kubeconfig', str(self.kubeconfig), 'config', 'view', '-o', 'json']))
            name = 'k3d-' + self.profile['name']
            contexts = value.get('contexts') or []
            users = {v['context']['user'] for v in contexts}
            if (any(v['name'] != name or v['context']['cluster'] != name for v in contexts)
                    or any(v['name'] != name for v in value.get('clusters') or [])
                    or {v['name'] for v in value.get('users') or []} != users):
                raise ValueError()
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ContractError('cluster_kubeconfig_foreign_context') from exc

    def api_endpoint(self, port: int) -> None:
        try:
            value = json.loads(self.run(['kubectl', '--kubeconfig', str(self.kubeconfig), 'config', 'view', '-o', 'json']))
            clusters = value['clusters']
            if (len(clusters) != 1 or clusters[0]['name'] != 'k3d-' + self.profile['name']
                    or clusters[0]['cluster']['server'] != 'https://127.0.0.1:' + str(port)
                    or clusters[0]['cluster'].get('insecure-skip-tls-verify', False)):
                raise ValueError()
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            raise ContractError('cluster_api_endpoint_unproven') from exc

    def contexts(self) -> None:
        path = self.root / 'kubernetes-contexts.json'
        existing = _private_json(path) if path.exists() else {'schema_version': '1.0.0', 'contexts': {}}
        if set(existing) != {'schema_version', 'contexts'} or existing['schema_version'] != '1.0.0' or not isinstance(existing['contexts'], dict):
            raise ContractError('cluster_context_profile_conflict')
        for alias, namespace in self.profile['context_aliases'].items():
            selected = {'context': 'k3d-' + self.profile['name'], 'namespace': namespace}
            if namespace in self.profile.get('image_pull', {}).get('namespaces', []):
                selected['image_pull_secret'] = PULL_SECRET
            if alias in existing['contexts'] and existing['contexts'][alias] != selected:
                raise ContractError('cluster_context_profile_conflict')
            existing['contexts'][alias] = selected
        write(path, existing)

    def namespace(self, namespace: str) -> None:
        raw = self.kube(['get', 'namespace', namespace, '--ignore-not-found', '-o', 'json'])
        if raw.strip():
            try:
                value = json.loads(raw)
                labels = value['metadata']['labels']
                if value['metadata']['name'] != namespace or labels.get(OWNER) != 'adw' or labels.get(PROFILE) != self.digest[:63]:
                    raise ValueError()
            except (ValueError, KeyError, TypeError) as exc:
                raise ContractError('cluster_namespace_ownership_unproven') from exc
            return
        definition = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {
            'name': namespace, 'labels': {OWNER: 'adw', PROFILE: self.digest[:63]}}}
        # Kubernetes label values are bounded to 63 characters; use the same
        # prefix on namespace readback, while Docker retains the full hash.
        self.kube(['apply', '--server-side', '--field-manager', 'adw', '-f', '-'],
                  data=json.dumps(definition).encode())

    def registry_owned(self, name: str, port: int) -> None:
        try:
            observed = json.loads(self.run(['docker', 'inspect', name]))
            mounts = observed[0].get('Mounts', [])
            bindings = observed[0].get('HostConfig', {}).get('PortBindings', {}).get('5000/tcp', [])
            if (not any(v.get('Source') == str(self.storage / 'registry') and v.get('Destination') == '/var/lib/registry' for v in mounts)
                    or not bindings or any(v.get('HostPort') != str(port)
                        or not ipaddress.ip_address(v.get('HostIp', '')).is_loopback for v in bindings)):
                raise ValueError()
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            raise ContractError('cluster_registry_ownership_unproven') from exc

    def orphan_network(self, *, remove: bool = False) -> bool:
        name = 'k3d-' + self.profile['name']
        names = self.run(['docker', 'network', 'ls', '--format', '{{.Name}}']).decode().splitlines()
        if name not in names:
            return False
        try:
            rows = json.loads(self.run(['docker', 'network', 'inspect', name]))
            if (not isinstance(rows, list) or len(rows) != 1
                    or rows[0].get('Name') != name or rows[0].get('Labels', {}).get('app') != 'k3d'
                    or not isinstance(rows[0].get('Containers'), dict) or rows[0]['Containers']
                    or any(v['name'] == self.profile['name'] for v in self.clusters())):
                raise ValueError()
        except (ValueError, TypeError, AttributeError) as exc:
            raise ContractError('cluster_orphan_network_ownership_unproven') from exc
        if remove:
            # Docker atomically refuses removal if a container connected since
            # the readback. Only this exact, empty, absent-cluster network is
            # eligible; never use a network prune or wildcard deletion.
            self.run(['docker', 'network', 'rm', name])
        return True

    def leftovers(self) -> dict[str, bool]:
        name = 'k3d-' + self.profile['name']
        result = {}
        for key, command in [('containers', ['docker', 'ps', '-a', '--format', '{{.Names}}']),
                             ('networks', ['docker', 'network', 'ls', '--format', '{{.Name}}']),
                             ('volumes', ['docker', 'volume', 'ls', '--format', '{{.Name}}'])]:
            values = self.run(command).decode().splitlines()
            result[key] = not any(v == name or v.startswith(name + '-') for v in values)
        values = self.run(['kubectl', '--kubeconfig', str(self.kubeconfig), 'config', 'get-contexts', '-o', 'name']).decode().splitlines() if self.kubeconfig.exists() else []
        result['context'] = name not in values
        # All bootstrap objects live exclusively inside this exact cluster.
        result['bootstrap_resources'] = not any(v['name'] == self.profile['name'] for v in self.clusters())
        return result


def _seed_profile(root: Path, alias: str) -> dict | None:
    path = root / 'k3d-clusters.json'
    if path.exists() or path.is_symlink():
        return None  # Existing operator data always wins; never overwrite it.
    seed = cluster_seed()
    if seed is None:
        raise ContractError('cluster_profile_seed_missing')
    try:
        top = subprocess.run(['git', 'rev-parse', '--show-toplevel'], capture_output=True, timeout=10)
        tracked = subprocess.run(['git', 'ls-files', '--error-unmatch', '--', str(CLUSTER_SEED)],
                                 capture_output=True, timeout=10)
        if top.returncode or tracked.returncode or root.resolve().is_relative_to(Path(top.stdout.decode().strip()).resolve()):
            raise ValueError()
        selected = seed['clusters'][alias]
        required = {'name', 'namespaces', 'context_aliases', 'bind_address_env'}
        allowed = required | {'image', 'http_port', 'https_port', 'registry', 'storage_directory', 'tls', 'image_pull', 'app_secrets'}
        if (not isinstance(selected, dict) or not required <= set(selected) or set(selected) - allowed
                or selected['bind_address_env'] != 'PZ_ADW_K3D_BIND_ADDRESS'):
            raise ValueError()
        address = os.environ.get('PZ_ADW_K3D_BIND_ADDRESS', '')
        if not address:
            raise ContractError('cluster_bind_address_fact_missing')
        profile = {'image': 'rancher/k3s:v1.35.0-k3s1', 'http_port': 80, 'https_port': 443,
                   'registry': None, 'storage_directory': selected['name'] + '-k3d', **selected}
        profile.pop('bind_address_env')
        profile['bind_address'] = address
        data = {'schema_version': '1.0.0', 'clusters': {alias: profile}}
        _profile(root, alias, data)  # Closed full-profile validation before any local write.
        if root.is_symlink() or any(p.is_symlink() for p in root.parents):
            raise ValueError()
        return data
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        raise ContractError('cluster_profile_seed_invalid') from exc


def _write_seed_profile(root: Path, data: dict) -> None:
    path = root / 'k3d-clusters.json'
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    except FileExistsError:
        if _private_json(path) != data:
            raise ContractError('cluster_profile_initialization_conflict')
        return
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write('\n')


def manage(*, profile_root: Path, alias: str, action: str, operation_dir: Path, plan: bool = False) -> dict:
    if action not in {'up', 'teardown'}:
        raise ContractError('cluster_action_invalid')
    if not plan and not human():
        raise ContractError('cluster_lifecycle_requires_operator_mode')
    initial = _seed_profile(profile_root, alias) if action == 'up' else None
    lifecycle = Lifecycle(profile_root, alias, initial)
    if os.environ.get('PZ_ADW_KUBE_CONTEXT', 'k3d-' + lifecycle.profile['name']) != 'k3d-' + lifecycle.profile['name']:
        raise ContractError('cluster_context_mismatch')
    tls_profile = {key: value for key, value in lifecycle.profile.items() if key not in {'image_pull', 'app_secrets'}}
    values = bootstrap_facts(tls_profile) if action == 'up' and not plan else {}
    lifecycle.local_docker()
    lifecycle.kubeconfig_owned()
    profile, digest = lifecycle.profile, lifecycle.digest
    clusters = lifecycle.clusters()
    present = any(v['name'] == profile['name'] for v in clusters)
    if present:
        lifecycle.owned()
    if plan:
        return {'status': 'ok', 'phase': 'planned', 'action': action,
                'profile_sha256': digest, 'cluster_present': present,
                'registry_required': profile['registry'] is not None,
                'profile_initialization_required': initial is not None}
    selection = {'profile_sha256': digest, 'alias': alias, 'action': action}
    state_path = profile_root / ('cluster-state-' + alias + '.json')
    with locked(operation_dir), locked(profile_root / ('cluster-lock-' + alias)):
        if initial is not None:
            _write_seed_profile(profile_root, initial)
        path = operation_dir / 'operation.json'
        record = read(path) if path.exists() else {'schema_version': '1.0.0',
            'workflow': 'cluster-lifecycle', 'selection': selection, 'phase': 'selected'}
        if record.get('workflow') != 'cluster-lifecycle' or record.get('selection') != selection:
            raise ContractError('cluster_resume_selection_differs')
        foreign = lifecycle.foreign_hash()
        record.setdefault('foreign_before_sha256', foreign)
        if foreign != record['foreign_before_sha256']:
            raise ContractError('cluster_foreign_observation_changed')
        write(path, record)
        saved = read(state_path) if state_path.exists() else {'schema_version': '1.0.0', 'profile_sha256': digest}
        if saved.get('profile_sha256') != digest:
            if present or saved.get('cluster_created') is not False or not all(lifecycle.leftovers().values()):
                raise ContractError('cluster_profile_state_conflict')
            # A completed, fully verified teardown permits a new explicit
            # private profile; no running cluster or orphan can be adopted.
            saved = {'schema_version': '1.0.0', 'profile_sha256': digest}
            write(state_path, saved)

        def stage(phase):
            record['phase'] = phase
            write(path, record)

        registry = profile['registry']
        registry_name = 'k3d-' + registry['name'] if registry is not None else None
        if action == 'up':
            lifecycle.storage.mkdir(parents=True, exist_ok=True, mode=0o700)
            if registry is not None:
                if 'registry_port' not in saved:
                    port = registry['port']
                    if not port:
                        with socket.socket() as listener:
                            listener.bind(('localhost', 0))
                            port = listener.getsockname()[1]
                    saved['registry_port'] = port
                    write(state_path, saved)
                stage('registry-selected')
                registries = json.loads(lifecycle.run(['k3d', 'registry', 'list', '-o', 'json']))
                if not any(v.get('name') == registry_name for v in registries):
                    directory = lifecycle.storage / 'registry'
                    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                    stage('registry-create-requested')
                    lifecycle.run(['k3d', 'registry', 'create', registry['name'], '--port',
                        socket.gethostbyname('localhost') + ':' + str(saved['registry_port']), '--volume', str(directory) + ':/var/lib/registry', '--no-help'], timeout=180)
                else:
                    # Only the exact private-profile mount and bound port may
                    # be adopted after a lost create acknowledgement.
                    lifecycle.registry_owned(registry_name, saved['registry_port'])
                mirrors = {'mirrors': {'localhost:' + str(saved['registry_port']): {'endpoint': ['http://' + registry_name + ':5000']}}}
                mirror = lifecycle.storage / 'registries.yaml'
                write(mirror, mirrors)
            if not present:
                if 'api_port' not in saved:
                    with socket.socket() as listener:
                        listener.bind(('127.0.0.1', 0))
                        saved['api_port'] = listener.getsockname()[1]
                    write(state_path, saved)
                stage('cluster-create-requested')
                arguments = ['k3d', 'cluster', 'create', profile['name'], '--image', profile['image'],
                    '--servers', '1', '--agents', '0', '--wait', '--timeout', '240s',
                    '--api-port', '127.0.0.1:' + str(saved['api_port']),
                    '--kubeconfig-update-default=false', '--kubeconfig-switch-context=false',
                    '--runtime-label', OWNER + '=adw@all', '--runtime-label', PROFILE + '=' + digest + '@all',
                    '--port', profile['bind_address'] + ':' + str(profile['http_port']) + ':80@loadbalancer',
                    '--port', profile['bind_address'] + ':' + str(profile['https_port']) + ':443@loadbalancer']
                if registry is not None:
                    arguments += ['--registry-use', registry_name + ':5000', '--registry-config', str(mirror)]
                lifecycle.run(arguments, timeout=300)
            lifecycle.owned()
            stage('cluster-created')
            raw = lifecycle.run(['k3d', 'kubeconfig', 'get', profile['name']])
            if lifecycle.kubeconfig.is_symlink():
                raise ContractError('cluster_kubeconfig_path_invalid')
            descriptor = os.open(lifecycle.kubeconfig, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(raw)
            lifecycle.api_endpoint(saved['api_port'])
            lifecycle.contexts()
            record['target_namespaces_outside_scope'] = [namespace for namespace in profile['namespaces']
                if lifecycle.kube(['get', 'namespace', namespace, '--ignore-not-found', '-o', 'name']).strip()]
            stage('tls-bootstrap-requested')
            record['bootstrap'] = Bootstrap(lifecycle, values).run(target_resources=False)
            write(path, record)
            saved['cluster_created'] = True
            write(state_path, saved)
        else:
            registry_present = False
            if registry_name is not None:
                registries = json.loads(lifecycle.run(['k3d', 'registry', 'list', '-o', 'json']))
                registry_present = any(v.get('name') == registry_name for v in registries)
                if registry_present:
                    if not state_path.exists() or 'registry_port' not in saved:
                        raise ContractError('cluster_registry_ownership_unproven')
                    lifecycle.registry_owned(registry_name, saved['registry_port'])
            if present:
                stage('cluster-delete-requested')
                lifecycle.run(['k3d', 'cluster', 'delete', profile['name']], timeout=240)
            if registry_present:
                stage('registry-delete-requested')
                lifecycle.run(['k3d', 'registry', 'delete', registry_name], timeout=120)
            stage('orphan-network-check')
            record['orphan_network_removed'] = lifecycle.orphan_network(remove=True)
            write(path, record)
            # This private file was checked to contain only this cluster. The
            # default user kubeconfig and every unrelated context remain intact.
            lifecycle.kubeconfig_owned()
            lifecycle.kubeconfig.unlink(missing_ok=True)
            contexts_path = profile_root / 'kubernetes-contexts.json'
            if contexts_path.exists():
                contexts = _private_json(contexts_path)
                contexts['contexts'] = {key: value for key, value in contexts['contexts'].items()
                    if value.get('context') != 'k3d-' + profile['name']}
                write(contexts_path, contexts)
            leftovers = lifecycle.leftovers()
            if not all(leftovers.values()) or any(v['name'] == profile['name'] for v in lifecycle.clusters()):
                raise ContractError('cluster_teardown_leftovers')
            record['leftovers_absent'] = leftovers
            saved['cluster_created'] = False
            saved.pop('api_port', None)
            saved.pop('registry_port', None)
            write(state_path, saved)
        if lifecycle.foreign_hash() != record['foreign_before_sha256']:
            raise ContractError('cluster_foreign_observation_changed')
        record['foreign_clusters_unchanged'] = True
        stage('complete')
        return {'status': 'ok', 'phase': 'complete', 'action': action,
                'profile_sha256': digest, 'foreign_clusters_unchanged': True,
                **({'provisioning_required': True} if action == 'up' else {}),
                **({'bootstrap': record['bootstrap']} if action == 'up' else {}),
                **({'target_namespaces_outside_scope': record['target_namespaces_outside_scope']} if action == 'up' else {}),
                **({'leftovers_absent': record['leftovers_absent'],
                    'orphan_network_removed': record['orphan_network_removed'], 'dedicated_directory_retained': True,
                    'host_cached_images_retained': True, 'external_dns_and_credentials': 'human-owned'} if action == 'teardown' else {})}

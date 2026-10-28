"""Non-persisting observations of operator operations and deployment targets.

`pz:workflow:doctor` reports them; a mutating command that needs the same facts
re-runs them itself and applies its own policy. Nothing here writes a journal,
pointer, provider setting, cache or handover file, launches a project hook,
takes an operation lock or fetches Git objects. Bounded private scratch (the
rendered definition, registry authentication) is removed afterwards.
Observations never authorize anything: every caller owns its decision.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from .common import ContractError, FULL_SHA, project_dir
from .operator_registry import inspect
from .operator_sources import LOCAL_ONLY, config_source, lazy_fetch_suppressed
from .operator_state import OPERATION_ID
from .oras_registry import OrasRegistry
from .providers import bind, binding_for
from .release_manifest import image_variables, release_kind
from .status_identity import read as identity

MAX_JOURNAL_BYTES = 1024 * 1024
MAX_OPERATIONS = 512
MAX_ENTRIES = 4096
RESULTS = ('pass', 'differs', 'unknown', 'unavailable', 'unsupported', 'refused')
CHECKS = ('running_identity', 'configured_images', 'definition', 'required_keys')
WRITES = ('none', 'possible', 'unknown')
TERMINAL = {'complete', 'deprovisioned', 'retired', 'cancelled'}
PARENT_PHASES = {'selected', 'config-plan', 'config-apply', 'deploy', 'validate', 'complete'}
DEPLOYMENT_PHASES = {'selected', 'configured', 'runtime-requested', 'runtime-confirmed', 'pointers', 'complete',
                     'restore-configured', 'restore-runtime-requested', 'restore-runtime-confirmed',
                     'restore-empty-requested', 'restored'}
PUBLICATION_PHASES = {'selected', 'build', 'package', 'publish', 'deploy', 'complete'}
# Status-identity refusals that observe a real difference rather than a failed read.
IDENTITY_DIFFERS = {'release_runtime_manifest_differs', 'release_manifest_current_differs'}
IDENTITY_UNAVAILABLE = {'release_identity_unavailable', 'release_manifest_unavailable', 'release_manifest_unproven',
                        'runtime_container_discovery_failed', 'runtime_container_inspection_failed'}
SAFE_REASON = re.compile(r'^[a-z][a-z0-9_]{0,80}$')


def now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _reason(exc: BaseException, fallback: str) -> str:
    """Only a bounded reason code leaves; free text may carry remote details."""
    text = str(exc).split(':', 1)[0].strip().replace('-', '_')
    return text if isinstance(exc, ContractError) and SAFE_REASON.fullmatch(text) else fallback


def _record(path: Path) -> tuple[str, dict | None]:
    """A private journal read without following links: present, absent or invalid."""
    try:
        # Non-blocking: a FIFO in place of a journal must be rejected, not waited on.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
    except FileNotFoundError:
        return 'absent', None
    except OSError:
        return 'invalid', None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > MAX_JOURNAL_BYTES:
            return 'invalid', None
        value = json.loads(os.read(fd, MAX_JOURNAL_BYTES + 1))
    except (OSError, ValueError):
        return 'invalid', None
    finally:
        os.close(fd)
    if not isinstance(value, dict) or value.get('schema_version') != '1.0.0':
        return 'invalid', None
    return 'present', value


def _directory(root: Path, operation: str) -> Path | None:
    if not isinstance(operation, str) or not OPERATION_ID.fullmatch(operation):
        return None
    path = root / operation
    return None if path.is_symlink() or (path.exists() and not path.is_dir()) else path


def _node(role: str, operation: str, directory: Path | None, name: str) -> dict:
    if directory is None:
        return {'role': role, 'operation': operation, 'file': name, 'state': 'invalid', 'record': None,
                'directory': None}
    state, record = _record(directory / name)
    return {'role': role, 'operation': operation, 'file': name, 'state': state, 'record': record,
            'directory': directory}


def journal_tree(root: Path, operation: str) -> dict:
    """The bounded linked tree of one operation; nothing outside its declared links is read.

    Links: a publish-deploy parent's `deployment/operation.json`, and each
    deploy-existing record's `deploy_operation`, a sibling deploy-apply
    `deployment.json`. A directory with only `deployment.json` is its own root.
    """
    directory = _directory(root, operation)
    if directory is None:
        raise ContractError('operator_home_operation_id_invalid')
    top = _node('parent', operation, directory, 'operation.json')
    if top['state'] == 'absent':
        top = _node('deployment', operation, directory, 'deployment.json')
    nodes, excluded = [top], []
    record = top['record'] if top['state'] == 'present' else None
    if top['role'] == 'parent' and record is not None:
        deploy = record
        if record.get('workflow') == 'publish-deploy':
            nested = (directory / 'deployment')
            child = _node('publication-deployment', operation,
                          None if nested.is_symlink() else nested, 'operation.json')
            nodes.append(child)
            deploy = child['record'] if child['state'] == 'present' else None
        if isinstance(deploy, dict) and deploy.get('workflow') == 'deploy-existing' and 'deploy_operation' in deploy:
            name = deploy['deploy_operation']
            if isinstance(name, str) and name.startswith('deploy-apply-'):
                nodes.append(_node('deployment', name, _directory(root, name), 'deployment.json'))
            else:
                nodes.append({'role': 'deployment', 'operation': None, 'file': 'deployment.json',
                              'state': 'invalid', 'record': None, 'directory': None})
    for extra in ('previous-compose.yml', 'manifest.json'):
        if (directory / extra).exists():
            excluded.append(extra)  # Recovery inputs, never operation state.
    workflow = record.get('workflow') if record is not None else None
    return {'operation': operation, 'workflow': workflow if isinstance(workflow, str) else None,
            'role': top['role'], 'record': record, 'nodes': nodes, 'excluded': excluded}


def linked_operations(trees: list[dict]) -> set[str]:
    return {node['operation'] for tree in trees for node in tree['nodes'][1:]
            if node['role'] == 'deployment' and node['operation']}


def bounded_entries(directory: Path) -> list[os.DirEntry]:
    """At most MAX_ENTRIES directory entries, sorted after the bound; more refuses."""
    entries = []
    with os.scandir(directory) as scan:
        for entry in scan:
            entries.append(entry)
            if len(entries) > MAX_ENTRIES:
                raise ContractError('directory_inventory_exceeds_bound')
    return sorted(entries, key=lambda entry: entry.name)


def list_operations(root: Path) -> list[str]:
    """Top-level operation directories with a journal; bounded, links ignored."""
    if not root.is_dir() or root.is_symlink():
        return []
    names = []
    for entry in bounded_entries(root):
        if not OPERATION_ID.fullmatch(entry.name) or entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
            continue
        path = Path(entry.path)
        if (path / 'operation.json').exists() or (path / 'deployment.json').exists():
            names.append(entry.name)
        if len(names) > MAX_OPERATIONS:
            raise ContractError('operation_inventory_exceeds_bound')
    return names


def _phase(record: dict):
    """The phase that classifies writes; a retired journal keeps its original phase."""
    phase = record.get('phase')
    if phase != 'cancelled':
        return phase
    retirement = record.get('retirement')
    original = retirement.get('original_phase') if isinstance(retirement, dict) else None
    return original if isinstance(original, str) and original != 'cancelled' else None


def _deployment_writes(node: dict) -> tuple[str, dict]:
    """A deploy-apply journal; it records nothing before its first provider write."""
    if node['state'] == 'absent':
        return 'none', {'deployment_phase': 'absent'}
    if node['state'] != 'present':
        return 'unknown', {'deployment_phase': 'invalid'}
    phase = _phase(node['record'])
    if phase not in DEPLOYMENT_PHASES:
        return 'unknown', {'deployment_phase': 'unrecognized'}
    # `selected` is saved immediately before the configuration write, whose
    # acknowledgement can be lost; every later phase recorded a write.
    evidence = {'deployment_phase': phase}
    identity = node['record'].get('config_identity')
    if isinstance(identity, dict) and isinstance(identity.get('definition_sha256'), str):
        evidence['planned_definition_sha256'] = identity['definition_sha256']
    return 'possible', evidence


def _deploy_existing_writes(record: dict, nested: dict | None) -> tuple[str, dict]:
    phase, results = _phase(record), record.get('results')
    if phase not in PARENT_PHASES or not isinstance(results, dict):
        return 'unknown', {'parent_phase': 'unrecognized'}
    evidence = {'parent_phase': phase}
    classes = []
    legacy_apply = phase == 'config-apply' or 'config-apply' in results
    if legacy_apply and record.get('guarded_config'):
        return 'unknown', evidence | {'reason': 'guarded_record_has_parent_write'}
    if legacy_apply:
        # The parent configuration write can commit before its result is saved.
        classes.append('possible')
        evidence['parent_configuration_write'] = 'complete' if 'config-apply' in results else 'interrupted'
    plan = results.get('config-plan')
    if isinstance(plan, dict):
        for key in ('desired_compose_sha256', 'desired_definition_sha256'):
            if isinstance(plan.get(key), str):
                evidence['planned_definition_sha256'] = plan[key]
    if nested is None:
        if phase in {'deploy', 'validate', 'complete'} or 'deploy' in results:
            return 'unknown', evidence | {'reason': 'deployment_link_unrecorded'}
        classes.append('none')
    else:
        child, child_evidence = _deployment_writes(nested)
        classes.append(child)
        planned = child_evidence.pop('planned_definition_sha256', None)
        if planned is not None:
            evidence.setdefault('planned_definition_sha256', planned)
        evidence.update(child_evidence)
    return _combine(classes), evidence


def _combine(classes: list[str]) -> str:
    return 'unknown' if 'unknown' in classes else 'possible' if 'possible' in classes else 'none'


def write_classification(tree: dict) -> dict:
    """Target writes the linked tree may have caused: none, possible or unknown.

    `none` is only claimed from recorded journals that prove no provider write
    could have started. Publication (registry) writes are reported separately.
    """
    nodes = tree['nodes']
    top = nodes[0]
    if top['state'] != 'present':
        return {'classification': 'unknown', 'evidence': {'reason': 'journal_' + top['state']}}
    if top['role'] == 'deployment':
        value, evidence = _deployment_writes(top)
        return {'classification': value, 'evidence': evidence | {'linked': 'child-only'}}
    record, workflow = top['record'], tree['workflow']
    deployment = next((node for node in nodes[1:] if node['role'] == 'deployment'), None)
    if workflow == 'deploy-existing':
        value, evidence = _deploy_existing_writes(record, deployment)
        return {'classification': value, 'evidence': evidence}
    if workflow in {'publish', 'publish-deploy'}:
        phase = _phase(record)
        if phase not in PUBLICATION_PHASES or not isinstance(record.get('results'), dict):
            return {'classification': 'unknown', 'evidence': {'parent_phase': 'unrecognized'}}
        evidence = {'parent_phase': phase,
                    'publication': 'none' if phase in {'selected', 'build', 'package'} and 'publish' not in record['results']
                    else 'possible'}
        if workflow == 'publish':
            return {'classification': 'none', 'evidence': evidence}
        child = nodes[1]
        if child['state'] == 'absent':
            if phase in {'deploy', 'complete'}:
                return {'classification': 'unknown', 'evidence': evidence | {'reason': 'deployment_journal_absent'}}
            return {'classification': 'none', 'evidence': evidence}
        if child['state'] != 'present' or child['record'].get('workflow') != 'deploy-existing':
            return {'classification': 'unknown', 'evidence': evidence | {'reason': 'deployment_journal_invalid'}}
        value, nested = _deploy_existing_writes(child['record'], deployment)
        return {'classification': value, 'evidence': evidence | nested}
    return {'classification': 'unknown', 'evidence': {'reason': 'workflow_not_classified'}}


def is_terminal(record: dict | None) -> bool:
    if not isinstance(record, dict):
        return False
    return record.get('phase') in TERMINAL or record.get('status') in {'ok', 'cancelled'}


def context(tree: dict) -> dict:
    """Safe enums and identities of the root journal; never paths or raw values."""
    record = tree['record'] or {}
    if tree['role'] == 'deployment':
        selection = record.get('selection') if isinstance(record.get('selection'), dict) else {}
        values = {'workflow': 'deploy-apply', 'release_kind': selection.get('release_kind'),
                  'environment': selection.get('environment'), 'phase': record.get('phase'),
                  'source_sha': selection.get('source_sha')}
    else:
        values = {'workflow': tree['workflow'], 'release_kind': record.get('kind'),
                  'environment': record.get('environment'), 'phase': record.get('phase'),
                  'source_sha': record.get('source_sha')}
    values['operation_kind'] = tree['operation'].rsplit('-', 2)[0]
    values['status'] = record.get('status')
    for key in ('reason_code', 'superseded_by'):
        if isinstance(record.get(key), str):
            values[key] = record[key]
    values['needs_reconcile'] = record.get('needs_reconcile') is True
    values['terminal'] = is_terminal(record)
    clean = {}
    for key, value in values.items():
        if isinstance(value, bool) or value is None:
            clean[key] = value
        elif isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,80}', value):
            clean[key] = value
        else:
            clean[key] = 'invalid'
    return clean


def timestamps(record: dict | None) -> dict:
    """As recorded; never file mtimes or the date inside an operation ID."""
    result = {}
    for key in ('created_at', 'updated_at'):
        value = record.get(key) if isinstance(record, dict) else None
        try:
            valid = isinstance(value, str) and datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ') is not None
        except ValueError:
            valid = False
        result[key] = value if valid else 'unknown'
    return result


def binding_fingerprint(adapter: dict, environment: str, target: str) -> str:
    """Logical identity of a target's provider binding; hashed, never raw remote IDs."""
    item = adapter['targets'][environment]['items'][target]
    canonical = {'provider': item['provider'], 'provider_binding': item['provider_binding'],
                 'binding': binding_for(adapter, item)}
    encoded = json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode()
    return 'sha256:' + hashlib.sha256(encoded).hexdigest()


def recorded_scope(tree: dict, adapter: dict) -> dict:
    """The resolved target a journal proves; a null target is never resolved to today's default.

    `proven` needs an immutable recorded scope whose repository, release kind,
    environment, target, provider and binding fingerprint all equal today's;
    a bare target name is `name-only` and is never mapped to today's provider.
    """
    record = tree['record'] or {}
    selection = record.get('selection') if isinstance(record.get('selection'), dict) else {}
    environment = record.get('environment', selection.get('environment'))
    scope = record.get('scope') if isinstance(record.get('scope'), dict) else None
    target = scope.get('target') if scope else record.get('target', selection.get('target'))
    if target is None:
        # A nested deployment records the target it resolved; that is evidence for this tree.
        nested = next((node['record'] for node in tree['nodes'][1:]
                       if node['role'] == 'deployment' and node['state'] == 'present'), None)
        nested_selection = nested.get('selection') if isinstance(nested, dict) else None
        if isinstance(nested_selection, dict) and nested_selection.get('environment') == environment:
            target = nested_selection.get('target')
    if not isinstance(environment, str) or not isinstance(target, str):
        return {'status': 'unknown', 'reason': 'target_unrecorded', 'environment': environment
                if isinstance(environment, str) else None, 'target': None}
    group = adapter.get('targets', {}).get(environment)
    if not isinstance(group, dict) or target not in group.get('items', {}):
        return {'status': 'unknown', 'reason': 'target_not_in_inventory', 'environment': environment, 'target': target}
    current = binding_fingerprint(adapter, environment, target)
    if scope is None or not isinstance(scope.get('binding_sha256'), str):
        return {'status': 'name-only', 'reason': 'binding_unrecorded', 'environment': environment, 'target': target,
                'binding_sha256': 'unknown'}
    if scope['binding_sha256'] != current:
        return {'status': 'unknown', 'reason': 'binding_changed', 'environment': environment, 'target': target,
                'binding_sha256': scope['binding_sha256']}
    item = group['items'][target]
    kind = record.get('kind', selection.get('release_kind'))
    expected = {'repository': (adapter.get('repository') or {}).get('id'), 'release_kind': kind,
                'environment': environment, 'target': target, 'provider': item.get('provider'),
                'provider_binding': item.get('provider_binding')}
    if any(not isinstance(value, str) or scope.get(key) != value for key, value in expected.items()):
        return {'status': 'unknown', 'reason': 'scope_fields_differ', 'environment': environment, 'target': target,
                'binding_sha256': scope['binding_sha256']}
    return {'status': 'proven', 'environment': environment, 'target': target, 'binding_sha256': current}


_FLOCK = re.compile(r'^\d+:\s+(?:->\s+)?FLOCK\s+\S+\s+\S+\s+\S+\s+([0-9a-f]+):([0-9a-f]+):(\d+)\s')


def lock_state(directories: list[Path | None]) -> dict:
    """Whether any linked operation lock is observably held; never opens or creates a lock file.

    /proc/locks hides owners outside the reader's PID namespace and procfs
    mount, so absence is never proof: the state is `running` when a holder is
    observed and `unknown` otherwise. The mutating command acquires the real
    lock itself.
    """
    try:
        held = set()
        for line in Path('/proc/locks').read_text().splitlines():
            match = _FLOCK.match(line)
            if match is not None:
                held.add((int(match.group(1), 16), int(match.group(2), 16), int(match.group(3))))
    except OSError:
        return {'state': 'unknown', 'observation': 'unsupported'}
    for directory in directories:
        if directory is None:
            continue
        try:
            info = os.lstat(directory / '.lock')
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino) in held:
            return {'state': 'running', 'observation': 'proc-locks'}
    return {'state': 'unknown', 'observation': 'holder-not-observed'}


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    # Local objects only: no fetch, no lazy promisor fetch, no prompt.
    environment = {key: value for key, value in os.environ.items()
                   if key in {'HOME', 'PATH', 'LANG', 'LC_ALL', 'TMPDIR'}}
    environment.update(LOCAL_ONLY)
    return subprocess.run(['git', *args], cwd=repo, capture_output=True, text=True, env=environment, timeout=30)


def local_commit(repo: Path, ref: str) -> str | None:
    if not lazy_fetch_suppressed(repo):
        return None
    try:
        result = _git(repo, 'rev-parse', '--verify', '--quiet', '--end-of-options', ref + '^{commit}')
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and FULL_SHA.fullmatch(value) else None


def ancestry(repo: Path, commit: str | None, baseline: str | None) -> str:
    """Position of `commit` relative to `baseline`: same, ancestor (older), descendant (newer), diverged, unknown."""
    if not isinstance(commit, str) or not isinstance(baseline, str) or not FULL_SHA.fullmatch(commit) \
            or not FULL_SHA.fullmatch(baseline):
        return 'unknown'
    if commit == baseline:
        return 'same'
    if not lazy_fetch_suppressed(repo):
        return 'unknown'  # A partial clone could fetch missing objects.
    try:
        for sha in (commit, baseline):
            if _git(repo, 'cat-file', '-e', sha + '^{commit}').returncode:
                return 'unknown'
        older = _git(repo, 'merge-base', '--is-ancestor', commit, baseline).returncode
        newer = _git(repo, 'merge-base', '--is-ancestor', baseline, commit).returncode
        shallow = _git(repo, 'rev-parse', '--is-shallow-repository').stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 'unknown'
    if older == 0:
        return 'ancestor'
    if newer == 0:
        return 'descendant'
    # Missing history cannot prove divergence.
    return 'diverged' if older == 1 and newer == 1 and shallow == 'false' else 'unknown'


def _digest(mapping: dict) -> str:
    return 'sha256:' + hashlib.sha256(json.dumps(mapping, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _check(result: str, reason: str | None = None, *, coverage: list[str], evidence: dict | None = None) -> dict:
    value = {'result': result, 'coverage': coverage, 'evidence': evidence or {}}
    if reason is not None:
        value['reason'] = reason
    return value


def _key_contract(data) -> tuple[set[str], set[str]]:
    # Same closed key-schema contract as configuration plan and apply.
    if not isinstance(data, dict) or set(data) not in ({'keys'}, {'keys', 'optional_keys'}):
        raise ContractError('key_schema_invalid')
    keys, optional = data.get('keys'), data.get('optional_keys', [])
    if (not isinstance(keys, list) or not isinstance(optional, list) or len(keys) != len(set(keys))
            or len(optional) != len(set(optional)) or not set(optional) <= set(keys)):
        raise ContractError('key_schema_invalid')
    return set(keys) - set(optional), set(keys)


@contextmanager
def release_source(repo: Path, adapter: dict, environment: str, target: str, source_sha: str):
    """The tracked configuration of one release source from local objects only, in private scratch."""
    with config_source(repo, adapter, environment, target, source_sha, local_only=True) as (root, sha):
        if sha != source_sha:
            raise ContractError('release_source_differs')
        yield root


def _kind(repo: Path, adapter: dict, environment: str) -> str | None:
    try:
        config = json.loads((project_dir(repo) / 'pz-release.json').read_text())
        names = [name for name, environments in config['kind_environments'].items()
                 if environment in environments and name in adapter['release_kinds']]
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    return names[0] if len(names) == 1 else None


def _unobserved(result: str, reason: str) -> dict:
    return {name: _check(result, reason, coverage=[]) for name in CHECKS}


def target_checks(repo: Path, adapter: dict, environment: str, target: str, *,
                  profile_root: Path | None, registry_auth=nullcontext) -> dict:
    """See _target_checks; provider tool caches go to private scratch removed on every path."""
    with tempfile.TemporaryDirectory(prefix='pz-observe-cache-') as cache:
        return _target_checks(repo, adapter, environment, target, profile_root=profile_root,
                              registry_auth=registry_auth, cache=Path(cache))


def _target_checks(repo: Path, adapter: dict, environment: str, target: str, *,
                   profile_root: Path | None, registry_auth, cache: Path) -> dict:
    """Four independent read-only checks of one target against its pinned current release.

    Each check reports its own result and coverage; they are never collapsed
    into one verdict. All of them bind to the same current manifest, and the
    current pointer is re-read after every other read. `private` carries the
    owned image observations for hotfix matching; it is never emitted.
    """
    report = {'environment': environment, 'target': target, 'observed_at': now(),
              'pointer_recheck': 'unknown', 'checks': _unobserved('unknown', 'not_observed'), 'private': {}}
    group = adapter.get('targets', {}).get(environment)
    item = group.get('items', {}).get(target) if isinstance(group, dict) else None
    if not isinstance(item, dict):
        report['checks'] = _unobserved('unknown', 'target_not_in_inventory')
        return report
    report['provider'] = item.get('provider')
    try:
        report['binding_sha256'] = binding_fingerprint(adapter, environment, target)
    except (KeyError, TypeError, ContractError):
        report['binding_sha256'] = 'unknown'
    if item.get('mode') != 'active':
        report['checks'] = _unobserved('unsupported', 'target_not_active')
        return report
    kind_name = _kind(repo, adapter, environment)
    if kind_name is None:
        report['checks'] = _unobserved('unknown', 'release_kind_ambiguous')
        return report
    try:
        provider = bind(repo, adapter, target, item, profile_root)
        provider.cache_dir = cache  # Kubernetes: kubectl --cache-dir and Helm homes; unused by Dokploy.
        provider.discover(binding_for(adapter, item))
    except (ContractError, OSError, KeyError, TypeError, ValueError) as exc:
        report['checks'] = _unobserved('unavailable', _reason(exc, 'provider_unavailable'))
        return report
    kind = release_kind(adapter, kind_name)
    mapping = image_variables(kind)
    checks = report['checks']

    # 1. Running release identity: the full status observation, status=ok.
    observed = identity(repo, adapter, environment, target, provider, registry_auth)
    reason = observed.get('reason')
    if observed['status'] == 'ok':
        checks['running_identity'] = _check('pass', coverage=['manifest', 'runtime_images', 'routed_content',
                                                              'current_pointer_recheck'],
                                            evidence={'status': 'ok', 'parity': observed.get('parity', {}),
                                                      'routed_content': observed.get('routed_content', {}).get('status')})
    else:
        result = ('differs' if reason in IDENTITY_DIFFERS else 'unavailable' if reason in IDENTITY_UNAVAILABLE
                  else 'unsupported' if reason == 'provider_capability_unsupported' else 'unknown')
        checks['running_identity'] = _check(result, reason if isinstance(reason, str) else 'release_identity_unavailable',
                                            coverage=['manifest', 'runtime_images'],
                                            evidence={'parity': observed.get('parity', {})})
    pointers = observed.get('pointers', {})
    report['pointers'] = {key: value for key, value in pointers.items() if isinstance(value, str)}
    digest = observed.get('manifest_digest')
    if not isinstance(digest, str):
        for name in CHECKS[1:]:
            checks[name] = _check('unknown', 'current_release_unavailable', coverage=[])
        return report
    report['manifest_digest'] = digest
    report['source_sha'] = observed.get('source_sha')
    try:
        with registry_auth():
            inspected = inspect(adapter, kind_name, release_reference=kind['manifest_package'] + '@' + digest)
        if not inspected['available']:
            raise ContractError('release_manifest_unavailable')
        manifest = inspected['manifest']
        expected = {key: manifest['images'][component] for key, component in mapping.items()}
    except (ContractError, OSError, KeyError, TypeError, ValueError) as exc:
        for name in CHECKS[1:]:
            checks[name] = _check('unavailable', _reason(exc, 'release_manifest_unavailable'), coverage=[])
        return report
    report['private']['expected_images'] = expected

    # The runtime image map is only needed to explain a difference (hotfix candidates).
    if checks['running_identity']['result'] == 'differs':
        try:
            runtime = provider.observed_image_refs(set(mapping))
            if isinstance(runtime, dict) and set(runtime) == set(mapping):
                report['private']['runtime_images'] = dict(runtime)
        except (ContractError, OSError, ValueError, KeyError, TypeError):
            pass

    # 2. Configured owned image identity: the saved settings the next deployment uses.
    try:
        configured = provider.readback()
        owned = {key: configured.get(key) for key in mapping}
        del configured  # Other settings are values this observation never keeps.
        differing = sorted(key for key, value in owned.items() if value != expected[key])
        report['private']['configured_images'] = {key: value for key, value in owned.items() if isinstance(value, str)}
        checks['configured_images'] = _check('differs' if differing else 'pass',
                                             'configured_image_differs' if differing else None,
                                             coverage=['owned_image_keys'],
                                             evidence={'keys': len(owned), 'differing_keys': differing,
                                                       'expected_sha256': _digest(expected),
                                                       'configured_sha256': _digest(owned)})
    except (ContractError, OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        checks['configured_images'] = _check('unavailable', _reason(exc, 'configured_images_unavailable'), coverage=[])

    # 3 and 4. The tracked definition and the required key names of the current release source.
    source = manifest.get('source_sha')
    try:
        with release_source(repo, adapter, environment, target, source) as root:
            configuration = provider.configuration
            definition_path = root / configuration.definition_path
            schema_path = root / configuration.settings_schema_path
            required, allowed = _key_contract(json.loads(schema_path.read_text()))
            renderer = configuration.render_definition
            definition = renderer(definition_path) if renderer is not None else definition_path.read_bytes()
    except (ContractError, OSError, ValueError, UnicodeError) as exc:
        reason = _reason(exc, 'release_source_unavailable')
        checks['definition'] = _check('unknown', reason, coverage=[])
        checks['required_keys'] = _check('unknown', reason, coverage=[])
    else:
        rendered = hashlib.sha256(definition).hexdigest()
        coverage = (['definition_bytes', 'named_volume_compatibility', 'key_names'] if item['provider'] == 'dokploy'
                    else ['owned_declarative_objects', 'preserved_defaults', 'image_placeholders', 'secret_key_names'])
        try:
            plan = provider.config_plan(definition, required, allowed)
            changed = plan.get('compose_changed', plan.get('definition_changed'))
            if not isinstance(changed, bool):
                raise ContractError('definition_comparison_unavailable')
            evidence = {'rendered_sha256': rendered}
            if isinstance(plan.get('current_compose_sha256'), str):
                evidence['observed_sha256'] = plan['current_compose_sha256']
            elif item['provider'] == 'kubernetes':
                evidence['observed_sha256'] = hashlib.sha256(provider.read_state().definition).hexdigest()
            planned = plan.get('desired_definition_sha256', plan.get('desired_compose_sha256'))
            if isinstance(planned, str):
                evidence['planned_sha256'] = planned
            checks['definition'] = _check('differs' if changed else 'pass',
                                          'definition_differs_from_current_release_source' if changed else None,
                                          coverage=coverage, evidence=evidence)
        except (ContractError, OSError, ValueError, KeyError, TypeError) as exc:
            # A guard refusal is never "no difference".
            checks['definition'] = _check('refused' if isinstance(exc, ContractError) else 'unknown',
                                          _reason(exc, 'definition_comparison_unavailable'), coverage=coverage)
        try:
            pulled = provider.config_pull()
            names = pulled.get('environment_keys', pulled.get('config_keys'))
            if not isinstance(names, list):
                raise ContractError('key_names_unavailable')
            missing = sorted(required - set(names))
            checks['required_keys'] = _check('differs' if missing else 'pass',
                                             'required_keys_missing' if missing else None,
                                             coverage=['key_names'], evidence={'required': len(required),
                                                                               'missing_keys': missing})
        except (ContractError, OSError, ValueError, KeyError, TypeError) as exc:
            checks['required_keys'] = _check('unavailable', _reason(exc, 'key_names_unavailable'), coverage=[])

    # Bind every observation to the same current release.
    try:
        with registry_auth():
            current = OrasRegistry().resolve(kind['manifest_package'] + ':' +
                                             kind['pointer_tags']['current'].format(target=target))
        report['pointer_recheck'] = 'stable' if current == pointers.get('current') else 'changed'
    except (ContractError, OSError, ValueError, KeyError, TypeError):
        report['pointer_recheck'] = 'unknown'
    if report['pointer_recheck'] != 'stable':
        for value in checks.values():
            if value['result'] == 'pass':
                value.update(result='unknown', reason='current_pointer_' + report['pointer_recheck'])
    return report

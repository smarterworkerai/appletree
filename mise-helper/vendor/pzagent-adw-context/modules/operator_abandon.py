"""Trusted retirement policy: locked tree transitions and validated recovery roots."""
from contextlib import ExitStack, nullcontext
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from itertools import islice

from .common import ContractError, project_dir
from .execution import human
from .operator_state import (OPERATION_ID, journals, locked, read, write_journal as write, timestamp,
                             resolved_scope, require_resumable, terminal)
from .operator_registry import read_manifest
from .release_manifest import release_kind, image_variables, validate

MAX_RECORDS = 2048
MAX_TREE = 64
MAX_BYTES = 1024 * 1024
RETIRE_REASONS = {'abandoned', 'superseded'}
WORKFLOWS = {'deploy-existing', 'publish', 'publish-deploy'}


def _record(path):
    # Check all parents below this repository's journal root before following a file.
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > MAX_BYTES:
                raise ContractError('retirement_journal_unsafe')
            raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ContractError('retirement_journal_unsafe')
            value = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise ContractError('retirement_journal_unavailable') from exc
    if not isinstance(value, dict) or value.get('schema_version') != '1.0.0':
        raise ContractError('retirement_journal_invalid')
    return value


def _inventory(root):
    records = {}
    if not root.exists():
        return records
    if root.is_symlink() or not root.is_dir():
        raise ContractError('retirement_journal_root_unsafe')
    if any(path.is_symlink() or (path.exists() and path.stat().st_mode & 0o077)
           for path in (root, *root.parents[:3])):
        raise ContractError('retirement_journal_root_unsafe')
    entries = list(islice(root.iterdir(), MAX_RECORDS + 1))
    if len(entries) > MAX_RECORDS:
        raise ContractError('retirement_inventory_unbounded')
    entries.sort()
    for entry in entries:
        if not OPERATION_ID.fullmatch(entry.name) or entry.is_symlink() or not entry.is_dir():
            continue
        for directory in (entry, entry / 'deployment'):
            if directory.is_symlink() or (directory.exists() and (not directory.is_dir() or directory.stat().st_mode & 0o077)):
                raise ContractError('retirement_journal_unsafe')
            for filename in ('operation.json', 'deployment.json'):
                path = directory / filename
                if path.exists() or path.is_symlink():
                    key = path.relative_to(root).as_posix()
                    try:
                        records[key] = _record(path)
                    except ContractError:
                        records[key] = None
                    if len(records) > MAX_RECORDS:
                        raise ContractError('retirement_inventory_unbounded')
    return records


def tree(root: Path, directory: Path):
    """Validate both directions of links; a child retirement includes its parent."""
    relative = directory.relative_to(root).as_posix()
    if len(Path(relative).parts) != 1 or not OPERATION_ID.fullmatch(relative):
        raise ContractError('retirement_operation_invalid')
    records = _inventory(root)
    links = {key: set() for key in records}
    for key, record in records.items():
        if record is None:
            continue
        parent = Path(key).parent
        children = []
        nested = (parent / 'deployment/operation.json').as_posix()
        if record.get('workflow') == 'publish-deploy' and nested in records:
            children.append(nested)
        child = record.get('deploy_operation')
        if child is not None:
            if not isinstance(child, str) or not OPERATION_ID.fullmatch(child):
                links[key].add('invalid-link')
            else:
                child_path = child + '/deployment.json'
                if child_path in records:
                    children.append(child_path)
        retirement = record.get('retirement')
        if isinstance(retirement, dict):
            members = retirement.get('members')
            if not isinstance(members, list) or len(members) > MAX_TREE:
                links[key].add('invalid-link')
            else:
                for member in members:
                    if not isinstance(member, str) or member not in records:
                        links[key].add('invalid-link')
                    else:
                        children.append(member)
        for child_key in children:
            links[key].add(child_key)
            links[child_key].add(key)
    seeds = [key for key in records if Path(key).parent.as_posix() == relative]
    if not seeds:
        raise ContractError('retirement_operation_unknown')
    selected, pending = set(), list(seeds)
    while pending:
        key = pending.pop()
        if key in selected:
            continue
        if key not in records or records[key] is None:
            raise ContractError('retirement_tree_invalid')
        selected.add(key)
        if len(selected) > MAX_TREE:
            raise ContractError('retirement_tree_unbounded')
        pending.extend(links[key] - selected)
    return {key: records[key] for key in sorted(selected)}


def ensure_resumable(repo, directory, home=None):
    """A pending/retired parent also blocks directly addressed child resumes."""
    if not (project_dir(repo) / 'pzagent-adapter.json').is_file():
        return
    root = journals(repo, home)
    directory = directory.resolve()
    root = root.resolve()
    if root == directory or root not in directory.parents:
        return  # Legacy/internal directories retain their direct record guard.
    top = root / directory.relative_to(root).parts[0]
    try:
        records = tree(root, top)
    except ContractError as exc:
        if str(exc) == 'retirement_operation_unknown':
            return
        raise
    for record in records.values():
        require_resumable(record)
        if record.get('retirement_pending'):
            raise ContractError('operation_retirement_pending')


def classification(records):
    """Conservative trusted write policy; never infer no-write from child selected."""
    outcomes = []
    publication = 'none'
    for key, record in records.items():
        phase = (record.get('retirement') or {}).get('original_phase', record.get('phase'))
        workflow = record.get('workflow')
        results = record.get('results', {})
        if not isinstance(results, dict):
            outcomes.append('unknown')
            continue
        if Path(key).name == 'deployment.json':
            outcomes.append('possible' if phase in {'selected', 'configured', 'runtime-requested',
                'runtime-confirmed', 'pointers', 'complete', 'restored', 'restore-configured',
                'restore-runtime-requested', 'restore-runtime-confirmed', 'restore-empty-requested'} else 'unknown')
        elif workflow == 'deploy-existing':
            if (not set(results) <= {'config-plan', 'config-apply', 'deploy', 'validate'}
                    or (record.get('guarded_config') is True and ('config-apply' in results or phase == 'config-apply'))):
                outcomes.append('unknown')
            elif 'config-apply' in results or phase == 'config-apply' or 'deploy' in results:
                outcomes.append('possible')
            elif phase in {'selected', 'config-plan'} and set(results) <= {'config-plan'}:
                outcomes.append('none')
            elif record.get('guarded_config') is True and phase == 'deploy' and record.get('deploy_operation'):
                outcomes.append('none')  # Any child write requires its own durable journal.
            else:
                outcomes.append('unknown')
        elif workflow in {'publish', 'publish-deploy'}:
            if phase in {'selected', 'build', 'package'} and 'publish' not in results:
                outcomes.append('none')
            else:
                publication = 'possible'
                outcomes.append('none' if workflow == 'publish' or phase == 'deploy' else 'unknown')
        else:
            outcomes.append('unknown')
    value = 'unknown' if 'unknown' in outcomes else 'possible' if 'possible' in outcomes else 'none'
    return {'classification': value, 'publication': publication}


def _scope(adapter, records):
    scopes = [record.get('scope') for record in records.values()]
    if any(not isinstance(scope, dict) for scope in scopes):
        return None
    deployed = [scope for scope in scopes if scope.get('environment')]
    if not deployed:
        return None
    scope = deployed[0]
    try:
        expected = resolved_scope(adapter, scope['release_kind'], scope['environment'], scope['target'])
    except (KeyError, ContractError):
        return None
    if scope != expected or any(value != scope for value in deployed):
        return None
    if any(value.get('repository') != scope['repository'] or value.get('release_kind') != scope['release_kind'] for value in scopes):
        return None
    return scope


def validate_observations(observation, adapter, scope, manifest):
    """Own sufficiency: verify scope, manifest identities and required evidence coverage."""
    if not isinstance(observation, dict) or observation.get('pointer_recheck') != 'stable':
        return False
    if any(observation.get(key) != scope.get(key) for key in ('environment', 'target', 'provider', 'binding_sha256')):
        return False
    digest = observation.get('manifest_digest')
    if (not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest)
            or observation.get('pointers', {}).get('current') != digest
            or observation.get('source_sha') != manifest['source_sha']):
        return False
    checks = observation.get('checks')
    if not isinstance(checks, dict):
        return False
    for key in ('running_identity', 'configured_images', 'definition', 'required_keys'):
        value = checks.get(key)
        if not isinstance(value, dict) or value.get('result') != 'pass' or not value.get('coverage'):
            return False
    running = checks['running_identity'].get('evidence', {})
    if (running.get('status') != 'ok' or running.get('parity') != {'manifest_current': True, 'runtime_manifest': True}
            or running.get('routed_content') not in {'passed', 'disabled'}
            or not {'manifest', 'runtime_images', 'routed_content', 'current_pointer_recheck'} <= set(checks['running_identity']['coverage'])):
        return False
    kind = release_kind(adapter, scope['release_kind'])
    expected = {key: manifest['images'][component] for key, component in image_variables(kind).items()}
    image_digest = 'sha256:' + hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    images = checks['configured_images'].get('evidence', {})
    if (images.get('expected_sha256') != image_digest or images.get('configured_sha256') != image_digest
            or images.get('keys') != len(expected) or images.get('differing_keys') != []
            or 'owned_image_keys' not in checks['configured_images']['coverage']):
        return False
    definition = checks['definition'].get('evidence', {})
    planned = definition.get('planned_sha256')
    if (not isinstance(planned, str) or not re.fullmatch(r'[0-9a-f]{64}', planned)
            or definition.get('observed_sha256') != planned):
        return False
    coverage = ({'definition_bytes', 'named_volume_compatibility', 'key_names'} if scope['provider'] == 'dokploy'
                else {'owned_declarative_objects', 'preserved_defaults', 'image_placeholders', 'secret_key_names'})
    if not coverage <= set(checks['definition']['coverage']):
        return False
    keys = checks['required_keys'].get('evidence', {})
    if (type(keys.get('required')) is not int or not 0 <= keys['required'] <= 4096
            or keys.get('missing_keys') != [] or 'key_names' not in checks['required_keys']['coverage']):
        return False
    return True


def guard(repo, adapter, records, *, profile_root, registry_auth, target_retired=False):
    writes = classification(records)
    scope = _scope(adapter, records)
    if target_retired:
        if scope is None:
            raise ContractError('retirement_target_unproven')
        if adapter['targets'][scope['environment']]['items'][scope['target']].get('mode') == 'active':
            raise ContractError('retirement_target_still_active')
    if writes == {'classification': 'none', 'publication': 'none'}:
        return {'reconciled': True, 'basis': 'no-write', 'observed_at': timestamp()}
    if scope is None:
        return {'reconciled': False, 'basis': 'scope-unknown', 'observed_at': timestamp()}
    item = adapter['targets'][scope['environment']]['items'][scope['target']]
    if target_retired:
        if item.get('mode') == 'active':
            raise ContractError('retirement_target_still_active')
        if writes['publication'] != 'none':
            return {'reconciled': False, 'basis': 'publication-unknown', 'observed_at': timestamp()}
        return {'reconciled': True, 'basis': 'decommissioned', 'observed_at': timestamp(),
                'binding_sha256': scope['binding_sha256']}
    if item.get('mode') != 'active':
        return {'reconciled': False, 'basis': 'target-inactive', 'observed_at': timestamp()}
    try:
        from .workflow_observation import target_checks
        observation = target_checks(repo, adapter, scope['environment'], scope['target'],
                                   profile_root=profile_root, registry_auth=registry_auth or nullcontext)
    except (ContractError, OSError, KeyError, ValueError, TypeError, ImportError):
        observation = {}
    if not isinstance(observation, dict):
        observation = {}
    covered = False
    try:
        digest = observation.get('manifest_digest')
        if not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ContractError('retirement_current_manifest_unknown')
        kind = release_kind(adapter, scope['release_kind'])
        with (registry_auth() if registry_auth else nullcontext()):
            manifest = validate(read_manifest(kind['manifest_package'] + '@' + digest), adapter, scope['release_kind'])
        covered = validate_observations(observation, adapter, scope, manifest)
    except (ContractError, OSError, KeyError, ValueError, TypeError):
        covered = False
    # All-pass target parity cannot certify unknown historical effects. Only
    # the bounded new deployment intent is covered by these four observations.
    effects_known = _covered_effects(records)
    evidence = {}
    checks = observation.get('checks')
    for check_name, check in (checks.items() if isinstance(checks, dict) else []):
        if check_name not in {'running_identity', 'configured_images', 'definition', 'required_keys'} or not isinstance(check, dict):
            continue
        evidence[check_name] = {'result': check.get('result') if check.get('result') in {
            'pass', 'differs', 'unknown', 'unavailable', 'unsupported', 'refused'} else 'unknown'}
        facts = check.get('evidence')
        for name, value in (facts.items() if isinstance(facts, dict) else []):
            if name.endswith('_sha256') and isinstance(value, str) and re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', value):
                evidence[check_name][name] = value
    digest = observation.get('manifest_digest')
    if isinstance(digest, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        evidence['manifest_digest'] = digest
    source = observation.get('source_sha')
    if isinstance(source, str) and re.fullmatch(r'[0-9a-f]{40}', source):
        evidence['source_short'] = source[:12]
    return {'reconciled': bool(covered and effects_known),
            'basis': 'covered-config' if covered and effects_known else 'unproven-effects' if covered else 'checks-incomplete',
            'observed_at': timestamp(), 'binding_sha256': scope['binding_sha256'], 'evidence': evidence}


def _covered_effects(records):
    writes = classification(records)
    effects_known = writes['classification'] == 'possible' and writes['publication'] == 'none'
    for key, record in records.items():
        if Path(key).name == 'deployment.json':
            phase = (record.get('retirement') or {}).get('original_phase', record.get('phase'))
            effects_known = effects_known and record.get('write_intent') == {
                'provider_configuration': True, 'owned_images': True} and phase in {
                    'selected', 'configured', 'runtime-requested', 'runtime-confirmed', 'complete'}
            # complete is saved only after every pointer set passes final readback.
            # An interrupted pointers/restore stage has no such completion proof.
        elif record.get('workflow') == 'deploy-existing':
            effects_known = effects_known and record.get('guarded_config') is True
        else:
            effects_known = False
    return effects_known


def _time(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed if parsed.tzinfo is not None else None
    except (ValueError, TypeError, AttributeError):
        return None


def _supersedes(adapter, records, newer):
    if (classification(records) != {'classification': 'none', 'publication': 'none'}
            and not _covered_effects(records)):
        return False
    old_scope = _scope(adapter, records)
    new_scope = _scope(adapter, newer)
    if old_scope is None or old_scope != new_scope:
        return False
    old_dates = [_time(record.get('created_at')) for record in records.values()]
    parents = [record for record in newer.values() if record.get('workflow') in {'deploy-existing', 'publish-deploy'}]
    return bool(old_dates and all(old_dates) and parents and all(
        record.get('status') == 'ok' and record.get('phase') == 'complete'
        and _time(record.get('created_at')) is not None
        and _time(record['created_at']) > max(old_dates) for record in parents)
        and all(terminal(record) for record in newer.values()))


def _current_superseder(repo, adapter, newer, *, profile_root, registry_auth):
    """A completed journal alone cannot prove what the target runs now."""
    scope = _scope(adapter, newer)
    if scope is None:
        return False
    try:
        from .workflow_observation import target_checks
        observation = target_checks(repo, adapter, scope['environment'], scope['target'],
                                   profile_root=profile_root, registry_auth=registry_auth or nullcontext)
        digest = observation.get('manifest_digest')
        if not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            return False
        kind = release_kind(adapter, scope['release_kind'])
        reference = kind['manifest_package'] + '@' + digest
        with (registry_auth() if registry_auth else nullcontext()):
            manifest = validate(read_manifest(reference), adapter, scope['release_kind'])
        parents = [record for record in newer.values()
                   if record.get('workflow') in {'deploy-existing', 'publish-deploy'}]
        return bool(parents and all(record.get('release_reference') == reference
                    and record.get('source_sha') == manifest['source_sha'] for record in parents)
                    and validate_observations(observation, adapter, scope, manifest))
    except (ContractError, OSError, KeyError, ValueError, TypeError, AttributeError, ImportError):
        return False


def _reason(text):
    if not isinstance(text, str) or not text.strip() or len(text) > 240:
        raise ContractError('retirement_reason_required_bounded')
    safe = ' '.join(text.split())
    for name, value in os.environ.items():
        if len(value) >= 4 and any(word in name.upper() for word in ('TOKEN', 'SECRET', 'PASSWORD', 'KEY', 'URL', 'HOST')):
            safe = safe.replace(value, '[redacted]')
    safe = re.sub(r'\S*(?:https?://|@|\d+\.\d+\.\d+\.\d+|[A-Za-z0-9-]+\.[A-Za-z]{2,})\S*', '[redacted]', safe)
    safe = re.sub(r'\S{32,}', '[redacted]', safe)
    return safe[:240]


def retirement_releases(root, path, record):
    """Retention revalidates every member and shared receipt before dropping roots."""
    decision = record.get('retirement')
    if not isinstance(decision, dict) or record.get('needs_reconcile') is not False:
        return False
    members = decision.get('members')
    if not isinstance(members, list) or not members or len(members) > MAX_TREE:
        return False
    try:
        first = Path(members[0]).parts[0]
        if not OPERATION_ID.fullmatch(first):
            return False
        records = tree(root, root / first)
    except (ContractError, ValueError, IndexError):
        return False
    if sorted(records) != members or path.relative_to(root).as_posix() not in records:
        return False
    guard_result = decision.get('guard')
    if not isinstance(guard_result, dict) or not re.fullmatch(r'[0-9a-f]{64}', str(decision.get('transaction'))):
        return False
    if guard_result.get('reconciled') is not True or guard_result.get('basis') not in {'no-write', 'covered-config', 'decommissioned'}:
        return False
    transaction = hashlib.sha256(json.dumps({'members': members, 'guard': guard_result}, sort_keys=True).encode()).hexdigest()
    if decision['transaction'] != transaction:
        return False
    if not _time(guard_result.get('observed_at')):
        return False
    if guard_result.get('basis') == 'no-write' and classification(records) != {'classification': 'none', 'publication': 'none'}:
        return False
    if guard_result.get('basis') == 'covered-config':
        if not _covered_effects(records):
            return False
        evidence = guard_result.get('evidence', {})
        if not isinstance(evidence, dict) or any(not isinstance(evidence.get(name), dict)
                or evidence[name].get('result') != 'pass' for name in (
                'running_identity', 'configured_images', 'definition', 'required_keys')):
            return False
        for name, left, right in (('configured_images', 'expected_sha256', 'configured_sha256'),
                                   ('definition', 'planned_sha256', 'observed_sha256')):
            value = evidence[name].get(left)
            if (not isinstance(value, str) or not re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', value)
                    or evidence[name].get(right) != value):
                return False
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', str(evidence.get('manifest_digest'))):
            return False
    if guard_result.get('basis') != 'no-write':
        binding = guard_result.get('binding_sha256')
        if not isinstance(binding, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', binding):
            return False
        scopes = [value.get('scope', {}) for value in records.values()]
        if any(value.get('environment') and value.get('binding_sha256') != binding for value in scopes):
            return False
    for value in records.values():
        receipt = value.get('retirement')
        if (value.get('phase') != 'cancelled' or value.get('status') != 'cancelled'
                or value.get('reason_code') not in RETIRE_REASONS or value.get('needs_reconcile') is not False
                or value.get('retirement_pending') or not isinstance(receipt, dict)
                or any(receipt.get(key) != decision.get(key) for key in ('transaction', 'members', 'guard'))):
            return False
    return True


def abandon(repo, adapter, args, *, registry_auth=None):
    if not human():
        raise ContractError('workflow_abandon_human_only')
    reason = _reason(args.reason)
    root = journals(repo, getattr(args, 'operator_home', None))
    selected = tree(root, args.operation_dir)
    if any(Path(key).name != 'deployment.json' and record.get('workflow') not in WORKFLOWS
           for key, record in selected.items()):
        raise ContractError('retirement_workflow_unsupported')
    extra = None
    if args.superseded_by:
        if not OPERATION_ID.fullmatch(args.superseded_by):
            raise ContractError('retirement_superseder_invalid')
        extra = tree(root, root / args.superseded_by)
        if set(extra) & set(selected):
            raise ContractError('retirement_superseder_invalid')
    with ExitStack() as locks:
        directories = {str((root / key).parent) for key in [*selected, *(extra or {})]}
        for directory in sorted(directories):
            locks.enter_context(locked(Path(directory)))
        if tree(root, args.operation_dir) != selected:
            raise ContractError('retirement_tree_changed')
        if extra is not None:
            current = tree(root, root / args.superseded_by)
            if (current != extra or not _supersedes(adapter, selected, current)
                    or not _current_superseder(repo, adapter, current, profile_root=args.profile_root,
                                               registry_auth=registry_auth)):
                raise ContractError('retirement_superseder_unproven')
        if all(record.get('phase') == 'complete' and (
                Path(key).name == 'deployment.json' or record.get('status') == 'ok')
                for key, record in selected.items()):
            raise ContractError('retirement_operation_already_complete')
        result = guard(repo, adapter, selected, profile_root=args.profile_root,
                       registry_auth=registry_auth, target_retired=args.target_retired)
        if extra is not None:
            expected = {record['release_reference'].rsplit('@', 1)[-1] for record in extra.values()
                        if record.get('workflow') in {'deploy-existing', 'publish-deploy'}}
            if (not result['reconciled'] or (result['basis'] == 'covered-config'
                    and result.get('evidence', {}).get('manifest_digest') not in expected)):
                raise ContractError('retirement_superseder_unproven')
        if not result['reconciled'] and not args.acknowledge_unreconciled:
            raise ContractError('retirement_requires_reconciliation: run pz:workflow:doctor')
        members = sorted(selected)
        transaction = hashlib.sha256(json.dumps({'members': members, 'guard': result}, sort_keys=True).encode()).hexdigest()
        audit = {'reason': reason, 'operator_sha256': hashlib.sha256(('uid:' + str(os.getuid())).encode()).hexdigest(),
                 'recorded_at': timestamp()}
        # Persist intent on the root first. Resume checks the whole connected
        # tree, so a crash cannot expose a still-resumable sibling.
        for key, record in selected.items():
            previous = record.get('retirement') or {}
            original = previous.get('original_phase', record.get('phase'))
            history = previous.get('previous_audits', [])
            history = history[-14:] if isinstance(history, list) else []
            if isinstance(previous.get('audit'), dict):
                history = [*history, previous['audit']]
            record['retirement'] = {'transaction': transaction, 'members': members,
                                    'guard': result, 'original_phase': original, 'audit': audit,
                                    'previous_audits': history}
            record['retirement_pending'] = True
            write(root / key, record)
        for key, record in reversed(list(selected.items())):
            record.update(phase='cancelled', status='cancelled', reason_code='superseded' if extra else 'abandoned',
                          needs_reconcile=not result['reconciled'], retirement_pending=False)
            if extra:
                record['superseded_by'] = args.superseded_by
            else:
                record.pop('superseded_by', None)
            write(root / key, record)
    return {'status': 'ok', 'operation': args.operation_dir.name, 'phase': 'cancelled',
            'reason_code': 'superseded' if extra else 'abandoned', 'needs_reconcile': not result['reconciled'],
            'finding': result['basis'], 'observed_at': result['observed_at'], 'journal_count': len(selected)}

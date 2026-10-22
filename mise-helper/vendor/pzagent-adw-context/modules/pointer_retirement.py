"""Trusted, operator-only retirement of absent targets using owned OCI tombstones.

Only this operation's non-runnable placeholder versions may be deleted. Former
release versions are never deletion candidates, even when they become untagged.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
from urllib.parse import quote

from .common import ContractError, IDENTIFIER
from .execution import human
from .operator_github import api, pages
from .operator_registry import oras, read_manifest
from .operator_retention import _active_operation_roots
from .operator_state import locked, read, write
from .oras_registry import OrasRegistry
from .release_manifest import release_kind, validate
from .retention import Version, candidates
from .dokploy_lifecycle_api import API, HTTP, Missing
from .providers.dokploy import profile_credentials

DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
REMOTE_ID = re.compile(r'^[A-Za-z0-9_-]{1,128}$')
NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 _-]{0,126}$')
APP_NAME = re.compile(r'^[a-zA-Z0-9._-]{1,128}$')
ARTIFACT = 'application/vnd.adw.retired-pointer.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def _digest(value):
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def _operator():
    if not human():
        raise ContractError('pointer_retirement_operator_only')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', os.environ.get('ADW_RUN_ID', 'operator')):
        raise ContractError('pointer_retirement_run_id_invalid')


def _private(repo, profile, operation):
    if profile is None:
        raise ContractError('pointer_retirement_private_profile_required')
    profile = profile.absolute()
    if (any(p.is_symlink() for p in (profile, *profile.parents))
            or profile.resolve() == repo.resolve() or repo.resolve() in profile.resolve().parents
            or (profile.exists() and (not profile.is_dir() or profile.stat().st_mode & 0o077))):
        raise ContractError('pointer_retirement_private_profile_invalid')
    profile.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = hashlib.sha256(_bytes({'repository_path': str(repo.resolve()),
                                'operation_path': str(operation.resolve())})).hexdigest()
    path = profile / 'provider-operations' / key / 'operation.json'
    if any(p.is_symlink() for p in (path, path.parent, path.parent.parent)):
        raise ContractError('pointer_retirement_private_profile_invalid')
    return path


def _read_private(path):
    if (path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077
            or path.stat().st_size > 1024 * 1024):
        raise ContractError('pointer_retirement_private_journal_invalid')
    return read(path)


def _rows(value):
    if not isinstance(value, list) or len(value) > 4096 or any(not isinstance(x, dict) for x in value):
        raise ContractError('pointer_retirement_observation_invalid')
    return value


def absence(repo, adapter, profile, operation, target, provider=None):
    """Independently validate ownership scope and fresh raw provider absence."""
    state = _read_private(_private(repo, profile, operation))
    selection = state.get('selection', {})
    binding = selection.get('binding', {})
    if (state.get('workflow') != 'provider-provision' or state.get('phase') != 'complete'
            or state.get('decommission', {}).get('phase') != 'complete'
            or selection.get('repository') != adapter['repository']['id']
            or selection.get('target') != target or not re.fullmatch(r'[0-9a-f]{32}', state.get('nonce', ''))
            or any(not isinstance(binding.get(k), str) or not NAME.fullmatch(binding[k])
                   for k in ('project', 'environment', 'resource'))):
        raise ContractError('pointer_retirement_decommission_unproven')
    for group in adapter['targets'].values():
        if target in group['items']:
            raise ContractError('pointer_retirement_target_still_declared')
        for declaration in group['items'].values():
            if declaration['provider'] == 'dokploy':
                other = adapter['providers']['dokploy']['bindings'][declaration['provider_binding']]
                if all(other.get(k) == binding[k] for k in ('project', 'environment', 'resource')):
                    raise ContractError('pointer_retirement_binding_still_declared')
    resources = state.get('resources', {})
    if not isinstance(resources, dict) or not {'project', 'environment', 'compose'} <= set(resources) or set(resources) - {'project', 'environment', 'default_environment', 'compose'}:
        raise ContractError('pointer_retirement_ownership_invalid')
    for role, entry in resources.items():
        if (not isinstance(entry, dict) or not isinstance(entry.get('created'), bool)
                or not isinstance(entry.get('id'), str) or not REMOTE_ID.fullmatch(entry['id'])
                or (entry['created'] and entry.get('deleted') is not True)):
            raise ContractError('pointer_retirement_ownership_invalid')
    project, environment, compose = (resources[k] for k in ('project', 'environment', 'compose'))
    if (not compose['created'] or compose.get('parent') != environment['id']
            or environment.get('parent') != project['id']
            or compose.get('name') != binding['resource'] or environment.get('name') != binding['environment']
            or project.get('name') != binding['project']
            or not isinstance(compose.get('app_name'), str) or not APP_NAME.fullmatch(compose['app_name'])
            or not isinstance(compose.get('server_id'), str) or not REMOTE_ID.fullmatch(compose['server_id'])
            or compose['server_id'] != state.get('server_id')):
        raise ContractError('pointer_retirement_ownership_invalid')
    if provider is None:
        endpoint, credential = profile_credentials(profile)
        provider = API(HTTP(endpoint, credential))
    provider.validate()  # Compatibility refusal only; never an absence decision.
    # Refuse recreation of the logical resource under a new remote ID as well.
    for project_row in _rows(provider.projects()):
        if project_row.get('name') != binding['project']:
            continue
        project_id = project_row.get('projectId')
        if not isinstance(project_id, str) or not REMOTE_ID.fullmatch(project_id):
            raise ContractError('pointer_retirement_observation_invalid')
        for env_row in _rows(provider.environments(project_id)):
            if env_row.get('name') != binding['environment']:
                continue
            env_id = env_row.get('environmentId')
            if not isinstance(env_id, str) or not REMOTE_ID.fullmatch(env_id) or env_row.get('projectId') != project_id:
                raise ContractError('pointer_retirement_observation_invalid')
            if any(row.get('name') == binding['resource'] for row in _rows(provider.composes(env_id))):
                raise ContractError('pointer_retirement_resource_recreated')
    # An HTTP 404 is scoped to the journaled resource; an empty inventory is
    # scoped independently to the saved runtime label and registered server.
    for role, entry in resources.items():
        if not entry['created']:
            continue
        try:
            if role == 'compose':
                observed = provider.compose(entry['id'])
            elif role == 'project':
                observed = provider.project(entry['id'])
            else:
                observed = provider.environment(entry['id'])
        except Missing:
            observed = None
        else:
            # Even null/malformed success responses cannot prove absence.
            raise ContractError('pointer_retirement_resource_still_present')
    containers = provider.containers(compose['app_name'], compose['server_id'])
    if not isinstance(containers, list) or containers != []:
        raise ContractError('pointer_retirement_runtime_still_present')
    return _digest(_bytes(state))


def _packages(adapter, kind):
    owner = adapter['repository']['id'].split('/')[0]
    result = [kind['manifest_package'], *(c['package'] for c in kind['components'].values())]
    if len(set(result)) != len(result) or any(not p.startswith('ghcr.io/' + owner.lower() + '/') for p in result):
        raise ContractError('pointer_retirement_package_scope_invalid')
    return owner, result


def _placeholder(plan, package):
    return _bytes({'schemaVersion': 2, 'mediaType': MANIFEST, 'artifactType': ARTIFACT,
                   'config': {'mediaType': 'application/vnd.oci.empty.v1+json',
                              'digest': _digest(b'{}'), 'size': 2}, 'layers': [],
                   'annotations': {'org.adw.retirement.operation': plan['nonce'],
                                   'org.adw.retirement.binding': _digest(_bytes(plan['selection'])),
                                   'org.adw.retirement.package': package}})


def inventory(repo, adapter, kind_name, plan=None):
    """Validate complete release graph, admitting only exact owned placeholders."""
    kind = release_kind(adapter, kind_name)
    owner, packages = _packages(adapter, kind)
    identity = api('GET', '/users/' + quote(owner))
    if not isinstance(identity, dict) or identity.get('type') not in {'Organization', 'User'}:
        raise ContractError('pointer_retirement_owner_invalid')
    scope = '/orgs/' if identity['type'] == 'Organization' else '/users/'
    versions, locations, roots = [], {}, set()
    owned = {package + '@' + _digest(_placeholder(plan, package)): package for package in packages} if plan else {}
    for package in packages:
        route = scope + quote(owner) + '/packages/container/' + quote(package.split('/', 2)[2], safe='') + '/versions'
        for row in pages(route):
            try:
                digest, tags, number = row['name'], row['metadata']['container']['tags'], row['id']
                created = datetime.fromisoformat(row['created_at'].replace('Z', '+00:00')).timestamp()
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise ContractError('pointer_retirement_inventory_invalid') from exc
            if (not isinstance(digest, str) or not DIGEST.fullmatch(digest)
                    or not isinstance(tags, list) or any(not isinstance(t, str) or not t or len(t) > 128 for t in tags)
                    or len(set(tags)) != len(tags) or type(number) is not int or number <= 0):
                raise ContractError('pointer_retirement_inventory_invalid')
            identifier = package + '@' + digest
            if identifier in locations:
                raise ContractError('pointer_retirement_inventory_duplicate')
            refs = ()
            if identifier in owned:
                expected = _placeholder(plan, package)
                raw = oras('manifest', 'fetch', identifier, binary=True)
                allowed = {x['tag'] for x in plan['positions'] if x['package'] == package and x['old'] is not None}
                if raw != expected or _digest(raw) != digest or not set(tags) <= allowed:
                    raise ContractError('pointer_retirement_placeholder_foreign')
            elif package == kind['manifest_package']:
                manifest = validate(read_manifest(identifier), adapter, kind_name)
                refs = tuple(manifest['images'].values())
            if identifier not in owned and any(not re.fullmatch(r'(?:sha-[0-9a-f]{12}|upload-[0-9a-f]{32}|hotfix-[0-9a-f]{12}(?:-[0-9a-f]{12})?)', t) for t in tags):
                roots.add(identifier)
            versions.append(Version(identifier, created, tuple(tags), refs))
            locations[identifier] = route + '/' + str(number)
    for branch in adapter['repository']['protected_branches']:
        head = api('GET', '/repos/' + adapter['repository']['id'] + '/git/ref/heads/' + quote(branch, safe=''))
        sha = head.get('object', {}).get('sha', '') if isinstance(head, dict) else ''
        if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{40}', sha):
            raise ContractError('pointer_retirement_protected_head_invalid')
        roots.update(v.identifier for v in versions if 'sha-' + sha[:12] in v.tags)
    roots.update(_active_operation_roots(repo, kind_name, versions))
    if any(not set(version.references) <= set(locations) for version in versions):
        raise ContractError('pointer_retirement_reference_graph_incomplete')
    candidates(versions, roots, now=float('inf'), grace_hours=1)
    # A real manifest must never acquire a reference to any owned tombstone.
    if any(set(v.references) & set(owned) for v in versions):
        raise ContractError('pointer_retirement_placeholder_referenced')
    return versions, roots, locations


def orphans(repo, adapter, kind_name):
    """Read-only report; orphan status never grants deletion eligibility."""
    kind = release_kind(adapter, kind_name)
    versions, _, _ = inventory(repo, adapter, kind_name)
    declared = {name for group in adapter['targets'].values() for name in group['items']}
    found = {}
    for position, template in kind['pointer_tags'].items():
        pattern = re.compile('^' + re.escape(template).replace(r'\{target\}', r'([a-z][a-z0-9-]*)') + '$')
        for version in versions:
            for tag in version.tags:
                match = pattern.fullmatch(tag)
                if match and match[1] not in declared:
                    found.setdefault(match[1], set()).add(version.identifier.split('@')[0] + ':' + position)
    return {'status': 'ok', 'kind': kind_name, 'task': 'pz:release:pointers:orphans',
            'orphans': [{'target': target, 'pointer_count': len(found[target])} for target in sorted(found)],
            'mutations_requested': 0}


def _receipt(plan):
    return {'status': 'ok', 'task': 'pz:release:pointers:retire', 'phase': plan['phase'],
            'kind': plan['selection']['kind'], 'target': plan['selection']['target'],
            'operation_digest': plan['operation_digest'], 'pointer_count': sum(x['old'] is not None for x in plan['positions']),
            'deleted_placeholder_count': len(plan['deleted']), 'former_releases_preserved': True}


def _check_positions(plan, registry):
    for item in plan['positions']:
        live = registry.resolve(item['package'] + ':' + item['tag'])
        placeholder = _digest(_placeholder(plan, item['package']))
        allowed = {item['old'], placeholder} if item['old'] is not None else {None}
        if item['package'] in plan['deleted']:
            allowed = {None}
        if live not in allowed:
            raise ContractError('pointer_retirement_pointer_changed')


def _reconcile_deleted(plan, registry, private):
    for package, location in plan['deleting'].items():
        if package in plan['deleted']:
            continue
        try:
            api('GET', location)
        except ContractError as exc:
            if str(exc) != 'GitHub operation rejected (HTTP 404)':
                raise
        else:
            raise ContractError('pointer_retirement_delete_outcome_unproven')
        if registry.resolve(package + '@' + _digest(_placeholder(plan, package))) is not None:
            raise ContractError('pointer_retirement_delete_readback_invalid')
        if any(registry.resolve(package + ':' + x['tag']) is not None for x in plan['positions'] if x['package'] == package):
            raise ContractError('pointer_retirement_delete_readback_invalid')
        plan['deleted'].append(package)
        write(private, plan)


def retire(repo, adapter, *, kind_name, target, profile_root, operation_dir,
           deprovision_operation_dir, apply=False, approve_operation_digest=None,
           provider=None, registry=None):
    _operator()
    if not isinstance(target, str) or not IDENTIFIER.fullmatch(target):
        raise ContractError('pointer_retirement_target_invalid')
    kind = release_kind(adapter, kind_name)
    _, packages = _packages(adapter, kind)
    private = _private(repo, profile_root, operation_dir)
    decommission = _private(repo, profile_root, deprovision_operation_dir)
    if private == decommission:
        raise ContractError('pointer_retirement_requires_separate_operation')
    registry = registry or OrasRegistry()
    with locked(private.parent), locked(decommission.parent):
        proof = absence(repo, adapter, profile_root, deprovision_operation_dir, target, provider)
        selection = {'repository': adapter['repository']['id'], 'kind': kind_name,
                     'target': target, 'decommission_sha256': proof, 'packages': packages,
                     'pointer_tags': kind['pointer_tags']}
        if private.exists():
            plan = _read_private(private)
            if plan.get('workflow') != 'pointer-retirement' or plan.get('selection') != selection:
                raise ContractError('pointer_retirement_selection_changed')
        else:
            if apply:
                raise ContractError('pointer_retirement_plan_required')
            versions, _, _ = inventory(repo, adapter, kind_name)
            known = {v.identifier for v in versions}
            positions = []
            for position, template in kind['pointer_tags'].items():
                tag = template.format(target=target)
                manifest_digest = registry.resolve(kind['manifest_package'] + ':' + tag)
                manifest = (validate(read_manifest(kind['manifest_package'] + '@' + manifest_digest), adapter, kind_name)
                            if manifest_digest is not None else None)
                for package in packages:
                    old = registry.resolve(package + ':' + tag)
                    expected = (manifest_digest if package == kind['manifest_package'] else
                                next((ref.split('@')[1] for ref in manifest['images'].values() if ref.startswith(package + '@')), None)) if manifest else None
                    if old != expected or (old is not None and package + '@' + old not in known):
                        raise ContractError('pointer_retirement_pointer_graph_invalid')
                    positions.append({'package': package, 'tag': tag, 'old': old})
            plan = {'schema_version': '1.0.0', 'workflow': 'pointer-retirement', 'selection': selection,
                    'nonce': secrets.token_hex(16), 'positions': positions, 'phase': 'planned',
                    'uploaded': [], 'moved': [], 'deleting': {}, 'deleted': []}
            plan['operation_digest'] = _digest(_bytes({k: plan[k] for k in ('selection', 'nonce', 'positions')}))
            write(private, plan)
        if plan.get('operation_digest') != _digest(_bytes({k: plan[k] for k in ('selection', 'nonce', 'positions')})):
            raise ContractError('pointer_retirement_plan_invalid')
        if not apply:
            return _receipt(plan)
        if approve_operation_digest != plan['operation_digest']:
            raise ContractError('pointer_retirement_operation_approval_required')
        _reconcile_deleted(plan, registry, private)
        _check_positions(plan, registry)
        plan['phase'] = 'applying'
        write(private, plan)
        for package in packages:
            positions = [x for x in plan['positions'] if x['package'] == package and x['old'] is not None]
            if not positions or package in plan['deleted']:
                continue
            raw = _placeholder(plan, package)
            digest = _digest(raw)
            reference = package + '@' + digest
            # Digest-only pushes create no staging tag and no runnable payload.
            if package not in plan['uploaded']:
                if registry.resolve(reference) is None:
                    with tempfile.TemporaryDirectory(prefix='adw-retirement-') as temporary:
                        blob, manifest_path = Path(temporary) / 'empty.json', Path(temporary) / 'manifest.json'
                        blob.write_bytes(b'{}'); manifest_path.write_bytes(raw)
                        oras('blob', 'push', package + '@' + _digest(b'{}'), str(blob), '--media-type', 'application/vnd.oci.empty.v1+json')
                        oras('manifest', 'push', reference, str(manifest_path), '--media-type', MANIFEST)
                if registry.resolve(reference) != digest or oras('manifest', 'fetch', reference, binary=True) != raw:
                    raise ContractError('pointer_retirement_placeholder_readback_invalid')
                plan['uploaded'].append(package)
                write(private, plan)
            for item in positions:
                tag_ref = package + ':' + item['tag']
                current = registry.resolve(tag_ref)
                if current != digest:
                    if current != item['old']:
                        raise ContractError('pointer_retirement_pointer_changed')
                    registry.copy_if_unchanged(reference, tag_ref, item['old'])
                if registry.resolve(tag_ref) != digest:
                    raise ContractError('pointer_retirement_pointer_readback_invalid')
                if tag_ref not in plan['moved']:
                    plan['moved'].append(tag_ref); write(private, plan)
            absence(repo, adapter, profile_root, deprovision_operation_dir, target, provider)
            _check_positions(plan, registry)
            versions, roots, locations = inventory(repo, adapter, kind_name, plan)
            eligible = candidates(versions, roots, now=float('inf'), grace_hours=1)
            actual = next((v for v in versions if v.identifier == reference), None)
            if actual is None or set(actual.tags) != {x['tag'] for x in positions} or reference not in eligible:
                raise ContractError('pointer_retirement_placeholder_not_eligible')
            plan['deleting'][package] = locations[reference]
            write(private, plan)
            api('DELETE', locations[reference])
            try:
                api('GET', locations[reference])
            except ContractError as exc:
                if str(exc) != 'GitHub operation rejected (HTTP 404)':
                    raise
            else:
                raise ContractError('pointer_retirement_delete_readback_invalid')
            if registry.resolve(reference) is not None:
                raise ContractError('pointer_retirement_delete_readback_invalid')
            plan['deleted'].append(package)
            write(private, plan)
            _check_positions(plan, registry)
        _check_positions(plan, registry)
        for item in plan['positions']:
            if item['old'] is not None and registry.resolve(item['package'] + '@' + item['old']) != item['old']:
                raise ContractError('pointer_retirement_former_release_missing')
        plan['phase'] = 'complete'
        write(private, plan)
        return _receipt(plan)

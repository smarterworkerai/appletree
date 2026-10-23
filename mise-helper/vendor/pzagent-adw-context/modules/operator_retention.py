"""Shared GHCR retention with human runtime proof and receipt-gated CI."""
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import quote

from .common import project_dir
from .common import ContractError
from .execution import human
from .providers import bind, binding_for
from .operator_github import api, pages
from .operator_registry import read_manifest
from .operator_state import journals, locked, new_operation, read, write
from .release_manifest import release_kind, validate
from .retention import Version, candidates


MAX_OPERATION_JOURNALS = 2048
MAX_OPERATION_JOURNAL_BYTES = 1024 * 1024


def _walk_values(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child
            yield from _walk_values(child)
    elif isinstance(value, list):
        for child in value:
            yield None, child
            yield from _walk_values(child)


def _active_operation_roots(repo, kind_name, versions):
    """Protect immutable objects named by resumable publication/deployment journals,
    both legacy handover/ ones and those in the operator home."""
    bases = [repo / 'handover']
    if (project_dir(repo) / 'pzagent-adapter.json').exists():
        bases.append(journals(repo))
    bases = [base for base in bases if base.exists()]
    if not bases:
        return set()
    if any(base.is_symlink() for base in bases):
        raise ContractError('active operation journal is unsafe')
    known = {version.identifier: version for version in versions}
    packages = {identifier.split('@', 1)[0] for identifier in known}
    roots, count = set(), 0
    walks = (entry for base in bases for entry in os.walk(base, followlinks=False))
    for directory, children, files in walks:
        current = Path(directory)
        children[:] = sorted(name for name in children if not (current / name).is_symlink())
        for name in sorted(set(files) & {'operation.json', 'deployment.json'}):
            path = current / name
            count += 1
            if count > MAX_OPERATION_JOURNALS:
                raise ContractError('active operation journal inventory exceeds safety bound')
            if path.is_symlink() or path.stat().st_size > MAX_OPERATION_JOURNAL_BYTES:
                raise ContractError('active operation journal is unsafe')
            try:
                record = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                raise ContractError('active operation journal is unreadable') from exc
            if not isinstance(record, dict) or record.get('schema_version') != '1.0.0':
                raise ContractError('active operation journal is invalid')
            workflow = record.get('workflow')
            if ((workflow is not None and workflow not in {'publish', 'publish-deploy', 'deploy-existing'})
                    or (workflow is None and name != 'deployment.json')):
                continue
            status, phase = record.get('status'), record.get('phase')
            if status == 'ok' or (phase == 'complete' and status in {None, 'ok'}):
                continue
            declared_kinds = {child for key, child in _walk_values(record)
                              if key in {'kind', 'release_kind'} and isinstance(child, str)}
            if declared_kinds and kind_name not in declared_kinds:
                continue
            for _, child in _walk_values(record):
                if not isinstance(child, str):
                    continue
                if child in known:
                    roots.add(child)
                elif any(child.startswith(package + '@sha256:') for package in packages):
                    raise ContractError('active operation references a missing package version')
            if kind_name in declared_kinds:
                source_shas = {child for key, child in _walk_values(record)
                               if key in {'source_sha', 'release_source_sha'}
                               and isinstance(child, str) and re.fullmatch(r'[0-9a-f]{40}', child)}
                source_tags = {'sha-' + source[:12] for source in source_shas}
                roots.update(version.identifier for version in versions
                             if set(version.tags) & source_tags)
    return roots


def _operation_digest(kind_name, grace, selected, roots, locations):
    plan = {'schema_version': '1.0.0', 'kind': kind_name, 'grace_hours': grace,
            'candidates': [{'identifier': identifier, 'location': locations[identifier]}
                           for identifier in selected],
            'protected_roots': sorted(roots)}
    canonical = json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()
    return 'sha256:' + hashlib.sha256(canonical).hexdigest()


def inventory(repo, adapter, kind_name, profile_root, *, include_runtime=True):
    kind = release_kind(adapter, kind_name)
    owner = adapter['repository']['id'].split('/')[0]
    owner_type = api('GET', '/users/' + quote(owner))['type']
    scope = '/orgs/' if owner_type == 'Organization' else '/users/'
    packages = [kind['manifest_package'], *(entry['package'] for entry in kind['components'].values())]
    roots, versions, locations = set(), [], {}
    for package in packages:
        prefix = 'ghcr.io/' + owner.lower() + '/'
        if not package.startswith(prefix):
            raise ContractError('retention package is outside the declared GitHub owner')
        route = scope + quote(owner) + '/packages/container/' + quote(package[len(prefix):], safe='') + '/versions'
        for row in pages(route):
            digest = row.get('name', '')
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
                raise ContractError('package inventory digest invalid')
            identifier = package + '@' + digest
            tags = row['metadata']['container']['tags']
            references = ()
            if package == kind['manifest_package']:
                manifest = validate(read_manifest(identifier), adapter, kind_name)
                references = tuple(manifest['images'].values())
            if (any(not re.fullmatch(r'(?:sha-[0-9a-f]{12}|upload-[0-9a-f]{32}|hotfix-[0-9a-f]{12}(?:-[0-9a-f]{12})?)', tag) for tag in tags)
                    or (not include_runtime and any(tag.startswith('hotfix-') for tag in tags))):
                roots.add(identifier)
            created = datetime.fromisoformat(row['created_at'].replace('Z', '+00:00')).timestamp()
            versions.append(Version(identifier, created, tuple(tags), references))
            locations[identifier] = route + '/' + str(int(row['id']))
    # Preserve images reachable from the declared release-line heads as well.
    heads = [api('GET', '/repos/' + adapter['repository']['id'] + '/git/ref/heads/' + quote(branch, safe=''))['object']['sha']
             for branch in adapter['repository']['protected_branches']]
    tags = {'sha-' + sha[:12] for sha in heads}
    roots.update(version.identifier for version in versions if set(version.tags) & tags)
    roots.update(_active_operation_roots(repo, kind_name, versions))
    if not include_runtime:
        candidates(versions, roots, grace_hours=adapter['retention']['grace_hours'])
        return versions, roots, locations
    # Real runtime references protect deployments interrupted before pointer finalization.
    config = json.loads((project_dir(repo) / 'pz-release.json').read_text())
    environments = config['kind_environments'][kind_name]
    if not environments:
        raise ContractError('retention runtime inventory is not declared')
    from .operator_workflows import adw
    for environment in environments:
        for name, target in adapter['targets'][environment]['items'].items():
            arguments = [environment, '--target', name]
            if profile_root is not None:
                arguments += ['--profile-root', str(profile_root.resolve())]
            # Environment alone may describe a deployment that never became live.
            adw(repo, 'adw:deploy:status', arguments)
            provider = bind(repo, adapter, name, target, profile_root)
            provider.discover(binding_for(adapter, target))
            values = provider.live_image_refs()
            for variable, component in kind['image_variables'].items():
                reference = values.get(variable, '')
                if not reference.startswith(kind['components'][component]['package'] + '@sha256:'):
                    raise ContractError('retention cannot prove all runtime references; restore temporary hotfix first')
                roots.add(reference)
    # Validate the protected reference graph even for preview-only invocations.
    candidates(versions, roots, grace_hours=adapter['retention']['grace_hours'])
    return versions, roots, locations


def run(repo, adapter, args):
    ci_mode=not human()
    def authorize_ci():
        if not ci_mode:
            return None
        if args.authorization_file is None:
            raise ContractError('CI retention requires an authorization receipt')
        from .ci.release_authorization import revalidate_for_kind
        return revalidate_for_kind(args.authorization_file,adapter,kind_name=args.kind)
    authorize_ci()
    directory = (args.operation_dir or new_operation(repo)).resolve()
    with locked(directory):
        previous = read(directory / 'operation.json') if (directory / 'operation.json').exists() else None
        if previous and (previous.get('workflow') != 'retention' or previous.get('kind') != args.kind):
            raise ContractError('retention operation selection differs')
        if previous and previous.get('status') == 'ok':
            return previous
        versions, roots, locations = inventory(repo, adapter, args.kind, args.profile_root, include_runtime=not ci_mode)
        grace = previous['grace_hours'] if previous else (args.grace_hours if args.grace_hours is not None else adapter['retention']['grace_hours'])
        eligible = candidates(versions, roots, grace_hours=grace)
        requested_scope = getattr(args, 'only_candidate', None)
        candidate_scope = previous.get('candidate_scope') if previous else requested_scope
        if previous and requested_scope not in {None, candidate_scope}:
            raise ContractError('retention candidate scope differs from saved operation')
        if previous and previous['apply']:
            remaining = set(previous['candidates']) - set(previous['deleted'])
            if not remaining <= set(eligible):
                raise ContractError('retention candidates changed; inspect saved deletion journal')
            selected = sorted(remaining)
            record = previous
            if not ci_mode and record.get('approved_operation_digest') != record.get('operation_digest'):
                raise ContractError('retention resume has no valid operation-bound approval')
        else:
            if candidate_scope is not None:
                if candidate_scope not in eligible:
                    raise ContractError('requested retention candidate is not eligible')
                selected = [candidate_scope]
            else:
                selected = eligible
            digest = _operation_digest(args.kind, grace, selected, roots, locations)
            record = {'schema_version': '1.0.0', 'workflow': 'retention', 'kind': args.kind,
                      'apply': False, 'grace_hours': grace, 'candidate_scope': candidate_scope,
                      'candidates': selected,
                      'protected_roots': sorted(roots), 'deleted': [],
                      'operation_digest': digest, 'operation_dir': str(directory), 'status': 'preview'}
            if not args.apply:
                write(directory / 'operation.json', record)
                return record
            if not ci_mode:
                approved = getattr(args, 'approve_operation_digest', None)
                if previous is None or previous.get('operation_digest') != digest or approved != digest:
                    write(directory / 'operation.json', record)
                    raise ContractError('human retention apply requires this reviewed operation digest: ' + digest)
                record['approved_operation_digest'] = digest
            record['apply'] = True
            record['status'] = 'applying'
            write(directory / 'operation.json', record)
        if record['apply']:
            # Refresh complete graph before each deletion. No force or stale plan input.
            for identifier in selected:
                live, live_roots, live_locations = inventory(repo, adapter, args.kind, args.profile_root, include_runtime=not ci_mode)
                eligible = candidates(live, live_roots, grace_hours=grace)
                if identifier not in eligible or live_locations.get(identifier) != locations[identifier]:
                    raise ContractError('retention inventory changed; preserve completed deletion journal')
                authorize_ci()
                api('DELETE', locations[identifier])
                try:
                    api('GET', locations[identifier])
                except ContractError as exc:
                    if str(exc)!='GitHub operation rejected (HTTP 404)':
                        raise
                else:
                    raise ContractError('retention deletion readback still present')
                record['deleted'].append(identifier); write(directory / 'operation.json', record)
            record['status'] = 'ok'; write(directory / 'operation.json', record)
        return record

"""Approval-bound, journaled target-pointer handover without runtime activation."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path

from .approval import validate as approve
from .common import ContractError, git_common_state, project_dir
from .hooks import prove_source
from .operator_registry import inspect
from .operator_state import locked, read, write
from .oras_registry import OrasRegistry
from .target_pointers import DIGEST, _lock

CAPABILITY = 'pz:release:pointers:handover'


def _target(adapter: dict, name: str) -> tuple[str, dict]:
    matches = [(environment, group['items'][name]) for environment, group in adapter['targets'].items()
               if name in group['items']]
    if len(matches) != 1:
        raise ContractError('pointer_handover_target_ambiguous')
    return matches[0]


def _references(kind: dict, target: str) -> dict[tuple[str, str], str]:
    packages = {'manifest': kind['manifest_package'], **{
        component: declaration['package'] for component, declaration in kind['components'].items()}}
    if len(set(packages.values())) != len(packages):
        raise ContractError('pointer_handover_packages_ambiguous')
    return {(component, position): package + ':' + kind['pointer_tags'][position].format(target=target)
            for component, package in packages.items() for position in ('current', 'rollback')}


def _selection(repo: Path, adapter: dict, source: str, destination: str, kind_name: str | None) -> tuple[str, str]:
    if source == destination:
        raise ContractError('pointer_handover_targets_equal')
    source_environment, _ = _target(adapter, source)
    destination_environment, _ = _target(adapter, destination)
    try:
        config = json.loads((project_dir(repo) / 'pz-release.json').read_bytes())
        names = [name for name, environments in config['kind_environments'].items()
                 if source_environment in environments and destination_environment in environments
                 and (kind_name is None or name == kind_name)]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ContractError('pointer_handover_release_mapping_invalid') from exc
    if len(names) != 1 or names[0] not in adapter['release_kinds']:
        raise ContractError('pointer_handover_release_kind_ambiguous')
    return names[0], destination_environment


def handover(repo: Path, adapter: dict, *, source: str, destination: str,
             kind_name: str | None, replace: bool, operation_dir: Path,
             approval_path: Path | None, registry=None, plan: bool = False) -> dict:
    source_sha = prove_source(repo, adapter)
    selected, environment = _selection(repo, adapter, source, destination, kind_name)
    kind = adapter['release_kinds'][selected]
    source_refs, destination_refs = _references(kind, source), _references(kind, destination)
    registry = registry if registry is not None else OrasRegistry()
    selection = {'source_sha': source_sha, 'from': source, 'to': destination,
                 'kind': selected, 'replace': replace}
    path = operation_dir / 'operation.json'
    with locked(operation_dir), ExitStack() as stack:
        for target in sorted((source, destination)):
            stack.enter_context(_lock(git_common_state(repo, 'pointer-locks') / f'{target}-{selected}.lock'))
        record = read(path) if path.exists() else None
        if record is not None:
            if record.get('workflow') != 'pointer-handover' or record.get('selection') != selection:
                raise ContractError('pointer_handover_resume_selection_differs')
            source_values = record['source']
            prior = record['previous']
        else:
            source_values = {reference: registry.resolve(reference) for reference in source_refs.values()}
            prior = {reference: registry.resolve(reference) for reference in destination_refs.values()}
        if set(source_values) != set(source_refs.values()) or set(prior) != set(destination_refs.values()):
            raise ContractError('pointer_handover_journal_invalid')
        if any(v is not None and (not isinstance(v, str) or not DIGEST.fullmatch(v))
               for values in (source_values, prior) for v in values.values()):
            raise ContractError('pointer_handover_journal_invalid')
        if source_values[source_refs['manifest', 'current']] is None:
            raise ContractError('pointer_handover_source_absent')
        # Validate immutable manifest bytes and every component using the same
        # canonical registry reader used by release inspection. A pointer by
        # itself supplies no publication or runtime authority.
        for position in ('current', 'rollback'):
            digest = source_values[source_refs['manifest', position]]
            if digest is None:
                if any(source_values[source_refs[component, position]] is not None for component in kind['components']):
                    raise ContractError('pointer_handover_source_graph_differs')
                continue
            result = inspect(adapter, selected, release_reference=kind['manifest_package'] + '@' + digest)
            if not result['available']:
                raise ContractError('pointer_handover_release_unavailable')
            for component, image in result['manifest']['images'].items():
                if source_values[source_refs[component, position]] != image.split('@', 1)[1]:
                    raise ContractError('pointer_handover_source_graph_differs')
        if any(value is not None for value in prior.values()) and not replace:
            raise ContractError('pointer_handover_destination_exists')
        expected = {destination_refs[key]: source_values[source_refs[key]] for key in source_refs}
        # Deleting a tag cannot be emulated with ORAS manifest deletion, which
        # would destroy shared immutable releases. Refuse that shape up front.
        if any(expected[reference] is None and value is not None for reference, value in prior.items()):
            raise ContractError('pointer_handover_tag_removal_unsupported')
        digest = 'sha256:' + hashlib.sha256(json.dumps(
            {'selection': selection, 'source': source_values, 'previous': prior, 'expected': expected},
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if plan:
            return {'status': 'ok', 'from': source, 'to': destination, 'kind': selected,
                    'operation_digest': digest, 'runtime_activated': False,
                    'phase': 'planned', 'replace': replace}
        approve(approval_path, source_sha=source_sha, capability=CAPABILITY,
                environment=environment, target=destination, operation_digest=digest, exclusive_target=True)
        if record is None:
            record = {'schema_version': '1.0.0', 'workflow': 'pointer-handover',
                      'selection': selection, 'source': source_values, 'previous': prior,
                      'operation_digest': digest, 'phase': 'selected', 'completed': []}
            write(path, record)
        elif record.get('operation_digest') != digest:
            raise ContractError('pointer_handover_journal_invalid')

        def source_unchanged():
            if {r: registry.resolve(r) for r in source_values} != source_values:
                raise ContractError('pointer_handover_source_changed')

        source_unchanged()
        observed = {r: registry.resolve(r) for r in expected}
        if any(observed[r] not in {prior[r], expected[r]} for r in expected):
            raise ContractError('pointer_handover_destination_changed')
        if record['phase'] == 'complete':
            if observed != expected:
                raise ContractError('pointer_handover_completed_state_changed')
            return {'status': 'ok', 'from': source, 'to': destination, 'kind': selected,
                    'operation_digest': digest, 'runtime_activated': False, 'phase': 'complete'}
        try:
            for key in sorted(source_refs):
                reference = destination_refs[key]
                wanted = expected[reference]
                if registry.resolve(reference) == wanted:
                    continue
                source_unchanged()
                record['phase'] = 'copy-requested'
                record['requested'] = reference
                write(path, record)
                package = (kind['manifest_package'] if key[0] == 'manifest'
                           else kind['components'][key[0]]['package'])
                registry.copy_if_unchanged(package + '@' + wanted, reference, prior[reference])
                if registry.resolve(reference) != wanted:
                    raise ContractError('pointer_handover_copy_readback_differs')
                record['completed'].append(reference)
                record['phase'] = 'copy-confirmed'
                write(path, record)
            source_unchanged()
            if {r: registry.resolve(r) for r in expected} != expected:
                raise ContractError('pointer_handover_copy_readback_differs')
            record['phase'] = 'complete'
            record.pop('requested', None)
            write(path, record)
        except Exception:
            # New tags cannot safely be erased with a manifest delete. Keep the
            # exact graph for explicit resume/reconciliation; never touch source.
            record['phase'] = 'incomplete'
            write(path, record)
            raise
        return {'status': 'ok', 'from': source, 'to': destination, 'kind': selected,
                'operation_digest': digest, 'runtime_activated': False, 'phase': 'complete'}

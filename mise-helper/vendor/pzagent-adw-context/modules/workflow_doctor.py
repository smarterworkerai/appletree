"""Read-only diagnosis of operator operations and targets with recommended next steps.

Doctor observes and suggests; it never authorizes, runs a recommendation,
takes an operation lock or repairs a journal. Mutating commands re-run their
own guards and never treat this report as evidence.
"""
from __future__ import annotations

from contextlib import nullcontext
import json
from pathlib import Path
import re

from .common import ContractError, FULL_SHA, ensure_contained, project_dir
from .hotfix import _read_private
from .hotfix_state import KEY, SCHEMA
from .operator_state import OPERATION_ID, operation_root, repository_id
from .release_manifest import DIGEST_REF
from . import workflow_observation as observe

# The task exit classes (0/1/20/21): unknown shares 20 with `unsupported`; `status` tells them apart.
HEALTHY, FINDINGS, UNKNOWN = 0, 1, 20
MAX_ARTIFACTS = 256
MAX_RESULT_BYTES = 60000
NOT_VERIFIED = ['settings_values', 'secret_values', 'persistent_data', 'external_application_settings']
CODES = {
    'operation_open', 'operation_needs_reconcile', 'operation_journal_invalid', 'operation_terminal',
    'target_running_identity_differs', 'target_configured_image_differs', 'target_definition_differs',
    'target_required_keys_missing', 'target_check_unavailable', 'target_check_unknown',
    'target_check_refused', 'target_check_unsupported', 'target_current_pointer_changed',
}
CHECK_CODES = {'running_identity': 'target_running_identity_differs',
               'configured_images': 'target_configured_image_differs',
               'definition': 'target_definition_differs', 'required_keys': 'target_required_keys_missing'}


def _abandon_available() -> bool:
    """The abandon task ships with #176; until then doctor says it is not yet available."""
    try:
        return '["pz:workflow:abandon"]' in (Path(__file__).resolve().parents[1] / 'tasks.toml').read_text()
    except OSError:
        return False


def _command(task: str, *arguments: str) -> list[str]:
    return ['mise', 'run', task, '--', *arguments]


def _short(sha) -> str | None:
    return sha[:12] if isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{40}', sha) else None


def _bounded_text(value) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,80}', value) else None


# Hotfix candidates -----------------------------------------------------------

RUN_ID = re.compile(r'^[a-z][a-z0-9-]{0,62}$')
ARTIFACT_NAME = re.compile(r'^hotfix-restore-[0-9a-f]{12}-[0-9a-f]{12}\.json$')


def _artifacts(repo: Path) -> tuple[list[str], bool]:
    """Repository-relative restore artifacts in the generated layout, and whether the scan was complete.

    Every directory level is bounded before sorting; links and other names are never followed.
    """
    found, complete = [], True
    bases = ['handover']
    try:
        bases.append(str(project_dir(repo).relative_to(repo) / 'evidence'))
    except (ContractError, ValueError):
        pass
    for base in bases:
        directory = repo / base
        if directory.is_symlink() or not directory.is_dir():
            continue
        try:
            runs = observe.bounded_entries(directory)
        except (ContractError, OSError):
            complete = False
            continue
        for run in runs:
            if not RUN_ID.fullmatch(run.name) or run.is_symlink() or not run.is_dir(follow_symlinks=False):
                continue
            try:
                entries = observe.bounded_entries(Path(run.path))
            except (ContractError, OSError):
                complete = False
                continue
            for entry in entries:
                if ARTIFACT_NAME.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                    found.append(base + '/' + run.name + '/' + entry.name)
                    if len(found) >= MAX_ARTIFACTS:
                        return found, False
    return found, complete


def _artifact(repo: Path, relative: str, environment: str, target: str) -> dict | None:
    try:
        document = json.loads(_read_private(ensure_contained(repo, relative)))
    except (ContractError, OSError, ValueError):
        return None
    required = {'schema', 'environment', 'target', 'source_sha', 'prior', 'hotfix', 'before_sha256'}
    if (not isinstance(document, dict) or not required <= set(document)
            or set(document) - (required | {'provider_state'}) or document['schema'] != SCHEMA
            or document['environment'] != environment or document['target'] != target
            or not isinstance(document['source_sha'], str) or not FULL_SHA.fullmatch(document['source_sha'])
            or not isinstance(document['before_sha256'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', document['before_sha256'])
            or ('provider_state' in document and not isinstance(document['provider_state'], dict))):
        return None
    prior, hotfix = document['prior'], document['hotfix']
    if not isinstance(prior, dict) or not isinstance(hotfix, dict) or not prior or set(prior) != set(hotfix):
        return None
    if any(not isinstance(k, str) or not KEY.fullmatch(k) or not isinstance(v, str) or not v
           or '\n' in v or '\r' in v for mapping in (prior, hotfix) for k, v in mapping.items()):
        return None
    if any(not DIGEST_REF.fullmatch(image) for image in prior.values()):
        return None
    # The payload and any provider state stay here; only the image mappings are compared.
    return {'prior': dict(prior), 'hotfix': dict(hotfix)}


def hotfix_candidates(repo: Path, environment: str, target: str, expected: dict, observed: dict) -> dict:
    """Restore artifacts whose recorded hotfix matches an observation; never a verified active hotfix.

    `observed` maps an observation name (runtime, configured) to its owned image map.
    """
    matches, unsupported = [], []
    artifacts, complete = _artifacts(repo)
    for relative in artifacts:
        value = _artifact(repo, relative, environment, target)
        if value is None:
            continue
        prior, hotfix = value['prior'], value['hotfix']
        if set(prior) - set(expected) or prior != {key: expected[key] for key in prior}:
            continue  # Restoring it would not return to the current release.
        if all(hotfix[key] == prior[key] for key in hotfix):
            continue
        if any(not DIGEST_REF.fullmatch(image) for image in hotfix.values()):
            unsupported.append(relative)  # Local tags (SSH transfer) cannot be identified.
            continue
        for name, images in observed.items():
            if (set(images) == set(expected) and all(images[key] == hotfix[key] for key in hotfix)
                    and all(images[key] == expected[key] for key in expected if key not in hotfix)):
                matches.append({'artifact': relative, 'observation': name, 'keys': sorted(hotfix)})
    paths = sorted({match['artifact'] for match in matches})
    status = 'none' if not paths else 'matching' if len(paths) == 1 else 'ambiguous'
    if status == 'matching' and not complete:
        status = 'unknown'  # An unscanned artifact could match too; one candidate is unproven.
    if not paths and (unsupported or not complete):
        status = 'unknown'  # Local tags cannot be identified; an incomplete scan proves nothing.
    return {'status': status, 'candidates': matches if status == 'matching' else [],
            'ambiguous': paths if status == 'ambiguous' else [], 'unsupported': len(unsupported),
            'complete': complete}


# Target findings -------------------------------------------------------------

def _target_scope(repository: str, report: dict, adapter: dict) -> dict:
    scope = {'repository': repository, 'environment': report['environment'], 'target': report['target']}
    try:
        scope['binding_sha256'] = observe.binding_fingerprint(adapter, report['environment'], report['target'])
    except (KeyError, TypeError, ContractError):
        scope['binding_sha256'] = 'unknown'
    return scope


def _target_recommendation(report: dict, hotfix: dict, planned: dict) -> dict:
    """The target rows of the recommendation table, gated on all four checks."""
    checks, env, target = report['checks'], report['environment'], report['target']
    plan = _command('adw:deploy:config:plan', env, '--target', target)
    rerun = _command('pz:workflow:doctor', '--environment', env, '--target', target)
    if report['pointer_recheck'] == 'changed':
        return {'action': 'rerun-doctor', 'detail': 'The current pointer changed during observation; findings are stale.',
                'next_commands': [rerun], 'advisories': []}
    if any(value['result'] == 'refused' for value in checks.values()):
        return {'action': 'investigate', 'detail': 'The provider refused a comparison; this is not "no difference". '
                'Inspect the target before any configuration write.', 'next_commands': [plan], 'advisories': []}
    runtime = checks['running_identity']['result'] == 'differs' or checks['configured_images']['result'] == 'differs'
    if runtime and hotfix['status'] == 'matching':
        candidate = hotfix['candidates'][0]['artifact']
        return {'action': 'review-hotfix-candidate',
                'detail': 'Matching hotfix candidate; restore preconditions must be revalidated. Decide whether to '
                          'restore it or publish the hotfix as a release.',
                'next_commands': [],
                'advisories': ['mise run adw:hotfix:restore -- ' + env + ' --target ' + target +
                               ' --artifact ' + candidate + ' --profile-root <operator-profile> '
                               '--approval-file <restore-approval>']}
    if runtime:
        detail = ('Investigate and reconcile first; a new deploy can hit the same mismatch guard. Re-applying the '
                  'current release is a deliberate human choice.')
        if hotfix['status'] == 'ambiguous':
            detail = 'Several hotfix candidates match; doctor never picks one. ' + detail
        return {'action': 'reconcile-target', 'detail': detail, 'next_commands': [], 'advisories': []}
    definition = checks['definition']
    if definition['result'] == 'differs':
        observed = definition['evidence'].get('observed_sha256')
        correlated = sorted(operation for operation, digest in planned.items() if digest == observed)
        if correlated:
            return {'action': 'inspect-definition',
                    'detail': 'Definition differs from current release source and equals the planned definition of '
                              + ', '.join(correlated) + '; that correlates with its planned write but does not prove '
                              'it. Inspect before choosing to re-apply the current release with --sync-config, '
                              'which may overwrite intentional configuration.',
                    'next_commands': [plan], 'advisories': [], 'correlated_operations': correlated}
        return {'action': 'inspect-definition', 'detail': 'Definition differs from current release source; origin '
                'unproven. Inspect before overwriting.', 'next_commands': [plan], 'advisories': []}
    if checks['required_keys']['result'] == 'differs':
        return {'action': 'investigate', 'detail': 'Required configuration keys are missing; key names only, values '
                'are never checked.', 'next_commands': [], 'advisories': []}
    if any(value['result'] in {'unavailable', 'unknown', 'unsupported'} for value in checks.values()):
        return {'action': 'rerun-doctor-when-reachable', 'detail': 'Re-run doctor when the target is reachable; '
                'unobserved checks are never reported as healthy.', 'next_commands': [rerun], 'advisories': []}
    return {'action': 'none', 'detail': 'All in-scope observations pass; settings values, secrets and data are not '
            'verified.', 'next_commands': [], 'advisories': []}


def target_findings(repository: str, adapter: dict, report: dict, hotfix: dict, planned: dict) -> list[dict]:
    scope = _target_scope(repository, report, adapter)
    recommendation = _target_recommendation(report, hotfix, planned)
    coverage = {name: {'result': value['result'], 'coverage': value['coverage']}
                for name, value in report['checks'].items()}
    context = {'provider': _bounded_text(report.get('provider')), 'source_sha': _short(report.get('source_sha')),
               'manifest_digest': report.get('manifest_digest', 'unknown'), 'pointer_recheck': report['pointer_recheck']}
    findings = []
    if report['pointer_recheck'] == 'changed':
        findings.append(('target_current_pointer_changed', None, {}))
    for name, value in report['checks'].items():
        if value['result'] == 'pass':
            continue
        code = CHECK_CODES[name] if value['result'] == 'differs' else 'target_check_' + value['result']
        evidence = {'check': name, 'reason': value.get('reason'), **value['evidence']}
        if name in {'running_identity', 'configured_images'} and value['result'] == 'differs':
            evidence['hotfix'] = {'status': hotfix['status'], 'artifacts': sorted(
                {item['artifact'] for item in hotfix['candidates']} | set(hotfix['ambiguous']))}
        findings.append((code, name, evidence))
    return [{'code': code, 'scope': scope, 'context': context, 'evidence': evidence, 'coverage': coverage,
             'recommended_action': recommendation['action'], 'detail': recommendation['detail'],
             'next_commands': recommendation['next_commands'], 'advisories': recommendation['advisories'],
             'observed_at': report['observed_at']} for code, _, evidence in findings]


# Operation findings ----------------------------------------------------------

def _superseding(tree: dict, scope: dict, trees: list[dict], scopes: dict, locks: dict, writes: dict) -> str | None:
    """A newer completed operation for the same proven scope; suggested only, never automatic."""
    record = tree['record'] or {}
    created = observe.timestamps(record)['created_at']
    # Only a known-idle older operation is suggested (#176); lock state `unknown` never is.
    if (scope['status'] != 'proven' or created == 'unknown' or locks[tree['operation']]['state'] != 'idle'
            or writes[tree['operation']]['classification'] != 'none'):
        return None
    kind = record.get('kind') or (record.get('selection') or {}).get('release_kind')
    for other in trees:
        candidate = other['record'] or {}
        other_scope = scopes[other['operation']]
        other_created = observe.timestamps(candidate)['created_at']
        if (other['operation'] != tree['operation'] and candidate.get('status') == 'ok'
                and other['workflow'] in {'deploy-existing', 'publish-deploy'} and candidate.get('kind') == kind
                and other_scope['status'] == 'proven'
                and (other_scope['environment'], other_scope['target'], other_scope['binding_sha256'])
                == (scope['environment'], scope['target'], scope['binding_sha256'])
                and other_created != 'unknown' and other_created > created):
            return other['operation']
    return None


def _operation_recommendation(tree, scope, lock, write, superseded_by, local, target_report, target_rec,
                              offline, abandon) -> dict:
    operation = tree['operation']
    resume = _command('pz:workflow:resume', '--operation', operation)
    online = ['mise', 'run', 'pz:workflow:doctor', '--', '--operation', operation]

    def abandon_advice(extra: str = '') -> list[str]:
        if not abandon:
            return ['pz:workflow:abandon is not yet available in this release (#176); leave the operation untouched '
                    'until it is. Leaving it is conservative for the current runtime, but may keep packages '
                    'protected and the ambiguity unresolved.']
        return ['mise run pz:workflow:abandon -- --operation ' + operation + extra + ' --reason <why>']

    if lock['state'] == 'running':
        return {'action': 'wait', 'detail': 'An operation lock in its linked tree is held; wait for it to finish.',
                'next_commands': [], 'advisories': []}
    record = tree['record'] or {}
    if observe.is_terminal(record) and record.get('needs_reconcile') is not True:
        return {'action': 'none', 'detail': 'The operation is terminal; nothing to resume or retire.',
                'next_commands': [], 'advisories': []}
    if scope['status'] == 'name-only':
        inspect = _command('pz:workflow:doctor', '--environment', scope['environment'], '--target', scope['target'])
        return {'action': 'investigate', 'detail': 'The journal records the target name ' + scope['target'] +
                ' without a provider-binding fingerprint, so doctor does not map it to today\'s provider. '
                'Establish the scope before resuming or abandoning; the named target can be inspected separately.',
                'next_commands': [inspect], 'advisories': []}
    if scope['status'] == 'unknown':
        return {'action': 'investigate', 'detail': 'The journal does not prove its target scope (' +
                scope.get('reason', 'unknown') + '). Resume or abandon only after the scope is established; '
                'doctor never resolves a null target to today\'s default.', 'next_commands': [], 'advisories': []}
    if record.get('needs_reconcile') is True and observe.is_terminal(record):
        if target_rec is not None and target_rec['action'] == 'none':
            return {'action': 'rerun-abandon', 'detail': 'All target checks pass now. Re-run abandon; it re-runs '
                    'its own guard and this report is not evidence for it.', 'next_commands': [],
                    'advisories': ['mise run pz:workflow:abandon -- --operation ' + operation + ' --reason <why>']}
        if target_rec is None:
            return {'action': 'rerun-doctor-online' if offline else 'rerun-doctor-when-reachable',
                    'detail': 'Retired with unreconciled writes; the target was not observed.',
                    'next_commands': [online], 'advisories': []}
        return {'action': 'follow-target-findings', 'detail': 'Retired with unreconciled writes; reconcile the '
                'target first (' + target_rec['action'] + ').', 'next_commands': target_rec['next_commands'],
                'advisories': target_rec['advisories']}
    if target_report is not None and (target_report['pointer_recheck'] == 'changed' or any(
            value['result'] == 'refused' for value in target_report['checks'].values())):
        return {'action': 'investigate', 'detail': 'The target reported a provider refusal or a concurrent '
                'pointer change; resolve that before resuming or abandoning.', 'next_commands': [],
                'advisories': []}
    if write['classification'] != 'none':
        if target_rec is None:
            return ({'action': 'rerun-doctor-online', 'detail': 'A write is ' + write['classification'] +
                     '; follow the target findings first. Run doctor without --offline.',
                     'next_commands': [online], 'advisories': []} if offline else
                    {'action': 'rerun-doctor-when-reachable', 'detail': 'A write is ' + write['classification'] +
                     '; the target could not be observed. Re-run doctor when it is reachable.',
                     'next_commands': [online], 'advisories': []})
        return {'action': 'follow-target-findings', 'detail': 'A write is ' + write['classification'] +
                '; follow the target findings first (' + target_rec['action'] + ').',
                'next_commands': target_rec['next_commands'], 'advisories': target_rec['advisories']}
    unresolved = target_rec is not None and target_rec['action'] != 'none'
    caveat = (' Not a safety claim while any configuration, pointer or scope finding is unresolved.'
              if unresolved else '')
    if superseded_by is not None:
        return {'action': 'abandon-superseded', 'detail': 'No write recorded; superseded by ' + superseded_by +
                ' for the same proven scope.', 'next_commands': [],
                'advisories': abandon_advice(' --superseded-by ' + superseded_by)}
    position = target_report.get('ancestry') if target_report is not None else None
    if position == 'ancestor':
        return {'action': 'abandon-or-resume-rollback', 'detail': 'No write recorded. Resuming would deploy an '
                'older source on this target. Abandon if it is no longer wanted; resume only if the rollback is '
                'intended.' + caveat, 'next_commands': [], 'advisories': abandon_advice() + [
                    'mise run pz:workflow:resume -- --operation ' + operation + '  # deliberate rollback only']}
    if position in {'same', 'descendant'}:
        return {'action': 'resume-or-abandon', 'detail': 'No write recorded; the source is the same as or newer '
                'than the target\'s current source. Resume, or abandon if it is no longer wanted.' + caveat,
                'next_commands': [resume], 'advisories': abandon_advice()}
    if target_report is None and local == 'ancestor':
        return {'action': 'rerun-doctor-online', 'detail': 'No write recorded; older than local main. Whether '
                'resuming upgrades or rolls back the target is unknown. Run doctor without --offline.',
                'next_commands': [online], 'advisories': abandon_advice()}
    if tree['role'] == 'deployment':
        return {'action': 'investigate', 'detail': 'A deployment journal without a parent workflow; inspect it '
                'before re-entering adw:deploy:apply with its operation.', 'next_commands': [], 'advisories': []}
    if target_report is not None and position in {None, 'unknown'} and target_rec['action'] == \
            'rerun-doctor-when-reachable':
        return {'action': 'rerun-doctor-when-reachable', 'detail': 'No write recorded; the target\'s current '
                'source could not be observed. Re-run doctor when it is reachable.' + caveat,
                'next_commands': [online], 'advisories': abandon_advice()}
    return {'action': 'investigate', 'detail': 'No write recorded, but the source position relative to the target '
            'is ' + (position or 'unobserved') + '. Investigate before resuming; abandon if it is no longer wanted.'
            + caveat, 'next_commands': [], 'advisories': abandon_advice()}


def operation_finding(repository, adapter, repo, tree, scope, lock, write, superseded_by, target_report,
                      target_rec, offline, abandon, observed_at) -> dict:
    record = tree['record'] or {}
    context = observe.context(tree)
    source = context.get('source_sha')
    main = observe.local_commit(repo, 'refs/heads/main')
    local = observe.ancestry(repo, source, main)
    if target_report is not None:
        target_report = dict(target_report, ancestry=observe.ancestry(repo, source, target_report.get('source_sha')))
    recommendation = _operation_recommendation(tree, scope, lock, write, superseded_by, local, target_report,
                                               target_rec, offline, abandon)
    if lock['state'] == 'unknown' and recommendation['action'] != 'wait':
        recommendation['detail'] = ('Doctor cannot prove the operation is idle; these actions are conditional and '
                                    'the mutating command must acquire and revalidate the real operation lock. '
                                    + recommendation['detail'])
    context['source_sha'] = _short(source)
    evidence = {'write_classification': write['classification'], 'write_evidence': write['evidence'],
                'lock_state': lock['state'], 'lock_observation': lock['observation'],
                'ancestry_local_main': {'baseline': 'local-main', 'position': local},
                **observe.timestamps(record)}
    if target_report is not None:
        evidence['ancestry_target'] = {'baseline': 'target-current-source', 'position': target_report['ancestry']}
    if superseded_by:
        evidence['superseded_by'] = superseded_by
    code = ('operation_needs_reconcile' if record.get('needs_reconcile') is True and observe.is_terminal(record)
            else 'operation_terminal' if observe.is_terminal(record) else 'operation_open')
    coverage = {'journal': 'linked-tree', 'excluded': tree['excluded'],
                'target': 'offline' if offline else 'observed' if target_report is not None else 'not-observed'}
    return {'code': code, 'scope': {'repository': repository, 'operation': tree['operation'],
                                    'environment': scope.get('environment'), 'target': scope.get('target'),
                                    'scope_status': scope['status'],
                                    'binding_sha256': scope.get('binding_sha256', 'unknown')},
            'context': context, 'evidence': evidence, 'coverage': coverage,
            'recommended_action': recommendation['action'], 'conditional': lock['state'] == 'unknown',
            'detail': recommendation['detail'], 'next_commands': recommendation['next_commands'],
            'advisories': recommendation['advisories'], 'observed_at': observed_at}


# Report ----------------------------------------------------------------------

def _summary(finding: dict) -> str:
    scope = finding['scope']
    subject = scope.get('operation') or (scope['environment'] + '/' + scope['target'])
    return finding['code'] + ' ' + subject + ': ' + finding['recommended_action']


def run(repo: Path, adapter: dict, *, home: Path | None, profile_root: Path | None, operation: str | None,
        environment: str | None, target: str | None, offline: bool, registry_auth=nullcontext) -> tuple[dict, int]:
    """One bounded diagnosis; returns the result and its exit class."""
    if target is not None and environment is None:
        raise ContractError('--target requires --environment')
    if operation is not None and not OPERATION_ID.fullmatch(operation):
        raise ContractError('operator_home_operation_id_invalid')
    repository = repository_id(repo)
    root = operation_root(repo, home)
    observed_at = observe.now()
    names = observe.list_operations(root)
    trees = [observe.journal_tree(root, name) for name in names]
    linked = observe.linked_operations(trees)
    trees = [tree for tree in trees if tree['operation'] not in linked]
    if operation is not None:
        trees = [tree for tree in trees if tree['operation'] == operation]
        if not trees:
            raise ContractError('operator_home_operation_unknown')
    findings = []
    invalid = [tree for tree in trees if tree['record'] is None]
    for tree in invalid:
        findings.append({'code': 'operation_journal_invalid',
                         'scope': {'repository': repository, 'operation': tree['operation']}, 'context': {},
                         'evidence': {}, 'coverage': {'journal': 'invalid'}, 'recommended_action': 'investigate',
                         'detail': 'The journal is not a private, bounded, valid operation record.',
                         'next_commands': [], 'advisories': [], 'observed_at': observed_at})
    trees = [tree for tree in trees if tree['record'] is not None]
    # An explicitly named operation is reported even when terminal; otherwise open or unreconciled ones only.
    selected = [tree for tree in trees if operation is not None or not observe.is_terminal(tree['record'])
                or tree['record'].get('needs_reconcile') is True]
    scopes = {tree['operation']: observe.recorded_scope(tree, adapter) for tree in trees}
    writes = {tree['operation']: observe.write_classification(tree) for tree in trees}
    locks = {tree['operation']: observe.lock_state([node['directory'] for node in tree['nodes']]) for tree in trees}
    if environment is not None:
        selected = [tree for tree in selected if scopes[tree['operation']].get('environment') == environment
                    and (target is None or scopes[tree['operation']].get('target') == target)]

    # Targets: those an in-scope journal resolves, plus explicitly requested ones.
    wanted = []
    for tree in selected:
        scope = scopes[tree['operation']]
        if scope['status'] == 'proven':
            wanted.append((scope['environment'], scope['target']))
    if environment is not None:
        group = adapter.get('targets', {}).get(environment)
        if not isinstance(group, dict):
            raise ContractError('environment has no target inventory')
        requested = [target] if target is not None else sorted(group.get('items', {}))
        if target is not None and target not in group.get('items', {}):
            raise ContractError('logical target is not allowlisted')
        wanted.extend((environment, name) for name in requested)
    wanted = sorted(set(wanted))
    # Plan digests correlate only within a proven scope (same target, provider binding and render inputs).
    planned = {tree['operation']: writes[tree['operation']]['evidence'].get('planned_definition_sha256')
               for tree in trees if writes[tree['operation']]['evidence'].get('planned_definition_sha256')
               and scopes[tree['operation']]['status'] == 'proven'}
    reports, recommendations = {}, {}
    if not offline:
        for key in wanted:
            report = observe.target_checks(repo, adapter, *key, profile_root=profile_root,
                                           registry_auth=registry_auth)
            private = report.pop('private')
            expected = private.get('expected_images')
            observations = {name: private[name + '_images'] for name in ('runtime', 'configured')
                            if isinstance(private.get(name + '_images'), dict)}
            hotfix = (hotfix_candidates(repo, *key, expected, observations) if expected
                      else {'status': 'unknown', 'candidates': [], 'ambiguous': [], 'unsupported': 0})
            same_target = {operation: digest for operation, digest in planned.items()
                           if (scopes[operation].get('environment'), scopes[operation].get('target')) == key}
            recommendations[key] = _target_recommendation(report, hotfix, same_target)
            reports[key] = report
            findings.extend(target_findings(repository, adapter, report, hotfix, same_target))
    abandon = _abandon_available()
    for tree in selected:
        scope = scopes[tree['operation']]
        key = (scope.get('environment'), scope.get('target'))
        superseded = _superseding(tree, scope, trees, scopes, locks, writes)
        findings.append(operation_finding(repository, adapter, repo, tree, scope, locks[tree['operation']],
                                          writes[tree['operation']], superseded, reports.get(key),
                                          recommendations.get(key), offline, abandon, observed_at))
    unobserved = {'target_check_unknown', 'target_check_unavailable', 'target_check_unsupported'}
    findings_present = [finding for finding in findings if finding['code'] != 'operation_terminal']
    if any(finding['code'] not in unobserved for finding in findings_present):
        status, code = 'findings', FINDINGS
    elif findings_present or (offline and environment is not None) or not (selected or reports):
        # Unobserved checks, an offline request for a target, or nothing in scope at all:
        # nothing collected is never healthy.
        status, code = 'unknown', UNKNOWN
    else:
        status, code = 'healthy', HEALTHY
    if any(finding['code'] not in CODES for finding in findings):
        raise ContractError('doctor_finding_code_unlisted')
    result = {'status': status, 'mode': 'offline' if offline else 'live', 'observed_at': observed_at,
              'repository': repository, 'operations': len(selected), 'targets': len(reports),
              'not_verified': NOT_VERIFIED, 'findings': findings, 'truncated': 0,
              'summary': [_summary(finding) for finding in findings]}
    # The machine result is bounded; narrow with --operation or --environment to see the rest.
    while len(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()) > MAX_RESULT_BYTES and findings:
        findings.pop()
        result['summary'].pop()
        result['truncated'] += 1
    return result, code

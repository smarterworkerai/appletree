"""Create an owned, deterministic consumer scaffold from installed pinned vendors."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

if __package__ in {None, ''}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.adapter import expand as validate_adapter
from modules.bundle import validate_bundle
from modules.common import ContractError, FULL_SHA, IDENTIFIER, PROJECT_DIRECTORIES, ensure_contained, load_json, project_dir
from modules.context_sync import check_context_task_overrides, tool_lock_gaps
from modules.project_tasks import PROJECT_TASKS, ProjectParser, environment as command_environment
from modules.quality_tasks import engine

BUNDLE = Path(__file__).resolve().parents[1]
MARKER = 'pz:project:init'
# Operations the bundled provider hooks serve (their OPERATIONS plus describe). A scaffold routes a
# capability through bundle:provider only when that provider implements it; E2E and, on Dokploy, hotfix
# builds need a project hook, so the scaffold declares them unsupported.
BUNDLED_OPERATIONS = {
    'dokploy': frozenset({'describe', 'config-plan', 'deploy-status', 'health', 'readiness', 'runtime-proof'}),
    'kubernetes': frozenset({'describe', 'config-plan', 'deploy-status', 'health', 'readiness', 'runtime-proof',
                             'hotfix-build'}),
}


def document(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def checksum(value: bytes):
    return hashlib.sha256(value).hexdigest()


def target_path(repo: Path, name: str) -> Path:
    path = ensure_contained(repo, name)
    for candidate in (path, *path.parents):
        if candidate == repo:
            break
        if candidate.is_symlink():
            raise ContractError('project_init_path_unsafe')
    return path


def marked(existing: str, name: str, body: str) -> str:
    start, end = '<!-- ' + MARKER + ':' + name + ' -->', '<!-- /' + MARKER + ':' + name + ' -->'
    if name == 'gitignore':
        start, end = '# ' + MARKER, '# /' + MARKER
    block = start + '\n' + body.rstrip() + '\n' + end + '\n'
    if start not in existing and end not in existing:
        return existing + ('\n' if existing and not existing.endswith('\n\n') else '') + block
    if existing.count(start) != 1 or existing.count(end) != 1 or existing.index(end) < existing.index(start):
        raise ContractError('project_init_marker_invalid')
    begin = existing.index(start)
    finish = existing.index(end) + len(end)
    if existing[finish:finish + 1] == '\n':
        finish += 1
    return existing[:begin] + block + existing[finish:]


ORAS, ORAS_VERSION = 'aqua:oras-project/oras', '1.3.4'


def tool_pins(args):
    pins = {name: value for name, value in (('java', args.java), ('node', args.node)) if value is not None}
    for declaration in getattr(args, 'tool', []) or []:
        name, separator, version = declaration.partition('=')
        if (not separator or name in pins or len(name) > 128
                or not re.fullmatch(r'(?:[A-Za-z][A-Za-z0-9_.-]*:)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', name)
                or any(part in ('.', '..') for part in name.split('/'))):
            raise ContractError('project_init_tool_version_invalid')
        pins[name] = version
    for name, version in pins.items():
        if (not isinstance(version, str) or len(version) > 128
                or not re.fullmatch(r'(?:[A-Za-z][A-Za-z0-9_]*-)?[0-9]+(?:[.][0-9]+)*(?:[+][0-9A-Za-z._-]+)?', version)):
            raise ContractError('project_init_tool_version_invalid')
    return dict(sorted(pins.items()))


def scaffold(repo: Path, args) -> dict[str, bytes]:
    bundle = validate_bundle(BUNDLE)
    generic = engine(repo)
    directory = args.directory
    other = next(name for name in PROJECT_DIRECTORIES if name != directory)
    if (repo / other).exists():
        raise ContractError('project_directory_conflict')
    if args.provider not in {'dokploy', 'kubernetes'}:
        raise ContractError('provider_unsupported')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository):
        raise ContractError('project_init_repository_invalid')
    for values in (args.components, args.environments):
        if not values or len(values) != len(set(values)) or not all(IDENTIFIER.fullmatch(v) for v in values):
            raise ContractError('project_init_identifiers_invalid')
    if not IDENTIFIER.fullmatch(args.release_kind):
        raise ContractError('project_init_identifiers_invalid')
    prior_manifest = target_path(repo, directory + '/adw-task-manifest.json')
    prior_lock = target_path(repo, directory + '/pzagent-context-lock.json')
    prior = json.loads(prior_manifest.read_text()) if prior_manifest.is_file() else {}
    lock = json.loads(prior_lock.read_text()) if prior_lock.is_file() else {}
    if not isinstance(prior, dict) or not isinstance(lock, dict):
        raise ContractError('project_init_provenance_invalid')
    context_ref = args.context_ref or lock.get('source_ref')
    generic_ref = args.generic_ref or prior.get('sources', {}).get('generic', {}).get('ref')
    if not FULL_SHA.fullmatch(context_ref or '') or not FULL_SHA.fullmatch(generic_ref or ''):
        raise ContractError('project_init_pinned_vendor_refs_required')
    slug = args.repository.split('/')[1].lower()
    image_keys = {component: 'PROJECT_' + component.upper().replace('-', '_') + '_IMAGE'
                  for component in args.components}
    files = {}
    templates = BUNDLE / 'templates'
    files['mise-helper/tasks.toml'] = (templates / 'project-tasks.toml').read_text()
    files['mise-helper/project-commands.toml'] = (templates / 'project-commands.toml').read_text()
    files['mise-helper/README.md'] = (templates / 'project-helper-readme.md').read_text()
    pins = tool_pins(args)
    mise_pins = dict(pins)
    # publish-release.yml installs oras through mise-action, which runs `mise install --locked`
    # when mise.lock exists: declare and lock an exact, released version (1.3.4: 2026-08-27).
    mise_pins.setdefault(ORAS, ORAS_VERSION)
    if args.provider == 'kubernetes':
        for name, version in (('kubectl', '1.35.0'), ('kustomize', '5.7.1'), ('k3d', '5.8.3'), ('helm', '3.19.0')):
            mise_pins.setdefault(name, version)
    tools = ''.join((name if re.fullmatch(r'[A-Za-z0-9_-]+', name) else json.dumps(name))
                    + ' = ' + json.dumps(version) + '\n' for name, version in mise_pins.items())
    files['mise.toml'] = (templates / 'mise.toml').read_text().replace('2026.10.17', bundle['minimum_mise']).replace('2.2.0', generic.CONTRACT_VERSION).replace('# @TOOLS@', tools.rstrip())
    local = set(PROJECT_TASKS) | {'adw:verify:full'}
    context = {'adw:describe', 'adw:verify:full', 'adw:context:check', 'adw:context:sync', 'adw:local:clean'}
    manifest = {
        'schema_version': generic.SCHEMA_VERSION,
        'contract': {'name': generic.CONTRACT_NAME, 'version': generic.CONTRACT_VERSION, 'compatible': '>=2.0.0,<3.0.0'},
        'project': {'id': args.repository}, 'environments': args.environments,
        'required_secret_env': [], 'evidence': {'root': directory + '/evidence'},
        'sources': {}, 'capabilities': {},
        'verification': {'minimal': ['adw:build'], 'full': ['adw:build', 'adw:lint',
            'adw:static-analysis', 'adw:test:unit', 'adw:test:integration:fast']},
    }
    for layer, ref, path in (
        ('generic', generic_ref, 'mise-helper/vendor/agentic-delivery/tasks.toml'),
        ('context', context_ref, 'mise-helper/vendor/pzagent-adw-context/tasks.toml'),
        ('project', 'HEAD', 'mise-helper/tasks.toml')):
        content = files[path].encode() if path in files else ensure_contained(repo, path).read_bytes()
        manifest['sources'][layer] = {'layer': layer, 'ref': ref, 'path': path, 'checksum': 'sha256:' + checksum(content)}
    for task in sorted(generic.CANONICAL_TASKS):
        supported = task in local or task in context or task == 'adw:check' or task in generic.ENVIRONMENT_TASKS
        scope = args.environments if task in generic.ENVIRONMENT_TASKS else []
        if task in {'adw:hotfix:apply', 'adw:hotfix:restore'}:
            scope = [env for env in args.environments if env in {'pr-preview', 'telephony-preview'}]
            if 'hotfix-build' not in BUNDLED_OPERATIONS[args.provider]:
                scope = []
            supported = bool(scope)
        elif task in {'adw:test:e2e:fast', 'adw:test:e2e:full'}:
            scope = [env for env in args.environments if env == 'pr-preview']
            if not {'e2e-fast', 'e2e-full'} <= BUNDLED_OPERATIONS[args.provider]:
                scope = []
            supported = bool(scope)
        manifest['capabilities'][task] = {
            'source': 'project' if task in PROJECT_TASKS else 'context' if task in context or task not in {'adw:check'} else 'generic',
            'status': 'supported' if supported else 'unsupported',
            'side_effect': generic.TASK_SIDE_EFFECTS[task],
            'environments': scope}
    files[directory + '/adw-task-manifest.json'] = document(manifest)
    files[directory + '/pzagent-context-lock.json'] = document({
        'schema_version': '1.0.0', 'source_ref': context_ref,
        'package_version': bundle['version'], 'bundle_sha256': checksum((BUNDLE / 'bundle.json').read_bytes())})
    from modules.ci import release_signature
    from modules.context_sync import validate_release_record
    statement_path = getattr(args, 'release_statement', None)
    signature_path = getattr(args, 'release_signature', None)
    if bool(statement_path) != bool(signature_path):
        raise ContractError('project_init_release_assets_required')
    release_path = target_path(repo, directory + '/' + release_signature.RECORD)
    record_data = None
    if statement_path:
        for path in (Path(statement_path), Path(signature_path)):
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_048_576:
                raise ContractError('project_init_release_asset_unsafe')
        try:
            record_data = document(release_signature.record(
                Path(statement_path).read_bytes(), Path(signature_path).read_text(encoding='utf-8'))).encode()
        except (UnicodeError, release_signature.ProofError):
            raise ContractError('project_init_release_assets_invalid') from None
    elif release_path.exists() or release_path.is_symlink():
        if release_path.is_symlink() or not release_path.is_file() or release_path.stat().st_size > 1_048_576:
            raise ContractError('project_init_release_asset_unsafe')
        record_data = release_path.read_bytes()
    if record_data is not None:
        pinned_lock = json.loads(files[directory + '/pzagent-context-lock.json'])
        validate_release_record(record_data, BUNDLE, pinned_lock)
        files[directory + '/' + release_signature.RECORD] = record_data
    adapter = json.loads((templates / 'pzagent-adapter.json').read_text())
    adapter['repository']['id'] = args.repository
    adapter['providers'] = ({'dokploy': {'project': slug, 'bindings': {}}}
                            if args.provider == 'dokploy' else {'kubernetes': {'bindings': {}}})
    adapter['targets'] = {}
    if args.provider == 'kubernetes':
        adapter['schema_version'] = '1.2.0'
        adapter['hotfix']['transports'] = {'kubernetes': ['registry']}
        adapter['hotfix']['ssh_aliases'] = []
    adapter['release_kinds'] = {args.release_kind: {
        'schema': slug + '.' + args.release_kind + '-release/v1',
        'manifest_package': 'ghcr.io/' + args.repository.lower() + '-' + args.release_kind + '-release',
        'components': {c: {'package': 'ghcr.io/' + args.repository.lower() + '-' + c} for c in args.components},
        'image_variables': {key: component for component, key in image_keys.items()},
        'publication_pointers': ['published']}}
    operations = {
        'adw:describe': ('describe', ['profile']),
        'adw:deploy:config:plan': ('config-plan', ['role', 'order']),
        'adw:deploy:status': ('deploy-status', ['status']),
        'adw:health': ('health', ['status']), 'adw:readiness': ('readiness', ['status']),
        'adw:validate-deployment': ('runtime-proof', ['images']),
        'adw:hotfix:apply': ('hotfix-build', ['images']),
        'adw:test:e2e:fast': ('e2e-fast', ['status', 'selected', 'executed', 'skipped']),
        'adw:test:e2e:full': ('e2e-full', ['status', 'selected', 'executed', 'skipped'])}
    adapter['hooks']['dispatcher'] = {'command': 'bundle:provider'}
    adapter['hooks']['operations'] = {task: {'operation': operation, 'result_keys': keys,
        'timeout_seconds': 180} for task, (operation, keys) in operations.items()
        if manifest['capabilities'][task]['status'] == 'supported'}
    for environment in args.environments:
        binding = environment + '-' + args.release_kind
        if args.provider == 'kubernetes':
            namespace = slug + '-' + environment
            if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', namespace):
                raise ContractError('project_init_identifiers_invalid')
            adapter['targets'][environment] = {'default': None, 'items': {
                environment + '-k8s': {'mode': 'shadow', 'provider': 'kubernetes', 'provider_binding': binding}}}
            overlay = 'deploy/k8s/overlays/' + environment
            key = 'PROJECT_' + environment.upper().replace('-', '_') + '_BASE_URL'
            adapter['providers']['kubernetes']['bindings'][binding] = {
                'environment': environment, 'context_alias': environment, 'namespace': namespace,
                'release': {'kind': 'kustomize', 'path': overlay},
                'image_variables': {image_keys[c]: {'kind': 'Deployment', 'name': c, 'container': c}
                                    for c in args.components},
                'config_schema_path': 'deploy/k8s/keys.json', 'ingress_probe_base': key,
                'probes': {'base_url_env': key, 'health_path': '/health', 'readiness_path': '/ready'}}
            files[overlay + '/kustomization.yaml'] = document({
                'apiVersion': 'kustomize.config.k8s.io/v1beta1', 'kind': 'Kustomization',
                'namespace': namespace, 'resources': ['../../base']})
            files['deploy/k8s/.env.' + environment + '.example'] = (templates / 'providers/kubernetes/env.example').read_text()
            continue
        adapter['targets'][environment] = {'default': None, 'items': {
            environment + '-dokploy': {'mode': 'shadow', 'provider': 'dokploy', 'provider_binding': binding}}}
        compose = 'infra/dokploy/docker-compose.' + environment + '.yml'
        key_schema = 'infra/dokploy/' + environment + '.keys.json'
        adapter['providers']['dokploy']['bindings'][binding] = {
            'environment': environment, 'resource': slug + '-' + environment,
            'child_binding': 'PROJECT_DOKPLOY_COMPOSE_ID', 'compose_path': compose,
            'environment_schema_path': key_schema}
        services = ''.join('  ' + c + ':\n    image: ${' + image_keys[c] + ':?digest-pinned image required}\n' for c in args.components)
        files[compose] = (templates / 'providers/dokploy/compose.yml').read_text().replace('@SERVICES@', services)
        files['infra/dokploy/.env.' + environment + '.example'] = (templates / 'providers/dokploy/env.example').read_text().replace('@KEYS@', ''.join(key + '=\n' for key in image_keys.values()))
        files[key_schema] = document({'keys': list(image_keys.values()), 'optional_keys': []})
    if args.provider in {'dokploy', 'kubernetes'}:
        files['.env.deploy.example'] = (templates / 'providers' / args.provider / 'operator-env.example').read_text().replace(
            '@PROBE_KEYS@', ''.join('PROJECT_' + environment.upper().replace('-', '_') + '_BASE_URL=\n'
                                   for environment in args.environments))
    if args.provider == 'kubernetes':
        resources = []
        for component in args.components:
            for resource in ('deployment', 'service'):
                name = component + '-' + resource + '.json'
                files['deploy/k8s/base/' + name] = (templates / 'providers/kubernetes' / (resource + '.json')).read_text().replace('@COMPONENT@', component)
                resources.append(name)
        files['deploy/k8s/base/ingress.json'] = (templates / 'providers/kubernetes/ingress.json').read_text().replace('@RELEASE@', args.release_kind).replace('@COMPONENT@', args.components[0])
        resources.append('ingress.json')
        files['deploy/k8s/base/kustomization.yaml'] = document({
            'apiVersion': 'kustomize.config.k8s.io/v1beta1', 'kind': 'Kustomization', 'resources': resources})
        files['deploy/k8s/keys.json'] = document({'keys': []})
        files['deploy/k8s/README.md'] = (templates / 'providers/kubernetes/README.md').read_text()
    validate_adapter(adapter, manifest)
    files[directory + '/pzagent-adapter.json'] = document(adapter)
    files[directory + '/pz-release.json'] = document({'schema_version': '1.0.0',
        'platforms': ['linux/amd64'], 'kind_environments': {args.release_kind: args.environments},
        'components': {c: {'context': c, 'dockerfile': c + '/Dockerfile', 'stages': []} for c in args.components},
        # Stage-less components export no files; a project that adds build stages maps them here.
        'quality_exports': {c: {} for c in args.components},
        'hooks': {'build': 'bundle:release_build'}})
    sources = {'java': 'mise.lock' if 'java' in pins else '', 'node': 'package.json engines' if 'node' in pins else ''}
    sources.update({name: 'mise.toml [tools]' for name in pins if name not in ('java', 'node')})
    files[directory + '/build-toolchain.json'] = document({'schema_version': '1.0.0', 'sources': sources})
    facts = (templates / 'project-adw.md').read_text().replace('smarterworkerai/<repo>', args.repository).replace('<Project>', slug)
    facts = facts.replace(
        f'The project directory is `{PROJECT_DIRECTORIES[0]}/`, or `{PROJECT_DIRECTORIES[1]}/` in existing projects.',
        f'The project directory is `{directory}/`.')
    facts = facts.replace('.adw/', directory + '/')
    files[directory + '/ADW.md'] = facts
    for name in ('ci.yml', 'trust-root-bootstrap.yml', 'publish-release.yml', 'cleanup-retention.yml'):
        files['.github/workflows/' + name] = (templates / 'github' / name).read_bytes()
    for name, marker, body in (
        ('.gitignore', 'gitignore', directory + '/evidence/\n/handover/\n.ci-cache/\n.ci-artifacts/\nadw-test-reports/\n__pycache__/\n.env\n.env.*\n!.env.example\n!.env.*.example'),
        ('AGENTS.md', 'agents', (templates / 'repo-agents-snippet.md').read_text().replace('.adw/', directory + '/'))):
        path = target_path(repo, name)
        files[name] = marked(path.read_text() if path.exists() else '', marker, body)
    return {name: text.encode('utf-8') if isinstance(text, str) else text for name, text in files.items()}


def lock_tools(repo: Path) -> None:
    """Resolve the declared tool pins into mise.lock; the operator reviews and commits it."""
    with tempfile.TemporaryDirectory(prefix='pz-project-lock-') as raw:
        lock_env = command_environment({}, {})
        lock_env.update(MISE_TRUSTED_CONFIG_PATHS=str(repo), MISE_STATE_DIR=raw)
        locked = subprocess.run(['mise', 'lock'], cwd=repo, env=lock_env, capture_output=True, text=True)
    if locked.returncode:
        raise ContractError('project_init_tool_lock_failed')


def initialize(repo: Path, args) -> dict:
    repo = repo.resolve()
    if args.provider not in {'dokploy', 'kubernetes'}:
        raise ContractError('provider_unsupported')
    if args.directory not in PROJECT_DIRECTORIES:
        raise ContractError('project_init_directory_invalid')
    other = repo / next(name for name in PROJECT_DIRECTORIES if name != args.directory)
    if other.exists():
        raise ContractError('project_directory_conflict')
    ledger_path = target_path(repo, args.directory + '/project-init.json')
    ledger = json.loads(ledger_path.read_text()) if ledger_path.is_file() else {}
    if not isinstance(ledger, dict) or ledger and (ledger.get('owner') != MARKER or ledger.get('schema_version') != '1.0.0'
                   or not isinstance(ledger.get('files'), dict)):
        raise ContractError('project_init_ownership_invalid')
    files = scaffold(repo, args)
    conflicts, changed = [], []
    for name, desired in files.items():
        path = target_path(repo, name)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ContractError('project_init_path_unsafe')
        if not path.exists() or path.read_bytes() != desired:
            changed.append(name)
            bootstrap = (name == 'mise.toml' and path.exists()
                         and path.read_bytes() == (BUNDLE / 'templates/project-bootstrap.toml').read_bytes())
            block_start = '# ' + MARKER if name == '.gitignore' else '<!-- ' + MARKER + ':agents -->'
            append_block = (name in {'.gitignore', 'AGENTS.md'} and path.exists()
                            and name not in ledger.get('files', {}) and block_start not in path.read_text().splitlines())
            if (path.exists() and not append_block and not bootstrap
                    and checksum(path.read_bytes()) != ledger.get('files', {}).get(name)
                    and not args.force):
                conflicts.append(name)
    if conflicts:
        return {'status': 'blocked', 'reason': 'project_init_unowned_files', 'conflicts': sorted(conflicts)}
    state = document({'schema_version': '1.0.0', 'owner': MARKER,
                      'files': {name: checksum(value) for name, value in sorted(files.items())}}).encode()
    files[str(ledger_path.relative_to(repo))] = state
    snapshots = {}
    try:
        for name, data in files.items():
            path = target_path(repo, name)
            if path.exists() and path.read_bytes() == data:
                continue
            snapshots[name] = path.read_bytes() if path.exists() else None
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary = tempfile.mkstemp(prefix='.project-init-', dir=path.parent)
            try:
                with os.fdopen(descriptor, 'wb') as handle:
                    handle.write(data)
                os.replace(temporary, path)
            finally:
                Path(temporary).unlink(missing_ok=True)
        if tool_lock_gaps(repo):
            snapshots.setdefault('mise.lock', (repo / 'mise.lock').read_bytes() if (repo / 'mise.lock').is_file() else None)
            lock_tools(repo)
            changed.append('mise.lock')
            if tool_lock_gaps(repo):
                raise ContractError('project_init_tool_lock_incomplete')
        generic = engine(repo)
        # Describe validates the generated manifest against the installed generic ABI.
        described = generic.describe(repo)
        if described.exit_code:
            raise ContractError('project_init_contract_invalid')
        # Scope temporary trust to files just generated; do not write user trust settings.
        with tempfile.TemporaryDirectory(prefix='pz-project-check-') as raw:
            check_env = command_environment({}, {})
            check_env.update(MISE_TRUSTED_CONFIG_PATHS=str(repo), MISE_STATE_DIR=raw,
                             MISE_AUTO_INSTALL='false')
            # The generated build is deliberately unimplemented. context:check
            # requires its release producer and runs after the project fills the stubs.
            for task in ('adw:check',):
                checked = subprocess.run(['mise', 'run', task], cwd=repo, env=check_env,
                                         capture_output=True, text=True)
                if checked.returncode:
                    raise ContractError('project_init_contract_invalid')
    except Exception:
        for name, prior in snapshots.items():
            path = target_path(repo, name)
            if prior is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(prior)
        raise
    return {'status': 'ok', 'changed': sorted(changed), 'project_directory': args.directory,
            'next': ['Trust the generated mise.toml for normal use (mise trust mise.toml).',
                     'Implement the eight project tasks; full verification stays context-owned.',
                     'Run adw:context:check after implementing the release build handover.',
                     'Fill Docker recipes, application probes and provider resources before enabling remote capabilities.',
                     'Human: operator credentials, host preparation, registry access and explicit first-adoption operator opt-in.']}


def refresh_manifest(repo: Path) -> dict:
    repo = repo.resolve()
    check_context_task_overrides(repo)
    path = target_path(repo, str(project_dir(repo).relative_to(repo) / 'adw-task-manifest.json'))
    manifest = load_json(path)
    if not isinstance(manifest, dict) or not isinstance(manifest.get('sources'), dict):
        raise ContractError('project_init_manifest_source_invalid')
    sources = manifest.get('sources', {})
    projects = [value for value in sources.values() if isinstance(value, dict) and value.get('layer') == 'project']
    if len(projects) != 1 or projects[0].get('path') != 'mise-helper/tasks.toml':
        raise ContractError('project_init_manifest_source_invalid')
    source = projects[0]
    desired = 'sha256:' + checksum(target_path(repo, source['path']).read_bytes())
    changed = source.get('checksum') != desired
    source['checksum'] = desired
    if engine(repo).validate_manifest(manifest):
        raise ContractError('project_init_contract_invalid')
    if changed:
        descriptor, temporary = tempfile.mkstemp(prefix='.project-manifest-', dir=path.parent)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
                handle.write(document(manifest))
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    return {'status': 'ok', 'changed': [str(path.relative_to(repo))] if changed else []}


def main(argv=None):
    parser = ProjectParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=Path('.'))
    parser.add_argument('--repository')
    parser.add_argument('--release-kind')
    parser.add_argument('--components')
    parser.add_argument('--environments')
    parser.add_argument('--refresh-manifest', action='store_true', help='Refresh only the project task source checksum')
    parser.add_argument('--java')
    parser.add_argument('--node')
    parser.add_argument('--tool', action='append', default=[], metavar='NAME=VERSION',
                        help='Repeatable Mise tool pin, including backend-qualified names')
    parser.add_argument('--provider', choices=('dokploy', 'kubernetes'), default='dokploy')
    parser.add_argument('--dir', dest='directory', choices=PROJECT_DIRECTORIES, default=PROJECT_DIRECTORIES[0])
    parser.add_argument('--force', action='store_true')
    parser.add_argument('--context-ref', help='Pinned context commit when no context lock exists')
    parser.add_argument('--generic-ref', help='Pinned generic commit when no manifest exists')
    parser.add_argument('--release-statement', type=Path, help='Downloaded signed release statement for first adoption')
    parser.add_argument('--release-signature', type=Path, help='Downloaded SSH signature for the release statement')
    args = parser.parse_args(argv)
    try:
        if args.refresh_manifest:
            if any((args.repository, args.release_kind, args.components, args.environments, args.force,
                    args.java, args.node, args.tool, args.context_ref, args.generic_ref,
                    args.release_statement, args.release_signature)):
                parser.error('manifest refresh cannot initialize a project')
            result = refresh_manifest(args.repo_root)
        else:
            if not all((args.repository, args.release_kind, args.components, args.environments)):
                parser.error('initialization arguments required')
            args.components = args.components.split(',')
            args.environments = args.environments.split(',')
            result = initialize(args.repo_root, args)
        print(json.dumps(result, sort_keys=True))
        return 0 if result['status'] == 'ok' else 21
    except (ContractError, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        allowed = {'provider_unsupported', 'project_directory_conflict', 'project_init_pinned_vendor_refs_required',
                   'project_init_repository_invalid', 'project_init_identifiers_invalid', 'project_init_tool_version_invalid',
                   'project_init_path_unsafe', 'project_init_marker_invalid', 'project_init_manifest_source_invalid',
                   'project_init_contract_invalid', 'project_init_ownership_invalid', 'context_task_override_requires_removal'}
        reason = str(exc) if isinstance(exc, ContractError) and str(exc) in allowed else 'project_init_failed'
        print(json.dumps({'status': 'blocked', 'reason': reason}))
        return 21


if __name__ == '__main__':
    raise SystemExit(main())

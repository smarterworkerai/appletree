#!/usr/bin/env python3
"""Portable sealed quality outputs; CI authorization is caller-owned."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import tomllib

from modules import build_archive, build_outputs
from modules.ci import build_artifacts
from modules.ci.github_api import GitHub
from modules.common import project_dir
from modules.common import ContractError, FULL_SHA, ensure_contained, load_json
from modules.operator_state import read, write


def source_files(root: Path) -> list[Path]:
    evidence_prefix = (project_dir(root).name, 'evidence')
    if (root / '.git').exists():
        names = subprocess.check_output(
            ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root).decode().split('\0')
        paths = [Path(name) for name in sorted(set(names) - {''})]
    else:
        paths = [path.relative_to(root) for path in sorted(root.rglob('*'))]
    result = []
    excluded = {'.git', 'handover', 'target', 'node_modules', 'dist', 'coverage',
                '.ci-cache', '.ci-artifacts', 'adw-test-reports', 'playwright-report', 'test-results', '__pycache__'}
    for relative in paths:
        if (excluded.intersection(relative.parts) or relative.parts[:2] == evidence_prefix
                or any(part.startswith('.env') and not part.endswith('.example') for part in relative.parts)):
            continue
        path = root / relative
        if path.is_symlink():
            raise ContractError('release source must not contain symlinks')
        if path.is_file():
            result.append(relative)
    return result


def fingerprint(root: Path, paths=None) -> str:
    digest = hashlib.sha256()
    for relative in source_files(root) if paths is None else paths:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ContractError('release source file is missing or linked')
        digest.update(relative.as_posix().encode() + b'\0')
        # Git archives preserve executable identity, not developer umask/group bits.
        mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
        digest.update(str(mode).encode() + b'\0')
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def output_identity(state, component, stage):
    return {key: state[key] for key in ('source_sha', 'source_digest', 'platform', 'recipe_digest')} | {
        'component': component, 'stage': stage}


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def producer(root: Path, sha: str, env: dict) -> dict:
    actions = env.get('GITHUB_ACTIONS', '').lower() == 'true'
    simulation = bool(env.get('LAB_RUN')) or env.get('ACT', '').lower() == 'true'
    result = {'schema_version': '1.0.0', 'kind': 'simulation' if simulation else 'github-actions' if actions else 'human',
              'source_sha': sha,
              'contract_sha256': digest(project_dir(root) / 'adw-task-manifest.json'),
              'context_sha256': digest(project_dir(root) / 'pzagent-context-lock.json')}
    if actions:
        for field, variable in {'repository': 'GITHUB_REPOSITORY', 'run_id': 'GITHUB_RUN_ID',
                                'run_attempt': 'GITHUB_RUN_ATTEMPT', 'job': 'GITHUB_JOB',
                                'workflow_ref': 'GITHUB_WORKFLOW_REF'}.items():
            value = env.get(variable, '')
            if not value and not simulation:
                raise ContractError('quality export CI producer context is incomplete')
            result[field] = value
    return result


def tools(root: Path) -> dict:
    failure = 'quality outputs require the declared Java 21 and Node 22 toolchain'
    declaration = root / 'mise.toml'
    try:
        if declaration.is_symlink():
            raise ContractError(failure)
        selected = tomllib.loads(declaration.read_text()).get('tools')
        if not isinstance(selected, dict):
            raise ContractError(failure)
        declared = {name: selected[name] for name in ('java', 'node') if name in selected}
        if not declared or any(not isinstance(value, str) for value in declared.values()):
            raise ContractError(failure)
        if ('java' in declared and not re.fullmatch(r'(?:[A-Za-z][A-Za-z0-9_]*-)?21(?:[.][0-9A-Za-z+_.-]+)?', declared['java'])):
            raise ContractError(failure)
        if ('node' in declared and not re.fullmatch(r'22(?:[.]\d+){0,2}', declared['node'])):
            raise ContractError(failure)
    except (OSError, ValueError):
        raise ContractError(failure) from None
    result = {}
    try:
        if 'java' in declared:
            java = subprocess.run(['java', '-version'], capture_output=True, text=True, check=True)
            description = (java.stdout + java.stderr).strip()
            if 'version "21.' not in description:
                raise ContractError(failure)
            result['java'] = description
        if 'node' in declared:
            node = subprocess.check_output(['node', '--version'], text=True).strip()
            if not node.startswith('v22.'):
                raise ContractError(failure)
            result['node'] = node
    except (OSError, subprocess.CalledProcessError):
        raise ContractError(failure) from None
    return result


def validate_native_provenance(root: Path, workspace: Path, hook: dict, platform: str) -> None:
    """Compare a project's provenance record with declared workspace/source files."""
    if (not isinstance(hook, dict) or set(hook) != {'record', 'platform_field', 'files'}
            or not isinstance(hook['files'], dict) or not hook['files']
            or not isinstance(hook['platform_field'], str)):
        raise ContractError('quality_native_provenance_invalid')
    record = load_json(ensure_contained(workspace, hook['record']))
    if not isinstance(record, dict):
        raise ContractError('quality_native_provenance_invalid')
    if record.get(hook['platform_field']) != platform:
        raise ContractError('quality_native_provenance_mismatch')
    for field, declaration in hook['files'].items():
        if (not isinstance(declaration, dict) or set(declaration) != {'root', 'path'}
                or declaration['root'] not in {'source', 'workspace'}):
            raise ContractError('quality_native_provenance_invalid')
        base = root if declaration['root'] == 'source' else workspace
        path = ensure_contained(base, declaration['path'])
        if path.is_symlink() or record.get(field) != digest(path):
            raise ContractError('quality_native_provenance_mismatch')


def export_quality(root: Path, workspace: Path, output: Path, env: dict, *, split=False) -> Path:
    if output.exists() or output.is_symlink() or output == workspace or workspace in output.parents:
        raise ContractError('quality output destination exists or overlaps the build workspace')
    cfg = json.loads((project_dir(root) / 'pz-release.json').read_text())
    if (not isinstance(cfg.get('quality_exports'), dict) or not 0 < len(cfg['quality_exports']) <= 32
            or any(not build_artifacts.COMPONENT.fullmatch(name) for name in cfg['quality_exports'])):
        raise ContractError('invalid quality component declaration')
    observed_platform = platform.system().lower() + '/' + {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine(), platform.machine())
    if observed_platform not in cfg['platforms']:
        raise ContractError('quality output platform is not supported by release recipes')
    sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    if not FULL_SHA.fullmatch(sha) or env.get('ADW_BUILD_SOURCE_SHA', sha) != sha:
        raise ContractError('quality checkout differs from selected source')
    if env.get('GITHUB_ACTIONS', '').lower() == 'true':
        subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--'], cwd=root, check=True)
        if subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], cwd=root).strip():
            raise ContractError('CI quality source contains untracked files')
    paths = source_files(root)
    source_digest = fingerprint(root, paths)
    if source_digest != fingerprint(workspace, paths):
        raise ContractError('quality source changed during verification')
    state = {'schema_version': '1.0.0', 'source_sha': sha, 'source_root': '', 'source_digest': source_digest,
             'platform': observed_platform, 'components': list(cfg['quality_exports']),
             'recipe_digest': hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest(), 'stages': {}}
    record = producer(root, sha, env)
    record['tools'] = tools(root)
    for component in cfg['quality_exports']:
        native = cfg['components'][component].get('native_provenance')
        if native is not None:
            validate_native_provenance(root, workspace, native, observed_platform)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.quality-export-', dir=output.parent) as temporary:
        staging = Path(temporary)
        bundle = staging / 'bundle'; bundle.mkdir()
        for component, stages in cfg['quality_exports'].items():
            if set(stages) != set(cfg['components'][component]['stages']):
                raise ContractError('quality export is missing a declared build stage')
            for stage, files in stages.items():
                directory = bundle / 'artifacts' / component / stage
                for relative, destination in files.items():
                    original = workspace / relative
                    if original.is_symlink():
                        raise ContractError('quality output must not be linked')
                    source = ensure_contained(workspace, relative)
                    target = ensure_contained(directory / 'payload', destination)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if source.is_dir():
                        build_outputs.inventory(source)
                        shutil.copytree(source, target)
                    elif source.is_file():
                        shutil.copy2(source, target)
                    else:
                        raise ContractError('declared quality output is unavailable')
                build_outputs.seal(directory, output_identity(state, component, stage))
                state['stages'][component + '/' + stage] = {'artifacts': directory.relative_to(bundle).as_posix()}
        write(bundle / 'producer.json', record)
        if split:
            # Each archive is independently source/recipe/producer bound. A
            # static-only component still has its small build/producer record.
            uploads = {}
            for component in state['components']:
                if not build_artifacts.COMPONENT.fullmatch(component):
                    raise ContractError('invalid quality output component name')
                component_bundle = staging / '.component'
                component_bundle.mkdir()
                selected = {**state, 'components': [component],
                            'stages': {key: value for key, value in state['stages'].items()
                                       if key.split('/', 1)[0] == component}}
                if selected['stages']:
                    (component_bundle / 'artifacts').mkdir()
                    (bundle / 'artifacts' / component).rename(component_bundle / 'artifacts' / component)
                write(component_bundle / 'build.json', selected)
                write(component_bundle / 'producer.json', record)
                archive = staging / component / 'build-output.tar.gz'
                archive.parent.mkdir()
                build_archive.pack(component_bundle, archive)
                uploads[component] = {'path': component + '/build-output.tar.gz',
                                      'sha256': digest(archive), 'size': archive.stat().st_size}
                shutil.rmtree(component_bundle)
            write(staging / 'upload-manifest.json', {'schema_version': '1.0.0',
                  'source_sha': sha, 'components': uploads})
        else:
            # Explicit local/legacy export, never uploaded alongside components.
            write(bundle / 'build.json', state)
            build_archive.pack(bundle, staging / 'build-output.tar.gz')
        shutil.rmtree(bundle)
        staging.rename(output)
    return output / ('upload-manifest.json' if split else 'build-output.tar.gz')


def import_quality(root: Path, archive: Path, source: Path, output: Path, sha: str,
                   components: list[str], env: dict, expected_producer=None, *, exact_components=False) -> dict:
    """The CI umbrella must obtain expected_producer from authorized run/artifact readback."""
    if output.exists() or output.is_symlink():
        raise ContractError('build import destination already exists')
    cfg = json.loads((project_dir(root) / 'pz-release.json').read_text())
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.quality-import-', dir=output.parent) as temporary:
        selected = Path(temporary) / 'bundle'
        build_archive.unpack(archive, selected)
        state = read(selected / 'build.json'); record = read(selected / 'producer.json')
        if (not FULL_SHA.fullmatch(sha) or state['source_sha'] != sha or record['source_sha'] != sha
                or state['source_digest'] != fingerprint(source)
                or state['recipe_digest'] != hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()
                or state['platform'] not in cfg['platforms'] or not components
                or not set(components) <= set(state['components'])):
            raise ContractError('quality bundle is incompatible with selected release inputs')
        if (record['contract_sha256'] != digest(project_dir(source) / 'adw-task-manifest.json')
                or record['context_sha256'] != digest(project_dir(source) / 'pzagent-context-lock.json')):
            raise ContractError('quality bundle contract/context differs')
        if env.get('GITHUB_ACTIONS', '').lower() == 'true':
            required = {'kind', 'source_sha', 'contract_sha256', 'context_sha256',
                        'repository', 'run_id', 'run_attempt', 'job', 'workflow_ref'}
            if (not isinstance(expected_producer, dict) or set(expected_producer) != required
                    or expected_producer['kind'] != 'github-actions'
                    or any(record.get(key) != value for key, value in expected_producer.items())):
                raise ContractError('CI build import requires exact authorized producer binding')
        elif expected_producer is not None:
            raise ContractError('human build import does not accept CI authorization metadata')
        requested_stages = {component + '/' + stage for component in components for stage in cfg['components'][component]['stages']}
        if exact_components and (state['components'] != components or set(state['stages']) != requested_stages):
            raise ContractError('quality artifact contains unrelated component outputs')
        if not requested_stages <= set(state['stages']):
            raise ContractError('quality bundle is missing required stage outputs')
        for key, entry in state['stages'].items():
            component, stage = key.split('/', 1)
            build_outputs.verify(ensure_contained(selected, entry['artifacts']), output_identity(state, component, stage))
        state['source_root'] = str(source.resolve())
        state['components'] = components
        state['stages'] = {key: value for key, value in state['stages'].items() if key in requested_stages}
        write(selected / 'build.json', state)
        selected.rename(output)
    return state



def import_ci(root: Path, source: Path, output: Path, components: list[str],
              producer: build_artifacts.Producer, env: dict, api=None) -> dict:
    """Called only after the CI umbrella authorizes its release lane/PR/actor."""
    if (env.get('GITHUB_ACTIONS', '').lower() != 'true' or env.get('LAB_RUN')
            or env.get('ACT', '').lower() == 'true'
            or env.get('GITHUB_REPOSITORY') != producer.repository):
        raise ContractError('CI artifact import requires the hosted repository context')
    if output.exists() or output.is_symlink():
        raise ContractError('build import destination already exists')
    expected = producer.expected(digest(project_dir(source) / 'adw-task-manifest.json'),
                                 digest(project_dir(source) / 'pzagent-context-lock.json'))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.ci-quality-', dir=output.parent) as temporary:
        cfg = json.loads((project_dir(root) / 'pz-release.json').read_text())
        if (not components or len(components) != len(set(components))
                or not set(components) <= set(cfg['quality_exports'])):
            raise ContractError('quality component selection is invalid')
        client = api or GitHub(producer.repository)
        combined = Path(temporary) / 'combined'; combined.mkdir()
        state = None; artifacts = {}
        for component in components:
            archive = Path(temporary) / (component + '.tar.gz')
            metadata = build_artifacts.fetch(client, producer, archive, component)
            if metadata is None:
                return {'status': 'build-required', 'source_sha': producer.source_sha,
                        'reason': 'compatible component quality artifact unavailable',
                        'missing_component': component}
            imported = Path(temporary) / component
            current = import_quality(root, archive, source, imported, producer.source_sha,
                                     [component], env, expected, exact_components=True)
            # A component artifact must not smuggle another component's payload.
            actual = {path.relative_to(imported).parts[1]
                      for path in (imported / 'artifacts').glob('*')}
            if actual - {component}:
                raise ContractError('quality artifact contains unrelated component outputs')
            if state is None:
                state = {**current, 'components': list(components), 'stages': {}}
                shutil.copy2(imported / 'producer.json', combined / 'producer.json')
            elif any(current[key] != state[key] for key in
                     ('source_sha', 'source_digest', 'recipe_digest', 'platform', 'source_root')):
                raise ContractError('quality component identities differ')
            if read(imported / 'producer.json') != read(combined / 'producer.json'):
                raise ContractError('quality component producers differ')
            state['stages'].update(current['stages'])
            if (imported / 'artifacts').exists():
                shutil.copytree(imported / 'artifacts', combined / 'artifacts', dirs_exist_ok=True)
            artifacts[component] = {'id': metadata['id'], 'digest': metadata['digest']}
        write(combined / 'build.json', state)
        combined.rename(output)
        return {'status': 'imported', 'source_sha': state['source_sha'],
                'components': state['components'], 'artifacts': artifacts}

#!/usr/bin/env python3
"""Default release build/package hooks driven by declared Docker recipes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import shutil
import tempfile
import sys
from uuid import uuid4

# Also executable as an isolated hook process from a consumer checkout.
if __package__ in {None, ''}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules.common import project_dir
from modules.common import ContractError, FULL_SHA, ensure_contained
from modules.operator_state import read, write
from modules.buildkit_cache import plan as cache_plan
from modules import build_outputs


def run(*args, capture=False, log_path=None):
    if log_path is not None and not capture:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open('w') as log:
            result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, text=True)
    else:
        result = subprocess.run(args, capture_output=True, text=True)
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(result.stdout + result.stderr)
    if result.returncode:
        raise ContractError('release build tool failed: ' + args[0])
    return result.stdout.strip() if capture else None


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


def config(repo: Path | None = None):
    return json.loads((project_dir(repo or Path.cwd()) / 'pz-release.json').read_text())


def image_identity(reference, platform):
    rows = json.loads(run('docker', 'image', 'inspect', reference, capture=True))
    if len(rows) != 1 or rows[0]['Os'] + '/' + rows[0]['Architecture'] != platform:
        raise ContractError('local release image platform differs')
    return rows[0]['Id']



def output_identity(state, component, stage):
    return {key: state[key] for key in ('source_sha', 'source_digest', 'platform', 'recipe_digest')} | {
        'component': component, 'stage': stage}


def export_stage(output, state, component, stage, reference, paths):
    if (not isinstance(paths, list) or not paths
            or any(not isinstance(path, str) or not re.fullmatch(r'/[a-zA-Z0-9_./-]+', path)
                   or any(part in {'', '.', '..'} for part in path[1:].split('/')) for path in paths)):
        raise ContractError('invalid declared build output paths')
    destination = output / 'artifacts' / component / stage
    identity = output_identity(state, component, stage)
    if destination.exists():
        build_outputs.verify(destination, identity)
        return destination.relative_to(output).as_posix()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.export-', dir=destination.parent) as temporary:
        staging = Path(temporary)
        container = run('docker', 'create', reference, 'true', capture=True)
        try:
            for remote in paths:
                local = staging / 'payload' / remote.lstrip('/')
                local.parent.mkdir(parents=True, exist_ok=True)
                run('docker', 'cp', '-L', container + ':' + remote, str(local))
        finally:
            run('docker', 'rm', '-f', container)
        build_outputs.seal(staging, identity)
        staging.rename(destination)
    return destination.relative_to(output).as_posix()

def build(repo: Path | None = None):
    source = Path(os.environ['PZ_ADW_SOURCE_ROOT']).resolve()
    output = Path(os.environ['PZ_ADW_BUILD_DIR']).resolve()
    if output == source or source in output.parents:
        raise ContractError('build output directory must be outside the selected source')
    sha = os.environ['PZ_ADW_SOURCE_SHA']
    platform = os.environ['PZ_ADW_PLATFORM']
    components = json.loads(os.environ['PZ_ADW_COMPONENTS'])
    cfg = config(repo)
    if not FULL_SHA.fullmatch(sha) or platform not in cfg['platforms'] or not components or not set(components) <= set(cfg['components']):
        raise ContractError('invalid release build selection')
    identity = {'source_sha': sha, 'source_root': str(source), 'source_digest': fingerprint(source),
                'platform': platform, 'components': components,
                'recipe_digest': hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()}
    state_path = output / 'build.json'
    state = read(state_path) if state_path.exists() else {'schema_version': '1.0.0', **identity, 'stages': {}}
    if any(state.get(key) != value for key, value in identity.items()):
        raise ContractError('existing build outputs do not match selected source/recipe/platform')
    for name in components:
        recipe = cfg['components'][name]
        dockerfile = ensure_contained(source, recipe['dockerfile'])
        for stage in recipe['stages']:
            key = name + '/' + stage
            if key in state['stages']:
                old = state['stages'][key]
                if old.get('artifacts'):
                    build_outputs.verify(ensure_contained(output, old['artifacts']), output_identity(state, name, stage))
                elif image_identity(old['reference'], platform) != old['image_id']:
                    raise ContractError('retained build stage image changed')
                continue
            reference = 'pz-build:' + uuid4().hex
            caching = cache_plan(cfg.get('docker_cache', {}),
                                 recipe.get('cache_roles', {}).get(stage, name + '-' + stage),
                                 platform, sha, os.environ)
            print('Building ' + key, file=sys.stderr, flush=True)
            run(*caching['command'], '--progress=plain', *caching['arguments'],
                '--platform', platform, '--target', stage, '-t', reference,
                '-f', str(dockerfile), str(ensure_contained(source, recipe['context']) if recipe['context'] != '.' else source),
                log_path=output / 'logs' / (name + '-' + stage + '.log'))
            entry = {'reference': reference, 'image_id': image_identity(reference, platform)}
            if stage in recipe.get('exports', {}):
                entry['artifacts'] = export_stage(output, state, name, stage, reference, recipe['exports'][stage])
            state['stages'][key] = entry
            write(state_path, state)
    write(state_path, state)
    return {'status': 'ok', 'build_dir': str(output), 'source_sha': sha}


def runtime_recipe(text: str, stages: dict[str, str], *, files=False) -> str:
    lines = text.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if re.match(r'^FROM\s', line, re.I)]
    if not starts:
        raise ContractError('release recipe has no runtime stage')
    runtime = ''.join(lines[starts[-1]:])
    references = {name.strip('\"\'') for name in re.findall(r'--from=(\S+)', runtime)}
    # Docker resolves declared stage names locally; every other source is an
    # external image (including untagged Docker Hub names such as nginx).
    declared = {match[1] for index in starts[:-1]
                if (match := re.search(r'\sAS\s+(\S+)\s*$', lines[index], re.I))}
    references &= declared
    if references != set(stages):
        raise ContractError('runtime stage dependencies differ from project build declaration')
    syntax = lines[0] if lines and lines[0].startswith('# syntax=') else ''
    if files:
        return syntax + ''.join(f'FROM scratch AS {name}\nCOPY .adw-build-outputs/{name}/ /\n'
                                for name in stages) + runtime
    return syntax + ''.join(f'FROM {reference} AS {name}\n' for name, reference in stages.items()) + runtime


def package(request: dict, repo: Path | None = None):
    build_dir = Path(request['build_dir']).resolve()
    output = Path(request['output_dir']).resolve()
    state = read(build_dir / 'build.json')
    source = Path(state['source_root'])
    if output == source or source in output.parents:
        raise ContractError('package output directory must be outside the selected source')
    cfg = config(repo)
    if (state['source_sha'] != request['source_sha'] or state['platform'] != request['platform']
            or set(state['components']) != set(request['components'])
            or fingerprint(source) != state['source_digest']
            or hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest() != state['recipe_digest']):
        raise ContractError('package inputs differ from completed build')
    output.mkdir(parents=True, exist_ok=True)
    images = {}
    for name in request['components']:
        recipe = cfg['components'][name]
        stages = {}
        payloads = {}
        for stage in recipe['stages']:
            entry = state['stages'][name + '/' + stage]
            if entry.get('artifacts'):
                bundle = ensure_contained(build_dir, entry['artifacts'])
                build_outputs.verify(bundle, output_identity(state, name, stage))
                payloads[stage] = bundle / 'payload'
            elif image_identity(entry['reference'], state['platform']) != entry['image_id']:
                raise ContractError('package build stage changed')
            stages[stage] = entry.get('reference', 'file-output')
        files = set(payloads) == set(stages)
        if payloads and not files:
            raise ContractError('incomplete stage file handover')
        text = ensure_contained(source, recipe['dockerfile']).read_text()
        generated = output / (name + '.Dockerfile')
        generated.write_text(runtime_recipe(text, stages, files=files))
        # Generated Dockerfiles live outside the context. Preserve the selected
        # recipe's context filter instead of silently falling back to a broader one.
        ignore = ensure_contained(source, recipe['dockerfile'] + '.dockerignore')
        generated_ignore = output / (name + '.Dockerfile.dockerignore')
        if ignore.is_file():
            generated_ignore.write_bytes(ignore.read_bytes())
        else:
            generated_ignore.unlink(missing_ok=True)
        reference = 'pz-package:' + uuid4().hex
        print('Packaging ' + name, file=sys.stderr, flush=True)
        context = source if recipe['context'] == '.' else ensure_contained(source, recipe['context'])
        with tempfile.TemporaryDirectory(prefix='package-context-', dir=output) as temporary:
            if files:
                selected = Path(temporary) / 'source'
                shutil.copytree(context, selected)
                if (selected / '.adw-build-outputs').exists():
                    raise ContractError('source uses the reserved build-output context path')
                for stage, payload in payloads.items():
                    shutil.copytree(payload, selected / '.adw-build-outputs' / stage)
                exclusions = generated_ignore.read_text() if generated_ignore.exists() else (
                    (context / '.dockerignore').read_text() if (context / '.dockerignore').exists() else '')
                generated_ignore.write_text(exclusions + '\n!.adw-build-outputs/\n!.adw-build-outputs/**\n')
                context = selected
                caching = cache_plan(cfg.get('docker_cache', {}), name + '-runtime', state['platform'], state['source_sha'], os.environ)
            else:
                caching = {'command': ['docker', 'build'], 'arguments': []}
            run(*caching['command'], '--progress=plain', *caching['arguments'], '--platform', state['platform'],
                '--label', 'org.opencontainers.image.revision=' + state['source_sha'],
                '--build-arg', 'APPLICATION_SHA=' + state['source_sha'], '-t', reference,
                '-f', str(generated), str(context), log_path=output / 'logs' / (name + '.log'))
        images[name] = {'reference': reference, 'image_id': image_identity(reference, state['platform'])}
    return {'images': images}


def command(repo: Path, operation: str) -> list[str]:
    """Resolve the fixed default; projects may retain their existing package hook."""
    cfg = config(repo)
    if operation == 'package' and 'package_hook' in cfg:
        argv = cfg['package_hook']
        if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) and arg for arg in argv):
            raise ContractError('package hook declaration invalid')
        return argv
    if operation not in {'build', 'package'} or cfg.get('hooks', {}).get('build') != 'bundle:release_build':
        raise ContractError('release build hook declaration invalid')
    return [sys.executable, str(Path(__file__).resolve()), operation]


if __name__ == '__main__':

    try:
        if sys.argv[1:] not in (['build'], ['package']):
            raise ContractError('release build operation invalid')
        value = package(json.load(sys.stdin)) if sys.argv[1:] == ['package'] else build()
        print(json.dumps(value))
    except (ContractError, OSError, ValueError, KeyError):
        print(json.dumps({'status': 'blocked', 'reason': 'release build/package failed'}))
        raise SystemExit(21)

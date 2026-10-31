"""Local quality task facade over the generic contract and sealed output module."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from . import quality_outputs as outputs
from .ci import build_artifacts
from .ci.github_api import ApiError
from .common import project_dir
from .common import ContractError, json_result, load_json

TASKS = ('pz:quality:export', 'pz:quality:import')

# Public, fixed local refusals only; external exceptions keep the generic reason.
QUALITY_CONTRACT_REASONS = frozenset({
    'CI artifact import requires the hosted repository context',
    'CI build import requires exact authorized producer binding',
    'CI quality source contains untracked files',
    'build archive destination already exists',
    'build import destination already exists',
    'build payload directory is missing or linked',
    'build payload is empty',
    'build payload must contain regular files, not links or special files',
    'bundle path escapes its root',
    'bundle path is empty or invalid',
    'declared quality output is unavailable',
    'human build import does not accept CI authorization metadata',
    'invalid quality component declaration',
    'invalid quality output component name',
    'operation state must not be a symlink',
    'project_directory_conflict',
    'quality artifact contains unrelated component outputs',
    'quality bundle contract/context differs',
    'quality bundle is incompatible with selected release inputs',
    'quality bundle is missing required stage outputs',
    'quality checkout differs from selected source',
    'quality component identities differ',
    'quality component producers differ',
    'quality component selection is invalid',
    'quality export CI producer context is incomplete',
    'quality export is missing a declared build stage',
    'quality output destination exists or overlaps the build workspace',
    'quality output must not be linked',
    'quality output platform is not supported by release recipes',
    'quality outputs require the declared Java 21 and Node 22 toolchain',
    'quality source changed during verification',
    'quality_ci_execution_required',
    'quality_native_provenance_invalid',
    'quality_native_provenance_mismatch',
    'quality_output_path_invalid',
    'quality_toolchain_invalid',
    'quality_verification_graph_invalid',
    'quality_workspace_git_ancestry',
    'release source file is missing or linked',
    'release source must not contain symlinks',
})


def emit_upload_manifest(archive: Path, env: dict) -> None:
    if env.get('GITHUB_OUTPUT'):
        if '\n' in str(archive) or '\r' in str(archive):
            raise ContractError('quality_output_path_invalid')
        with open(env['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('build_upload_manifest=' + str(archive) + '\n')


def engine(repo):
    path = repo / 'mise-helper/vendor/agentic-delivery/adw_contract.py'
    spec = importlib.util.spec_from_file_location('_pz_generic_quality_contract', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _git_ancestor(root: Path) -> Path | None:
    return next((parent / '.git' for parent in (root, *root.parents)
                 if (parent / '.git').exists() or (parent / '.git').is_symlink()), None)


def _prune_workspaces(root: Path) -> None:
    """Reclaim old interrupted copies, without following links or deleting live owners."""
    cutoff = time.time() - 86400
    for index, entry in enumerate(root.iterdir()):
        if index >= 256:
            break
        try:
            if (not entry.name.startswith(('pz-quality-workspace-', 'pz-project-workspace-'))
                    or entry.is_symlink() or not entry.is_dir()
                    or entry.stat().st_uid != os.getuid() or entry.stat().st_mtime >= cutoff):
                continue
            owner = entry / '.owner-pid'
            if owner.is_symlink():
                continue
            if owner.exists():
                if not owner.is_file() or owner.stat().st_size > 32:
                    continue
                pid = int(owner.read_text())
                if pid <= 0:
                    continue
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    continue
            shutil.rmtree(entry)
        except (OSError, ValueError, OverflowError):
            continue


def temporary_workspace(prefix: str):
    """Keep copied source outside Git ancestry, including tools' own VCS walks."""
    rejected = []
    for location in ('temporary', 'cache'):
        candidate = None
        try:
            if location == 'temporary':
                candidate = Path(tempfile.gettempdir())
            else:
                configured = os.environ.get('XDG_CACHE_HOME') or ''
                cache = Path(configured) if Path(configured).is_absolute() else Path.home() / '.cache'
                candidate = cache / 'pzagent-adw-context' / 'workspaces'
            root = candidate.resolve()
            marker = _git_ancestor(root)
            if marker is not None:
                rejected.append({'root': str(root), 'reason': 'git_ancestor', 'marker': str(marker)})
                continue
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            if location == 'cache':
                try:
                    _prune_workspaces(root)
                except OSError:
                    pass  # Optional reclamation must not prevent an otherwise usable allocation.
            workspace = tempfile.TemporaryDirectory(prefix=prefix, dir=root)
            try:
                (Path(workspace.name) / '.owner-pid').write_text(str(os.getpid()) + '\n')
            except BaseException:
                workspace.cleanup()
                raise
            return workspace
        except (OSError, RuntimeError):
            rejected.append({'root': str(candidate) if candidate is not None else location, 'reason': 'unavailable'})
            continue
    print(json.dumps({'reason': 'quality_workspace_git_ancestry', 'candidates': rejected}), file=sys.stderr)
    raise ContractError('quality_workspace_git_ancestry')


def verify(repo: Path, mode: str, env: dict) -> None:
    manifest = load_json(project_dir(repo) / 'adw-task-manifest.json')
    children = manifest['verification']['full']
    forbidden = {'adw:verify:full', 'adw:test:integration:full', 'adw:test:e2e:fast', 'adw:test:e2e:full'}
    if not children or len(children) != len(set(children)) or forbidden.intersection(children):
        raise ContractError('quality_verification_graph_invalid')
    with temporary_workspace(prefix='pz-quality-workspace-') as raw:
        workspace = Path(raw) / 'source'
        workspace.mkdir()
        for relative in outputs.source_files(repo):
            destination = workspace / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(repo / relative, destination)
        child_env = dict(env, ADW_SHARED_WORKSPACE=str(workspace))
        # Installation is required even when omitted from the quality evidence graph.
        tasks = ['adw:install'] + [task for task in children if task != 'adw:install']
        for task in tasks:
            subprocess.run(['mise', 'run', task], cwd=repo, env=child_env, check=True,
                           stdout=sys.stderr)
        if mode == 'ci' and env.get('ADW_BUILD_OUTPUT_DIR'):
            archive = outputs.export_quality(repo, workspace, Path(env['ADW_BUILD_OUTPUT_DIR']).resolve(), env, split=True)
            emit_upload_manifest(archive, env)


def dispatch(args) -> int:
    try:
        repo = args.repo_root.resolve()
        env = dict(os.environ)
        if args.command == 'quality-leaves':
            verify(repo, args.execution_mode, env)
            return 0
        if args.command == 'context-describe':
            result = engine(repo).describe(repo)
            if result.exit_code:
                print(json.dumps(result.payload, sort_keys=True))
                return result.exit_code
            report = dict(result.payload)
            report['context_tasks'] = {task: {'source': 'context', 'side_effect': 'local-write'}
                                       for task in (*TASKS, 'pz:workflows:sync')}
            print(json.dumps(report, sort_keys=True))
        elif args.command == 'quality-export':
            path = outputs.export_quality(repo, args.workspace.resolve(), args.output.resolve(), env, split=True)
            if args.execution_mode == 'ci':
                emit_upload_manifest(path, env)
            print(json_result(status='ok', upload_manifest=str(path)))
        elif args.command == 'quality-import':
            request = json.load(sys.stdin)
            if args.fetch_ci:
                if args.execution_mode != 'ci':
                    raise ContractError('quality_ci_execution_required')
                result = outputs.import_ci(repo, Path(request['source_root']), Path(request['output_dir']),
                    request['components'], build_artifacts.Producer(**request['producer']), env)
            else:
                result = outputs.import_quality(repo, Path(request['archive']), Path(request['source_root']),
                    Path(request['output_dir']), request['source_sha'], request['components'], env,
                    request.get('expected_producer'))
                result = {'status': 'ok', 'source_sha': result['source_sha'], 'components': result['components']}
            print(json_result(**result))
        else:
            generic = engine(repo)
            manifest = load_json(project_dir(repo) / 'adw-task-manifest.json')
            # The generic engine owns aggregate and child evidence validation.
            command = [sys.executable, str(Path(__file__).resolve().parents[1] / 'pzagent_context.py'),
                       'quality-leaves', '--repo-root', str(repo), '--execution-mode', args.execution_mode]
            result = generic.run_command(repo, 'adw:verify:full', command=command,
                                      children=manifest['verification']['full'])
            print(json.dumps(result.payload or result.evidence, sort_keys=True))
            return result.exit_code
        return 0
    except ContractError as exc:
        # Never echo paths, response bodies or other data carried by a foreign exception.
        reason = str(exc) if str(exc) in QUALITY_CONTRACT_REASONS else 'quality_task_failed'
        print(json_result(status='blocked', reason=reason))
        return 21
    except (ApiError, OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError):
        print(json_result(status='blocked', reason='quality_task_failed'))
        return 21

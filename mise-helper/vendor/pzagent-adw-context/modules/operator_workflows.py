"""Human release selection and thin local orchestration of canonical ADW tasks."""
import json
import os
from pathlib import Path
import subprocess
import sys

from .common import ContractError
from .operator_credentials import clean_environment, DOKPLOY, SSH, REGISTRY, KUBE
from .operator_registry import inspect
from .operator_sources import resolve
from .operator_state import locked, new_operation, read, write
from .oras_registry import OrasRegistry


def selection(repo, adapter, args):
    sha = resolve(repo, args.ref, args.remote) if args.ref else None
    return inspect(adapter, args.kind, source_sha=sha, release_reference=args.release_ref)


def adw(repo: Path, task: str, arguments: list[str]) -> dict:
    """Call the public task, preserving the shared implementation and exit code."""
    child = clean_environment()
    child.update({key: os.environ[key] for key in DOKPLOY | SSH | KUBE if key in os.environ})
    if task in {'adw:deploy:apply', 'adw:deploy:config:plan', 'adw:deploy:config:apply'}:
        child.update({key: os.environ[key] for key in REGISTRY if key in os.environ})
    result = subprocess.run(['mise', 'run', task, '--', *arguments], cwd=repo,
                            capture_output=True, text=True, env=child)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ContractError('ADW child did not return JSON; check mise version and task installation') from exc
    if not isinstance(value, dict):
        raise ContractError('ADW child returned an invalid result')
    if result.returncode:
        # Children expose bounded reasons; never surface raw subprocess stderr.
        raise ContractError(value.get('reason', 'ADW child failed'))
    return value


def deploy_existing(repo: Path, adapter: dict, args) -> dict:
    directory = args.operation_dir or new_operation(repo)
    directory = directory.resolve()
    with locked(directory):
        path = directory / 'operation.json'
        if path.exists():
            record = read(path)
            if args.command != 'workflow-resume':
                raise ContractError('operation already exists; use workflow resume or start a new operation')
            if record.get('workflow') != 'deploy-existing':
                raise ContractError('operation is not a deployment workflow')
            selected = inspect(adapter, record['kind'], release_reference=record['release_reference'])
        else:
            selected = selection(repo, adapter, args)
            if not selected['available']:
                raise ContractError('selected version has no complete published release; publish this exact revision first')
            record = {'schema_version': '1.0.0', 'workflow': 'deploy-existing',
                      'kind': args.kind, 'environment': args.environment, 'target': args.target,
                      'source_sha': selected['source_sha'], 'release_reference': selected['release_reference'],
                      'sync_config': args.sync_config, 'config_ref': args.config_ref or selected['source_sha'],
                      'remote': args.remote,
                      'verify': args.verify, 'phase': 'selected', 'results': {}}
            record['on_failure'] = getattr(args, 'on_failure', 'stop')
            write(path, record)
        if not selected['available']:
            raise ContractError('recorded release is no longer completely available')
        write(directory / 'manifest.json', selected['manifest'])
        arguments = [record['environment']]
        if record['target']:
            arguments += ['--target', record['target']]
        if args.env_file:
            arguments += ['--env-file', str(args.env_file.resolve())]
        if args.profile_root:
            arguments += ['--profile-root', str(args.profile_root.resolve())]
        def run(name, task, extra):
            if name in record['results']:
                return record['results'][name]
            record['phase'] = name
            write(path, record)
            value = adw(repo, task, [*arguments, *extra])
            record['results'][name] = value
            write(path, record)
            return value
        try:
            if record['sync_config']:
                config_arguments = ['--ref', record['config_ref']]
                # Older journals used origin; resume must retain the selected
                # remote even when the caller supplies only the operation path.
                if record.get('remote', 'origin') != 'origin':
                    config_arguments += ['--remote', record['remote']]
                run('config-plan', 'adw:deploy:config:plan', config_arguments)
                run('config-apply', 'adw:deploy:config:apply', [*config_arguments,
                    '--snapshot-path', str(directory / 'previous-compose.yml')])
            # Re-enter a deployment with its journal when resuming; it reads back
            # uncertain provider writes and never blindly resubmits a deployment.
            recovery = ['--reconcile-pointers'] if getattr(args, 'reconcile_pointers', False) else []
            config_restore = (['--restore-compose', str(directory / 'previous-compose.yml')]
                              if record['sync_config'] else [])
            run('deploy', 'adw:deploy:apply', ['--kind', record['kind'],
                '--release-ref', record['release_reference'], '--operation-dir', str(directory / 'deploy'),
                '--on-failure', record.get('on_failure', 'stop'), *config_restore, *recovery])
            if record['verify']:
                run('validate', 'adw:validate-deployment', [])
            record['phase'] = 'complete'
            record['status'] = 'ok'
            record.pop('reason', None)
            write(path, record)
        except Exception:
            record['status'] = 'incomplete'
            record['reason'] = 'inspect the recorded stage and explicitly resume'
            write(path, record)
            print('Operation retained at ' + str(directory), file=sys.stderr)
            raise
        return {'status': 'ok', 'operation_dir': str(directory),
                'release_reference': record['release_reference'], 'environment': record['environment'],
                'results': record['results']}


def rollback(repo: Path, adapter: dict, args) -> dict:
    group = adapter['targets'].get(args.environment)
    if not group or (args.target or group['default']) not in group['items']:
        raise ContractError('unknown rollback target')
    target = args.target or group['default']
    kind = adapter['release_kinds'][args.kind]
    pointer = kind['manifest_package'] + ':' + kind['pointer_tags']['rollback'].format(target=target)
    digest = OrasRegistry().resolve(pointer)
    if digest is None:
        raise ContractError('target has no retained rollback release')
    args.release_ref = kind['manifest_package'] + '@' + digest
    args.ref = None
    # Optional config sync follows the selected immutable release source SHA.
    # Keep the caller choice; deploy_existing records it for interruption/resume.
    args.config_ref = None
    return deploy_existing(repo, adapter, args)

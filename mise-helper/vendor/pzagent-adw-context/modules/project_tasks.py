"""Declarative local project commands; quality authority stays with the contract."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from uuid import uuid4

if __package__ in {None, ''}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.common import ContractError, ensure_contained, load_json, project_dir
from modules.quality_outputs import source_files
from modules.quality_tasks import engine
from modules.operator_credentials import KEYS, clean_environment, bootstrap_keys
from modules import task_evidence

PROJECT_TASKS = ('adw:install', 'adw:build', 'adw:lint', 'adw:static-analysis',
                 'adw:test:unit', 'adw:test:integration:fast',
                 'adw:test:integration:full', 'adw:verify:minimal')
TASK_OPTIONS = {'implemented', 'commands', 'release_commands', 'isolated_workspace',
                'env', 'unset_env', 'inherit_env', 'inherit_env_reason', 'reports', 'report_prefix', 'maven_cache', 'cache_env'}
COMMAND_OPTIONS = {'argv', 'cwd', 'env', 'stdout_file', 'workspace_pattern'}
ENV_KEY = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
OPERATOR_ENV = KEYS | {
    'DOCKER_CONFIG', 'DOCKER_AUTH_CONFIG', 'REGISTRY_AUTH_FILE', 'ORAS_CONFIG',
    'SSH_AUTH_SOCK', 'SSH_AGENT_PID', 'PZ_ADW_APPROVAL_FILE', 'PZ_ADW_APPROVAL_NONCE',
}


class ProjectParser(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps({'status': 'blocked', 'reason': 'project_usage_invalid'}))
        raise SystemExit(20)


def _strings(value):
    return isinstance(value, list) and all(isinstance(v, str) and v for v in value)


def _environment(value):
    return isinstance(value, dict) and all(ENV_KEY.fullmatch(k) and isinstance(v, str)
                                          for k, v in value.items())


def inheritance(task: dict) -> set[str]:
    keys = task.get('inherit_env', [])
    reason = task.get('inherit_env_reason', '')
    if (not _strings(keys) or len(keys) != len(set(keys))
            or not all(ENV_KEY.fullmatch(key) for key in keys)
            or not isinstance(reason, str) or len(reason) > 240
            or bool(keys) != bool(reason.strip()) or '\n' in reason or '\r' in reason):
        raise ContractError('project_operator_environment_not_declared')
    return set(keys)


def load(repo: Path) -> dict:
    path = repo / 'mise-helper/project-commands.toml'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1048576:
        raise ContractError('project_commands_unavailable')
    try:
        config = tomllib.loads(path.read_text())
    except (ValueError, OSError):
        raise ContractError('project_commands_invalid') from None
    if (set(config) - {'schema_version', 'defaults', 'tasks'}
            or config.get('schema_version') != '1.0.0'
            or not isinstance(config.get('tasks'), dict)
            or set(config['tasks']) != set(PROJECT_TASKS)):
        raise ContractError('project_commands_invalid')
    defaults = config.get('defaults', {})
    if not isinstance(defaults, dict) or set(defaults) - (TASK_OPTIONS - {'implemented', 'commands', 'release_commands', 'inherit_env', 'inherit_env_reason'}):
        raise ContractError('project_commands_invalid')
    for name, declaration in config['tasks'].items():
        if not isinstance(declaration, dict) or set(declaration) - TASK_OPTIONS:
            raise ContractError('project_commands_invalid')
        task = {**defaults, **declaration}
        for key in ('env', 'cache_env'):
            if not _environment(defaults.get(key, {})) or not _environment(declaration.get(key, {})):
                raise ContractError('project_commands_invalid')
            task[key] = {**defaults.get(key, {}), **declaration.get(key, {})}
        if not _strings(defaults.get('unset_env', [])) or not _strings(declaration.get('unset_env', [])):
            raise ContractError('project_commands_invalid')
        task['unset_env'] = list(dict.fromkeys([*defaults.get('unset_env', []), *declaration.get('unset_env', [])]))
        if (not isinstance(task.get('implemented'), bool)
                or task.get('isolated_workspace', 'none') not in {'maven', 'none'}
                or not _environment(task.get('env', {}))
                or not _environment(task.get('cache_env', {}))
                or not _strings(task.get('unset_env', []))
                or not _strings(task.get('inherit_env', []))
                or not _strings(task.get('reports', []))
                or not isinstance(task.get('report_prefix', ''), str)
                or not isinstance(task.get('maven_cache', False), bool)):
            raise ContractError('project_commands_invalid')
        inherited = inheritance(task)
        if (set(task.get('env', {})) | set(task.get('cache_env', {}))) & (OPERATOR_ENV - inherited):
            raise ContractError('project_commands_invalid')
        for variable in task.get('unset_env', []):
            if not ENV_KEY.fullmatch(variable.rstrip('*')) or '*' in variable[:-1]:
                raise ContractError('project_commands_invalid')
        for pattern in task.get('reports', []):
            if Path(pattern).is_absolute() or '..' in Path(pattern).parts:
                raise ContractError('project_commands_invalid')
        if task.get('report_prefix'):
            ensure_contained(repo, task['report_prefix'])
        for kind in ('commands', 'release_commands'):
            commands = task.get(kind, [])
            if not isinstance(commands, list) or (task['implemented'] and kind == 'commands' and not commands):
                raise ContractError('project_commands_invalid')
            for command in commands:
                if (not isinstance(command, dict) or set(command) - COMMAND_OPTIONS
                        or not _strings(command.get('argv')) or not command['argv']
                        or command.get('cwd', 'workspace') not in {'workspace', 'repository'}
                        or not _environment(command.get('env', {}))):
                    raise ContractError('project_commands_invalid')
                if set(command.get('env', {})) & (OPERATOR_ENV - inherited):
                    raise ContractError('project_commands_invalid')
                if 'stdout_file' in command:
                    ensure_contained(repo, command['stdout_file'])
                if 'workspace_pattern' in command:
                    try:
                        pattern = re.compile(command['workspace_pattern'], re.MULTILINE)
                    except (TypeError, re.error):
                        raise ContractError('project_commands_invalid') from None
                    if pattern.groups != 1:
                        raise ContractError('project_commands_invalid')
        config['tasks'][name] = task
    return config


@contextmanager
def workspace(repo: Path, isolation: str):
    shared = os.environ.get('ADW_SHARED_WORKSPACE')
    if shared:
        path = Path(shared).resolve()
        if not path.is_dir():
            raise ContractError('project_workspace_unavailable')
        yield path
    elif isolation == 'none':
        yield repo
    else:
        with tempfile.TemporaryDirectory(prefix='pz-project-workspace-') as raw:
            destination = Path(raw) / 'source'
            destination.mkdir()
            for relative in source_files(repo):
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(repo / relative, target)
            yield destination


def timing(task: str, kind: str, name: str, started: float, passed: bool):
    directory = os.environ.get('ADW_TIMING_DIR')
    if not directory:
        return
    value = {'schema_version': '1.0.0', 'kind': kind,
             'task': task.removeprefix('adw:').replace(':', '-'), 'name': name,
             'wall_seconds': round(time.perf_counter() - started, 6),
             'status': 'passed' if passed else 'failed'}
    try:
        output = Path(directory)
        output.mkdir(parents=True, exist_ok=True)
        (output / (uuid4().hex + '.json')).write_text(json.dumps(value, sort_keys=True) + '\n')
    except OSError:
        print('ADW timing attachment could not be written', file=sys.stderr)


def reports(source: Path, patterns: list[str], prefix: str = ''):
    output = os.environ.get('ADW_TEST_REPORT_DIR')
    if not output:
        return
    destination = Path(output).resolve()
    if prefix:
        destination = ensure_contained(destination, prefix)
    for pattern in patterns:
        if Path(pattern).is_absolute() or '..' in Path(pattern).parts:
            raise ContractError('project_report_path_invalid')
        for path in source.glob(pattern):
            if path.is_symlink() or not path.is_file():
                continue
            if source.resolve() not in path.resolve().parents:
                raise ContractError('project_report_path_invalid')
            relative = path.relative_to(source)
            target = destination / relative
            if destination not in target.resolve().parents:
                raise ContractError('project_report_path_invalid')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def expand(value: str, context: dict[str, str]) -> str:
    for key, replacement in context.items():
        value = value.replace('{' + key + '}', replacement)
    return value


def bindings(values: dict, task: dict, context: dict) -> dict:
    if set(values) & bootstrap_keys():
        raise ContractError('project_bootstrap_environment_refused')
    if set(values) & (OPERATOR_ENV - inheritance(task)):
        raise ContractError('project_operator_environment_not_declared')
    return {key: expand(value, context) for key, value in values.items()}


def environment(task: dict, context: dict[str, str]) -> dict:
    if inheritance(task) & bootstrap_keys():
        raise ContractError('project_bootstrap_environment_refused')
    env = clean_environment()
    for key in OPERATOR_ENV:
        env.pop(key, None)
    for key in inheritance(task):
        if key in os.environ:
            env[key] = os.environ[key]
    for pattern in task.get('unset_env', []):
        for key in list(env):
            if key.startswith(pattern[:-1]) if pattern.endswith('*') else key == pattern:
                del env[key]
    env.update(bindings(task.get('env', {}), task, context))
    return env


def _maven_cache(repo: Path, env: dict, context: dict) -> list[str]:
    options = []
    if env.get('ADW_DEPENDENCY_CACHE_ROOT'):
        from modules.dependency_cache import cache_root
        cache = cache_root(repo, Path(env['ADW_DEPENDENCY_CACHE_ROOT']))
        cache.mkdir(parents=True, exist_ok=True)
        env.update(MAVEN_USER_HOME=str(cache / 'maven-user'), npm_config_cache=str(cache / 'npm'))
        context['dependency_cache'] = str(cache)
        options += ['--strict-checksums', '-Dmaven.repo.local=' + str(cache / 'maven')]
    if env.get('ADW_BUILD_CACHE_ROOT'):
        options += ['-Dmaven.build.cache.location=' + str(Path(env['ADW_BUILD_CACHE_ROOT']) / 'maven')]
    return options


def execute(repo: Path, name: str, config: dict):
    task = config['tasks'][name]
    started = time.perf_counter()
    passed = False
    try:
        with workspace(repo, task.get('isolated_workspace', 'none')) as selected:
            context = {'repository': str(repo), 'workspace': str(selected),
                       'command_workspace': str(selected), 'task': name}
            env = environment(task, context)
            if name == 'adw:verify:minimal':
                env['ADW_SHARED_WORKSPACE'] = str(selected)
            maven_options = _maven_cache(repo, env, context) if task.get('maven_cache') else []
            if 'dependency_cache' in context:
                for key, value in task.get('cache_env', {}).items():
                    env.setdefault(key, bindings({key: value}, task, context)[key])
            commands = (task.get('release_commands') if env.get('PZ_ADW_BUILD_DIR') else None) or task['commands']
            report_source = selected
            try:
                for command in commands:
                    argv = [expand(value, context) for value in command['argv']]
                    if Path(argv[0]).name in {'mvn', 'mvnw'}:
                        argv[1:1] = maven_options
                    cwd = repo if command.get('cwd') == 'repository' else selected
                    child_env = {**env, **bindings(command.get('env', {}), task, context)}
                    capture = 'stdout_file' in command or 'workspace_pattern' in command
                    command_started = time.perf_counter()
                    command_passed = False
                    try:
                        result = subprocess.run(argv, cwd=cwd, env=child_env, text=True,
                                                stdout=subprocess.PIPE if capture else sys.stderr,
                                                stderr=subprocess.STDOUT if capture else None)
                        if capture:
                            print(result.stdout, file=sys.stderr, end='')
                        if 'stdout_file' in command:
                            log = ensure_contained(selected, command['stdout_file'])
                            log.parent.mkdir(parents=True, exist_ok=True)
                            log.write_text(result.stdout)
                        if 'workspace_pattern' in command:
                            match = re.search(command['workspace_pattern'], result.stdout, re.MULTILINE)
                            if match and Path(match.group(1)).is_dir():
                                report_source = Path(match.group(1)).resolve()
                                context['command_workspace'] = str(report_source)
                            elif result.returncode == 0:
                                raise ContractError('project_command_workspace_unavailable')
                        result.check_returncode()
                        command_passed = True
                    finally:
                        timing(name, 'command', Path(argv[0]).name, command_started, command_passed)
            finally:
                reports(report_source, task.get('reports', []), task.get('report_prefix', ''))
        passed = True
    finally:
        timing(name, 'task', name.removeprefix('adw:').replace(':', '-'), started, passed)


def main(argv=None):
    parser = ProjectParser(description=__doc__)
    parser.add_argument('task', choices=PROJECT_TASKS)
    parser.add_argument('--repo-root', type=Path, default=Path('.'))
    parser.add_argument('--execute', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    repo = args.repo_root.resolve()
    started = task_evidence.now()
    try:
        config = load(repo)
        missing = [name for name, declaration in config['tasks'].items() if not declaration['implemented']]
        if not config['tasks'][args.task]['implemented'] or (args.task == 'adw:verify:minimal' and missing):
            result = {'status': 'blocked', 'reason': args.task + ' not implemented: see mise-helper/README.md',
                      'unimplemented_tasks': missing}
            task_evidence.record(repo, task=args.task, identifier=task_evidence.run_id(),
                                 started_at=started, exit_code=21, result=result, environment=None, target=None)
            print(json.dumps(result, sort_keys=True))
            return 21
        if args.execute:
            execute(repo, args.task, config)
            return 0
        generic = engine(repo)
        manifest = load_json(project_dir(repo) / 'adw-task-manifest.json')
        children = manifest['verification']['minimal'] if args.task == 'adw:verify:minimal' else []
        result = generic.run_command(repo, args.task,
            command=[sys.executable, str(Path(__file__).resolve()), args.task, '--repo-root', str(repo), '--execute'],
            children=children)
        print(json.dumps(result.payload or result.evidence, sort_keys=True))
        return result.exit_code
    except (ContractError, KeyError, ValueError, OSError, subprocess.CalledProcessError):
        result = {'status': 'blocked', 'reason': 'project_task_failed'}
        if not args.execute:
            try:
                task_evidence.record(repo, task=args.task, identifier=task_evidence.run_id(),
                    started_at=started, exit_code=21, result=result, environment=None, target=None)
            except (ContractError, OSError):
                pass
        print(json.dumps(result), file=sys.stderr if args.execute else sys.stdout)
        return 21


if __name__ == '__main__':
    raise SystemExit(main())

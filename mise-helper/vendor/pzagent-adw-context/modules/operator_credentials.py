"""Vault-backed, operation-scoped credentials: explicit process values, then the vault (#193)."""
from contextlib import contextmanager
import os
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

from .common import ContractError

GROUPS = (('DOKPLOY_API_KEY', 'DOKPLOY_TOKEN'), ('GITHUB_TOKEN', 'GH_TOKEN'))
DOKPLOY = {'DOKPLOY_URL', 'DOKPLOY_API_KEY', 'DOKPLOY_TOKEN'}
REGISTRY = {'GITHUB_TOKEN', 'GH_TOKEN', 'REGISTRY_TOKEN'}
SSH = {'PZ_ADW_SSH_ALIAS', 'TERMINAL_SSH_HOST', 'TERMINAL_SSH_USER',
       'TERMINAL_SSH_PORT', 'TERMINAL_SSH_KEY'}
KUBE = {'KUBECONFIG', 'PZ_ADW_KUBE_CONTEXT', 'PZ_ADW_PROFILE_ROOT'}
CLOUDFLARE = {'CF_DNS_API_TOKEN'}
CLUSTER_ONLY = {'ACME_EMAIL', 'PZ_ADW_K3D_BIND_ADDRESS'}
BOOTSTRAP = CLOUDFLARE | CLUSTER_ONLY | {'GHCR_USERNAME', 'GHCR_PULL_TOKEN'}
KEYS = DOKPLOY | REGISTRY | SSH | KUBE | BOOTSTRAP
CREDENTIAL_FREE = 'PZ_ADW_CREDENTIAL_FREE'


AGENT_CONTEXT = ('AGENT_ID', 'HERDR_TAB_ID', 'CLAUDE_CODE_SESSION_ID', 'CODEX_SESSION_ID')
OPERATOR_SESSION = 'PZ_SECRETCTL_OPERATOR_SESSION'


def secretctl_selector(parent: dict[str, str]) -> list[str]:
    """`--operator <id>` for a human terminal with an unlocked pz-secretctl session, else nothing.

    Any agent context (AGENT_ID, a Herdr tab or an agent CLI session) uses its own
    agent identity and never an operator session, even one it inherited by accident.
    """
    raw = parent.get(OPERATOR_SESSION)
    if not raw or any(parent.get(name) for name in AGENT_CONTEXT):
        return []
    try:
        name = json.loads(raw)['id']
    except (ValueError, TypeError, KeyError):
        raise ContractError('vault_operator_session_invalid') from None
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name):
        raise ContractError('vault_operator_session_invalid')
    return ['--operator', name]


def vault_values(keys: set[str], parent: dict[str, str], *, operator: str | None = None) -> dict[str, str]:
    """Read only requested IDs through secretctl; subprocess output stays in memory.

    A human terminal with an unlocked pz-secretctl session reads through
    `--operator <id>` (secretctl_selector); it never selects an agent or the
    recovery identity. An explicit `operator` must match this shell's session.
    """
    if not keys:
        return {}
    selector = secretctl_selector(parent)
    if operator is not None and selector != ['--operator', operator]:
        # An explicitly requested operator never falls back to an agent identity.
        raise ContractError('vault_operator_session_unavailable')
    binary = shutil.which(parent.get('PZ_ADW_SECRETCTL', 'pz-secretctl'),
                          path=parent.get('PATH', os.defpath))
    if binary is None:
        return {}
    try:
        selected = []
        for key in sorted(keys):
            result = subprocess.run([binary, *selector, 'show', key], env=parent,
                                    capture_output=True, timeout=30)
            if result.returncode == 3:  # Not in this identity's own/shared catalog.
                continue
            if result.returncode:
                raise ContractError('vault_credential_lookup_failed')
            selected.append(key)
        if not selected:
            return {}
        command = [binary, *selector, 'run']
        for key in selected:
            command.extend(['--env', key + '=' + key])
        # Only variable names enter argv. No get, shell, plaintext file or value
        # reaches the caller's output, evidence, exception text or parent shell.
        command.extend(['--', sys.executable, '-I', '-c',
                        'import json,os,sys;json.dump({k:os.environ[k] for k in sys.argv[1:]},sys.stdout)',
                        *selected])
        result = subprocess.run(command, env=parent, capture_output=True, timeout=60)
        if result.returncode or len(result.stdout) > 1024 * 1024:
            raise ContractError('vault_credential_read_failed')
        values = json.loads(result.stdout)
        if (not isinstance(values, dict) or set(values) != set(selected)
                or any(not isinstance(value, str) or '\x00' in value for value in values.values())):
            raise ContractError('vault_credential_response_invalid')
        return values
    except ContractError:
        raise
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        raise ContractError('vault_credential_read_failed') from None


VAULT_ID = re.compile(r'^[A-Za-z][A-Za-z0-9_.-]{0,127}$')
VAULT_SCOPE = re.compile(r'^shared/[a-z][a-z0-9-]{0,62}$')
GENERATE_KINDS = {'password', 'hex', 'base64url'}


def _secretctl(parent: dict[str, str]) -> str:
    binary = shutil.which(parent.get('PZ_ADW_SECRETCTL', 'pz-secretctl'), path=parent.get('PATH', os.defpath))
    if binary is None:
        raise ContractError('vault_unavailable: pz-secretctl is not installed')
    return binary


def vault_secrets(ids: set[str], parent: dict[str, str], *,
                  locations: dict[str, str] | None = None) -> tuple[dict[str, str], set[str]]:
    """Read namespaced shared vault IDs; returns (values by ID, IDs the vault does not hold).

    Application values live in the shared scope only (`--scope shared`), so an agent's
    own entry of the same ID never shadows them. `locations` receives each present ID's
    vault (`shared/<vault>`). IDs map to synthetic variable names for `pz-secretctl run`,
    so only names enter argv and values only ever exist in this process's memory.
    """
    if any(not isinstance(item, str) or not VAULT_ID.fullmatch(item) for item in ids):
        raise ContractError('vault_id_invalid')
    if not ids:
        return {}, set()
    binary, selector = _secretctl(parent), secretctl_selector(parent)
    try:
        present, missing = [], set()
        for item in sorted(ids):
            result = subprocess.run([binary, *selector, 'show', item, '--scope', 'shared'], env=parent,
                                    capture_output=True, timeout=30)
            if result.returncode == 3:
                missing.add(item)
            elif result.returncode:
                raise ContractError('vault_unavailable: no vault identity here (an agent identity, or the '
                                    'operator unlock once pz-secretctl offers it)')
            else:
                present.append(item)
                found = re.search(r'^scope:\s+shared \((shared/[A-Za-z0-9._-]+)\)\s*$',
                                  result.stdout.decode(errors='replace'), re.M)
                if locations is not None and found:
                    locations[item] = found[1]
        if not present:
            return {}, missing
        names = {f'PZ_ADW_VAULT_{index}': item for index, item in enumerate(present)}
        command = [binary, *selector, 'run', '--scope', 'shared']
        for name, item in names.items():
            command.extend(['--env', item + '=' + name])
        command.extend(['--', sys.executable, '-I', '-c',
                        'import json,os,sys;json.dump({k:os.environ[k] for k in sys.argv[1:]},sys.stdout)', *names])
        result = subprocess.run(command, env=parent, capture_output=True, timeout=60)
        if result.returncode or len(result.stdout) > 8 * 1024 * 1024:
            raise ContractError('vault_credential_read_failed')
        values = json.loads(result.stdout)
        if (not isinstance(values, dict) or set(values) != set(names)
                or any(not isinstance(value, str) or '\x00' in value for value in values.values())):
            raise ContractError('vault_credential_response_invalid')
        return {names[name]: value for name, value in values.items()}, missing
    except ContractError:
        raise
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        raise ContractError('vault_credential_read_failed') from None


def entry_command(scope: str, item: str, description: str, parent: dict[str, str]) -> str | None:
    """The exact `secret add` a person runs, with the acting identity's literal ID; None if unknown.

    The arguments are shell-quoted, so a description can never execute when pasted.
    """
    selector = secretctl_selector(parent)
    if not selector:
        try:
            result = subprocess.run([_secretctl(parent), 'whoami'], env=parent, capture_output=True, timeout=30)
        except (ContractError, OSError, subprocess.SubprocessError):
            return None
        match = re.search(r'^agent:\s+([A-Za-z0-9_-]{1,64})\b', result.stdout.decode(errors='replace'), re.M)
        if result.returncode or match is None:
            return None
        selector = ['--agent', match[1]]
    return shlex.join(['pz-secretctl', 'secret', 'add', scope, item, '--prompt', *selector,
                       '--description', description])


def vault_generate(scope: str, item: str, kind: str, parent: dict[str, str], *, length: int | None = None,
                   description: str = '') -> None:
    """Create a new random value in the vault (`pz-secretctl secret generate`); it is never seen here."""
    if not VAULT_SCOPE.fullmatch(scope) or not VAULT_ID.fullmatch(item) or kind not in GENERATE_KINDS:
        raise ContractError('vault_generate_invalid')
    command = [_secretctl(parent), *secretctl_selector(parent), 'secret', 'generate', scope, item,
               '--kind', kind, '--description', description[:200]]
    if length is not None:
        command.extend(['--length', str(length)])
    try:
        result = subprocess.run(command, env=parent, capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        raise ContractError('vault_generate_failed') from None
    if result.returncode:
        raise ContractError('vault_generate_failed')


CLUSTER_SEED = Path('infra/k8s/cluster-profile.json')


def cluster_seed() -> dict | None:
    """Read only a bounded local seed; its sources name keys, never values."""
    path = Path.cwd() / CLUSTER_SEED
    if not path.exists() and not path.is_symlink():
        return None
    try:
        if path.stat().st_size > 65536 or any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError()
        seed = json.loads(path.read_bytes())
        if (not isinstance(seed, dict) or set(seed) != {'schema_version', 'clusters'}
                or seed['schema_version'] != '1.0.0' or not isinstance(seed['clusters'], dict)
                or not seed['clusters'] or len(seed['clusters']) > 8):
            raise ValueError()
        return seed
    except (OSError, ValueError, TypeError) as exc:
        raise ContractError('cluster_profile_seed_invalid') from exc


def private_profile_path(root: Path, path: Path) -> Path:
    """Resolve ancestors above the explicit root; never follow links inside it."""
    if root.is_symlink():
        raise ValueError('private root is linked')
    anchor = root.resolve()
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path.relative_to(anchor)
    if '..' in relative.parts:
        raise ValueError('private path escapes root')
    selected = anchor
    for part in relative.parts:
        selected = selected / part
        if selected.is_symlink():
            raise ValueError('private path is linked')
    return selected


def bootstrap_keys(profile_root: Path | None = None, parent: dict[str, str] | None = None) -> set[str]:
    """Discover only declared key names; never read or return their values."""
    source = os.environ if parent is None else parent
    raw = source.get('PZ_ADW_PROFILE_ROOT')
    root = profile_root or (Path(raw) if raw else None)
    keys = set(BOOTSTRAP)
    try:
        if root is not None:
            root = private_profile_path(root, root)
        path = root / 'k3d-clusters.json' if root is not None else None
        if path is not None and (path.exists() or path.is_symlink()):
            if path.is_symlink() or path.stat().st_mode & 0o077 or path.stat().st_size > 65536:
                raise ValueError()
            profiles = json.loads(path.read_bytes())['clusters']
        else:
            seed = cluster_seed()
            profiles = seed['clusters'] if seed is not None else {}
        profiles = dict(profiles)
        provisioning = root / 'kubernetes-provisioning.json' if root is not None else None
        if provisioning is not None and (provisioning.exists() or provisioning.is_symlink()):
            if (any(p.is_symlink() for p in (provisioning, *provisioning.parents))
                    or provisioning.stat().st_mode & 0o077 or provisioning.stat().st_size > 65536):
                raise ValueError()
            data = json.loads(provisioning.read_bytes())
            if (set(data) != {'schema_version', 'targets'} or data['schema_version'] != '1.0.0'
                    or not isinstance(data['targets'], dict)):
                raise ValueError()
            profiles.update({'provision-' + key: value for key, value in data['targets'].items()})
        for profile in profiles.values():
            for block, fields in (('tls', {'acme_email_env': '_EMAIL'}), ('image_pull', {'token_env': '_TOKEN', 'username_env': '_USERNAME'})):
                for field, suffix in fields.items():
                    key = profile.get(block, {}).get(field)
                    if key is not None:
                        if (not isinstance(key, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', key)
                                or not key.endswith(suffix)):
                            raise ValueError()
                        keys.add(key)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError) as exc:
        raise ContractError('cluster_profile_invalid') from exc
    return keys


def kubernetes_bootstrap_keys(profile_root: Path | None, context_alias: str) -> set[str]:
    """Grant only one target's declared pull/application input names."""
    raw = os.environ.get('PZ_ADW_PROFILE_ROOT')
    root = profile_root or (Path(raw) if raw else None)
    if root is None:
        return set()
    try:
        root = private_profile_path(root, root)
        path = root / 'kubernetes-provisioning.json'
        if not path.exists() and not path.is_symlink():
            return set()
        if (any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file()
                or path.stat().st_mode & 0o077 or path.stat().st_size > 65536):
            raise ValueError()
        data = json.loads(path.read_bytes())
        if (set(data) != {'schema_version', 'targets'} or data['schema_version'] != '1.0.0'
                or not isinstance(data['targets'], dict)):
            raise ValueError()
        selected = data['targets'][context_alias]
        if not isinstance(selected, dict) or set(selected) - {'tls', 'image_pull', 'app_secrets'}:
            raise ValueError()
        keys = set()
        for field, suffix in (('token_env', '_TOKEN'), ('username_env', '_USERNAME')):
            key = selected.get('image_pull', {}).get(field)
            if key is not None:
                if (not isinstance(key, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', key)
                        or not key.endswith(suffix) or key in REGISTRY | CLOUDFLARE | CLUSTER_ONLY):
                    raise ValueError()
                keys.add(key)
        return keys
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError) as exc:
        raise ContractError('kubernetes_provision_profile_invalid') from exc


def resolve(repo: Path, *, mode: str = 'human', environ: dict[str, str] | None = None,
            profile_root: Path | None = None, keys: set[str] | None = None,
            operator: str | None = None) -> dict[str, str]:
    """Explicit process values, then the vault; no credential files (#193).

    Hosted CI and credential-free invocations never call the vault. The CLI
    supplies its operation's key grant before resolution, so unused credentials
    are never decrypted.
    """
    parent = dict(os.environ if environ is None else environ)
    if parent.get(CREDENTIAL_FREE) == '1':
        return {}
    wanted = set(keys) if keys is not None else KEYS | bootstrap_keys(profile_root, parent)
    if any(not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', key) for key in wanted):
        raise ContractError('credential_key_selection_invalid')
    human = mode == 'human'
    explicit = {key: value for key, value in parent.items() if value}   # an empty export is unset
    # Ask only for canonical IDs the process environment does not already supply.
    requested = set()
    for key in wanted:
        group = next((group for group in GROUPS if key in group), (key,))
        if not any(alias in explicit for alias in group):
            requested.add(group[0])
    if human:
        # Names only: a stale export (for example from an old agent-env.sh) must not
        # silently shadow the vault. Operator-home and cluster plumbing are not vault keys.
        shadowed = sorted({next((group for group in GROUPS if key in group), (key,))[0]
                           for key in wanted - KUBE
                           if any(alias in explicit for alias in next((group for group in GROUPS if key in group), (key,)))})
        if shadowed:
            print('NOTE: the process environment overrides the vault for: ' + ', '.join(shadowed), file=sys.stderr)
    vault = vault_values(requested, parent, operator=operator) if human else {}
    layers = (explicit, vault)
    result = {key: next((layer[key] for layer in layers if key in layer), '')
              for key in wanted}
    for group in GROUPS:
        if not wanted.intersection(group):
            continue
        layer = next((layer for layer in layers if any(key in layer for key in group)), {})
        selected = {layer[key] for key in group if layer.get(key)}
        if len(selected) > 1:
            raise ContractError('conflicting credential aliases: ' + ', '.join(group))
        for key in group:
            if key in wanted:
                result[key] = next(iter(selected), '')
    return {key: value for key, value in result.items() if value}


def clean_environment(parent: dict[str, str] | None = None) -> dict[str, str]:
    """An environment for project code and external tools: no credential and no operator session.

    An unlocked operator capability reads every vault scope; only the provider's own
    pz-secretctl calls and the canonical tasks a workflow starts may carry it.
    """
    result = dict(os.environ if parent is None else parent)
    for key in KEYS | bootstrap_keys(parent=result) | {OPERATOR_SESSION}:
        result.pop(key, None)
    return result


@contextmanager
def credentials(values: dict[str, str], allowed: set[str]):
    """For synchronous CLI/provider code; never export into the parent shell."""
    previous = {key: os.environ.get(key) for key in KEYS | set(values) | bootstrap_keys()}
    try:
        for key in previous:
            os.environ.pop(key, None)
        os.environ.update({key: value for key, value in values.items() if key in allowed})
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

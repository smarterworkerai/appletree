"""Optional dotenv input, parsed as data and scoped to a provider operation."""
from contextlib import contextmanager
import os
import json
from pathlib import Path
import re
import stat
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


def bootstrap_keys(profile_root: Path | None = None, parent: dict[str, str] | None = None) -> set[str]:
    """Discover only declared key names; never read or return their values."""
    source = os.environ if parent is None else parent
    raw = source.get('PZ_ADW_PROFILE_ROOT')
    root = profile_root or (Path(raw) if raw else None)
    keys = set(BOOTSTRAP)
    path = root / 'k3d-clusters.json' if root is not None else None
    try:
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
            for entries in profile.get('app_secrets', {}).values():
                for fields in entries.values():
                    for source in fields.values():
                        if not isinstance(source, dict):
                            raise ValueError()
                        key = source.get('env')
                        if key is not None:
                            if (set(source) != {'env'} or not isinstance(key, str)
                                    or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', key)
                                    or not key.endswith(('_KEY', '_TOKEN', '_PASSWORD', '_SECRET'))
                                    or key in REGISTRY | CLOUDFLARE):
                                raise ValueError()
                            keys.add(key)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ContractError('cluster_profile_invalid') from exc
    return keys


def dotenv(path: Path, *, required: bool = False) -> dict[str, str]:
    if not path.exists():
        if required:
            raise ContractError('explicit deployment environment file is missing')
        return {}
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 65536:
            raise ContractError('deployment environment file is not a bounded regular file')
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            print(f'WARNING: {path} holds credentials but is readable by others (mode {mode:o}); run chmod 600', file=sys.stderr)
        text = path.read_text(encoding='utf-8')
    except (OSError, UnicodeError) as exc:
        raise ContractError('deployment environment file cannot be read') from exc
    result = {}
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:].lstrip()
        match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)', line)
        if not match or match[1] in result:
            raise ContractError(f'invalid or duplicate dotenv assignment on line {line_number}')
        key, value = match.groups()
        if value.startswith(('"', "'")):
            quote = value[0]
            end = value.rfind(quote)
            if end == 0 or (value[end + 1:].strip() and not value[end + 1:].strip().startswith('#')):
                raise ContractError(f'invalid dotenv quoting on line {line_number}')
            value = value[1:end]
        else:
            value = re.split(r'\s+#', value, maxsplit=1)[0].rstrip()
        if '\x00' in value:
            raise ContractError(f'invalid dotenv value on line {line_number}')
        # No interpolation, backslash processing, source or eval.
        result[key] = value
    return result


def resolve(repo: Path, *, env_file: Path | None = None, mode: str = 'human',
            environ: dict[str, str] | None = None, profile_root: Path | None = None) -> dict[str, str]:
    parent = dict(os.environ if environ is None else environ)
    if mode == 'ci' and env_file is not None:
        raise ContractError('CI does not accept a deployment environment file')
    values = dotenv(env_file if env_file is not None else repo / '.env.deploy',
                    required=env_file is not None) if mode == 'human' else {}
    result = {key: parent.get(key, values.get(key, '')) for key in KEYS | bootstrap_keys(profile_root, parent)}
    for group in GROUPS:
        layer = parent if any(key in parent for key in group) else values
        selected = {layer[key] for key in group if layer.get(key)}
        if len(selected) > 1:
            raise ContractError('conflicting credential aliases: ' + ', '.join(group))
        for key in group:
            result[key] = next(iter(selected), '')
    return {key: value for key, value in result.items() if value}


def clean_environment(parent: dict[str, str] | None = None) -> dict[str, str]:
    result = dict(os.environ if parent is None else parent)
    for key in KEYS | bootstrap_keys(parent=result):
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

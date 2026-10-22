#!/usr/bin/env python3
"""Expose optional declared registry cache capabilities to the CI umbrella."""
import argparse
import json
from pathlib import Path
from modules.buildkit_cache import validate_config
from modules.common import project_dir
from modules.common import ContractError


def configuration(root: Path) -> dict:
    path = project_dir(root) / 'pz-release.json'
    if path.is_symlink():
        raise ContractError('Docker cache declaration must not be linked')
    if not path.exists():
        return {'enabled': 'false'}
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ContractError('Release configuration must be an object')
    if 'docker_cache' not in value:
        return {'enabled': 'false'}
    validate_config(value['docker_cache'])
    return {'enabled': 'true', 'registry': value['docker_cache']['repository'].split('/', 1)[0]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--github-output', type=Path, required=True)
    args = parser.parse_args()
    try:
        values = configuration(args.root)
        with args.github_output.open('a') as output:
            for key, value in values.items():
                output.write(key + '=' + value + '\n')
    except (ContractError, OSError, ValueError, KeyError, TypeError):
        raise SystemExit('Docker cache configuration is invalid')

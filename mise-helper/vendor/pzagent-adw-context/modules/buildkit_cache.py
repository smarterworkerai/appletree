"""Optional registry-layer cache policy for Docker-backed project build hooks.

The caller owns recipes and role names. Cache content never proves quality or
release availability. Human/local writers cannot update the trusted CI scope.
"""
from __future__ import annotations

import re

from .common import ContractError, FULL_SHA

TOKEN = re.compile(r'[a-z0-9][a-z0-9_.-]{0,47}')
REPOSITORY = re.compile(r'[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-z0-9][a-z0-9/_.-]*')
PLATFORM = re.compile(r'linux/(?:amd64|arm64|arm/v[5-8]|386|ppc64le|s390x|riscv64)')


def validate_config(config: dict) -> None:
    if (not isinstance(config, dict) or set(config) != {'repository', 'epoch'}
            or not isinstance(config['repository'], str)
            or not REPOSITORY.fullmatch(config['repository'])
            or any(part in {'', '.', '..'} for part in config['repository'].split('/'))
            or not isinstance(config['epoch'], str) or not TOKEN.fullmatch(config['epoch'])):
        raise ContractError('invalid Docker cache repository or epoch')


def plan(config: dict, role: str, platform: str, source_sha: str, environ: dict) -> dict:
    """Return explicit argv additions, or the ordinary uncached build command."""
    builder = environ.get('PZ_ADW_BUILDX_BUILDER', '')
    if not builder:
        return {'command': ['docker', 'build'], 'arguments': [], 'reference': None, 'write': False}
    if (not all(isinstance(value, str) for value in (builder, role, platform))
            or not TOKEN.fullmatch(builder) or not TOKEN.fullmatch(role) or not PLATFORM.fullmatch(platform)):
        raise ContractError('invalid Docker cache builder, role or platform')
    if not isinstance(source_sha, str) or not FULL_SHA.fullmatch(source_sha):
        raise ContractError('Docker cache source identity is invalid')
    validate_config(config)
    scope = environ.get('PZ_ADW_DOCKER_CACHE_SCOPE', 'trusted')
    write = environ.get('PZ_ADW_DOCKER_CACHE_WRITE', 'false')
    if scope not in {'trusted', 'local'} or write not in {'true', 'false'}:
        raise ContractError('invalid Docker cache scope or write policy')
    actions = environ.get('GITHUB_ACTIONS', '').lower() == 'true'
    if actions and scope != 'trusted':
        raise ContractError('GitHub Actions cannot consume the local operator cache scope')
    if write == 'true' and scope == 'trusted':
        protected = (actions and environ.get('GITHUB_REF_PROTECTED') == 'true'
                     and environ.get('GITHUB_REF', '').startswith('refs/heads/'))
        push = environ.get('GITHUB_EVENT_NAME') == 'push' and environ.get('GITHUB_SHA') == source_sha
        publication = (environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
                       and environ.get('PZ_ADW_AUTHORIZED_SOURCE_SHA') == source_sha)
        # The privileged publication umbrella supplies this exact SHA only after
        # its existing authorization gate. It is not standalone release proof.
        if not protected or not (push or publication):
            raise ContractError('trusted Docker cache writes require a protected push or authorized protected publication')
    reference = '{}:{}-{}-{}-{}'.format(
        config['repository'], config['epoch'], scope, role, platform.replace('/', '-'))
    arguments = ['--cache-from', 'type=registry,ref=' + reference]
    if write == 'true':
        arguments += ['--cache-to', 'type=registry,ref=' + reference
                      + ',mode=max,oci-mediatypes=true,image-manifest=true,ignore-error=true']
    return {'command': ['docker', 'buildx', 'build', '--builder', builder, '--load'],
            'arguments': arguments, 'reference': reference, 'write': write == 'true'}

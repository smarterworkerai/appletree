"""Construct SSH argv from a logical alias or the selected Hermes-style route."""
import os
from pathlib import Path
import shlex

from .common import ContractError


def command(alias: str, *remote: str) -> list[str]:
    host = os.environ.get('TERMINAL_SSH_HOST') or alias
    if not host or host.startswith('-') or any(character.isspace() for character in host):
        raise ContractError('invalid SSH destination')
    args = ['ssh', '-o', 'BatchMode=yes']
    if os.environ.get('TERMINAL_SSH_HOST'):
        user = os.environ.get('TERMINAL_SSH_USER')
        if user:
            args += ['-l', user]
        port = os.environ.get('TERMINAL_SSH_PORT')
        if port:
            if not port.isdigit() or not 1 <= int(port) <= 65535:
                raise ContractError('invalid SSH port')
            args += ['-p', port]
        key = os.environ.get('TERMINAL_SSH_KEY')
        if key:
            args += ['-i', str(Path(key).expanduser())]
    return [*args, host, shlex.join(remote)]

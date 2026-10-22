"""Invocation-local policy; library callers retain the strict default."""
from contextlib import contextmanager
from contextvars import ContextVar
import os

from .common import ContractError

_MODE = ContextVar('pz_execution_mode', default='ci')


def human() -> bool:
    return _MODE.get() == 'human'


@contextmanager
def execution(mode: str):
    if mode not in {'human', 'ci'}:
        raise ContractError('unknown execution mode')
    if mode == 'human' and os.environ.get('GITHUB_ACTIONS') == 'true':
        raise ContractError('Actions cannot invoke the human operator entrypoint')
    token = _MODE.set(mode)
    try:
        yield
    finally:
        _MODE.reset(token)

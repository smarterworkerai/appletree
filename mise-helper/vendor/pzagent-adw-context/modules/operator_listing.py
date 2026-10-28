"""Offline journal summaries; no recommendations or live lookups."""
from datetime import datetime
import re

from .common import ContractError, IDENTIFIER
from .operator_state import journals, OPERATION_ID, terminal
from .operator_abandon import _inventory, tree, classification


def _name(value):
    return value if isinstance(value, str) and IDENTIFIER.fullmatch(value) else 'unknown'


def _timestamp(value):
    try:
        if not isinstance(value, str) or len(value) > 40:
            return 'unknown'
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return value if parsed.tzinfo is not None else 'unknown'
    except (ValueError, TypeError, AttributeError):
        return 'unknown'


def status_all(repo, home=None):
    root = journals(repo, home)
    records = _inventory(root)
    rows = []
    for key, record in records.items():
        if record is None:
            rows.append({'operation': key.split('/')[0], 'phase': 'unknown',
                         'journal': key.split('/', 1)[-1],
                         'write_classification': 'unknown', 'lock_state': 'unknown'})
            continue
        operation = key.split('/')[0]
        if not OPERATION_ID.fullmatch(operation):
            continue
        selection = record.get('selection') if isinstance(record.get('selection'), dict) else {}
        scope = record.get('scope') if isinstance(record.get('scope'), dict) else {}
        try:
            writes = classification(tree(root, root / operation))['classification']
        except ContractError:
            writes = 'unknown'
        sha = record.get('source_sha', selection.get('source_sha'))
        binding = scope.get('binding_sha256')
        proven = (scope.get('repository') and scope.get('release_kind')
                  and isinstance(binding, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', binding))
        rows.append({'operation': operation, 'journal': key.removeprefix(operation + '/'),
            'workflow': record.get('workflow') if record.get('workflow') in {
                'deploy-existing', 'publish', 'publish-deploy', 'retention', 'source-line'} else
                'deploy-apply' if key.endswith('/deployment.json') else 'unknown',
            'operation_kind': operation.rsplit('-', 2)[0],
            'release_kind': _name(record.get('kind', selection.get('release_kind'))),
            'environment': _name(record.get('environment', selection.get('environment'))),
            'target': _name(scope.get('target')) if proven else 'unknown',
            'scope': 'recorded' if proven else 'unknown',
            'phase': _name(record.get('phase')), 'terminal': terminal(record),
            'created_at': _timestamp(record.get('created_at')), 'updated_at': _timestamp(record.get('updated_at')),
            'source_short': sha[:12] if isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{40}', sha) else 'unknown',
            'write_classification': writes, 'lock_state': 'unknown',
            'needs_reconcile': record.get('needs_reconcile') is True,
            'retirement_pending': record.get('retirement_pending') is True,
            'reason_code': record.get('reason_code') if record.get('reason_code') in {'abandoned', 'superseded', 'refused'} else 'unknown'})
    return {'status': 'ok', 'offline': True, 'operations': rows}

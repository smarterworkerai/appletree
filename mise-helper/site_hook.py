"""Retain bundled readiness validation and verify the routed static assets."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / 'vendor/pzagent-adw-context'))
from modules.adapter import load
from modules.common import ContractError, project_dir
from modules.hooks import HookFailure
from modules.providers.dokploy_hooks import dispatch
from site_checks import SiteError, check_remote

try:
    if sys.argv[1:] != ['readiness']:
        raise SiteError('readiness-operation-invalid')
    request = json.load(sys.stdin)
    root = Path.cwd()
    adapter = load(project_dir(root) / 'pzagent-adapter.json')
    result = dispatch(root, adapter, 'readiness', request)
    selected = adapter['targets'][request['environment']]['items'][request['target']]
    binding = adapter['providers']['dokploy']['bindings'][selected['provider_binding']]
    check_remote(os.environ[binding['probes']['base_url_env']])
    response = {'schema_version': '1.0.0', 'status': 'ok', 'result': result}
except HookFailure as error:
    response = {'schema_version': '1.0.0', 'status': error.status, 'reason_code': error.reason_code}
except (SiteError, ContractError, KeyError, ValueError, TypeError, OSError, IndexError):
    response = {'schema_version': '1.0.0', 'status': 'blocked', 'reason_code': 'application-assets-unavailable'}
print(json.dumps(response, sort_keys=True))

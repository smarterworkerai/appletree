"""Project E2E hook: canonical target validation plus real browser execution."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / 'vendor/pzagent-adw-context'))
from modules.adapter import load
from modules.common import ContractError, FULL_SHA, project_dir
from modules.hooks import HookFailure
from modules.providers.dokploy_hooks import dispatch
from browser_checks import BrowserError, run_browser
from site_checks import SiteError, check_remote

WIRE_KEYS = {'schema_version', 'capability', 'operation', 'source_sha', 'environment', 'target'}


def execute(root, adapter, operation, request):
    capability = {'e2e-fast': 'adw:test:e2e:fast', 'e2e-full': 'adw:test:e2e:full'}.get(operation)
    if (capability is None or not isinstance(request, dict) or set(request) != WIRE_KEYS
            or request.get('schema_version') != '1.0.0'
            or request.get('capability') != capability or request.get('operation') != operation
            or not isinstance(request.get('source_sha'), str)
            or not FULL_SHA.fullmatch(request['source_sha'])):
        raise BrowserError('e2e-request-invalid')
    declared = adapter['capabilities'][capability]
    if declared['status'] != 'supported' or request['environment'] not in declared['environments']:
        raise BrowserError('e2e-environment-unsupported')
    # Reuse the bundled active-target/provider/origin validator and readiness probe.
    readiness = {**request, 'capability': 'adw:readiness', 'operation': 'readiness'}
    dispatch(root, adapter, 'readiness', readiness)
    selected = adapter['targets'][request['environment']]['items'][request['target']]
    binding = adapter['providers']['dokploy']['bindings'][selected['provider_binding']]
    origin = os.environ[binding['probes']['base_url_env']]
    check_remote(origin)
    return run_browser(root, origin, operation.removeprefix('e2e-'))


def main(argv):
    try:
        if len(argv) != 1:
            raise BrowserError('e2e-request-invalid')
        root = Path.cwd()
        adapter = load(project_dir(root) / 'pzagent-adapter.json')
        result = execute(root, adapter, argv[0], json.load(sys.stdin))
        response = {'schema_version': '1.0.0', 'status': 'ok', 'result': result}
    except HookFailure as error:
        response = {'schema_version': '1.0.0', 'status': error.status, 'reason_code': error.reason_code}
    except BrowserError as error:
        response = {'schema_version': '1.0.0', 'status': 'blocked', 'reason_code': str(error)}
    except SiteError:
        response = {'schema_version': '1.0.0', 'status': 'blocked', 'reason_code': 'e2e-assets-unavailable'}
    except (ContractError, KeyError, ValueError, TypeError, OSError, IndexError):
        response = {'schema_version': '1.0.0', 'status': 'blocked', 'reason_code': 'e2e-request-invalid'}
    print(json.dumps(response, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))

"""Run the browser with closed counts and secret-safe failure responses."""
import json
import os
from pathlib import Path
import signal
import subprocess

BROWSER_REASONS = {
    'e2e-request-invalid', 'e2e-browser-missing', 'e2e-browser-failed',
    'e2e-page-failed', 'e2e-render-failed', 'e2e-resize-failed', 'e2e-timeout',
}


class BrowserError(ValueError):
    pass


def run_browser(root, origin, mode):
    if mode not in {'fast', 'full'}:
        raise BrowserError('e2e-request-invalid')
    # Browser code needs no provider credentials or private operator bindings.
    environment = {key: value for key, value in os.environ.items()
                   if key in {'PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL',
                              'PLAYWRIGHT_BROWSERS_PATH', 'XDG_CACHE_HOME'}}
    process = subprocess.Popen(
        ['node', str(Path(root) / 'mise-helper/browser_e2e.mjs'), origin, mode],
        cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True)
    try:
        stdout, _ = process.communicate(timeout=135)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise BrowserError('e2e-timeout') from None
    try:
        proof = json.loads(stdout)
    except (ValueError, TypeError):
        raise BrowserError('e2e-proof-invalid') from None
    if (isinstance(proof, dict) and set(proof) == {'status', 'reason_code'}
            and proof['status'] == 'blocked' and isinstance(proof['reason_code'], str)
            and proof['reason_code'] in BROWSER_REASONS):
        raise BrowserError(proof['reason_code'])
    expected = 2 if mode == 'full' else 1
    if (process.returncode != 0 or not isinstance(proof, dict)
            or set(proof) != {'status', 'selected', 'executed', 'skipped'}
            or proof['status'] != 'passed'
            or any(type(proof[key]) is not int for key in ('selected', 'executed', 'skipped'))
            or proof['selected'] != expected or proof['executed'] != expected
            or proof['skipped'] != 0):
        raise BrowserError('e2e-proof-invalid')
    return proof

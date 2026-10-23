"""Exercise the actual E2E declaration, HTTP target checks and execution proof."""
from copy import deepcopy
from functools import partial
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'mise-helper'))
sys.path.insert(0, str(ROOT / 'mise-helper/vendor/pzagent-adw-context'))
from modules.adapter import load
from modules.hooks import HookFailure, _argv
from browser_checks import BrowserError, run_browser
import e2e_hook
from site_checks import QuietHandler, SiteError


class E2EHookTest(unittest.TestCase):
    def setUp(self):
        self.adapter = load(ROOT / '.adw/pzagent-adapter.json')
        self.environment = 'pr-preview'
        self.target = self.adapter['targets'][self.environment]['default']
        selected = self.adapter['targets'][self.environment]['items'][self.target]
        self.binding = self.adapter['providers']['dokploy']['bindings'][selected['provider_binding']]
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        (root / 'assets').mkdir()
        (root / 'index.html').write_text(
            '<title>Apple Tree</title><canvas id="scene"></canvas>'
            '<script type="module" src="/assets/app.js"></script>'
            '<link rel="stylesheet" href="/assets/app.css">')
        (root / 'assets/app.js').write_text('application')
        (root / 'assets/app.css').write_text('style')
        server = ThreadingHTTPServer(('localhost', 0), partial(QuietHandler, directory=str(root)))
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()

        def close():
            server.shutdown()
            server.server_close()
            worker.join()

        self.addCleanup(close)
        self.origin = 'http://localhost:' + str(server.server_port)
        environment = patch.dict(os.environ, {self.binding['probes']['base_url_env']: self.origin})
        environment.start()
        self.addCleanup(environment.stop)

    def request(self, mode='fast'):
        return {'schema_version': '1.0.0', 'capability': 'adw:test:e2e:' + mode,
                'operation': 'e2e-' + mode, 'source_sha': 'a' * 40,
                'environment': self.environment, 'target': self.target}

    def test_declared_fast_and_full_preserve_nonempty_counts(self):
        for mode, count in [('fast', 1), ('full', 2)]:
            with self.subTest(mode=mode):
                request = self.request(mode)
                argv, operation = _argv(ROOT, self.adapter, request['capability'])
                self.assertEqual(Path(argv[-2]), ROOT / 'mise-helper/e2e_hook.py')
                self.assertEqual(argv[-1], request['operation'])
                self.assertEqual(operation['operation'], request['operation'])
                proof = {'status': 'passed', 'selected': count, 'executed': count, 'skipped': 0}
                with patch.object(e2e_hook, 'run_browser', return_value=proof) as browser:
                    self.assertEqual(e2e_hook.execute(ROOT, self.adapter, argv[-1], request), proof)
                    browser.assert_called_once_with(ROOT, self.origin, mode)

    def test_invalid_request_and_undeclared_target_never_launch_browser(self):
        request = self.request()
        invalid = [
            [], {**request, 'source_sha': 'short'}, {**request, 'schema_version': 'unknown'},
            {**request, 'operation': 'e2e-full'}, {**request, 'capability': 'adw:readiness'},
            {**request, 'extra': True}, {**request, 'environment': 'production'},
            {**request, 'target': 'undeclared-target'},
        ]
        with patch.object(e2e_hook, 'run_browser') as browser:
            for value in invalid:
                with self.subTest(request=value), self.assertRaises((BrowserError, HookFailure)):
                    e2e_hook.execute(ROOT, self.adapter, 'e2e-fast', value)
            adapter = deepcopy(self.adapter)
            adapter['targets'][self.environment]['items'][self.target]['mode'] = 'disabled'
            with self.assertRaises(HookFailure):
                e2e_hook.execute(ROOT, adapter, 'e2e-fast', request)
            browser.assert_not_called()

    def test_asset_failure_prevents_browser(self):
        (Path(self.directory.name) / 'assets/app.js').unlink()
        with patch.object(e2e_hook, 'run_browser') as browser, self.assertRaises(SiteError):
            e2e_hook.execute(ROOT, self.adapter, 'e2e-fast', self.request())
        browser.assert_not_called()

    def test_cli_returns_closed_redacted_refusal(self):
        request = {**self.request(), 'target': 'private-value-must-not-escape'}
        argv, _ = _argv(ROOT, self.adapter, request['capability'])
        child = subprocess.run(argv, cwd=ROOT, input=json.dumps(request), text=True,
                               capture_output=True, timeout=15)
        self.assertEqual(child.returncode, 0)
        result = json.loads(child.stdout)
        self.assertEqual(set(result), {'schema_version', 'status', 'reason_code'})
        self.assertEqual(result['status'], 'blocked')
        self.assertNotIn(request['target'], child.stdout + child.stderr)


class BrowserProofTest(unittest.TestCase):
    def process(self, output, returncode=0):
        process = Mock()
        process.communicate.return_value = (output, 'private-value-must-not-escape')
        process.returncode = returncode
        return process

    def test_only_exact_nonempty_counts_are_accepted(self):
        for mode, count in [('fast', 1), ('full', 2)]:
            proof = {'status': 'passed', 'selected': count, 'executed': count, 'skipped': 0}
            with patch('browser_checks.subprocess.Popen', return_value=self.process(json.dumps(proof))) as start:
                with patch.dict(os.environ, {'DOKPLOY_TOKEN': 'private-value-must-not-escape'}):
                    self.assertEqual(run_browser(ROOT, 'http://localhost', mode), proof)
                self.assertNotIn('DOKPLOY_TOKEN', start.call_args.kwargs['env'])
                self.assertTrue(start.call_args.kwargs['start_new_session'])

    def test_empty_skipped_malformed_and_failed_proofs_refuse_without_child_output(self):
        valid = {'status': 'passed', 'selected': 2, 'executed': 2, 'skipped': 0}
        invalid = [
            {}, [], {**valid, 'executed': 0}, {**valid, 'skipped': 1},
            {**valid, 'selected': True}, {**valid, 'extra': 'private-value-must-not-escape'},
            {**valid, 'status': 'failed'}, {**valid, 'selected': 1, 'executed': 1},
            {'status': 'blocked', 'reason_code': 'private-value-must-not-escape'},
        ]
        for proof in invalid:
            with self.subTest(proof=proof):
                with patch('browser_checks.subprocess.Popen', return_value=self.process(json.dumps(proof))):
                    with self.assertRaisesRegex(BrowserError, '^e2e-proof-invalid$'):
                        run_browser(ROOT, 'http://localhost', 'full')
        for output, code in [('private-value-must-not-escape', 0), (json.dumps(valid), 1)]:
            with patch('browser_checks.subprocess.Popen', return_value=self.process(output, code)):
                with self.assertRaisesRegex(BrowserError, '^e2e-proof-invalid$'):
                    run_browser(ROOT, 'http://localhost', 'full')

    def test_known_browser_failure_keeps_safe_reason(self):
        result = {'status': 'blocked', 'reason_code': 'e2e-browser-missing'}
        with patch('browser_checks.subprocess.Popen', return_value=self.process(json.dumps(result), 1)):
            with self.assertRaisesRegex(BrowserError, '^e2e-browser-missing$'):
                run_browser(ROOT, 'http://localhost', 'fast')

    def test_timeout_kills_only_the_owned_process_group_and_reaps_it(self):
        process = self.process('')
        process.pid = 123456
        process.communicate.side_effect = [subprocess.TimeoutExpired('redacted', 135), ('', '')]
        with patch('browser_checks.subprocess.Popen', return_value=process):
            with patch('browser_checks.os.killpg') as kill:
                with self.assertRaisesRegex(BrowserError, '^e2e-timeout$'):
                    run_browser(ROOT, 'http://localhost', 'fast')
                kill.assert_called_once_with(process.pid, signal.SIGKILL)
                self.assertEqual(process.communicate.call_count, 2)

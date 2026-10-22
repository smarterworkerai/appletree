"""Exercise the declared hook through its real dispatcher and routed assets."""
from functools import partial
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'mise-helper'))
sys.path.insert(0, str(ROOT / 'mise-helper/vendor/pzagent-adw-context'))
from modules.adapter import load
from modules.hooks import _argv
from modules.operator_credentials import clean_environment
from site_checks import QuietHandler


class ReadinessHookTest(unittest.TestCase):
    def test_declared_dispatch_validates_target_and_page_assets(self):
        adapter = load(ROOT / '.adw/pzagent-adapter.json')
        argv, operation = _argv(ROOT, adapter, 'adw:readiness')
        environment = 'pr-preview'
        target = adapter['targets'][environment]['default']
        selected = adapter['targets'][environment]['items'][target]
        binding = adapter['providers']['dokploy']['bindings'][selected['provider_binding']]
        request = {'schema_version': '1.0.0', 'capability': 'adw:readiness',
                   'operation': operation['operation'], 'source_sha': 'a' * 40,
                   'environment': environment, 'target': target}
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            (directory / 'assets').mkdir()
            (directory / 'index.html').write_text(
                '<title>Apple Tree</title><canvas id="scene"></canvas>'
                '<script type="module" src="/assets/app.js"></script>'
                '<link rel="stylesheet" href="/assets/app.css">')
            (directory / 'assets/app.js').write_text('application')
            (directory / 'assets/app.css').write_text('style')
            server = ThreadingHTTPServer(('localhost', 0), partial(QuietHandler, directory=raw))
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            child = clean_environment()
            child[binding['probes']['base_url_env']] = 'http://localhost:' + str(server.server_port)

            def invoke(value):
                result = subprocess.run(argv, cwd=ROOT, env=child, input=json.dumps(value),
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, 'hook process must return a closed response')
                return json.loads(result.stdout)

            try:
                self.assertEqual(invoke(request), {'schema_version': '1.0.0',
                                 'status': 'ok', 'result': {'status': 'passed'}})
                self.assertEqual(invoke({**request, 'target': 'undeclared-target'})['status'], 'blocked')
                (directory / 'assets/app.js').unlink()
                rejected = invoke(request)
                self.assertEqual(rejected['status'], 'blocked')
                self.assertEqual(rejected['reason_code'], 'application-assets-unavailable')
            finally:
                server.shutdown()
                server.server_close()
                worker.join()

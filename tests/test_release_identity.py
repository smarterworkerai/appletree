"""The packaged marker proves the selected source on every declared public target."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'mise-helper/vendor/pzagent-adw-context'))
from modules.common import ContractError
from modules.routed_content import verify

SHA = 'a' * 40


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class ReleaseIdentityTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name)
        self.adapter = json.loads((ROOT / '.adw/pzagent-adapter.json').read_text())
        self.targets = json.loads((ROOT / '.adw/routed-content.json').read_text())['targets']

    def generate(self, source):
        return subprocess.run(['sh', str(ROOT / 'mise-helper/write_release_marker.sh'), str(self.output)],
                              env=dict(os.environ, APPLICATION_SHA=source), text=True, capture_output=True)

    def serve(self):
        server = ThreadingHTTPServer(('localhost', 0), partial(QuietHandler, directory=str(self.output)))
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        return 'http://localhost:' + str(server.server_port)

    def test_real_image_marker_producer_and_all_three_target_contracts_match(self):
        result = self.generate(SHA)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.output / '.well-known/adw-release.json').read_text()), {'source_sha': SHA})
        self.assertEqual(len(self.targets), 3)
        base = self.serve()
        for target, probe in self.targets.items():
            with self.subTest(target=target):
                self.assertEqual(verify(ROOT, self.adapter, target, SHA,
                                        environ={probe['base_url_env']: base}),
                                 {'status': 'passed', 'source_sha': SHA})

    def test_wrong_source_and_missing_marker_refuse(self):
        self.assertEqual(self.generate(SHA).returncode, 0)
        base = self.serve()
        target, probe = next(iter(self.targets.items()))
        environment = {probe['base_url_env']: base}
        with self.assertRaisesRegex(ContractError, '^routed_content_identity_unproven$'):
            verify(ROOT, self.adapter, target, 'b' * 40, environ=environment)
        (self.output / '.well-known/adw-release.json').unlink()
        with self.assertRaisesRegex(ContractError, '^routed_content_identity_unproven$'):
            verify(ROOT, self.adapter, target, SHA, environ=environment)

    def test_missing_or_malformed_source_never_writes_a_marker(self):
        for source in ('', 'a' * 39, 'A' * 40, 'a' * 39 + '\n', 'a' * 40 + '\nextra'):
            with self.subTest(source=source):
                result = self.generate(source)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr.strip(), 'release-marker-source-invalid')
                self.assertFalse((self.output / '.well-known/adw-release.json').exists())


if __name__ == '__main__':
    unittest.main()

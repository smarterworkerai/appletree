"""Routed page and asset checks identify themselves like the bundled probe."""
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mise-helper'))
from site_checks import QuietHandler, SiteError, check_remote


class RoutedAssetsTest(unittest.TestCase):
    def test_page_and_assets_use_the_probe_identity_and_missing_assets_still_refuse(self):
        observed = []

        class ProbeOnlyHandler(QuietHandler):
            def do_GET(self):
                observed.append((self.path, self.headers.get('User-Agent'), self.headers.get('Accept')))
                if (self.headers.get('User-Agent') != 'pzagent-health'
                        or self.headers.get('Accept') != 'application/json'):
                    self.send_error(403)
                    return
                super().do_GET()

        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            (directory / 'assets').mkdir()
            (directory / 'index.html').write_text(
                '<title>Apple Tree</title><canvas id="scene"></canvas>'
                '<script type="module" src="/assets/app.js"></script>'
                '<link rel="stylesheet" href="/assets/app.css">')
            (directory / 'assets/app.js').write_text('application')
            (directory / 'assets/app.css').write_text('style')
            server = ThreadingHTTPServer(('localhost', 0), partial(ProbeOnlyHandler, directory=raw))
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                origin = 'http://localhost:' + str(server.server_port)
                check_remote(origin)
                self.assertEqual(observed, [('/', 'pzagent-health', 'application/json'),
                                           ('/assets/app.js', 'pzagent-health', 'application/json'),
                                           ('/assets/app.css', 'pzagent-health', 'application/json')])
                (directory / 'assets/app.js').unlink()
                with self.assertRaises(SiteError):
                    check_remote(origin)
            finally:
                server.shutdown()
                server.server_close()
                worker.join()

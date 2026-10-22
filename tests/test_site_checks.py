"""The deployment smoke rejects a shell page with absent or foreign assets."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mise-helper'))
from site_checks import SiteError, assets, check_dist

PAGE = ('<title>Apple Tree</title><canvas id="scene"></canvas>'
        '<script type="module" src="/assets/app.js"></script>'
        '<link rel="stylesheet" href="/assets/app.css">')


class StaticApplicationTest(unittest.TestCase):
    def test_scene_page_returns_the_actual_script_and_style_dependencies(self):
        self.assertEqual(assets(PAGE), ['/assets/app.js', '/assets/app.css'])

    def test_missing_scene_or_module_or_styles_cannot_pass(self):
        for html in (PAGE.replace('id="scene"', 'id="other"'),
                     PAGE.replace('type="module"', 'type="text/plain"'),
                     PAGE.replace('rel="stylesheet"', 'rel="icon"'),
                     PAGE.replace('Apple Tree', 'Error')):
            with self.subTest(html=html), self.assertRaises(SiteError):
                assets(html)

    def test_cross_origin_and_traversal_assets_refuse(self):
        for path in ('//foreign.invalid/app.js', '/assets/../private', '/assets/%2e%2e/private',
                     '/assets/app.js?other=1', '/assets/app.js#other', '/assets//app.js'):
            with self.subTest(path=path), self.assertRaises(SiteError):
                assets(PAGE.replace('/assets/app.js', path))

    def test_compiled_site_requires_nonempty_actual_assets(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'index.html').write_text(PAGE)
            (root / 'assets').mkdir()
            with self.assertRaises(SiteError):
                check_dist(root)
            (root / 'assets/app.js').write_text('application')
            (root / 'assets/app.css').write_text('')
            with self.assertRaises(SiteError):
                check_dist(root)
            (root / 'assets/app.css').write_text('style')
            self.assertEqual(check_dist(root), ['/assets/app.js', '/assets/app.css'])

    def test_linked_compiled_asset_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'index.html').write_text(PAGE)
            (root / 'assets').mkdir()
            (root / 'actual').write_text('application')
            (root / 'assets/app.js').symlink_to(root / 'actual')
            (root / 'assets/app.css').write_text('style')
            with self.assertRaises(SiteError):
                check_dist(root)


if __name__ == '__main__':
    unittest.main()

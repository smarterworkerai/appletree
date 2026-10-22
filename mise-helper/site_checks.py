"""Source hygiene and semantic HTTP smoke for the compiled static application."""
from functools import partial
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import threading
import time
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen
import uuid


class SiteError(ValueError):
    pass


class Index(HTMLParser):
    def __init__(self):
        super().__init__()
        self.canvas = False
        self.in_title = False
        self.title = ''
        self.scripts = []
        self.styles = []

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == 'canvas' and attrs.get('id') == 'scene':
            self.canvas = True
        if tag == 'title':
            self.in_title = True
        if tag == 'script' and attrs.get('type') == 'module' and attrs.get('src'):
            self.scripts.append(attrs['src'])
        if tag == 'link' and attrs.get('rel') == 'stylesheet' and attrs.get('href'):
            self.styles.append(attrs['href'])

    def handle_endtag(self, tag):
        if tag == 'title':
            self.in_title = False

    def handle_data(self, text):
        if self.in_title:
            self.title += text


def assets(html):
    page = Index()
    page.feed(html)
    if page.title.strip() != 'Apple Tree' or not page.canvas or not page.scripts or not page.styles:
        raise SiteError('compiled-page-contract-missing')
    result = []
    for value in page.scripts + page.styles:
        parsed = urlsplit(value)
        decoded = unquote(parsed.path)
        parts = PurePosixPath(decoded).parts
        if (parsed.scheme or parsed.netloc or parsed.query or parsed.fragment
                or not decoded.startswith('/assets/') or '..' in parts or '\\' in decoded
                or '//' in decoded or decoded.endswith('/')):
            raise SiteError('compiled-asset-reference-invalid')
        if decoded not in result:
            result.append(decoded)
    return result


def check_dist(directory):
    page = directory / 'index.html'
    references = assets(page.read_text())
    for reference in references:
        selected = directory / reference.lstrip('/')
        if selected.is_symlink() or not selected.is_file() or selected.stat().st_size == 0:
            raise SiteError('compiled-asset-missing')
    return references


def check_remote(origin):
    parsed = urlsplit(origin)
    if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment or parsed.path not in {'', '/'}):
        raise SiteError('site-origin-invalid')
    # Match the bundled runtime HTTP probe; its headers are not exported as a helper.
    headers = {'Accept': 'application/json', 'User-Agent': 'pzagent-health'}
    try:
        with urlopen(Request(origin.rstrip('/') + '/', headers=headers), timeout=15) as response:
            if response.status != 200:
                raise SiteError('site-document-unavailable')
            html = response.read(2_000_000).decode()
        for reference in assets(html):
            with urlopen(Request(origin.rstrip('/') + reference, headers=headers), timeout=15) as response:
                body = response.read(8_000_000)
                content_type = response.headers.get_content_type()
                if response.status != 200 or not body or content_type == 'text/html':
                    raise SiteError('site-asset-unavailable')
    except SiteError:
        raise
    except Exception:
        raise SiteError('site-request-failed') from None


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *arguments):
        pass


def http_smoke():
    directory = Path('dist').resolve()
    check_dist(directory)
    server = ThreadingHTTPServer(('localhost', 0), partial(QuietHandler, directory=str(directory)))
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        check_remote('http://localhost:' + str(server.server_port))
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
    print('PASS: compiled page, scene canvas and all script/style assets over HTTP')


def container_smoke():
    owner = 'adw-appletree-' + uuid.uuid4().hex[:12]
    container = None
    try:
        subprocess.run(['docker', 'build', '--label', 'com.smarterworkerai.adw.owner=' + owner,
                        '-t', owner, '.'], check=True)
        container = subprocess.check_output(['docker', 'run', '-d', '--rm', '--label',
                     'com.smarterworkerai.adw.owner=' + owner, '-p', '127.0.0.1::3333', owner], text=True).strip()
        port = subprocess.check_output(['docker', 'port', container, '3333/tcp'], text=True).strip().rsplit(':', 1)[1]
        for attempt in range(30):
            try:
                check_remote('http://localhost:' + port)
                break
            except SiteError:
                if attempt == 29:
                    raise
                time.sleep(1)
        print('PASS: actual runtime image serves the compiled page and assets')
    finally:
        if container:
            subprocess.run(['docker', 'rm', '-f', container], capture_output=True)
        subprocess.run(['docker', 'image', 'rm', owner], capture_output=True)


def lint():
    paths = [Path('README.md'), Path('AGENTS.md'), Path('.adw/ADW.md')]
    paths += list(Path('mise-helper').glob('*.py')) + list(Path('tests').glob('*.py'))
    paths += list(Path('infra/dokploy').glob('*')) + list(Path('infra/dokploy').glob('.*.example'))
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_text()
        if not text.endswith('\n') or any(line != line.rstrip() for line in text.splitlines()):
            raise SiteError('source-whitespace-invalid')
        if path.name.endswith('.example'):
            if any(line and not line.startswith('#') and not re.fullmatch(r'[A-Z][A-Z0-9_]*=', line)
                   for line in text.splitlines()):
                raise SiteError('example-value-must-be-empty')
    print('PASS: project source/doc hygiene and empty operator examples')


def static_analysis():
    recipe = json.loads(Path('.adw/pz-release.json').read_text())
    if recipe['components']['web']['context'] != '.' or recipe['components']['web']['stages'] != ['build']:
        raise SiteError('release-recipe-does-not-match-application')
    if recipe['quality_exports']['web']['build'] != {'dist': 'app/dist'}:
        raise SiteError('compiled-output-mapping-invalid')
    dockerfile = Path('Dockerfile').read_text()
    if len(re.findall(r'^FROM \S+@sha256:[a-f0-9]{64} AS ', dockerfile, re.M)) != 2 or 'HEALTHCHECK' not in dockerfile:
        raise SiteError('runtime-recipe-needs-pins-and-health')
    adapter = json.loads(Path('.adw/pzagent-adapter.json').read_text())
    for binding in adapter['providers']['dokploy']['bindings'].values():
        definition = Path(binding['compose_path']).read_text()
        if 'labels:' in definition or 'ports:' in definition or '${APPLETREE_IMAGE' not in definition:
            raise SiteError('deployment-routing-or-image-ownership-invalid')
        schema = json.loads(Path(binding['environment_schema_path']).read_text())
        if schema != {'keys': ['APPLETREE_IMAGE']}:
            raise SiteError('static-app-runtime-key-contract-invalid')
    print('PASS: actual release outputs, pinned runtime recipe and platform-owned routing')


if __name__ == '__main__':
    try:
        action = sys.argv[1]
        {'lint': lint, 'static-analysis': static_analysis, 'http-smoke': http_smoke,
         'container-smoke': container_smoke}[action]()
    except (SiteError, KeyError, IndexError, OSError, ValueError):
        print('FAIL: application delivery check refused', file=sys.stderr)
        raise SystemExit(1)

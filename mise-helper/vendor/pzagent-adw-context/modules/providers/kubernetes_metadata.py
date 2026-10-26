"""Namespace/Secret metadata only, over a private authenticated kubectl Unix proxy.

GET and PATCH negotiate PartialObjectMetadata exclusively: there is no full
object fallback and no Secret data request, decode or output. The proxy's socket
is private, its paths are target-scoped, and it is stopped when the call ends.
"""
from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
from urllib.parse import quote

from ..common import ContractError

ACCEPT = 'application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1'
MAX_BYTES = 512 * 1024
NAME = re.compile(r'^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$')
IDENTITY_KEYS = {'adw.pzagent.io/repository', 'adw.pzagent.io/environment', 'adw.pzagent.io/target'}
OWNERSHIP_KEYS = ('adw.pzagent.io/provision-operation', 'adw.pzagent.io/provision-nonce')


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=30)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


class MetadataClient:
    def __init__(self, path, namespace, only_secret=None):
        if not isinstance(namespace, str) or not NAME.fullmatch(namespace):
            raise ContractError('kubernetes_metadata_scope_invalid')
        self.socket, self.namespace, self.only_secret = path, namespace, only_secret

    def _path(self, kind, name, namespace):
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ContractError('kubernetes_metadata_scope_invalid')
        if self.only_secret is not None:
            # Read-only mode: exactly one named Secret's metadata, nothing else.
            if (kind, namespace, name) != ('Secret', self.namespace, self.only_secret):
                raise ContractError('kubernetes_metadata_scope_invalid')
            return '/api/v1/namespaces/' + quote(namespace, safe='') + '/secrets/' + quote(name, safe='')
        if kind == 'Namespace' and namespace is None and name == self.namespace:
            return '/api/v1/namespaces/' + quote(name, safe='')
        if kind == 'Secret' and namespace == self.namespace:
            return '/api/v1/namespaces/' + quote(namespace, safe='') + '/secrets/' + quote(name, safe='')
        raise ContractError('kubernetes_metadata_scope_invalid')

    def _request(self, method, kind, name, namespace, patch=None):
        path = self._path(kind, name, namespace)
        connection = _UnixConnection(self.socket)
        headers = {'Accept': ACCEPT}
        body = None
        if patch is not None:
            headers['Content-Type'] = 'application/json-patch+json'
            body = json.dumps(patch, separators=(',', ':')).encode()
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            if response.status == 404 and method == 'GET':
                return None
            if response.status != 200:
                raise ContractError('kubernetes_metadata_http_' + str(response.status))
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ContractError('kubernetes_metadata_response_unbounded')
            value = json.loads(raw)
            if (not isinstance(value, dict) or set(value) != {'apiVersion', 'kind', 'metadata'}
                    or value['apiVersion'] != 'meta.k8s.io/v1' or value['kind'] != 'PartialObjectMetadata'
                    or not isinstance(value['metadata'], dict)):
                raise ContractError('kubernetes_metadata_response_invalid')
            metadata = value['metadata']
            if (metadata.get('name') != name or not isinstance(metadata.get('uid'), str) or not metadata['uid']
                    or not isinstance(metadata.get('resourceVersion'), str) or not metadata['resourceVersion']
                    or (namespace is not None and metadata.get('namespace') != namespace)):
                raise ContractError('kubernetes_metadata_response_invalid')
            return {'metadata': metadata}
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise ContractError('kubernetes_metadata_transport_failed') from exc
        finally:
            connection.close()

    def get(self, kind, name, namespace):
        return self._request('GET', kind, name, namespace)

    def annotate(self, kind, name, namespace, metadata, additions):
        if self.only_secret is not None:
            raise ContractError('kubernetes_metadata_scope_invalid')
        if (not additions or not set(additions) <= IDENTITY_KEYS
                or any(not isinstance(v, str) or not v for v in additions.values())
                or any(key in metadata.get('annotations', {}) for key in additions)):
            raise ContractError('kubernetes_metadata_annotation_invalid')
        patch = []
        for key in ('uid', 'resourceVersion'):
            value = metadata.get(key)
            if not isinstance(value, str) or not value:
                raise ContractError('kubernetes_metadata_precondition_missing')
            patch.append({'op': 'test', 'path': '/metadata/' + key, 'value': value})
        for key in OWNERSHIP_KEYS:
            value = metadata.get('annotations', {}).get(key)
            if not isinstance(value, str) or not value:
                raise ContractError('kubernetes_metadata_precondition_missing')
            patch.append({'op': 'test', 'path': '/metadata/annotations/' + key.replace('~', '~0').replace('/', '~1'),
                          'value': value})
        patch.extend({'op': 'add', 'path': '/metadata/annotations/' + key.replace('~', '~0').replace('/', '~1'),
                      'value': value} for key, value in sorted(additions.items()))
        return self._request('PATCH', kind, name, namespace, patch)


# AF_UNIX paths are limited to 107 bytes; a long TMPDIR falls back to /tmp for the proxy socket.
SOCKET_PATH_LIMIT = 100


def socket_directory_base():
    base = tempfile.gettempdir()
    return base if len(os.fsencode(base)) + len('/adw-kube-meta-XXXXXXXX/proxy.sock') <= SOCKET_PATH_LIMIT else '/tmp'


@contextmanager
def metadata_api(provider, *, secret=None):
    """Target-scoped metadata client; with secret=(namespace, name), read-only metadata of exactly that Secret."""
    if not provider.context or provider.kubeconfig is None or not NAME.fullmatch(provider.namespace):
        raise ContractError('kubernetes_context_not_discovered')
    if secret is not None and (len(secret) != 2 or not all(isinstance(v, str) and NAME.fullmatch(v) for v in secret)):
        raise ContractError('kubernetes_metadata_scope_invalid')
    with tempfile.TemporaryDirectory(prefix='adw-kube-meta-', dir=socket_directory_base()) as temporary:
        path = Path(temporary) / 'proxy.sock'
        rejected = 'POST,PUT,DELETE,HEAD,OPTIONS,CONNECT,TRACE'
        if secret is None:
            scope = re.escape('/api/v1/namespaces/' + provider.namespace)
            accepted = '^' + scope + r'(/secrets/[a-z0-9][a-z0-9.-]*)?$'
        else:
            accepted = '^' + re.escape('/api/v1/namespaces/' + secret[0] + '/secrets/' + secret[1]) + '$'
            rejected += ',PATCH'
        command = ['kubectl', '--context', provider.context, '--kubeconfig', str(provider.kubeconfig),
                   'proxy', '--unix-socket=' + str(path), '--accept-hosts=^localhost$',
                   '--accept-paths=' + accepted, '--reject-methods=' + rejected]
        try:
            process = subprocess.Popen(command, env=provider._environment(),
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            raise ContractError('kubernetes_metadata_proxy_unavailable') from exc
        try:
            deadline = time.monotonic() + 10
            while not path.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise ContractError('kubernetes_metadata_proxy_unavailable')
                time.sleep(0.05)
            yield (MetadataClient(path, provider.namespace) if secret is None
                   else MetadataClient(path, secret[0], only_secret=secret[1]))
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

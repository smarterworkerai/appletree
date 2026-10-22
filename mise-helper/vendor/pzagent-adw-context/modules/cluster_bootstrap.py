"""Optional, profile-bound local-cluster bootstrap; Secrets are stdin-only."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
from urllib.request import urlopen

from .common import ContractError
from .operator_credentials import REGISTRY

CERT_MANAGER_VERSION = 'v1.21.2'
CERT_MANAGER_SHA256 = 'e03b668ec8675214af6b0a671699d088f2601fa3878e0dbe1b41d3feafd1879f'
CERT_MANAGER_URL = ('https://github.com/cert-manager/cert-manager/releases/download/'
                    + CERT_MANAGER_VERSION + '/cert-manager.yaml')
PULL_SECRET = 'adw-ghcr-pull'
OWNER, PROFILE = 'pzagent.owner', 'pzagent.profile'
ENV_KEY = re.compile(r'[A-Z][A-Z0-9_]{0,127}')
# Generated credentials are limited to internal test values, never API/provider keys.
GENERATABLE_KEY = re.compile(r'(?:POSTGRES_PASSWORD|(?:[A-Z][A-Z0-9_]*_)?(?:DB_PASSWORD|DATABASE_PASSWORD|STORAGE_SECRET|SIGNING_SECRET|INTERNAL_SERVICE_TOKEN))')
OBJECT_NAME = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')

DOMAIN = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}')


def validate(profile: dict) -> None:
    """Validate optional closed blocks before any cluster mutation."""
    try:
        if 'tls' in profile:
            tls = profile['tls']
            if (not isinstance(tls, dict) or set(tls) != {'provider', 'domain', 'issuer', 'acme_email_env'}
                    or tls['provider'] != 'cloudflare-dns01' or tls['issuer'] not in {'staging', 'production'}
                    or not isinstance(tls['domain'], str) or len(tls['domain']) > 253
                    or not DOMAIN.fullmatch(tls['domain']) or not ENV_KEY.fullmatch(tls['acme_email_env'])
                    or not tls['acme_email_env'].endswith('_EMAIL')):
                raise ValueError()
        if 'image_pull' in profile:
            pull = profile['image_pull']
            if isinstance(pull, dict) and pull.get('token_env') in REGISTRY:
                raise ContractError('cluster_pull_operator_credential_refused')
            if (not isinstance(pull, dict) or set(pull) != {'registry', 'token_env', 'username_env', 'namespaces'}
                    or pull['registry'] != 'ghcr.io' or not ENV_KEY.fullmatch(pull['token_env'])
                    or not ENV_KEY.fullmatch(pull['username_env']) or not pull['token_env'].endswith('_TOKEN')
                    or not pull['username_env'].endswith('_USERNAME') or pull['token_env'] == 'CF_DNS_API_TOKEN'
                    or not isinstance(pull['namespaces'], list) or not pull['namespaces']
                    or len(set(pull['namespaces'])) != len(pull['namespaces'])
                    or not set(pull['namespaces']) <= set(profile['namespaces'])):
                raise ValueError()
        if 'app_secrets' in profile:
            namespaces = profile['app_secrets']
            if (not isinstance(namespaces, dict) or not namespaces or len(namespaces) > 16
                    or not set(namespaces) <= set(profile['namespaces'])):
                raise ValueError()
            for namespace, entries in namespaces.items():
                aliases = [alias for alias, ns in profile['context_aliases'].items() if ns == namespace]
                if len(aliases) != 1 or not isinstance(entries, dict) or not entries or len(entries) > 16:
                    raise ValueError()
                for name, fields in entries.items():
                    if (not isinstance(name, str) or not OBJECT_NAME.fullmatch(name)
                            or name in {PULL_SECRET, 'adw-cloudflare', 'adw-wildcard-tls'}
                            or not isinstance(fields, dict) or not fields or len(fields) > 64):
                        raise ValueError()
                    for key, source in fields.items():
                        if not isinstance(key, str) or not ENV_KEY.fullmatch(key) or not isinstance(source, dict):
                            raise ValueError()
                        if set(source) == {'env'}:
                            operator_key = source['env']
                            if (not isinstance(operator_key, str) or not ENV_KEY.fullmatch(operator_key)
                                    or not operator_key.endswith(('_KEY', '_TOKEN', '_PASSWORD', '_SECRET'))
                                    or operator_key in REGISTRY | {'CF_DNS_API_TOKEN'}):
                                raise ValueError()
                        elif (set(source) != {'generate'} or source['generate'] != 'random-32'
                              or not GENERATABLE_KEY.fullmatch(key)):
                            raise ValueError()
    except (KeyError, ValueError, TypeError) as exc:
        raise ContractError('cluster_bootstrap_profile_invalid') from exc


def facts(profile: dict) -> dict:
    """Preflight missing facts before creating anything; never return publicly."""
    values = {}
    for block, fields in (('tls', ('acme_email_env',)), ('image_pull', ('token_env', 'username_env'))):
        if block in profile:
            for field in fields:
                key = profile[block][field]
                value = os.environ.get(key, '')
                if not value or len(value) > 16384 or any(c in value for c in '\r\n\x00'):
                    raise ContractError('cluster_bootstrap_fact_missing')
                values[field] = value
    if 'tls' in profile:
        token = os.environ.get('CF_DNS_API_TOKEN', '')
        if not token or len(token) > 16384 or any(c in token for c in '\r\n\x00'):
            raise ContractError('cluster_bootstrap_fact_missing')
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', values['acme_email_env']):
            raise ContractError('cluster_bootstrap_email_invalid')
        values['cloudflare'] = token
    if 'image_pull' in profile and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}', values['username_env']):
        raise ContractError('cluster_bootstrap_username_invalid')
    application = {}
    for namespace, entries in profile.get('app_secrets', {}).items():
        for name, fields in entries.items():
            for key, source in fields.items():
                if 'env' in source:
                    value = os.environ.get(source['env'], '')
                    if not value or len(value) > 16384 or any(c in value for c in '\r\n\x00'):
                        raise ContractError('cluster_bootstrap_fact_missing')
                    application[(namespace, name, key)] = value
    values['app_secrets'] = application
    return values


def manifest() -> bytes:
    try:
        with urlopen(CERT_MANAGER_URL, timeout=45) as response:
            raw = response.read(8 * 1024 * 1024 + 1)
    except (OSError, ValueError) as exc:
        raise ContractError('cluster_cert_manager_download_failed') from exc
    if hashlib.sha256(raw).hexdigest() != CERT_MANAGER_SHA256:
        raise ContractError('cluster_cert_manager_checksum_mismatch')
    return raw


def manifest_items(raw: bytes) -> list[dict]:
    """kubectl create prints each input object as a separate JSON document."""
    try:
        text = raw.decode()
        decoder = json.JSONDecoder()
        items: list[dict] = []
        identities = set()
        while text.strip():
            value, end = decoder.raw_decode(text.lstrip())
            text = text.lstrip()[end:]
            if not isinstance(value, dict):
                raise ValueError()
            batch = value['items'] if value.get('kind') == 'List' else [value]
            if not isinstance(batch, list):
                raise ValueError()
            for item in batch:
                identity = (item['kind'], item['metadata'].get('namespace', ''), item['metadata']['name'])
                if (not all(isinstance(v, str) for v in identity) or not identity[0] or not identity[2]
                        or identity in identities or not isinstance(item['apiVersion'], str)):
                    raise ValueError()
                identities.add(identity)
                items.append(item)
                if len(items) > 128:
                    raise ValueError()
        if not items:
            raise ValueError()
        return items
    except (UnicodeError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ContractError('cluster_cert_manager_manifest_invalid') from exc


class Bootstrap:
    def __init__(self, lifecycle, values: dict) -> None:
        self.lifecycle, self.values = lifecycle, values
        self.labels = {OWNER: 'adw', PROFILE: lifecycle.digest[:63]}

    def owned(self, kind: str, name: str, namespace: str | None, extra_labels: dict | None = None) -> bool:
        args = ['get', kind, name, '--ignore-not-found', '-o', 'jsonpath={.metadata.name}{"\\n"}{.metadata.labels}']
        if namespace:
            args += ['--namespace', namespace]
        raw = self.lifecycle.kube(args)
        if raw.strip():
            try:
                observed, _, label_bytes = raw.partition(b'\n')
                labels = json.loads(label_bytes) if label_bytes.strip() else {}
                if observed.decode() != name or any(labels.get(k) != v for k, v in (self.labels | (extra_labels or {})).items()):
                    raise ValueError()
            except (ValueError, TypeError, AttributeError) as exc:
                raise ContractError('cluster_bootstrap_ownership_unproven') from exc
            return True
        return False

    def apply(self, items: list[dict]) -> None:
        for item in items:
            metadata = item['metadata']
            self.owned(item['kind'], metadata['name'], metadata.get('namespace'))
            metadata.setdefault('labels', {}).update(self.labels)
        self.lifecycle.kube(['apply', '--server-side', '--field-manager', 'adw-bootstrap', '-f', '-', '-o', 'name'],
                            data=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items}).encode())

    def secret(self, name: str, namespace: str, values: dict, kind='Opaque', extra_labels: dict | None = None) -> None:
        # base64 is the Kubernetes wire format, not a redaction mechanism.
        # No client-side apply/last-applied annotation or on-disk payload.
        item = {'apiVersion': 'v1', 'kind': 'Secret', 'type': kind,
                'metadata': {'name': name, 'namespace': namespace, 'labels': extra_labels or {}},
                'data': {key: base64.b64encode(value.encode()).decode() for key, value in values.items()}}
        self.apply([item])
        if not self.owned('Secret', name, namespace, extra_labels):
            raise ContractError('cluster_bootstrap_readback_unproven')

    def run(self, *, target_resources=True) -> dict:
        profile = self.lifecycle.profile
        report = {'tls_ready': False, 'image_pull_ready': False}
        if 'tls' in profile:
            tls = profile['tls']
            try:
                self.lifecycle.kube(['wait', '--for=create', 'crd/tlsstores.traefik.io', '--timeout=180s'], timeout=195)
                self.lifecycle.kube(['wait', '--for=condition=Established', 'crd/tlsstores.traefik.io', '--timeout=90s'], timeout=105)
            except ContractError as exc:
                if str(exc) == 'cluster_context_mismatch':
                    raise
                raise ContractError('cluster_traefik_tlsstore_unavailable') from exc
            stores = self.lifecycle.kube(['get', 'tlsstores.traefik.io', '--all-namespaces', '-o',
                'jsonpath={.items[?(@.metadata.name=="default")].metadata.namespace}'])
            if stores.decode().split() not in ([], ['kube-system']):
                raise ContractError('cluster_bootstrap_ownership_unproven')
            self.owned('TLSStore', 'default', 'kube-system')
            self.lifecycle.namespace('cert-manager')
            raw = manifest()
            # Only the checksum-verified official release is decoded. All
            # pre-existing objects must belong to this same private profile.
            converted = self.lifecycle.kube(['create', '--dry-run=client', '--validate=false', '-f', '-', '-o', 'json'], data=raw)
            items = manifest_items(converted)
            self.apply(items)
            for deployment in ('cert-manager', 'cert-manager-cainjector', 'cert-manager-webhook'):
                self.lifecycle.kube(['rollout', 'status', 'deployment/' + deployment, '--namespace', 'cert-manager', '--timeout=180s'], timeout=195)
            self.lifecycle.kube(['wait', '--for=condition=Established', 'crd/clusterissuers.cert-manager.io', 'crd/certificates.cert-manager.io', '--timeout=90s'], timeout=105)
            self.secret('adw-cloudflare', 'cert-manager', {'api-token': self.values['cloudflare']})
            issuer = 'adw-acme-' + tls['issuer']
            issuer_present = self.owned('ClusterIssuer', issuer, None)
            if not issuer_present:
                # Do not let a new issuer adopt an existing account credential.
                raw = self.lifecycle.kube(['get', 'Secret', issuer + '-account', '--namespace', 'cert-manager',
                                          '--ignore-not-found', '-o', 'name'])
                if raw.strip():
                    raise ContractError('cluster_bootstrap_ownership_unproven')
            endpoint = 'https://acme-' + ('staging-' if tls['issuer'] == 'staging' else '') + 'v02.api.letsencrypt.org/directory'
            self.apply([{'apiVersion': 'cert-manager.io/v1', 'kind': 'ClusterIssuer', 'metadata': {'name': issuer},
                'spec': {'acme': {'server': endpoint, 'email': self.values['acme_email_env'],
                    'privateKeySecretRef': {'name': issuer + '-account'}, 'solvers': [{
                        'selector': {'dnsNames': ['*.' + tls['domain']]},
                        'dns01': {'cloudflare': {'apiTokenSecretRef': {'name': 'adw-cloudflare', 'key': 'api-token'}}}}]}}}])
            self.lifecycle.kube(['wait', '--for=condition=Ready', 'clusterissuer/' + issuer, '--timeout=180s'], timeout=195)
            self.owned('Secret', 'adw-wildcard-tls', 'kube-system')
            self.apply([{'apiVersion': 'cert-manager.io/v1', 'kind': 'Certificate',
                'metadata': {'name': 'adw-wildcard', 'namespace': 'kube-system'},
                'spec': {'secretName': 'adw-wildcard-tls', 'issuerRef': {'name': issuer, 'kind': 'ClusterIssuer'},
                         'dnsNames': ['*.' + tls['domain']], 'secretTemplate': {'labels': self.labels}}}])
            self.lifecycle.kube(['wait', '--for=condition=Ready', 'certificate/adw-wildcard', '--namespace', 'kube-system', '--timeout=300s'], timeout=315)
            ready = self.lifecycle.kube(['get', 'Certificate', 'adw-wildcard', '--namespace', 'kube-system',
                '-o', 'jsonpath={.status.conditions[?(@.type=="Ready")].status}'])
            if ready.strip() != b'True':
                raise ContractError('cluster_certificate_readback_unproven')
            self.apply([{'apiVersion': 'traefik.io/v1alpha1', 'kind': 'TLSStore',
                'metadata': {'name': 'default', 'namespace': 'kube-system'},
                'spec': {'defaultCertificate': {'secretName': 'adw-wildcard-tls'}}}])
            reference = self.lifecycle.kube(['get', 'TLSStore', 'default', '--namespace', 'kube-system',
                '-o', 'jsonpath={.spec.defaultCertificate.secretName}'])
            if reference.strip() != b'adw-wildcard-tls':
                raise ContractError('cluster_tlsstore_readback_unproven')
            report['tls_ready'] = True
        if target_resources and 'image_pull' in profile:
            pull = profile['image_pull']
            auth = base64.b64encode((self.values['username_env'] + ':' + self.values['token_env']).encode()).decode()
            config = json.dumps({'auths': {pull['registry']: {'auth': auth}}}, separators=(',', ':'))
            for namespace in pull['namespaces']:
                self.secret(PULL_SECRET, namespace, {'.dockerconfigjson': config}, 'kubernetes.io/dockerconfigjson')
            report['image_pull_ready'] = True
        if target_resources and 'app_secrets' in profile:
            for namespace, entries in profile['app_secrets'].items():
                alias = next(alias for alias, ns in profile['context_aliases'].items() if ns == namespace)
                labels = {'app.kubernetes.io/managed-by': 'adw', 'adw.pzagent.io/target': alias}
                for name, fields in entries.items():
                    # Existing owned values are never read, regenerated or rotated on retry.
                    if not self.owned('Secret', name, namespace, labels):
                        values = {key: (self.values['app_secrets'][(namespace, name, key)] if 'env' in source
                                        else secrets.token_urlsafe(32)) for key, source in fields.items()}
                        self.secret(name, namespace, values, extra_labels=labels)
                    observed = self.lifecycle.kube(['get', 'Secret', name, '--namespace', namespace,
                        '-o', 'go-template={{range $key, $value := .data}}{{$key}}{{"\\n"}}{{end}}'])
                    if set(observed.decode().splitlines()) != set(fields):
                        raise ContractError('cluster_app_secret_readback_unproven')
            report['app_secrets_ready'] = True
        return report

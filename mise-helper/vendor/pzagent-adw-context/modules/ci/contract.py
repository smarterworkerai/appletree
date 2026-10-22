"""Resolve the immutable context identity from the exact GitHub source commit."""
from __future__ import annotations
import json
import hashlib
import re
from .github_api import ApiError, project_files
from .quality_proof import ProofError
from ..common import FULL_SHA


def contract_ref(api, source_sha: str) -> str:
    if not isinstance(source_sha,str) or not FULL_SHA.fullmatch(source_sha):
        raise ProofError('contract_source_invalid')
    try:
        metadata=project_files(api,source_sha,'adw-task-manifest.json','pzagent-context-lock.json')
        _,manifest_bytes=metadata['adw-task-manifest.json']
        _,lock_bytes=metadata['pzagent-context-lock.json']
        _,bundle_bytes=api.content('mise-helper/vendor/pzagent-adw-context/bundle.json',source_sha)
        manifest=json.loads(manifest_bytes)
        lock=json.loads(lock_bytes)
        bundle=json.loads(bundle_bytes)
        sources=manifest['sources']
        if not isinstance(sources,dict) or len(sources)>4:
            raise ProofError('contract_sources_invalid')
        matching=[(source_id,value) for source_id,value in sources.items()
                  if isinstance(source_id,str) and isinstance(value,dict) and value.get('layer')=='context']
        if len(matching)!=1:
            raise ProofError('context_source_missing')
        _,source=matching[0]
        ref=source.get('ref')
        if (not isinstance(ref,str) or not FULL_SHA.fullmatch(ref)
            or source.get('path')!='mise-helper/vendor/pzagent-adw-context/tasks.toml'
            or lock.get('source_ref')!=ref
            or not isinstance(bundle,dict)
            or bundle.get('schema_version')!='1.0.0'
            or bundle.get('package')!='pzagent-adw-context'
            or not isinstance(bundle.get('version'),str)
            or not re.fullmatch(r'0\.\d+\.\d+',bundle['version'])
            or lock.get('package_version')!=bundle['version']
            or lock.get('schema_version')!='1.0.0'
            or not isinstance(manifest.get('contract'),dict)
            or not re.fullmatch(r'2\.\d+\.\d+',str(manifest['contract'].get('version','')))):
            raise ProofError('contract_pin_mismatch')
        # The generic contract version is whatever the vendored generic engine at this exact
        # commit implements; the manifest must declare the same one (same rule as adw:context:check).
        _,engine=api.content('mise-helper/vendor/agentic-delivery/adw_contract.py',source_sha)
        declared=re.search(r'^CONTRACT_VERSION\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$',engine.decode('utf-8','replace'),re.M)
        if declared is None or declared.group(1)!=manifest['contract']['version']:
            raise ProofError('generic_engine_mismatch')
        _,tasks=api.content('mise-helper/vendor/pzagent-adw-context/tasks.toml',source_sha)
        if (source.get('checksum')!='sha256:'+hashlib.sha256(tasks).hexdigest()
            or lock.get('bundle_sha256')!=hashlib.sha256(bundle_bytes).hexdigest()):
            raise ProofError('contract_checksum_mismatch')
        return ref
    except ApiError as exc:
        reason = 'project_directory_conflict' if str(exc) == 'project_directory_conflict' else 'contract_lookup_failed'
        raise ProofError(reason) from None
    except (UnicodeDecodeError,json.JSONDecodeError,KeyError,TypeError,AttributeError):
        raise ProofError('contract_malformed') from None

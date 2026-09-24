"""Resolve the immutable context identity from the exact GitHub source commit."""
from __future__ import annotations
import json
import hashlib
from .github_api import ApiError
from .quality_proof import ProofError
from ..common import FULL_SHA


def contract_ref(api, source_sha: str) -> str:
    if not isinstance(source_sha,str) or not FULL_SHA.fullmatch(source_sha):
        raise ProofError('contract_source_invalid')
    try:
        _,manifest_bytes=api.content('.hermes/adw-task-manifest.json',source_sha)
        _,lock_bytes=api.content('.hermes/pzagent-context-lock.json',source_sha)
        manifest=json.loads(manifest_bytes)
        lock=json.loads(lock_bytes)
        sources=manifest['sources']
        if not isinstance(sources,list) or len(sources)>4:
            raise ProofError('contract_sources_invalid')
        matching=[s for s in sources if isinstance(s,dict) and s.get('layer')=='context']
        if len(matching)!=1:
            raise ProofError('context_source_missing')
        source=matching[0]
        ref=source.get('ref')
        if (not isinstance(ref,str) or not FULL_SHA.fullmatch(ref)
            or source.get('path')!='mise-helper/vendor/pzagent-adw-context/tasks.toml'
            or lock.get('source_ref')!=ref
            or lock.get('package_version')!='0.2.5'
            or lock.get('schema_version')!='1.0.0'
            or manifest.get('contract',{}).get('version')!='2.0.0'):
            raise ProofError('contract_pin_mismatch')
        _,tasks=api.content('mise-helper/vendor/pzagent-adw-context/tasks.toml',source_sha)
        _,bundle=api.content('mise-helper/vendor/pzagent-adw-context/bundle.json',source_sha)
        if (source.get('checksum')!='sha256:'+hashlib.sha256(tasks).hexdigest()
            or lock.get('bundle_sha256')!=hashlib.sha256(bundle).hexdigest()):
            raise ProofError('contract_checksum_mismatch')
        return ref
    except ApiError:
        raise ProofError('contract_lookup_failed') from None
    except (UnicodeDecodeError,json.JSONDecodeError,KeyError,TypeError,AttributeError):
        raise ProofError('contract_malformed') from None

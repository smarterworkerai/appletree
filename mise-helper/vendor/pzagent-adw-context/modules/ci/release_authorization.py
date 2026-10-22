"""Closed CI release receipt validation and authoritative proof replay."""
from __future__ import annotations
import os
from pathlib import Path

from ..common import ContractError, closed_object, load_json
from .build_artifacts import Producer
from .github_api import ApiError, GitHub
from .publication_proof import authorize_release
from .quality_proof import ProofError

FIELDS={
    'schema_version','repository','source_sha','pr_number','target_branch',
    'actor','workflow_path','run_id','run_attempt','job_id','tested_tree',
    'contract_ref','proof_scope','release_kind',
    'publication_lane','publication_pointer','expected_pointer_digest',
    'quality_producer',
}
QUALITY_PRODUCER_FIELDS={'repository','source_sha','run_id','run_attempt',
                         'event','branch','pr_number'}


def load(path: Path) -> dict:
    receipt=closed_object(load_json(path,max_bytes=32768),required=FIELDS,
                          allowed=FIELDS,name='release authorization receipt')
    if receipt.get('schema_version')!='2.2.0':
        raise ContractError('release authorization receipt schema is unsupported')
    producer=closed_object(receipt.get('quality_producer'),required=QUALITY_PRODUCER_FIELDS,
                           allowed=QUALITY_PRODUCER_FIELDS,name='quality producer')
    try:
        identity=Producer(**producer)
    except (ApiError,TypeError):
        raise ContractError('release authorization quality producer is invalid') from None
    if (identity.event!='pull_request' or identity.repository!=receipt.get('repository')
        or identity.source_sha!=receipt.get('source_sha')
        or identity.run_id!=receipt.get('run_id')
        or identity.run_attempt!=receipt.get('run_attempt')
        or identity.pr_number!=receipt.get('pr_number')):
        raise ContractError('release authorization quality producer differs')
    return receipt


def revalidate_for_kind(path: Path, adapter: dict, *, kind_name: str) -> dict:
    receipt=load(path)
    return revalidate(path,adapter,kind_name=kind_name,
                      source_sha=receipt['source_sha'],
                      publication_pointer=None,expected_pointer_digest=None)


def revalidate(path: Path, adapter: dict, *, kind_name: str, source_sha: str,
               publication_pointer: str | None,
               expected_pointer_digest: str | None) -> dict:
    """Recompute the exact receipt before any registry mutation."""
    if os.environ.get('GITHUB_ACTIONS','').lower()!='true':
        raise ContractError('CI release authorization requires GitHub Actions')
    receipt=load(path)
    repository=adapter['repository']['id']
    actor=os.environ.get('GITHUB_TRIGGERING_ACTOR') or os.environ.get('GITHUB_ACTOR','')
    if (receipt['repository']!=repository or receipt['actor']!=actor
        or receipt['source_sha']!=source_sha or receipt['release_kind']!=kind_name
        or receipt['publication_lane']!=kind_name
        or receipt['publication_pointer']!=publication_pointer
        or receipt['expected_pointer_digest']!=expected_pointer_digest):
        raise ContractError('release authorization differs from requested publication')
    if receipt['proof_scope']=='pull_request':
        pr_number=receipt['pr_number'];target=None
    elif receipt['proof_scope']=='destination':
        pr_number=None;target=receipt['target_branch']
    else:
        raise ContractError('release authorization proof scope is invalid')
    try:
        expected=authorize_release(
            GitHub(repository),source_sha=source_sha,run_id=receipt['run_id'],
            attempt=receipt['run_attempt'],actor=actor,adapter=adapter,
            proof_scope=receipt['proof_scope'],pr_number=pr_number,target=target,
            release_kind=kind_name,publication_lane=receipt['publication_lane'],
            publication_pointer=publication_pointer,
            expected_pointer_digest=expected_pointer_digest)
    except (ProofError,ApiError,KeyError,TypeError,ValueError) as exc:
        raise ContractError('release authorization revalidation failed') from exc
    if expected!=receipt:
        raise ContractError('release authorization changed before publication')
    return receipt

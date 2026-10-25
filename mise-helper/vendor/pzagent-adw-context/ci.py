#!/usr/bin/env python3
"""Read-only CI routing and exact-source PR premerge proof."""
from __future__ import annotations
import argparse
from dataclasses import replace
import json
import os
import time
from pathlib import Path
from modules.adapter import load as load_adapter
from modules.common import ContractError
from modules.ci.contract import contract_ref
from modules.ci.ci_only import require_ci_only
from modules.ci.evidence import job_evidence
from modules.ci.github_api import ApiError, GitHub, lookup_detail, project_files
from modules.ci.live_pr import read_pr
from modules.ci.policy import classify
from modules.ci.publication_proof import destination_gate, with_transient_retry
from modules.ci.provenance import bootstrap_status, trust_root_gate, trusted_source
from modules.ci.quality_proof import ProofError, Pull, premerge_check
from modules.ci.reuse import prior_gate
from modules.ci.vendor_integrity import check as check_vendor_integrity
from modules.ci.workflow_drift import validate as validate_workflow


def _load_same_source_adapter(api: GitHub, adapter_path: Path, sha: str):
    manifest_path = adapter_path.parent / "adw-task-manifest.json"
    try:
        manifest_bytes = manifest_path.read_bytes()
        metadata = project_files(api, sha, 'pzagent-adapter.json', 'adw-task-manifest.json')
        if adapter_path.read_bytes() != metadata['pzagent-adapter.json'][1]:
            raise ProofError('adapter_source_mismatch')
        remote_manifest = metadata['adw-task-manifest.json'][1]
    except ApiError as exc:
        reason = 'project_directory_conflict' if str(exc) == 'project_directory_conflict' else 'manifest_source_mismatch'
        raise ProofError(reason) from None
    except OSError:
        raise ProofError("manifest_source_mismatch") from None
    if manifest_bytes != remote_manifest:
        raise ProofError("manifest_source_mismatch")
    adapter = load_adapter(adapter_path, manifest_path)
    return adapter


def live_request(repository: str, number: int, expected_sha: str, adapter_path: Path):
    if adapter_path is None:
        raise ProofError('adapter_missing')
    api=GitHub(repository)
    first=api.get(f'pulls/{number}')
    if first['head']['sha']!=expected_sha:
        raise ProofError('stale_source_head')
    ref=contract_ref(api,expected_sha)
    pr,rev=read_pr(api,number,contract_ref=ref)
    if pr.head_sha!=expected_sha:
        raise ProofError('stale_source_head')
    adapter=_load_same_source_adapter(api,adapter_path,pr.head_sha)
    if adapter['repository']['id']!=repository:
        raise ProofError('adapter_repository_mismatch')
    if pr.target_branch not in adapter['repository']['protected_branches']:
        raise ProofError('destination_not_protected')
    trusted_source(api,pr)
    return api,pr,rev,adapter


def declared_pair(adapter,pr):
    if {'source':pr.source_branch,'target':pr.target_branch} not in adapter['delivery']['promotion_pairs']:
        raise ProofError('undeclared_promotion_pair')


def destination_request(repository: str, target: str, expected_sha: str, adapter_path: Path):
    api=GitHub(repository)
    adapter=_load_same_source_adapter(api,adapter_path,expected_sha)
    if adapter['repository']['id']!=repository:
        raise ProofError('adapter_repository_mismatch')
    commit=api.get(f'git/commits/{expected_sha}')
    parents=commit.get('parents') if isinstance(commit,dict) else None
    if not isinstance(parents,list):
        raise ProofError('destination_commit_invalid')
    if len(parents)>1:
        raise ProofError('destination_merge_commit')
    return destination_gate(api,source_sha=expected_sha,adapter=adapter,target=target)


def proof_attempt(api,pr,rev,*,target: str):
    if pr.target_branch!=target or pr.state!='open' or pr.merged:
        raise ProofError('target_or_state_invalid')
    if (rev.live_source_sha!=pr.head_sha or rev.live_target_sha!=pr.base_sha
        or not rev.ff or rev.merge_tree!=rev.source_tree):
        raise ProofError('merge_tree_requires_branch_sync')
    root=prior_gate(api,pr,rev)
    return {'status':'proved','proof_kind':'proof','source_sha':pr.head_sha,
            'tested_tree':rev.source_tree,'gate_run_id':root.run_id,
            'gate_attempt':root.attempt}


def _bootstrap_pull(api: GitHub, repository: str, number: int) -> Pull:
    record=api.get(f'pulls/{number}')
    try:
        head=record['head'];base=record['base']
        same=(head['repo']['full_name']==repository and base['repo']['full_name']==repository)
        pull=Pull(repository=repository,number=number,source_branch=head['ref'],
                  target_branch=base['ref'],head_sha=head['sha'],base_sha=base['sha'],
                  merge_sha=record.get('merge_commit_sha') or head['sha'],
                  state=record['state'],same_repository=same,approved_head_sha=None,
                  merged=record.get('merged') is True)
    except (KeyError,TypeError):
        raise ProofError('bootstrap_pull_invalid') from None
    if pull.state!='open' or not pull.same_repository:
        raise ProofError('bootstrap_pull_invalid')
    return pull


def bootstrap_request(repository: str, number: int):
    api=GitHub(repository)
    pull=_bootstrap_pull(api,repository,number)
    # v0.6.0 CI calls bootstrap-status from the unprivileged pull_request gate.
    # Preserve that first-repin path while controller events continue producing
    # the decision that is uploaded as the immutable artifact.
    if os.environ.get('GITHUB_EVENT_NAME')=='pull_request':
        return trust_root_gate(api,pull)
    return bootstrap_status(api,pull)


def trust_root_request(repository: str, number: int, wait_seconds: int = 300):
    api=GitHub(repository)
    return trust_root_gate(api,_bootstrap_pull(api,repository,number),wait_seconds=wait_seconds)


def _blocked(reason, detail=None):
    result={'status':'blocked','reason':reason}
    if lookup_detail(detail):
        result['detail']=lookup_detail(detail)
    print(json.dumps(result,sort_keys=True))
    return 21


def _proof_rejected(exc):
    if isinstance(exc,ProofError):
        return exc.reason
    if isinstance(exc,ApiError):
        return 'api_error'
    return 'readback_invalid'


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest='command',required=True)
    coordinator=sub.add_parser('release-coordinator')
    coordinator.add_argument('operation', choices=('configure', 'inventory', 'prepare', 'package', 'publish'))
    command=sub.add_parser('classify')
    command.add_argument('--event',required=True,choices=['push','pull_request','workflow_dispatch'])
    command.add_argument('--branch',required=True)
    command.add_argument('--protected',nargs='+')
    command.add_argument('--adapter',type=Path)
    command.add_argument('--manual-confirm',action='store_true')
    command.add_argument('--repository')
    command.add_argument('--pr',type=int)
    command.add_argument('--target')
    command.add_argument('--expected-sha')
    for name in ('proof-pr','premerge-check'):
        proof=sub.add_parser(name)
        proof.add_argument('--repository',required=True)
        proof.add_argument('--pr',required=True,type=int)
        proof.add_argument('--target',required=True)
        proof.add_argument('--expected-sha',required=True)
        proof.add_argument('--adapter',required=True,type=Path)
    destination=sub.add_parser('proof-destination')
    destination.add_argument('--repository',required=True)
    destination.add_argument('--target',required=True)
    destination.add_argument('--expected-sha',required=True)
    destination.add_argument('--adapter',required=True,type=Path)
    bootstrap=sub.add_parser('bootstrap-status')
    bootstrap.add_argument('--repository',required=True)
    bootstrap.add_argument('--pr',required=True,type=int)
    gate=sub.add_parser('trust-root-gate')
    gate.add_argument('--repository',required=True)
    gate.add_argument('--pr',required=True,type=int)
    gate.add_argument('--wait-seconds',type=int,default=300)
    drift=sub.add_parser('workflow-drift')
    drift.add_argument('--root',type=Path,default=Path('.'))
    integrity=sub.add_parser('vendor-integrity')
    integrity.add_argument('--root',type=Path,default=Path('.'))
    args=parser.parse_args(argv)
    if args.command == 'release-coordinator':
        from modules import ci_release
        import subprocess
        try:
            ci_release.main([args.operation])
            return 0
        except ci_release.ContractError as exc:
            # Coordinator errors are fixed local messages; public task detail is identifier-only.
            return _blocked(str(exc) if os.environ.get('LAB_RUN') else 'ci_release_handover_failed')
        except (ContractError, ApiError, OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError):
            return _blocked('ci_release_handover_failed')
    if args.command=='bootstrap-status':
        try:
            print(json.dumps(bootstrap_request(args.repository,args.pr),sort_keys=True))
            return 0
        except (ProofError,ApiError,KeyError,TypeError,ValueError) as exc:
            return _blocked(exc.reason if isinstance(exc,ProofError) else 'readback_invalid')
    if args.command=='trust-root-gate':
        try:
            result=trust_root_request(args.repository,args.pr,args.wait_seconds)
        except (ProofError,ApiError,KeyError,TypeError,ValueError) as exc:
            reason=exc.reason if isinstance(exc,ProofError) else 'readback_invalid'
            result={'allowed':False,'decided_by':'none','reason':reason,
                    'message':'Trust-root gate could not validate the live decision.'}
        print(json.dumps(result,sort_keys=True))
        return 0 if result['allowed'] else 21
    if args.command=='workflow-drift':
        try:
            validate_workflow(args.root)
            print(json.dumps({'status':'passed','workflow_drift':False},sort_keys=True))
            return 0
        except ContractError:
            return _blocked('workflow_template_drift')
    if args.command=='vendor-integrity':
        try:
            print(json.dumps(check_vendor_integrity(args.root.resolve()),sort_keys=True))
            return 0
        except (ContractError,ProofError) as exc:
            # Fixed closed reasons naming bundle-relative paths only; never file contents.
            return _blocked(exc.reason if isinstance(exc,ProofError) else str(exc))
        except (OSError,ValueError,TypeError,KeyError):
            return _blocked('vendor_integrity_unreadable')
    if args.command!='classify':
        try:
            if args.command=='proof-destination':
                result=with_transient_retry(
                    lambda:destination_request(args.repository,args.target,args.expected_sha,args.adapter),
                    sleep=time.sleep)
                print(json.dumps(result,sort_keys=True))
                return 0
            api,pr,rev,adapter=live_request(args.repository,args.pr,args.expected_sha,args.adapter)
            if args.command=='proof-pr':
                declared_pair(adapter,pr)
                result=proof_attempt(api,pr,rev,target=args.target)
            else:
                evidence=job_evidence(api,pr,rev)
                parent=None
                if any(e.kind=='proof' for e in evidence):
                    declared_pair(adapter,pr)
                    parent=prior_gate(api,pr,rev)
                    evidence=[replace(e,parent_run_id=parent.run_id,parent_attempt=parent.attempt)
                              if e.kind=='proof' else e for e in evidence]
                require_ci_only(api,pr.head_sha,adapter['ci']['ci_only_checks'])
                result=premerge_check(pr,rev,evidence,target=args.target,parent=parent)
            print(json.dumps(result,sort_keys=True))
            return 0
        except (ProofError,ApiError,ContractError,OSError,KeyError,TypeError,ValueError) as exc:
            return _blocked(exc.reason if isinstance(exc,ProofError) else 'readback_invalid',
                            getattr(exc,'detail',None))
    try:
        if args.adapter:
            adapter=load_adapter(args.adapter)
            if args.repository and adapter['repository']['id']!=args.repository:
                raise ContractError('adapter_repository_mismatch')
            protected=tuple(adapter['repository']['protected_branches'])
        elif args.protected:
            protected=tuple(args.protected)
        else:
            raise ContractError('protected_branches_missing')
        d=classify(event=args.event,branch=args.branch,protected=protected,
                   manual_confirm=args.manual_confirm)
        proof_rejected=''
        # A transient lookup lag retried for a minute is cheaper than the full graph it
        # would otherwise trigger; a real rejection still falls back at once.
        if args.event=='pull_request' and args.adapter:
            def pull_request_proof():
                api,pr,rev,live_adapter=live_request(args.repository,args.pr,args.expected_sha,args.adapter)
                declared_pair(live_adapter,pr)
                return proof_attempt(api,pr,rev,target=args.target)
            try:
                with_transient_retry(pull_request_proof,sleep=time.sleep)
                d=classify(event=args.event,branch=args.branch,
                           protected=protected,proof=True)
            except (ProofError,ApiError,ContractError,OSError,KeyError,TypeError,ValueError) as exc:
                proof_rejected=_proof_rejected(exc)
                pass  # A rejected/missing proof always runs the full gate.
        if args.event=='push' and d.mode=='full' and args.adapter:
            try:
                with_transient_retry(
                    lambda:destination_request(args.repository,args.branch,args.expected_sha,args.adapter),
                    sleep=time.sleep)
                d=classify(event=args.event,branch=args.branch,
                           protected=protected,proof=True)
            except (ProofError,ApiError,ContractError,OSError,KeyError,TypeError,ValueError) as exc:
                proof_rejected=_proof_rejected(exc)
                pass
    except (ContractError,OSError,ValueError):
        return _blocked('adapter_invalid')
    mapping={'full':'full-quality','minimal':'fast-feedback','proof':'reuse'}
    output={'mode':mapping[d.mode],'reason':d.reason,
            'proof_rejected':proof_rejected,
            'reuse_sha':args.expected_sha if d.mode=='proof' else ''}
    target=os.environ.get('GITHUB_OUTPUT')
    if target:
        with Path(target).open('a',encoding='utf-8') as handle:
            for key,value in output.items():
                handle.write(f'{key}={value}\n')
    print(json.dumps(output,sort_keys=True))
    return 0

if __name__=='__main__':
    raise SystemExit(main())

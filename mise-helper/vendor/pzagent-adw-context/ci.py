#!/usr/bin/env python3
"""Read-only CI routing and exact-source PR premerge proof."""
from __future__ import annotations
import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
from modules.adapter import load as load_adapter
from modules.common import ContractError
from modules.ci.contract import contract_ref
from modules.ci.ci_only import require_ci_only
from modules.ci.evidence import job_evidence
from modules.ci.github_api import ApiError, GitHub
from modules.ci.live_pr import read_pr
from modules.ci.policy import classify
from modules.ci.publication_proof import destination_gate
from modules.ci.provenance import trusted_source
from modules.ci.quality_proof import ProofError, premerge_check
from modules.ci.reuse import prior_gate
from modules.ci.workflow_drift import validate as validate_workflow


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
    adapter=load_adapter(adapter_path)
    if adapter['repository']['id']!=repository:
        raise ProofError('adapter_repository_mismatch')
    if adapter_path.read_bytes()!=api.content('.hermes/pzagent-adapter.json',pr.head_sha)[1]:
        raise ProofError('adapter_source_mismatch')
    if pr.target_branch not in adapter['repository']['protected_branches']:
        raise ProofError('destination_not_protected')
    trusted_source(api,pr)
    return api,pr,rev,adapter


def declared_pair(adapter,pr):
    if {'source':pr.source_branch,'target':pr.target_branch} not in adapter['delivery']['promotion_pairs']:
        raise ProofError('undeclared_promotion_pair')


def destination_request(repository: str, target: str, expected_sha: str, adapter_path: Path):
    api=GitHub(repository)
    adapter=load_adapter(adapter_path)
    if adapter['repository']['id']!=repository:
        raise ProofError('adapter_repository_mismatch')
    if adapter_path.read_bytes()!=api.content('.hermes/pzagent-adapter.json',expected_sha)[1]:
        raise ProofError('adapter_source_mismatch')
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


def _blocked(reason):
    print(json.dumps({'status':'blocked','reason':reason},sort_keys=True))
    return 21


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest='command',required=True)
    command=sub.add_parser('classify')
    command.add_argument('--event',required=True,choices=['push','pull_request','workflow_dispatch'])
    command.add_argument('--branch',required=True)
    command.add_argument('--protected',nargs='+')
    command.add_argument('--adapter',type=Path)
    command.add_argument('--marker',action='store_true')
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
    drift=sub.add_parser('workflow-drift')
    drift.add_argument('--root',type=Path,default=Path('.'))
    args=parser.parse_args(argv)
    if args.command=='workflow-drift':
        try:
            validate_workflow(args.root)
            print(json.dumps({'status':'passed','workflow_drift':False},sort_keys=True))
            return 0
        except ContractError:
            return _blocked('workflow_template_drift')
    if args.command!='classify':
        try:
            if args.command=='proof-destination':
                print(json.dumps(destination_request(args.repository,args.target,args.expected_sha,args.adapter),sort_keys=True))
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
            return _blocked(exc.reason if isinstance(exc,ProofError) else 'readback_invalid')
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
                   marker=args.marker,manual_confirm=args.manual_confirm)
        if args.event=='pull_request' and not args.marker and args.adapter:
            try:
                api,pr,rev,live_adapter=live_request(args.repository,args.pr,args.expected_sha,args.adapter)
                declared_pair(live_adapter,pr)
                proof_attempt(api,pr,rev,target=args.target)
                d=classify(event=args.event,branch=args.branch,
                           protected=protected,marker=False,proof=True)
            except (ProofError,ApiError,ContractError,OSError,KeyError,TypeError,ValueError):
                pass  # A rejected/missing proof always runs the full gate.
        if args.event=='push' and d.mode=='full' and not args.marker and args.adapter:
            try:
                destination_request(args.repository,args.branch,args.expected_sha,args.adapter)
                d=classify(event=args.event,branch=args.branch,
                           protected=protected,marker=False,proof=True)
            except (ProofError,ApiError,ContractError,OSError,KeyError,TypeError,ValueError):
                pass
    except (ContractError,OSError,ValueError):
        return _blocked('adapter_invalid')
    mapping={'full':'full-quality','minimal':'fast-feedback','suppressed':'suppressed','proof':'reuse'}
    output={'mode':mapping[d.mode],'reason':d.reason,
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

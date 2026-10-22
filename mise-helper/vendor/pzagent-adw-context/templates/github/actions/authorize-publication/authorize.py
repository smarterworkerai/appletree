#!/usr/bin/env python3
"""Fail-closed publication adapter; all approval comes from the shared proof engine."""
import json
import os
import re
import sys
import tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[4]))
from modules.adapter import load as load_adapter
from modules.ci.github_api import ApiError,GitHub,project_files
from modules.ci.quality_proof import ProofError
from modules.ci.publication_proof import authorize,authorize_release
from modules.common import ContractError,project_dir

REASON=re.compile(r'[a-z][a-z0-9_]{0,79}')


def _blocked(reason):
    """Fixed reason identifiers are safe to show; anything else stays generic."""
    reason=reason if isinstance(reason,str) and REASON.fullmatch(reason) else ''
    message='blocked: publication proof invalid'+(f' ({reason})' if reason else '')
    print(message,file=sys.stderr)
    for variable,line in (('GITHUB_OUTPUT',f'reason={reason}\n'),
                          ('GITHUB_STEP_SUMMARY',f'{message}\n')):
        target=os.environ.get(variable)
        if target:
            try:
                with open(target,'a',encoding='utf-8') as handle:
                    handle.write(line)
            except OSError:
                pass
    return 21


def main():
    try:
        sha=os.environ.get('SOURCE_SHA','')
        repo=os.environ.get('GITHUB_REPOSITORY','')
        actor=os.environ.get('GITHUB_TRIGGERING_ACTOR') or os.environ.get('GITHUB_ACTOR','')
        run_id=int(os.environ.get('CI_RUN_ID',''))
        attempt=int(os.environ.get('CI_RUN_ATTEMPT',''))
        if not re.fullmatch(r'[0-9a-f]{40}',sha):
            raise ProofError('source_sha_invalid')
        api=GitHub(repo)
        metadata=project_files(api,sha,'pzagent-adapter.json','adw-task-manifest.json')
        source_bytes=metadata['pzagent-adapter.json'][1]
        manifest_bytes=metadata['adw-task-manifest.json'][1]
        with tempfile.TemporaryDirectory() as directory:
            hermes=project_dir(Path(directory))
            hermes.mkdir()
            path=hermes/'pzagent-adapter.json'
            manifest_path=hermes/'adw-task-manifest.json'
            path.write_bytes(source_bytes)
            manifest_path.write_bytes(manifest_bytes)
            adapter=load_adapter(path,manifest_path)
        if adapter['repository']['id']!=repo:
            raise ProofError('adapter_repository_mismatch')
        if os.environ.get('CI_WORKFLOW_PATH')!=adapter['ci']['workflow_path']:
            raise ProofError('publication_workflow_mismatch')
        release_kind=os.environ.get('RELEASE_KIND','')
        if release_kind:
            scope=os.environ.get('PROOF_SCOPE','')
            raw_pr=os.environ.get('PR_NUMBER','')
            pr_number=int(raw_pr) if raw_pr else None
            target=os.environ.get('TARGET') or None
            pointer=os.environ.get('PUBLICATION_POINTER') or None
            expectation=os.environ.get('EXPECTED_POINTER_DIGEST') or None
            record=authorize_release(
                api,source_sha=sha,run_id=run_id,attempt=attempt,actor=actor,
                adapter=adapter,proof_scope=scope,pr_number=pr_number,target=target,
                release_kind=release_kind,
                publication_lane=os.environ.get('PUBLICATION_LANE',''),
                publication_pointer=pointer,expected_pointer_digest=expectation)
        else:
            record=authorize(api,source_sha=sha,run_id=run_id,attempt=attempt,
                             actor=actor,adapter=adapter)
        output=Path(os.environ['AUTHORIZATION_PATH'])
        output.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n',encoding='utf-8')
        print(json.dumps({'authorized':True,'source_sha':sha},sort_keys=True))
        return 0
    except (ProofError,ApiError) as exc:
        return _blocked(exc.reason if isinstance(exc,ProofError) else str(exc))
    except (ContractError,KeyError,OSError,TypeError,ValueError):
        return _blocked(None)

if __name__=='__main__':
    raise SystemExit(main())

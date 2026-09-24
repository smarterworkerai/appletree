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
from modules.ci.github_api import ApiError,GitHub
from modules.ci.quality_proof import ProofError
from modules.ci.publication_proof import authorize
from modules.common import ContractError


def main():
    try:
        sha=os.environ.get('SOURCE_SHA','')
        repo=os.environ.get('GITHUB_REPOSITORY','')
        actor=os.environ.get('GITHUB_ACTOR','')
        run_id=int(os.environ.get('CI_RUN_ID',''))
        attempt=int(os.environ.get('CI_RUN_ATTEMPT',''))
        diagnostic=os.environ.get('DIAGNOSTIC_PUBLISH','false')
        if diagnostic not in ('true','false'):
            raise ProofError('diagnostic_flag_invalid')
        if not re.fullmatch(r'[0-9a-f]{40}',sha):
            raise ProofError('source_sha_invalid')
        api=GitHub(repo)
        source_bytes=api.content('.hermes/pzagent-adapter.json',sha)[1]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'pzagent-adapter.json'
            path.write_bytes(source_bytes)
            adapter=load_adapter(path)
        if adapter['repository']['id']!=repo:
            raise ProofError('adapter_repository_mismatch')
        if os.environ.get('CI_WORKFLOW_PATH')!=adapter['ci']['workflow_path']:
            raise ProofError('publication_workflow_mismatch')
        record=authorize(api,source_sha=sha,run_id=run_id,attempt=attempt,
                         actor=actor,adapter=adapter,diagnostic=diagnostic=='true')
        output=Path(os.environ['AUTHORIZATION_PATH'])
        output.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n',encoding='utf-8')
        print(json.dumps({'authorized':True,'source_sha':sha},sort_keys=True))
        return 0
    except (ProofError,ApiError,ContractError,KeyError,OSError,TypeError,ValueError):
        print('blocked: publication proof invalid',file=sys.stderr)
        return 21

if __name__=='__main__':
    raise SystemExit(main())

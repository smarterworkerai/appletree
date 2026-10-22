"""Evidence-aware PR fast-forward promotion and explicit release-line rollback."""
from __future__ import annotations
import time
from urllib.parse import quote

from .ci.github_api import ApiError, GitHub
from .ci import greenfield
from .ci.publication_proof import destination_gate, pull_request_gate, with_transient_retry
from .ci.quality_proof import ProofError
from .common import ContractError, FULL_SHA
from .execution import human
from .operator_github import api
from .operator_sources import resolve
from .operator_state import locked, new_operation, read, write

MERGE_POLL_ATTEMPTS = 15
MERGE_POLL_SECONDS = 2
READBACK_POLL_ATTEMPTS = 12
READBACK_POLL_SECONDS = 5
REF_POLL_ATTEMPTS = 4
REF_POLL_SECONDS = 2
# Rejections that GitHub's eventual consistency can produce for a few seconds after a
# fast-forward; anything else is a real refusal and is reported at once.
TRANSIENT_DESTINATION_PREFIXES = ('destination_exact_gate_missing', 'destination_association_',
                                  'destination_candidate_')


def _ref_sha(record):
    try:
        value=record['object']['sha']
    except (KeyError,TypeError):
        raise ContractError('release line identity invalid') from None
    if not isinstance(value,str) or not FULL_SHA.fullmatch(value):
        raise ContractError('release line identity invalid')
    return value


def _operator_ref(prefix, line):
    return _ref_sha(api('GET', prefix + '/git/ref/heads/' + quote(line,safe='')))


def _promotion_ref_readback(prefix, record, current):
    """Retry only a lagging previous ref; never repeat the write or accept a foreign ref."""
    for attempt in range(REF_POLL_ATTEMPTS):
        if current==record['result_sha']:
            return
        if current!=record['previous_sha']:
            raise ContractError('release line readback differs')
        if attempt+1<REF_POLL_ATTEMPTS:
            time.sleep(REF_POLL_SECONDS)
            current=_operator_ref(prefix,record['line'])
    raise ContractError('ref update response was uncertain; inspect before retrying')


# Where to look when a proof lookup kept returning nothing for the whole retry window.
LOOKUP_HINTS = {
    'bootstrap_controller_missing': ('no trust-root controller run was listed for the PR head; check with your token: '
        'gh api "repos/<owner>/<repo>/actions/workflows/trust-root-bootstrap.yml/runs?event=pull_request_target'
        '&branch=<head branch>&head_sha=<head sha>"'),
    'bootstrap_controller_unusable': ('the controller run exists but has no usable completed decision artifact yet; '
        'inspect the run with gh run view <id> --repo <owner>/<repo>'),
}


def _proof(call, label):
    try:
        return call()
    except (ProofError,ApiError) as exc:
        reason=exc.reason if isinstance(exc,ProofError) else str(exc)
        hint=LOOKUP_HINTS.get(reason)
        raise ContractError(label + ': ' + reason + (f' ({hint})' if hint else '')) from None


def _validate_promotion_gate(gate, adapter, args, *, expected=None):
    if gate.get('target_branch')!=args.line:
        raise ContractError('pull request base differs from --line')
    source=gate.get('source_sha');previous=gate.get('base_sha')
    branch=gate.get('source_branch')
    if (not isinstance(source,str) or not FULL_SHA.fullmatch(source)
        or not isinstance(previous,str) or not FULL_SHA.fullmatch(previous)
        or not isinstance(branch,str) or not branch):
        raise ContractError('promotion proof identity is invalid')
    protected=adapter['repository']['protected_branches']
    pair={'source':branch,'target':args.line}
    if branch in protected and pair not in adapter['delivery']['promotion_pairs']:
        raise ContractError('protected source is not a declared promotion pair')
    if args.line=='main' and pair not in adapter['delivery']['promotion_pairs']:
        raise ContractError('direct promotion to main is forbidden; use a declared promotion pair')
    if expected is not None:
        fields={
            'source_sha':source,'previous_sha':previous,'source_branch':branch,
            'quality_run_id':gate.get('run_id'),'quality_attempt':gate.get('run_attempt'),
            'tested_tree':gate.get('tested_tree'),'contract_ref':gate.get('contract_ref'),
        }
        if any(expected.get(key)!=value for key,value in fields.items()):
            raise ContractError('live pull-request proof differs from saved operation')
    return source,previous,branch


def _promotion_gate(github, adapter, args, *, source_sha=None, run_id=None, attempt=None):
    # Read-only pre-check, usually run minutes after CI: a controller run or evidence listing
    # that is momentarily empty is far more likely a listing lag than a real absence.
    gate=_proof(
        lambda:with_transient_retry(
            lambda:pull_request_gate(
                github,source_sha=source_sha,pr_number=args.pr,adapter=adapter,
                run_id=run_id,attempt=attempt),
            sleep=time.sleep),
        'promotion proof rejected')
    return gate


def _merged_readback(github, *, pr_number, line, source_sha):
    ref_path=f'git/ref/heads/{line}'
    for attempt in range(MERGE_POLL_ATTEMPTS):
        try:
            destination=_ref_sha(github.get(ref_path))
            pull=github.get(f'pulls/{pr_number}')
        except (ApiError,ContractError):
            destination=None;pull=None
        if destination not in {None,source_sha}:
            raise ContractError('release line readback differs')
        if (destination==source_sha and isinstance(pull,dict)
            and pull.get('state')=='closed' and pull.get('merged') is True
            and isinstance(pull.get('merged_at'),str)
            and pull.get('merge_commit_sha')==source_sha
            and isinstance(pull.get('head'),dict)
            and pull['head'].get('sha')==source_sha):
            return
        if attempt+1<MERGE_POLL_ATTEMPTS:
            time.sleep(MERGE_POLL_SECONDS)
    raise ContractError('pull request merge readback is pending; resume this operation')


def _destination_proof(github, adapter, record):
    """Prove the fast-forwarded destination; tolerate GitHub's short post-merge lag."""
    for attempt in range(READBACK_POLL_ATTEMPTS):
        try:
            return destination_gate(
                github,source_sha=record['source_sha'],adapter=adapter,
                target=record['line'],run_id=record['quality_run_id'],
                attempt=record['quality_attempt'],pr_number=record['pr_number'])
        except (ProofError,ApiError) as exc:
            reason=exc.reason if isinstance(exc,ProofError) else str(exc)
            transient=isinstance(exc,ProofError) and reason.startswith(TRANSIENT_DESTINATION_PREFIXES)
            if not transient or attempt+1>=READBACK_POLL_ATTEMPTS:
                raise ContractError('destination proof rejected: '+reason) from None
            time.sleep(READBACK_POLL_SECONDS)


def _promote(repo, adapter, args):
    if args.strategy!='fast-forward':
        raise ContractError('promotion supports only the fast-forward strategy')
    directory=(args.operation_dir or new_operation(repo)).resolve()
    prefix='/repos/' + adapter['repository']['id']
    update_path=prefix + '/git/refs/heads/' + quote(args.line,safe='')
    github=GitHub(adapter['repository']['id'])
    with locked(directory):
        path=directory/'operation.json'
        if path.exists():
            record=read(path)
            required={'pr_number','source_branch','quality_run_id','quality_attempt',
                      'tested_tree','contract_ref','source_sha','previous_sha'}
            if (record.get('workflow')!='source-line'
                or record.get('line')!=args.line
                or record.get('strategy')!='fast-forward'
                or record.get('pr_number')!=args.pr
                or not required<=set(record)):
                raise ContractError('source-line operation selection differs')
            if record.get('phase')=='complete':
                return record
        else:
            gate=_promotion_gate(github,adapter,args)
            source,previous,branch=_validate_promotion_gate(gate,adapter,args)
            if args.ref is not None and resolve(repo,args.ref,args.remote)!=source:
                raise ContractError('--ref assertion differs from live pull-request head')
            if _operator_ref(prefix,args.line)!=previous:
                raise ContractError('destination changed; inspect before starting a new source-line operation')
            record={
                'schema_version':'1.0.0','workflow':'source-line','phase':'selected',
                'line':args.line,'strategy':'fast-forward','pr_number':args.pr,
                'source_branch':branch,'source_sha':source,'previous_sha':previous,
                'quality_run_id':gate['run_id'],'quality_attempt':gate['run_attempt'],
                'tested_tree':gate['tested_tree'],'contract_ref':gate['contract_ref'],
                'operation_dir':str(directory),
            }
            write(path,record)
        current=_operator_ref(prefix,args.line)
        if record['phase']=='selected':
            if current!=record['previous_sha']:
                raise ContractError('destination changed; inspect before starting a new source-line operation')
            gate=_promotion_gate(
                github,adapter,args,source_sha=record['source_sha'],
                run_id=record['quality_run_id'],attempt=record['quality_attempt'])
            _validate_promotion_gate(gate,adapter,args,expected=record)
            if args.ref is not None and resolve(repo,args.ref,args.remote)!=record['source_sha']:
                raise ContractError('--ref assertion differs from live pull-request head')
            if _operator_ref(prefix,args.line)!=record['previous_sha']:
                raise ContractError('destination changed; inspect before starting a new source-line operation')
            record['result_sha']=record['source_sha']
            record['phase']='requested'
            write(path,record)
            greenfield.before_mutation(github, args.pr)
            api('PATCH',update_path,{'sha':record['source_sha'],'force':False})
            current=_operator_ref(prefix,args.line)
        elif record['phase']!='requested':
            raise ContractError('source-line operation phase is invalid')
        _promotion_ref_readback(prefix,record,current)
        _merged_readback(
            github,pr_number=record['pr_number'],line=record['line'],
            source_sha=record['source_sha'])
        proof=_destination_proof(github,adapter,record)
        if (proof.get('pr_number')!=record['pr_number']
            or proof.get('tested_tree')!=record['tested_tree']
            or proof.get('contract_ref')!=record['contract_ref']):
            raise ContractError('destination proof differs from promotion journal')
        record['phase']='complete';record['status']='ok';write(path,record)
        return record


def _rollback(repo, adapter, args):
    if not args.ref:
        raise ContractError('source-line rollback requires --ref')
    directory=(args.operation_dir or new_operation(repo)).resolve()
    prefix='/repos/' + adapter['repository']['id']
    ref_path=prefix + '/git/ref/heads/' + quote(args.line,safe='')
    update_path=prefix + '/git/refs/heads/' + quote(args.line,safe='')
    with locked(directory):
        path=directory/'operation.json'
        if path.exists():
            record=read(path)
            if record.get('operation_kind')!='release-line-rollback':
                raise ContractError('legacy source-line journal cannot be resumed; inspect it and start a new operation')
            if (record.get('workflow')!='source-line' or record.get('line')!=args.line
                or record.get('strategy')!=args.strategy):
                raise ContractError('source-line operation selection differs')
            if record.get('phase')=='complete':
                return record
        else:
            source=resolve(repo,args.ref,args.remote)
            previous=_ref_sha(api('GET',ref_path))
            record={'schema_version':'1.0.0','workflow':'source-line',
                    'operation_kind':'release-line-rollback','phase':'selected',
                    'line':args.line,'strategy':args.strategy,'source_sha':source,
                    'previous_sha':previous,'operation_dir':str(directory)}
            write(path,record)
        current=_ref_sha(api('GET',ref_path))
        if record.get('result_sha')==current:
            record['phase']='complete';record['status']='ok';write(path,record);return record
        if current!=record['previous_sha']:
            raise ContractError('destination changed; inspect before starting a new source-line operation')
        if record['strategy']=='restore-tree':
            tree=api('GET',prefix + '/git/commits/' + record['source_sha'])['tree']['sha']
            if 'result_sha' not in record:
                created=api('POST',prefix + '/git/commits',{
                    'message':'Restore release tree ' + record['source_sha'],
                    'tree':tree,'parents':[record['previous_sha']]})
                record['result_sha']=created['sha'];write(path,record)
            api('PATCH',update_path,{'sha':record['result_sha'],'force':False})
        elif record['strategy']=='fast-forward':
            record['result_sha']=record['source_sha'];write(path,record)
            api('PATCH',update_path,{'sha':record['source_sha'],'force':False})
        elif record['strategy']=='merge':
            if record['phase']=='requested':
                raise ContractError('merge response was uncertain; inspect destination before retrying')
            record['phase']='requested';write(path,record)
            result=api('POST',prefix + '/merges',{
                'base':record['line'],'head':record['source_sha'],
                'commit_message':'Restore release ' + record['source_sha']})
            record['result_sha']=result['sha'] if result else record['previous_sha'];write(path,record)
        else:
            raise ContractError('unsupported source-line strategy')
        if _ref_sha(api('GET',ref_path))!=record['result_sha']:
            raise ContractError('release line readback differs')
        record['phase']='complete';record['status']='ok';write(path,record)
        return record


def change(repo, adapter, args):
    if not human():
        raise ContractError('source-line operations require human mode')
    if args.line not in adapter['repository']['protected_branches']:
        raise ContractError('destination is not a declared release line')
    if getattr(args,'pr',None) is not None:
        if getattr(args, 'greenfield', False):
            with greenfield.operator_admission(repo, adapter, args):
                return _promote(repo, adapter, args)
        return _promote(repo,adapter,args)
    return _rollback(repo,adapter,args)

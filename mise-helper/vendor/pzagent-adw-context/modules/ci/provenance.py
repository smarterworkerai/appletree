"""Fail closed when the PR edits the trusted CI/proof implementation."""
from __future__ import annotations
import base64
import hashlib
import json
import os
import re
import subprocess
import time
import tempfile
from pathlib import Path
import stat
import zipfile
from .github_api import project_files, ApiError
from .quality_proof import ProofError, Pull
from . import greenfield

BOOTSTRAP_COMMAND = re.compile(r'^BOOTSTRAP_(ENABLED|DISABLED) ([0-9a-f]{64})$')

TRUSTED_PATHS = (
    '.hermes/adw-task-manifest.json',
    'mise-helper/vendor/agentic-delivery/adw_contract.py',
    'mise-helper/vendor/agentic-delivery/tasks.toml',
    '.github/workflows/ci.yml',
    '.github/workflows/trust-root-bootstrap.yml',
    '.github/workflows/publish-release.yml',
    '.github/workflows/cleanup-retention.yml',
    'mise-helper/vendor/pzagent-adw-context/ci.py',
    'mise-helper/vendor/pzagent-adw-context/pzagent_context.py',
    'mise-helper/vendor/pzagent-adw-context/templates/github/actions/classify-ci-event/action.yml',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/__init__.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/build_artifacts.py',
    'mise-helper/vendor/pzagent-adw-context/modules/__init__.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/policy.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/github_api.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/live_pr.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/contract.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/evidence.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/quality_proof.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/publication_proof.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/release_authorization.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/reuse.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/workflow_drift.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/ci_only.py',
    'mise-helper/vendor/pzagent-adw-context/modules/quality_outputs.py',
    'mise-helper/vendor/pzagent-adw-context/modules/quality_tasks.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci_release.py',
    'mise-helper/vendor/pzagent-adw-context/modules/workflows_sync.py',
    'mise-helper/vendor/pzagent-adw-context/modules/adapter.py',
    'mise-helper/vendor/pzagent-adw-context/modules/common.py',
    'mise-helper/vendor/pzagent-adw-context/modules/bundle.py',
    'mise-helper/vendor/pzagent-adw-context/modules/operator_publish.py',
    'mise-helper/vendor/pzagent-adw-context/modules/operator_retention.py',
    'mise-helper/vendor/pzagent-adw-context/modules/release_manifest.py',
    'mise-helper/vendor/pzagent-adw-context/modules/oras_registry.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/provenance.py',
    'mise-helper/vendor/pzagent-adw-context/templates/github/publish-release.yml',
    'mise-helper/vendor/pzagent-adw-context/templates/github/cleanup-retention.yml',
    'mise-helper/vendor/pzagent-adw-context/templates/github/actions/authorize-publication/action.yml',
    'mise-helper/vendor/pzagent-adw-context/templates/github/actions/authorize-publication/authorize.py',
    'mise-helper/vendor/pzagent-adw-context/templates/github/actions/publish-immutable-release/action.yml',
    'mise-helper/vendor/pzagent-adw-context/templates/github/actions/publish-immutable-release/publish.py',
    'mise-helper/vendor/pzagent-adw-context/modules/providers/__init__.py',
    'mise-helper/vendor/pzagent-adw-context/modules/execution.py',
    'mise-helper/vendor/pzagent-adw-context/modules/build_outputs.py',
    'mise-helper/vendor/pzagent-adw-context/modules/retention.py',
    'mise-helper/vendor/pzagent-adw-context/modules/operator_registry.py',
    'mise-helper/vendor/pzagent-adw-context/modules/operator_lines.py',
    'mise-helper/vendor/pzagent-adw-context/modules/merged_source_proof.py',
    'mise-helper/vendor/pzagent-adw-context/modules/operator_state.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/trusted_decisions.json',
    '.adw/adw-task-manifest.json',
    'mise-helper/vendor/pzagent-adw-context/modules/pointer_retirement.py',
    'mise-helper/vendor/pzagent-adw-context/modules/ci/greenfield.py',
)


VENDOR_PREFIX = 'mise-helper/vendor/pzagent-adw-context/'
PROVIDER = 'smarterworkerai/pzagent-adw-context'
PROVIDER_SNAPSHOT = 'skills/pzagent/pzagent-adw-context/assets/mise/v2/'
PROVIDER_BUNDLE = PROVIDER_SNAPSHOT + 'bundle.json'
# Consumer workflow files that must be byte-identical to the vendored templates.
WORKFLOW_TEMPLATES = (
    ('.github/workflows/ci.yml', 'templates/github/ci.yml'),
    ('.github/workflows/trust-root-bootstrap.yml', 'templates/github/trust-root-bootstrap.yml'),
    ('.github/workflows/publish-release.yml', 'templates/github/publish-release.yml'),
    ('.github/workflows/cleanup-retention.yml', 'templates/github/cleanup-retention.yml'),
)
# A released-vendor repin may change only the vendored context, its manifest source
# record and the byte-identical workflow templates; anything else keeps the admin gate.
RELEASED_VENDOR_PATHS = frozenset(
    [path for path in TRUSTED_PATHS if path.startswith(VENDOR_PREFIX)]
    + ['.hermes/adw-task-manifest.json', '.adw/adw-task-manifest.json'] + [path for path, _ in WORKFLOW_TEMPLATES])


def _provider_get(path: str, token: str):
    """Read the provider through a dedicated read-only token, never the PR's."""
    env = {**os.environ, 'GH_TOKEN': token}
    env.pop('GITHUB_TOKEN', None)
    result = subprocess.run(['gh', 'api', '--method', 'GET', f'repos/{PROVIDER}/{path}'],
                            text=True, capture_output=True, check=False, timeout=60, env=env)
    if result.returncode:
        raise ApiError('provider_lookup_failed')
    return json.loads(result.stdout)


def _released_vendor(api, pull: Pull, changed: list[str]) -> str | None:
    """Return the release tag when the PR vendors exactly a published provider release."""
    token = os.environ.get('PZAGENT_PROVIDER_TOKEN')
    if not token or not changed or not set(changed) <= RELEASED_VENDOR_PATHS:
        return None
    try:
        metadata = project_files(api, pull.head_sha, 'adw-task-manifest.json', 'pzagent-context-lock.json')
        manifest_path = metadata['adw-task-manifest.json'][0]
        base_metadata = project_files(api, pull.base_sha, 'adw-task-manifest.json')
        if base_metadata['adw-task-manifest.json'][0] != manifest_path:
            return None  # A directory migration always needs an administrator decision.
        lock = json.loads(metadata['pzagent-context-lock.json'][1])
        ref, version = lock['source_ref'], lock['package_version']
        bundle = api.content(VENDOR_PREFIX + 'bundle.json', pull.head_sha)[1]
        if (not re.fullmatch(r'[0-9a-f]{40}', str(ref)) or not re.fullmatch(r'\d+\.\d+\.\d+', str(version))
                or hashlib.sha256(bundle).hexdigest() != lock['bundle_sha256']):
            return None
        tag = f'v{version}'
        release = _provider_get(f'releases/tags/{tag}', token)
        target = _provider_get(f'git/ref/tags/{tag}', token)['object']
        if target.get('type') == 'tag':
            target = _provider_get(f"git/tags/{target['sha']}", token)['object']
        if release.get('draft') or release.get('prerelease') or target.get('type') != 'commit' or target.get('sha') != ref:
            return None
        published = _provider_get(f'contents/{PROVIDER_BUNDLE}?ref={ref}', token)
        if base64.b64decode(published.get('content', '')) != bundle:
            return None
        inventory = {item['path']: item['sha256'] for item in json.loads(bundle)['files']}
        vendored = [path for path in changed if path.startswith(VENDOR_PREFIX)]
        workflows = [pair for pair in WORKFLOW_TEMPLATES if pair[0] in changed]
        head_blobs = _tree_blobs(api, pull.head_sha) if vendored or workflows else {}
        provider_blobs = _provider_blobs(ref, token) if head_blobs is not None and (vendored or workflows) else {}
        if head_blobs is not None and provider_blobs is not None:
            # Blob SHAs identify bytes exactly: a vendored file equals the released snapshot
            # file, and a workflow equals its template, when their blobs match. Two tree
            # reads replace one download per changed file.
            for path in vendored:
                expected = provider_blobs.get(PROVIDER_SNAPSHOT + path.removeprefix(VENDOR_PREFIX))
                if expected is None or head_blobs.get(path) != expected:
                    return None
            for workflow_path, template_path in workflows:
                expected = provider_blobs.get(PROVIDER_SNAPSHOT + template_path)
                if expected is None or head_blobs.get(workflow_path) != expected:
                    return None
        else:
            for path in vendored:
                expected = inventory.get(path.removeprefix(VENDOR_PREFIX))
                if expected != hashlib.sha256(api.content(path, pull.head_sha)[1]).hexdigest():
                    return None
            for workflow_path, template_path in workflows:
                workflow = api.content(workflow_path, pull.head_sha)[1]
                if hashlib.sha256(workflow).hexdigest() != inventory.get(template_path):
                    return None
        if manifest_path in changed:
            head = json.loads(metadata['adw-task-manifest.json'][1])
            base = json.loads(base_metadata['adw-task-manifest.json'][1])
            record = head.get('sources', {}).pop('context', None)
            base.get('sources', {}).pop('context', None)
            if head != base or record != {'layer': 'context', 'ref': ref, 'path': VENDOR_PREFIX + 'tasks.toml',
                                          'checksum': 'sha256:' + str(inventory.get('tasks.toml'))}:
                return None
        return tag
    except (ApiError, KeyError, TypeError, ValueError, OSError, subprocess.TimeoutExpired):
        return None  # Any doubt keeps the manual administrator decision.


def _content_at(api, path: str, ref: str):
    try:
        return api.content(path,ref)
    except ApiError as exc:
        if str(exc)=='content_absent':
            return None
        raise


def _blob_map(commit: object, tree_of: 'callable', wanted: set[str] | None) -> dict[str, str] | None:
    """Path → blob SHA for one commit from a recursive tree listing; None when unusable."""
    try:
        tree=commit.get('tree',{}).get('sha') if isinstance(commit,dict) and isinstance(commit.get('tree'),dict) else None
        if not isinstance(tree,str) or not re.fullmatch(r'[0-9a-f]{40}',tree):
            return None
        listing=tree_of(tree)
    except (ApiError, KeyError, TypeError, ValueError, OSError, subprocess.TimeoutExpired):
        return None
    entries=listing.get('tree') if isinstance(listing,dict) else None
    if not isinstance(listing,dict) or listing.get('truncated') is not False or not isinstance(entries,list):
        return None
    blobs: dict[str,str]={}
    for entry in entries:
        if (isinstance(entry,dict) and entry.get('type')=='blob' and isinstance(entry.get('path'),str)
            and (wanted is None or entry['path'] in wanted)
            and isinstance(entry.get('sha'),str) and re.fullmatch(r'[0-9a-f]{40}',entry['sha'])):
            if entry['path'] in blobs:
                return None
            blobs[entry['path']]=entry['sha']
    return blobs


def _tree_blobs(api, sha: str, wanted: set[str] | None = None) -> dict[str, str] | None:
    """Blob SHAs of a consumer commit's files from a single recursive tree read.

    A blob SHA identifies the bytes exactly, so comparing blob SHAs equals comparing
    downloaded contents. Returns None whenever the tree cannot be used (lookup failure,
    oversized or truncated listing, unexpected shape); callers then fall back to per-file
    content reads, which keep the historical fail-closed behaviour and error classes.
    """
    try:
        commit=api.get(f'git/commits/{sha}')
    except ApiError:
        return None
    return _blob_map(commit, lambda tree: api.get(f'git/trees/{tree}?recursive=1'), wanted)


def _provider_blobs(ref: str, token: str) -> dict[str, str] | None:
    """Blob SHAs of the provider release commit, read through the provider token only."""
    try:
        commit=_provider_get(f'git/commits/{ref}', token)
    except (ApiError, KeyError, TypeError, ValueError, OSError, subprocess.TimeoutExpired):
        return None
    return _blob_map(commit, lambda tree: _provider_get(f'git/trees/{tree}?recursive=1', token), None)


def _trusted_blobs(api, sha: str) -> dict[str, str] | None:
    return _tree_blobs(api, sha, set(TRUSTED_PATHS))


def _changed_paths(api, pull: Pull) -> list[str]:
    head_blobs=_trusted_blobs(api,pull.head_sha)
    base_blobs=_trusted_blobs(api,pull.base_sha) if head_blobs is not None else None
    if head_blobs is not None and base_blobs is not None:
        return [path for path in TRUSTED_PATHS if head_blobs.get(path)!=base_blobs.get(path)]
    try:
        changed=[]
        for path in TRUSTED_PATHS:
            head=_content_at(api,path,pull.head_sha)
            base=_content_at(api,path,pull.base_sha)
            if head!=base:
                changed.append(path)
        return changed
    except ApiError:
        raise ProofError('trusted_base_missing') from None


def _fingerprint(pull: Pull, changed: list[str]) -> str:
    payload={
        'schema':'pzagent-trust-root-bootstrap/v1',
        'repository':pull.repository,
        'pull_request':pull.number,
        'head_sha':pull.head_sha,
        'base_sha':pull.base_sha,
        'changed_paths':changed,
    }
    encoded=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def _controller_binding(pull: Pull) -> str:
    """Bind a trusted-controller check even when GitHub drops PR associations."""
    payload={
        'schema':'pzagent-trust-root-controller/v1',
        'repository':pull.repository,
        'pull_request':pull.number,
        'head_sha':pull.head_sha,
        'base_sha':pull.base_sha,
    }
    encoded=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
    return 'pzagent-trust-root-controller:v1:'+hashlib.sha256(encoded).hexdigest()


def _message(result: dict) -> str:
    if result['status']=='normal':
        return ('No extra approval is needed: this PR does not change the trusted '
                'CI/provenance source.')
    changed='\n'.join(f"- `{path}`" for path in result['changed_paths'])
    identity=(f"This decision is bound to PR #{result['pull_request']}, head "
              f"`{result['head_sha']}`, base `{result['base_sha']}`. Any head push "
              'or base update changes the fingerprint and invalidates the approval.')
    if result['status']=='released-vendor':
        return (f"No administrator decision is needed: the trusted-path changes vendor exactly the "
                f"published provider release `{result['release']}` (tag, commit and bundle bytes verified "
                "by the default-branch controller). Normal CI, exact-tree, merge and publication checks "
                f"still apply.\n\n{identity}\n\nChanged trusted paths:\n{changed}")
    if result['status']=='enabled':
        decision=(f"Approved by repository administrator `@{result['approver']}`. "
                  'Normal CI, exact-tree, merge and publication checks still apply.')
    elif result['status']=='disabled':
        decision=(f"Explicitly declined by repository administrator `@{result['approver']}`. "
                  'The trust-root rotation remains blocked.')
    else:
        decision=('Waiting for a repository administrator. To approve this exact revision, '
                  'add a new PR comment containing exactly:\n\n'
                  f"```text\n{result['expected_comment']}\n```\n\n"
                  'To decline or revoke it, use the same fingerprint with '
                  '`BOOTSTRAP_DISABLED`. After the controller records success, '
                  'use **Re-run all jobs** for any ADW CI attempt that already stopped at the '
                  'fail-fast trust-root gate.')
    return ('This PR changes code that defines or validates CI/provenance trust. '
            'The normal provenance proof therefore needs an explicit administrator '
            'decision before this revision can advance.\n\n'
            f"**Status:** {decision}\n\n{identity}\n\nChanged trusted paths:\n{changed}")


def _artifact_inventory(page: dict) -> list[dict]:
    items=page.get('artifacts') if isinstance(page,dict) else None
    if (not isinstance(items,list) or not all(isinstance(item,dict) for item in items)
        or type(page.get('total_count')) is not int or page['total_count']!=len(items)
        or len(items)>100):
        raise ProofError('bootstrap_artifact_inventory_invalid')
    return items


def _artifact_decision(api, pull: Pull, run: dict, changed: list[str]) -> dict | None:
    run_id=run['id']
    name=f'pzagent-trust-root-decision-{pull.number}-{pull.head_sha}'
    matches=[item for item in _artifact_inventory(api.run_artifacts(run_id))
             if item.get('name')==name]
    if not matches:
        return None
    if len(matches)!=1:
        raise ProofError('bootstrap_artifact_ambiguous')
    item=matches[0]
    if item.get('expired') is True:
        return None
    workflow=item.get('workflow_run');repository=run['repository']
    if (type(item.get('id')) is not int or item['id']<1 or item.get('expired') is not False
        or not isinstance(item.get('digest'),str)
        or not re.fullmatch(r'sha256:[0-9a-f]{64}',item['digest'])
        or type(item.get('size_in_bytes')) is not int
        or not 0 < item['size_in_bytes'] <= 65536
        or not isinstance(workflow,dict) or workflow.get('id')!=run_id
        or workflow.get('head_sha')!=pull.head_sha
        or workflow.get('head_branch')!=pull.source_branch
        or workflow.get('repository_id')!=repository['id']
        or workflow.get('head_repository_id')!=repository['id']):
        raise ProofError('bootstrap_artifact_identity_invalid')
    with tempfile.TemporaryDirectory(prefix='.trust-root-') as temporary:
        archive=Path(temporary)/'decision.zip'
        try:
            api.download_artifact(item['id'],archive,max_bytes=65536)
            if (archive.stat().st_size!=item['size_in_bytes']
                or 'sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest()!=item['digest']):
                raise ProofError('bootstrap_artifact_digest_invalid')
            with zipfile.ZipFile(archive) as zipped:
                entries=zipped.infolist()
                if len(entries)!=1:
                    raise ProofError('bootstrap_artifact_entries_invalid')
                entry=entries[0];kind=stat.S_IFMT(entry.external_attr >> 16)
                if (entry.filename!='bootstrap-status.json' or entry.is_dir()
                    or kind not in (0,stat.S_IFREG) or entry.flag_bits & 1
                    or not 0 < entry.file_size <= 32768):
                    raise ProofError('bootstrap_artifact_entries_invalid')
                result=json.loads(zipped.read(entry))
        except ProofError:
            raise
        except (ApiError,OSError,zipfile.BadZipFile,NotImplementedError,RuntimeError,
                json.JSONDecodeError,UnicodeDecodeError):
            raise ProofError('bootstrap_artifact_unreadable') from None
    common={'schema_version','repository','pull_request','head_sha','base_sha','changed_paths',
            'required','allowed','status','fingerprint','expected_comment',
            'controller_external_id','approver','message'}
    if (not isinstance(result,dict) or set(result) not in (common,common|{'release'})
        or result.get('schema_version')!='1.0.0' or result.get('repository')!=pull.repository
        or result.get('pull_request')!=pull.number or result.get('head_sha')!=pull.head_sha
        or result.get('base_sha')!=pull.base_sha
        or result.get('required') is not True or type(result.get('allowed')) is not bool
        or result.get('controller_external_id')!=_controller_binding(pull)
        or not isinstance(result.get('message'),str) or len(result['message'])>20000):
        raise ProofError('bootstrap_artifact_decision_invalid')
    reported=result.get('changed_paths')
    if (not isinstance(reported,list) or not reported
        or not all(isinstance(path,str) for path in reported)
        or reported!=[path for path in changed if path in reported]):
        raise ProofError('bootstrap_artifact_decision_invalid')
    status=result.get('status');fingerprint=_fingerprint(pull,reported)
    released=(status=='released-vendor' and set(result)==common|{'release'}
              and result['allowed'] and isinstance(result.get('release'),str)
              and re.fullmatch(r'v\d+\.\d+\.\d+',result['release'])
              and result.get('fingerprint')=='' and result.get('expected_comment')=='')
    manual=(status in ('enabled','disabled','waiting') and set(result)==common
            and result.get('fingerprint')==fingerprint
            and result.get('expected_comment')=='BOOTSTRAP_ENABLED '+fingerprint)
    valid=(released
           or (manual and status=='enabled' and result['allowed'] and isinstance(result.get('approver'),str))
           or (manual and status=='disabled' and not result['allowed'] and isinstance(result.get('approver'),str))
           or (manual and status=='waiting' and not result['allowed'] and result.get('approver') is None))
    if not valid:
        raise ProofError('bootstrap_artifact_decision_invalid')
    if reported!=changed and status!='disabled':
        # An authentic older controller may not know newly trusted paths. Its
        # smaller-scope decision grants no authority over the expanded set.
        # Use the existing live, exact-current-fingerprint administrator path;
        # retain explicit denials and every artifact integrity/binding check.
        return None
    return result


def _controller_artifact_state(api, pull: Pull, changed: list[str]) -> tuple[str, bool | None]:
    """Resolve the exact source-branch controller run and its immutable decision."""
    try:
        runs=api.controller_runs(branch=pull.source_branch,head_sha=pull.head_sha)
    except ApiError:
        raise ProofError('bootstrap_controller_lookup_failed') from None
    exact=[run for run in runs
           if run.get('event')=='pull_request_target'
           and run.get('path')=='.github/workflows/trust-root-bootstrap.yml'
           and run.get('head_branch')==pull.source_branch
           and run.get('head_sha')==pull.head_sha]
    if not exact:
        return 'absent',None
    completed=[run for run in exact if run.get('status')=='completed']
    if not completed:
        if any(run.get('status') in ('requested','waiting','pending','queued','in_progress')
               for run in exact):
            return 'pending',None
        return 'fallback',None
    run=max(completed,key=lambda item:item.get('id') if type(item.get('id')) is int else -1)
    repository=run.get('repository');head_repository=run.get('head_repository')
    if (type(run.get('id')) is not int or run['id']<1
        or type(run.get('run_attempt')) is not int or run['run_attempt']<1
        or run.get('event')!='pull_request_target'
        or run.get('path')!='.github/workflows/trust-root-bootstrap.yml'
        or run.get('head_branch')!=pull.source_branch or run.get('head_sha')!=pull.head_sha
        or not isinstance(repository,dict) or not isinstance(head_repository,dict)
        or type(repository.get('id')) is not int or repository['id']<1
        or repository.get('full_name')!=api.repository
        or head_repository.get('id')!=repository['id']
        or head_repository.get('full_name')!=api.repository):
        return 'fallback',None
    if run.get('conclusion')!='success':
        return 'fallback',None
    try:
        result=_artifact_decision(api,pull,run,changed)
    except ApiError:
        raise ProofError('bootstrap_artifact_lookup_failed') from None
    if result is None:
        return 'fallback',None
    if result['status']=='waiting':
        return 'waiting',None
    return 'completed',result['allowed']


def _controller_decision(api, pull: Pull) -> bool | None:
    """Return an exact artifact-backed controller decision when one is final."""
    changed=_changed_paths(api,pull)
    if not changed:
        return None
    state,decision=_controller_artifact_state(api,pull,changed)
    return decision if state=='completed' else None


def bootstrap_status(api, pull: Pull, *, allow_released_vendor: bool = True,
                     changed: list[str] | None = None) -> dict:
    changed=_changed_paths(api,pull) if changed is None else changed
    result={
        'schema_version':'1.0.0',
        'repository':pull.repository,
        'pull_request':pull.number,
        'head_sha':pull.head_sha,
        'base_sha':pull.base_sha,
        'changed_paths':changed,
        'required':bool(changed),
        'allowed':not changed,
        'status':'normal' if not changed else 'waiting',
        'fingerprint':'',
        'expected_comment':'',
        'controller_external_id':_controller_binding(pull),
        'approver':None,
    }
    released=_released_vendor(api,pull,changed) if changed and allow_released_vendor else None
    if released:
        result.update(status='released-vendor',allowed=True,release=released)
    elif changed:
        token=_fingerprint(pull,changed)
        result['fingerprint']=token
        result['expected_comment']=f'BOOTSTRAP_ENABLED {token}'
        decisions=[];permissions={}
        try:
            comments=api.list(f'issues/{pull.number}/comments')
            for comment in comments:
                body=comment.get('body')
                match=BOOTSTRAP_COMMAND.fullmatch(body.strip() if isinstance(body,str) else '')
                actor=(comment.get('user') or {}).get('login')
                comment_id=comment.get('id')
                if (not match or match.group(2)!=token or not isinstance(actor,str)
                    or type(comment_id) is not int or comment_id<1):
                    continue
                if actor not in permissions:
                    record=api.get(f'collaborators/{actor}/permission')
                    permissions[actor]=record.get('permission') if isinstance(record,dict) else None
                if permissions[actor]=='admin':
                    decisions.append((comment_id,match.group(1),actor))
        except ApiError:
            raise ProofError('bootstrap_authorization_unavailable') from None
        if decisions:
            _,decision,actor=max(decisions)
            result['status']='enabled' if decision=='ENABLED' else 'disabled'
            result['allowed']=decision=='ENABLED'
            result['approver']=actor
    result['message']=_message(result)
    return result


def _admin_gate(api, pull: Pull, changed: list[str]) -> dict:
    result=bootstrap_status(api,pull,allow_released_vendor=False,changed=changed)
    if result['status']=='enabled':
        return {'allowed':True,'decided_by':'admin-comment','reason':'admin_approved',
                'message':result['message']}
    reason='bootstrap_disabled' if result['status']=='disabled' else 'bootstrap_required'
    return {'allowed':False,'decided_by':'admin-comment' if result['status']=='disabled' else 'none',
            'reason':reason,'message':result['message']}


APPEARANCE_GRACE_SECONDS = 60


def trust_root_gate(api, pull: Pull, *, wait_seconds: int = 300,
                    sleep=time.sleep, monotonic=time.monotonic) -> dict:
    """Wait for an artifact-backed controller decision, then use exact admin policy."""
    if type(wait_seconds) is not int or not 0 <= wait_seconds <= 600:
        raise ProofError('bootstrap_wait_invalid')
    changed=_changed_paths(api,pull)
    if not changed:
        return {'allowed':True,'decided_by':'no-trusted-change','reason':'no_trusted_change',
                'message':'No trusted CI/provenance source changed.'}
    start=monotonic(); deadline=start+wait_seconds
    # The PR's CI run and the controller's pull_request_target run are created within
    # seconds of each other; a gate that queries first sees no controller run at all.
    # Give the controller run a bounded time to appear before falling back to the comment.
    appearance_deadline=start+min(APPEARANCE_GRACE_SECONDS,wait_seconds)
    while True:
        state,decision=_controller_artifact_state(api,pull,changed)
        if state=='completed':
            if decision:
                return {'allowed':True,'decided_by':'controller','reason':'controller_approved',
                        'message':'The exact PR revision was approved by the trust-root controller artifact.'}
            return {'allowed':False,'decided_by':'controller','reason':'bootstrap_required',
                    'message':'The trust-root controller explicitly rejected this exact PR revision.'}
        if state in ('fallback','waiting') or (state=='absent' and monotonic()>=appearance_deadline):
            return _admin_gate(api,pull,changed)
        remaining=deadline-monotonic()
        if remaining<=0:
            return {'allowed':False,'decided_by':'none','reason':'controller_timeout',
                    'message':f'trust-root controller did not complete within {wait_seconds} s'}
        # The controller finishes in a few seconds since 0.6.3; poll often enough not to idle.
        sleep(min(5,remaining))


def trusted_source(api, pull: Pull) -> None:
    changed=_changed_paths(api,pull)
    if not changed:
        return
    state,decision=_controller_artifact_state(api,pull,changed)
    if state=='completed':
        if decision:
            return
        raise ProofError('bootstrap_required')
    if greenfield.has_operator_admission() and greenfield.trusted_decision(api, pull):
        return
    result=bootstrap_status(api,pull,allow_released_vendor=False,changed=changed)
    if result['status']=='disabled':
        raise ProofError('bootstrap_disabled')
    if (state in ('absent','pending','fallback') and pull.state=='closed' and pull.merged
            and greenfield.trusted_decision(api, pull)):
        return
    if result['allowed'] and state in ('pending','fallback','waiting'):
        return
    # Nobody decided. Name what is missing: "an administrator must decide" (a visible run
    # whose artifact waits) differs from "the controller's decision cannot be read now"
    # (no run listed, or a run without a usable artifact), which operators retry.
    if state=='absent':
        raise ProofError('bootstrap_controller_missing')
    if state in ('pending','fallback'):
        raise ProofError('bootstrap_controller_unusable')
    raise ProofError('bootstrap_required')

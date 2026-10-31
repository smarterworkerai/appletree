#!/usr/bin/env python3
"""Single bounded CLI for the vendored pz ADW runtime."""
from __future__ import annotations

import argparse
import contextlib
from contextlib import ExitStack
import io
import json
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.adapter import load as load_adapter
from modules.common import project_dir
from modules.common import (
    ContractError, EXIT_CONTRACT, EXIT_OPERATION, EXIT_USAGE, IDENTIFIER, UsageError,
    json_result,
)
from modules.context_sync import check_consumer, sync, trusted_freshness
from modules.hooks import HookFailure, invoke as invoke_hook, request as hook_request
from modules.remote_config import config_apply, config_plan, config_pull
from modules.remote_probe import run as run_probe
from modules.remote_deploy import deploy
from modules.hotfix import apply as apply_hotfix, restore as restore_hotfix
from modules.operator_state import new_operation
from modules.remote_validation import run_e2e, validate_deployment


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)
    for name in ('quality-export', 'quality-import', 'quality-verify', 'quality-leaves', 'context-describe'):
        command = sub.add_parser(name)
        command.add_argument('--repo-root', type=Path, default=Path('.'))
        command.add_argument('--execution-mode', choices=('human', 'ci'), default='ci' if os.environ.get('GITHUB_ACTIONS', '').lower() == 'true' else 'human')
        if name == 'quality-export':
            command.add_argument('--workspace', type=Path, required=True)
            command.add_argument('--output', type=Path, required=True)
        elif name == 'quality-import':
            command.add_argument('--fetch-ci', action='store_true')
    workflows = sub.add_parser('workflows-sync')
    workflows.add_argument('--repo-root', type=Path, default=Path('.'))
    workflows.add_argument('--check', action='store_true')
    check = sub.add_parser("context-check")
    check.add_argument("--repo-root", type=Path, default=Path("."))
    check.add_argument("--strict-freshness", action="store_true")
    check.add_argument("--lookup-freshness", action="store_true")
    update = sub.add_parser("context-sync")
    update.add_argument("--repo-root", type=Path, default=Path("."))
    update.add_argument("--source", required=True)
    update.add_argument("--bundle-sha256", required=True)
    update.add_argument("--allow-downgrade", action="store_true")
    clean = sub.add_parser("local-clean")
    clean.add_argument("--repo-root", type=Path, default=Path("."))
    clean.add_argument("--prefix")
    clean.add_argument("--dry-run", action="store_true")
    clean.add_argument("--aggressive", action="store_true")
    clean.add_argument("--yes", action="store_true")
    rehearse = sub.add_parser("rehearsal")
    rehearse.add_argument("--repo-root", type=Path, default=Path("."))
    rehearse.add_argument("--lane", action="append", required=True, help="ENV=RELEASE_KIND, preview lanes only")
    rehearse.add_argument("--ref", required=True, help="source to publish and deploy")
    rehearse.add_argument("--hotfix-transport", action="append", help="ENV=TRANSPORT override")
    rehearse.add_argument('--release-ref', action='append', help='ENV_OR_TARGET=IMMUTABLE already-published release; inspect exact source before deploying')
    rehearse.add_argument("--billable", action="store_true", help="also run the live fast E2E")
    rehearse.add_argument("--no-rollback", action="store_true", help="skip the rollback/roll-forward round trip")
    rehearse.add_argument("--output", type=Path)
    call = sub.add_parser("invoke")
    call.add_argument("capability")
    call.add_argument("--repo-root", type=Path, default=Path("."))
    call.add_argument("--environment", required=True)
    call.add_argument("--target")
    pull = sub.add_parser("config-pull")
    pull.add_argument("--repo-root", type=Path, default=Path("."))
    pull.add_argument("--environment", required=True)
    pull.add_argument("--target")
    pull.add_argument("--profile-root", type=Path, required=True)
    plan = sub.add_parser("config-plan")
    plan.add_argument("--repo-root", type=Path, default=Path("."))
    plan.add_argument("--environment", required=True)
    plan.add_argument("--target")
    plan.add_argument("--profile-root", type=Path, required=True)
    apply_config = sub.add_parser("config-apply")
    apply_config.add_argument("--repo-root", type=Path, default=Path("."))
    apply_config.add_argument("--environment", required=True)
    apply_config.add_argument("--target")
    apply_config.add_argument("--approval-file", type=Path, required=True)
    apply_config.add_argument("--profile-root", type=Path, required=True)
    apply_config.add_argument("--snapshot-path", type=Path)
    probe = sub.add_parser("probe")
    probe.add_argument("capability", choices=["adw:deploy:status", "adw:health", "adw:readiness"])
    probe.add_argument("--repo-root", type=Path, default=Path("."))
    probe.add_argument("--environment", required=True)
    probe.add_argument("--target")
    probe.add_argument("--profile-root", type=Path, required=True)
    deploy_cmd = sub.add_parser("deploy-apply")
    deploy_cmd.add_argument("--repo-root", type=Path, default=Path("."))
    deploy_cmd.add_argument("--environment", required=True)
    deploy_cmd.add_argument("--target")
    deploy_cmd.add_argument("--approval-file", type=Path, required=True)
    deploy_cmd.add_argument("--profile-root", type=Path, required=True)
    deploy_cmd.add_argument("--release-kind", required=True)
    deploy_cmd.add_argument("--release-source-sha", required=True)
    deploy_cmd.add_argument("--release-manifest", type=Path, required=True)
    deploy_cmd.add_argument("--manifest-reference", required=True)
    deploy_cmd.add_argument("--expected-pointers", type=Path, required=True)
    deploy_cmd.add_argument("--restore-compose", type=Path)
    deploy_cmd.add_argument('--config-ref')
    deploy_cmd.add_argument('--config-snapshot', type=Path)
    e2e = sub.add_parser("e2e")
    e2e.add_argument("capability", choices=["adw:test:e2e:fast", "adw:test:e2e:full"])
    e2e.add_argument("--repo-root", type=Path, default=Path("."))
    e2e.add_argument("--environment", required=True)
    e2e.add_argument("--target")
    e2e.add_argument("--approval-file", type=Path, required=True)
    validation = sub.add_parser("validate-deployment")
    validation.add_argument("--repo-root", type=Path, default=Path("."))
    validation.add_argument("--environment", required=True)
    validation.add_argument("--target")
    validation.add_argument("--approval-file", type=Path, required=True)
    validation.add_argument("--profile-root", type=Path, required=True)
    hotfix = sub.add_parser("hotfix-apply")
    hotfix.add_argument("--repo-root", type=Path, default=Path("."))
    hotfix.add_argument("--environment", required=True)
    hotfix.add_argument("--target")
    hotfix.add_argument("--approval-file", type=Path, required=True)
    hotfix.add_argument("--transport", choices=["registry", "ssh-docker"], default=os.environ.get("PZ_ADW_HOTFIX_TRANSPORT", "registry"))
    hotfix.add_argument("--ssh-alias")
    hotfix.add_argument("--profile-root", type=Path, required=True)
    hotfix.add_argument("--run-id", default=os.environ.get("ADW_RUN_ID"))
    restore = sub.add_parser("hotfix-restore")
    restore.add_argument("--repo-root", type=Path, default=Path("."))
    restore.add_argument("--environment", required=True)
    restore.add_argument("--target")
    restore.add_argument("--approval-file", type=Path, required=True)
    restore.add_argument("--profile-root", type=Path, required=True)
    restore.add_argument("--artifact", type=Path, required=True)
    servers = sub.add_parser('provider-servers')
    servers.add_argument('--repo-root', type=Path, default=Path('.'))
    servers.add_argument('--profile-root', type=Path)
    servers.add_argument('environment', nargs='?')
    servers.add_argument('--target')
    show = sub.add_parser('secrets-show')
    show.add_argument('--repo-root', type=Path, default=Path('.'))
    show.add_argument('--profile-root', type=Path)
    show.add_argument('environment')
    examples = sub.add_parser('secrets-examples')
    examples.add_argument('--repo-root', type=Path, default=Path('.'))
    examples.add_argument('--check', action='store_true', help='Only compare; exit non-zero when stale (CI)')
    show.add_argument('--offline', action='store_true',
                      help='Only what the committed key schemas expect: no credentials, vault or provider access')
    for name in ('provider-domains', 'provider-env-apply', 'data-import'):
        # #187: operator-only Dokploy tasks on one owned Compose.
        ops = sub.add_parser(name)
        ops.add_argument('--repo-root', type=Path, default=Path('.'))
        ops.add_argument('--profile-root', type=Path)
        ops.add_argument('environment')
        ops.add_argument('--target')
        ops.add_argument('--apply', action='store_true')
        if name == 'provider-env-apply':
            ops.add_argument('--replace', action='append', default=[], metavar='KEY')
        if name == 'data-import':
            ops.add_argument('--file', type=Path, required=True)
            ops.add_argument('--confirm', metavar='ENVIRONMENT')
    for name in ('provider-provision', 'provider-deprovision', 'provider-examine', 'provider-claim',
                 'provider-journal-rebuild'):
        lifecycle = sub.add_parser(name)
        lifecycle.add_argument('--repo-root', type=Path, default=Path('.'))
        lifecycle.add_argument('--profile-root', type=Path)
        if name in {'provider-provision', 'provider-deprovision'}:
            lifecycle.add_argument('--plan', action='store_true')
        if name in {'provider-provision', 'provider-examine', 'provider-claim'}:
            lifecycle.add_argument('environment')
            lifecycle.add_argument('--target')
        if name == 'provider-provision':
            lifecycle.add_argument('--adopt', action='store_true')
            lifecycle.add_argument('--server', help='Explicit registered server name; otherwise discover the environment placement')
        elif name == 'provider-deprovision':
            lifecycle.add_argument('--operation', dest='operation_id')
            lifecycle.add_argument('--list', dest='list_operations', action='store_true')
            lifecycle.add_argument('--confirm-data-loss', action='store_true')
            lifecycle.add_argument('--backup-reference')
            lifecycle.add_argument('--include-runtime', action='store_true',
                                   help='Kubernetes: first remove the runtime this provider applied to the target; '
                                        'persistent claims also need --confirm-data-loss and --backup-reference')
        elif name == 'provider-claim':
            lifecycle.add_argument('--approve-examination-digest', required=True)
        elif name == 'provider-journal-rebuild':
            lifecycle.add_argument('environment', nargs='?')
            lifecycle.add_argument('--target')
            lifecycle.add_argument('--operation', dest='operation_id', help='Dokploy: the ownership operation ID')
            lifecycle.add_argument('--write', action='store_true', help='Write a missing journal / apply annotations')
            lifecycle.add_argument('--annotate-identity', action='store_true',
                                   help='Kubernetes: add missing identity annotations to journal-owned objects')
    for name in ('release-pointers-retire', 'release-pointers-orphans'):
        pointers = sub.add_parser(name)
        pointers.add_argument('--repo-root', type=Path, default=Path('.'))
        pointers.add_argument('--kind', required=True)
        if name == 'release-pointers-retire':
            pointers.add_argument('--target', required=True)
            pointers.add_argument('--profile-root', type=Path)
            pointers.add_argument('--operation', dest='operation_id', help='Resume this retirement operation')
            pointers.add_argument('--deprovision-operation', required=True,
                                  help='Operation ID of the completed provider deprovision')
            pointers.add_argument('--apply', action='store_true')
            pointers.add_argument('--approve-operation-digest')
            pointers.add_argument('--cluster-retired', action='store_true',
                                  help='Kubernetes: the deprovisioned target\'s cluster was replaced; its context must '
                                       'answer with a different cluster identity. Recorded in the plan and its digest')
    handover = sub.add_parser('release-pointers-handover')
    handover.add_argument('--repo-root', type=Path, default=Path('.'))
    handover.add_argument('--from', dest='source_target', required=True)
    handover.add_argument('--to', dest='destination_target', required=True)
    handover.add_argument('--kind')
    handover.add_argument('--replace', action='store_true')
    handover.add_argument('--plan', action='store_true')
    handover.add_argument('--operation', dest='operation_id', help='Resume this handover operation')
    handover.add_argument('--approval-file', type=Path)
    for name in ('cluster-up', 'cluster-teardown'):
        cluster = sub.add_parser(name)
        cluster.add_argument('cluster_alias')
        cluster.add_argument('--repo-root', type=Path, default=Path('.'))
        cluster.add_argument('--profile-root', type=Path)
        if name == 'cluster-teardown':
            cluster.add_argument('--purge-certificates', action='store_true',
                                 help='Remove the shared ACME cache entry for this cluster domain and environment instead of exporting it')
        cluster.add_argument('--operation', dest='operation_id', help='Resume this cluster operation')
        cluster.add_argument('--plan', action='store_true')
    operator_commands = ('release-inspect', 'workflow-deploy-existing', 'workflow-status', 'workflow-resume', 'workflow-abandon', 'release-rollback',
                         'release-package', 'release-publish', 'workflow-publish', 'workflow-publish-deploy',
                         'release-promote', 'release-retention', 'release-prove-merged-branch', 'workflow-doctor')
    for name in operator_commands:
        command = sub.add_parser(name)
        command.add_argument('--repo-root', type=Path, default=Path('.'))
        command.set_defaults(kind=None, scope='runtime', line=None, strategy=None, pr=None,
            apply=False, grace_hours=None, reconcile_pointers=False, on_failure='stop',
            platform='linux/amd64', build_dir=None, package_dir=None, environment=None,
            target=None, ref=None, release_ref=None, operation_dir=None, operation_id=None, sync_config=False,
            config_ref=None, verify=False, profile_root=None, detail=None,
            authorization_file=None, publication_pointer=None,
            expected_pointer_digest=None)
        command.add_argument('--profile-root', type=Path)
        if name == 'workflow-abandon':
            command.add_argument('--reason', required=True)
            command.add_argument('--superseded-by')
            command.add_argument('--acknowledge-unreconciled', action='store_true')
            command.add_argument('--target-retired', action='store_true')
        if name == 'workflow-status':
            command.add_argument('--all', action='store_true')
        if name in {'release-inspect', 'workflow-deploy-existing', 'release-rollback',
                    'release-package', 'workflow-publish', 'workflow-publish-deploy', 'release-retention'}:
            command.add_argument('--kind', required=name != 'release-rollback')
        if name in {'release-inspect', 'workflow-deploy-existing'}:
            choice = command.add_mutually_exclusive_group(required=True)
            choice.add_argument('--ref')
            choice.add_argument('--release-ref')
        elif name in {'release-promote', 'release-rollback', 'workflow-publish', 'workflow-publish-deploy'}:
            command.add_argument('--ref', required=name not in {'release-promote','release-rollback'})
        if name not in {'release-inspect', 'release-package', 'release-publish'}:
            command.add_argument('--operation', dest='operation_id',
                                 help='Operation ID; workflow status/resume select the single open one when omitted')
        if name == 'release-rollback':
            command.add_argument('--scope', choices=('runtime', 'release-line'), default='runtime')
        if name == 'release-promote':
            command.add_argument('--pr',type=int,required=True)
            command.add_argument('--greenfield', action='store_true',
                                 help='Released operator launcher only: admit an absent default ADW root')
            command.add_argument('--line',required=True)
            command.add_argument('--strategy',choices=('fast-forward',),default='fast-forward')
        elif name == 'release-rollback':
            command.add_argument('--line')
            command.add_argument('--strategy',choices=('merge','fast-forward','restore-tree'),
                                 default='restore-tree')
        if name in {'workflow-deploy-existing', 'workflow-publish-deploy', 'release-rollback'}:
            command.add_argument('--environment', required=name != 'release-rollback')
            command.add_argument('--target')
            command.add_argument('--verify', action='store_true')
            command.add_argument('--on-failure', choices=('stop', 'restore'), default='stop')
        if name in {'workflow-deploy-existing', 'workflow-publish-deploy', 'release-rollback'}:
            command.add_argument('--sync-config', action='store_true')
        if name in {'workflow-deploy-existing', 'workflow-publish-deploy'}:
            command.add_argument('--config-ref')
        if name == 'workflow-resume':
            command.add_argument('--reconcile-pointers', action='store_true')
        if name == 'workflow-doctor':
            command.add_argument('--environment')
            command.add_argument('--target')
            command.add_argument('--offline', action='store_true',
                                 help='Journals and local Git only: no provider, registry or network access')
        if name in {'workflow-status', 'workflow-resume'}:
            command.add_argument('--environment')
            command.add_argument('--target')
            command.add_argument('--line')
            command.add_argument('--pr', type=int)
        if name in {'workflow-publish', 'workflow-publish-deploy'}:
            command.add_argument('--platform', default='linux/amd64')
        if name == 'release-prove-merged-branch':
            command.add_argument('--pr', type=int, required=True)
            command.add_argument('--source-branch', required=True)
            command.add_argument('--target-branch', required=True)
        if name == 'release-inspect':
            command.add_argument('--detail', choices=('components',))
            command.add_argument('--platform', default='linux/amd64')
        if name == 'release-package':
            command.add_argument('--build-dir', type=Path, required=True)
        if name in {'release-package', 'release-publish'}:
            command.add_argument('--package-dir', type=Path, required=True)
        if name == 'release-publish':
            command.add_argument('--authorization-file', type=Path)
            command.add_argument('--publication-pointer')
            command.add_argument('--expected-pointer-digest')
        if name == 'release-retention':
            command.add_argument('--authorization-file', type=Path)
            command.add_argument('--apply', action='store_true')
            command.add_argument('--approve-operation-digest')
            command.add_argument('--only-candidate')
            command.add_argument('--grace-hours', type=int)
    for name, command in sub.choices.items():
        if name.startswith(('context-', 'quality-')) or name in {'local-clean', 'workflows-sync'}:
            continue
        command.add_argument('--execution-mode', choices=('human', 'ci'),
                             default='ci' if os.environ.get('GITHUB_ACTIONS') == 'true' else 'human')
        command.add_argument('--remote', default='origin')
        for action in command._actions:
            if action.dest in {'profile_root', 'approval_file', 'release_kind', 'release_source_sha',
                               'release_manifest', 'manifest_reference', 'expected_pointers'}:
                action.required = False
        if name in {'config-plan', 'config-apply'}:
            command.add_argument('--ref')
        if name == 'deploy-apply':
            command.add_argument('--reconcile-pointers', action='store_true')
            command.add_argument('--on-failure', choices=('stop', 'restore'), default='stop')
            command.add_argument('--kind')
            choice = command.add_mutually_exclusive_group()
            choice.add_argument('--ref')
            choice.add_argument('--release-ref')
            command.add_argument('--operation', dest='operation_id')
    check.add_argument('--development', action='store_true')
    return root


def _invoke(args: argparse.Namespace) -> dict:
    repo = args.repo_root.resolve()
    adapter = load_adapter(project_dir(repo) / 'pzagent-adapter.json')
    capability = adapter["capabilities"].get(args.capability)
    if (
        capability is None
        or capability["status"] != "supported"
        or args.environment not in capability["environments"]
    ):
        raise UsageError("capability is unsupported for requested environment")
    if capability["side_effect"] in {"remote-write", "destructive"}:
        raise ContractError(
            "remote-write capability requires a shared safety-engine command; "
            "direct project-hook invocation is forbidden"
        )
    return invoke_hook(
        repo,
        adapter,
        args.capability,
        hook_request(args.capability, environment=args.environment, target=args.target),
    )


def _main(args: argparse.Namespace) -> int:
    try:
        if args.command == 'release-rollback' and args.scope == 'release-line' and args.sync_config:
            raise UsageError('--sync-config applies only to runtime rollback')
        if args.command == 'release-prove-merged-branch':
            from modules.merged_source_proof import operator_prove
            repo = args.repo_root.resolve()
            result = {'status': 'ok', **operator_prove(
                repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'), pr_number=args.pr,
                source_branch=args.source_branch, target_branch=args.target_branch, remote=args.remote)}
        elif args.command == 'release-promote' or (args.command == 'release-rollback' and args.scope == 'release-line'):
            from modules.operator_lines import change
            repo = args.repo_root.resolve()
            result = change(repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'), args)
        elif args.command == 'release-retention':
            from modules.operator_retention import run
            repo = args.repo_root.resolve()
            adapter = load_adapter(project_dir(repo) / 'pzagent-adapter.json')
            result = run(repo, adapter, args)
            if not args.apply:
                from modules.pointer_retirement import orphans
                result['orphan_pointers'] = orphans(repo, adapter, args.kind)['orphans']
        elif args.command in {'release-pointers-retire', 'release-pointers-orphans'}:
            from modules.pointer_retirement import retire, orphans
            repo = args.repo_root.resolve()
            adapter = load_adapter(project_dir(repo) / 'pzagent-adapter.json')
            if args.command == 'release-pointers-orphans':
                result = orphans(repo, adapter, args.kind)
            else:
                args.operation_dir = args.operation_dir or new_operation(repo, 'retire')
                result = retire(repo, adapter, kind_name=args.kind, target=args.target,
                    profile_root=args.profile_root, operation_dir=args.operation_dir,
                    deprovision_operation=args.deprovision_operation, apply=args.apply,
                    approve_operation_digest=args.approve_operation_digest, cluster_retired=args.cluster_retired)
                from modules.task_evidence import record_operator
                record_operator(args.operation_dir, result)
        elif args.command == 'provider-servers':
            from modules.dokploy_inventory import servers
            repo = args.repo_root.resolve()
            result = servers(repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'),
                environment=args.environment, target=args.target, profile_root=args.profile_root,
                operation_dir=new_operation(repo, 'servers'))
        elif args.command == 'secrets-examples':
            from modules import operator_compose_ops as ops
            repo = args.repo_root.resolve()
            result = ops.secret_examples(repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'), check=args.check)
            print(json_result(**result))
            return 0 if result['status'] == 'ok' else EXIT_CONTRACT
        elif args.command == 'secrets-show':
            from modules import operator_compose_ops as ops
            repo = args.repo_root.resolve()
            result = ops.secrets_show(repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'),
                environment=args.environment, profile_root=args.profile_root, offline=args.offline,
                # The offline view reads committed files only and writes nothing (codex-1728).
                operation_dir=None if args.offline else new_operation(repo, 'secrets-show'))
        elif args.command in {'provider-domains', 'provider-env-apply', 'data-import'}:
            from modules import operator_compose_ops as ops
            repo = args.repo_root.resolve()
            adapter = load_adapter(project_dir(repo) / 'pzagent-adapter.json')
            common = dict(environment=args.environment, target=args.target, profile_root=args.profile_root,
                          apply=args.apply)
            if args.command == 'provider-domains':
                result = ops.domains(repo, adapter, operation_dir=new_operation(repo, 'domains'), **common)
            elif args.command == 'provider-env-apply':
                result = ops.env_apply(repo, adapter, operation_dir=new_operation(repo, 'env-apply'),
                                       replace=args.replace, **common)
            else:
                result = ops.data_import(repo, adapter, operation_dir=new_operation(repo, 'data-import'),
                                         file=args.file, confirm=args.confirm, **common)
        elif args.command in {'provider-provision', 'provider-deprovision', 'provider-examine', 'provider-claim',
                              'provider-journal-rebuild'}:
            from modules import provider_lifecycle as lifecycle
            repo = args.repo_root.resolve()
            profile = args.profile_root
            adapter = load_adapter(project_dir(repo) / 'pzagent-adapter.json')
            if args.command == 'provider-provision':
                result = lifecycle.provision(repo, adapter, environment=args.environment, target=args.target,
                    profile_root=profile, operation_dir=new_operation(repo, 'provision'), adopt=args.adopt,
                    plan=args.plan, server=args.server)
            elif args.command == 'provider-examine':
                result = lifecycle.examine(repo, adapter, environment=args.environment, target=args.target,
                    profile_root=profile, operation_dir=new_operation(repo, 'examine'))
            elif args.command == 'provider-claim':
                result = lifecycle.claim(repo, adapter, environment=args.environment, target=args.target,
                    profile_root=profile, operation_dir=new_operation(repo, 'claim'),
                    approve_examination_digest=args.approve_examination_digest)
            elif args.command == 'provider-journal-rebuild':
                group = adapter['targets'].get(args.environment or '', {})
                declaration = group.get('items', {}).get(args.target or group.get('default'), {})
                if declaration.get('provider') == 'kubernetes':
                    from modules.providers import kubernetes_lifecycle as kube
                    if args.operation_id:
                        raise UsageError('Kubernetes journals are selected by environment and --target')
                    result = (kube.annotate_identity(repo, adapter, environment=args.environment, target=args.target,
                                                     profile_root=profile, plan=not args.write)
                              if args.annotate_identity else
                              kube.rebuild_journal(repo, adapter, environment=args.environment, target=args.target,
                                                   profile_root=profile, write_journal=args.write))
                else:
                    if args.annotate_identity or not args.operation_id:
                        raise UsageError('Dokploy journals are rebuilt by --operation <id>')
                    result = lifecycle.rebuild_journal(repo, adapter, operation_id=args.operation_id,
                                                       profile_root=profile, write_journal=args.write)
            elif args.list_operations:
                if args.operation_id or args.plan:
                    raise ContractError('provider_list_selection_invalid')
                result = lifecycle.list_operations(adapter, profile_root=profile)
            else:
                if not args.operation_id or not IDENTIFIER.fullmatch(args.operation_id):
                    raise ContractError('provider_operation_id_required')
                result = lifecycle.deprovision(repo, adapter, profile_root=profile,
                    operation_dir=new_operation(repo, 'deprovision'), operation_id=args.operation_id, plan=args.plan,
                    confirm_data_loss=args.confirm_data_loss, backup_reference=args.backup_reference,
                    include_runtime=args.include_runtime)
        elif args.command == 'release-pointers-handover':
            from modules.pointer_handover import handover
            repo = args.repo_root.resolve()
            args.operation_dir = args.operation_dir or new_operation(repo, 'handover')
            result = handover(repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'),
                source=args.source_target, destination=args.destination_target,
                kind_name=args.kind, replace=args.replace, operation_dir=args.operation_dir,
                approval_path=args.approval_file, plan=args.plan)
        elif args.command in {'cluster-up', 'cluster-teardown'}:
            from modules.cluster_lifecycle import manage
            args.operation_dir = args.operation_dir or new_operation(args.repo_root.resolve(), 'k3d')
            result = manage(profile_root=args.profile_root, alias=args.cluster_alias,
                action=args.command.removeprefix('cluster-'), operation_dir=args.operation_dir, plan=args.plan,
                purge_certificates=getattr(args, 'purge_certificates', False))
        elif args.command in {'release-package', 'release-publish', 'workflow-publish', 'workflow-publish-deploy'}:
            from modules import operator_publish
            repo = args.repo_root.resolve()
            adapter = load_adapter(project_dir(repo) / 'pzagent-adapter.json')
            if args.command == 'release-package':
                if not args.build_dir or not args.package_dir:
                    raise UsageError('--build-dir and --package-dir are required')
                with operator_publish.locked(args.package_dir):
                    result = operator_publish.package(repo, adapter, kind_name=args.kind, build_dir=args.build_dir, output_dir=args.package_dir)
            elif args.command == 'release-publish':
                if not args.package_dir:
                    raise UsageError('--package-dir is required')
                with operator_publish.locked(args.package_dir):
                    result = operator_publish.publish(
                        repo, adapter, args.package_dir,
                        authorization_file=args.authorization_file,
                        publication_pointer=args.publication_pointer,
                        expected_pointer_digest=args.expected_pointer_digest,
                    )
            else:
                if args.config_ref and not args.sync_config:
                    raise UsageError('--config-ref requires --sync-config')
                result = operator_publish.workflow(repo, adapter, args)
        elif args.command == "context-check":
            result = check_consumer(
                args.repo_root.resolve(),
                freshness_lookup=trusted_freshness if (args.strict_freshness or args.lookup_freshness) else None,
                strict_freshness=args.strict_freshness,
                development=args.development,
            )
        elif args.command == "context-sync":
            result = sync(
                args.repo_root.resolve(), args.source,
                bundle_sha256=args.bundle_sha256,
                allow_downgrade=args.allow_downgrade,
            )
        elif args.command == "local-clean":
            from modules.local_cleanup import clean, protected_volumes
            repo = args.repo_root.resolve()
            adapter = load_adapter(project_dir(repo) / 'pzagent-adapter.json')
            result = clean(prefix=args.prefix, dry_run=args.dry_run,
                           aggressive=args.aggressive, yes=args.yes,
                           protected=protected_volumes(repo, adapter))
        elif args.command == 'workflow-doctor':
            from modules.workflow_doctor import run as doctor
            repo = args.repo_root.resolve()
            result, code = doctor(repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'),
                                  home=getattr(args, 'operator_home', None), profile_root=args.profile_root,
                                  operation=args.operation_id, environment=args.environment, target=args.target,
                                  offline=args.offline)
            for line in result['summary']:
                print(line, file=sys.stderr)
            print(json_result(**result))
            return code
        elif args.command == 'workflow-abandon':
            from modules.operator_abandon import abandon
            from modules.operator_registry import authentication
            from modules.operator_credentials import REGISTRY
            repo = args.repo_root.resolve()
            result = abandon(repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'), args,
                registry_auth=lambda: authentication({key: os.environ[key] for key in REGISTRY if key in os.environ}))
        elif args.command in {'release-inspect', 'workflow-deploy-existing', 'workflow-resume', 'workflow-status', 'release-rollback'}:
            from modules import operator_workflows as workflows
            from modules.operator_state import read
            repo = args.repo_root.resolve()
            if args.config_ref and not args.sync_config:
                raise UsageError('--config-ref requires --sync-config')
            adapter = load_adapter(project_dir(repo) / 'pzagent-adapter.json')
            if args.command == 'workflow-status':
                if args.all:
                    from modules.operator_listing import status_all
                    result = status_all(repo, getattr(args, 'operator_home', None))
                else:
                    path = args.operation_dir / 'operation.json'
                    result = read(path if path.exists() else args.operation_dir / 'deployment.json')
            elif args.command == 'release-inspect':
                if not args.ref and not args.release_ref:
                    raise UsageError('select --ref or --release-ref')
                selected = workflows.selection(repo, adapter, args)
                if args.detail == 'components':
                    from modules.operator_publish import component_inventory
                    if selected['source_sha'] is None:
                        raise ContractError('selected release source is unavailable')
                    result = component_inventory(
                        adapter, args.kind, selected['source_sha'], args.platform,
                    )
                else:
                    result = selected
            elif args.command == 'workflow-resume':
                from modules.operator_state import require_resumable
                path = args.operation_dir / 'operation.json'
                if not path.exists():
                    record = read(args.operation_dir / 'deployment.json')
                    require_resumable(record)
                    raise UsageError('child deployment resume requires adw:deploy:apply with its recorded release/configuration inputs')
                record = read(path)
                require_resumable(record)
                if record.get('workflow') in {'publish', 'publish-deploy'}:
                    from modules.operator_publish import workflow
                    result = workflow(repo, adapter, args)
                elif record.get('workflow') == 'source-line':
                    from modules.operator_lines import change
                    args.line = record['line']; args.strategy = record['strategy']; args.ref = record['source_sha']
                    args.pr = record.get('pr_number')
                    result = change(repo, adapter, args)
                elif record.get('workflow') == 'retention':
                    from modules.operator_retention import run
                    args.kind = record['kind']; args.apply = record['apply']; args.grace_hours = record['grace_hours']
                    result = run(repo, adapter, args)
                else:
                    result = workflows.deploy_existing(repo, adapter, args)
            else:
                if not args.environment:
                    raise UsageError('--environment is required')
                if args.command == 'release-rollback':
                    if not args.kind:
                        raise UsageError('runtime rollback requires --kind')
                    result = workflows.rollback(repo, adapter, args)
                else:
                    if not args.ref and not args.release_ref:
                        raise UsageError('select --ref or --release-ref')
                    result = workflows.deploy_existing(repo, adapter, args)
        elif args.command == "config-pull":
            repo = args.repo_root.resolve()
            result = config_pull(
                repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'),
                environment=args.environment, requested_target=args.target,
                profile_root=args.profile_root,
            )
        elif args.command == "config-plan":
            from modules.operator_sources import config_source
            repo = args.repo_root.resolve()
            adapter = load_adapter(project_dir(repo) / 'pzagent-adapter.json')
            with config_source(repo, adapter, args.environment, args.target, args.ref, args.remote) as (desired_root, config_sha):
                result = config_plan(
                    repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'),
                    environment=args.environment, requested_target=args.target,
                    profile_root=args.profile_root, desired_root=desired_root,
                )
            result['config_source_sha'] = config_sha
        elif args.command == "config-apply":
            from modules.operator_sources import config_source
            repo = args.repo_root.resolve()
            adapter = load_adapter(project_dir(repo) / 'pzagent-adapter.json')
            with config_source(repo, adapter, args.environment, args.target, args.ref, args.remote) as (desired_root, config_sha):
                result = config_apply(
                    repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'),
                    environment=args.environment, requested_target=args.target,
                    approval_path=args.approval_file,
                    profile_root=args.profile_root, desired_root=desired_root,
                    snapshot_path=args.snapshot_path,
                )
            result['config_source_sha'] = config_sha
        elif args.command == "probe":
            from modules.operator_registry import authentication
            from modules.operator_credentials import REGISTRY
            repo = args.repo_root.resolve()
            result = run_probe(
                repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'),
                capability=args.capability, environment=args.environment,
                requested_target=args.target, profile_root=args.profile_root,
                registry_auth=lambda: authentication({key: os.environ[key] for key in REGISTRY if key in os.environ}),
            )
        elif args.command == "deploy-apply":
            if bool(args.config_ref) != bool(args.config_snapshot):
                raise UsageError('--config-ref and --config-snapshot must be supplied together')
            if args.config_ref and args.restore_compose:
                raise UsageError('--config-ref and --restore-compose are mutually exclusive')
            from contextlib import nullcontext
            from modules.operator_sources import resolve, config_source
            from modules.operator_registry import inspect
            from modules.operator_state import write, locked
            repo = args.repo_root.resolve()
            adapter = load_adapter(project_dir(repo) / 'pzagent-adapter.json')
            selected = None
            if args.kind or args.ref or args.release_ref:
                if not args.kind or (not args.ref and not args.release_ref):
                    raise UsageError('--kind and exactly one of --ref / --release-ref are required')
                selected = inspect(adapter, args.kind,
                                   source_sha=resolve(repo, args.ref, args.remote) if args.ref else None,
                                   release_reference=args.release_ref)
                if not selected['available']:
                    raise ContractError('selected release is incomplete; publish the chosen revision first')
                args.operation_dir = args.operation_dir or new_operation(repo, 'deploy-apply')
                args.release_manifest = args.operation_dir / 'manifest.json'
                args.release_kind = args.kind
                args.release_source_sha = selected['source_sha']
                args.manifest_reference = selected['release_reference']
            if not all((args.release_kind, args.release_source_sha, args.release_manifest, args.manifest_reference)):
                raise UsageError('complete release inputs are required')
            args.operation_dir = args.operation_dir or new_operation(repo, 'deploy-apply')
            with locked(args.operation_dir):
                if selected is not None:
                    write(args.release_manifest, selected['manifest'])
                configuration = (config_source(repo, adapter, args.environment, args.target, args.config_ref, args.remote)
                                 if args.config_ref else nullcontext((None, None)))
                with configuration as (desired_root, config_sha):
                    result = deploy(
                        repo, adapter, environment=args.environment, requested_target=args.target,
                        approval_path=args.approval_file, profile_root=args.profile_root,
                        release_kind=args.release_kind, release_source_sha=args.release_source_sha,
                        manifest_path=args.release_manifest, manifest_reference=args.manifest_reference,
                        expected_pointers_path=args.expected_pointers,
                        state_path=args.operation_dir / 'deployment.json',
                        restore_compose_path=args.restore_compose,
                        reconcile_pointers=args.reconcile_pointers, on_failure=args.on_failure,
                        desired_root=desired_root, config_source_sha=config_sha,
                        config_snapshot_path=args.config_snapshot,
                    )
            result['operation_dir'] = str(args.operation_dir.resolve())
        elif args.command == "e2e":
            repo = args.repo_root.resolve()
            result = run_e2e(repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'), capability=args.capability, environment=args.environment, requested_target=args.target, approval_path=args.approval_file)
        elif args.command == "validate-deployment":
            repo = args.repo_root.resolve()
            result = validate_deployment(repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'), environment=args.environment, requested_target=args.target, approval_path=args.approval_file, profile_root=args.profile_root)
        elif args.command == "hotfix-apply":
            if args.run_id is None:
                if args.execution_mode != 'human':
                    raise UsageError('CI hotfix requires --run-id')
                args.run_id = 'hotfix-' + secrets.token_hex(12)
            if args.transport == 'ssh-docker' and args.ssh_alias is None:
                args.ssh_alias = os.environ.get('PZ_ADW_SSH_ALIAS')
            repo = args.repo_root.resolve()
            result = apply_hotfix(
                repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'),
                environment=args.environment, requested_target=args.target,
                approval_path=args.approval_file, profile_root=args.profile_root,
                run_id=args.run_id,
                transport=args.transport, ssh_alias=args.ssh_alias,
            )
        elif args.command == "hotfix-restore":
            repo = args.repo_root.resolve()
            result = restore_hotfix(repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'), environment=args.environment, requested_target=args.target, approval_path=args.approval_file, profile_root=args.profile_root, artifact_path=args.artifact)
        else:
            result = _invoke(args)
        print(json_result(**result))
        if args.command == 'provider-provision':
            sys.stdout.flush()
            print('Operation: ' + result['operation'], file=sys.stderr, flush=True)
        if args.command == 'probe' and args.capability == 'adw:deploy:status':
            if result.get('status') == 'blocked':
                return EXIT_CONTRACT
            if result.get('status') == 'failed':
                return EXIT_OPERATION
        return 0
    except UsageError as exc:
        print(json_result(status="unsupported", reason=str(exc)))
        return EXIT_USAGE
    except HookFailure as exc:
        print(json_result(status=exc.status, reason=str(exc)))
        return EXIT_OPERATION if exc.status == "failed" else EXIT_CONTRACT
    except ContractError as exc:
        print(json_result(status="blocked", reason=str(exc)))
        return EXIT_CONTRACT


REMOTE_TASKS = {
    "config-pull": "adw:deploy:config:pull", "config-plan": "adw:deploy:config:plan",
    "config-apply": "adw:deploy:config:apply", "deploy-apply": "adw:deploy:apply",
    "validate-deployment": "adw:validate-deployment",
    "hotfix-apply": "adw:hotfix:apply", "hotfix-restore": "adw:hotfix:restore",
}


class _Tee(io.TextIOBase):
    """Pass stdout through unchanged while keeping a copy for the evidence record."""

    def __init__(self, stream):
        self.stream, self.copy = stream, io.StringIO()

    def write(self, text):
        self.copy.write(text)
        return self.stream.write(text)

    def flush(self):
        self.stream.flush()


REMOVED_FLAGS = {'--operation-dir': '--operation <id>', '--deprovision-operation-dir': '--deprovision-operation <id>'}
OPERATION_COMMANDS = {'release-pointers-retire', 'release-pointers-handover', 'cluster-up', 'cluster-teardown',
                      'workflow-deploy-existing', 'workflow-status', 'workflow-resume', 'workflow-abandon', 'release-rollback',
                      'workflow-publish', 'workflow-publish-deploy', 'release-promote', 'release-retention', 'deploy-apply'}


def _operator_paths(args: argparse.Namespace) -> None:
    """One operator home for every command; operations are addressed by ID, never by path."""
    from modules.operator_state import operator_home, operation_path, operation_root
    explicit = getattr(args, 'profile_root', None)
    if hasattr(args, 'profile_root') and (explicit is not None or os.environ.get('PZ_ADW_PROFILE_ROOT')
                                          or args.execution_mode == 'human'):
        args.operator_home = operator_home(explicit)
        args.profile_root = args.operator_home / 'profile'
    if args.command not in OPERATION_COMMANDS:
        return
    repo = args.repo_root.resolve()
    if args.command == 'workflow-status' and args.all:
        if args.operation_id:
            raise UsageError('--all and --operation are mutually exclusive')
        args.operation_dir = None
        return
    if args.command == 'workflow-abandon' and not args.operation_id:
        raise UsageError('abandon requires --operation')
    if args.command == 'workflow-abandon':
        from modules.operator_abandon import _reason
        # The offline credential scope clears process secrets. Redact while
        # their values are still available, without loading any credential file.
        args.reason = _reason(args.reason)
    if getattr(args, 'operation_id', None):
        args.operation_dir = operation_path(repo, args.operation_id, getattr(args, 'operator_home', None))
        if args.command in {'workflow-status', 'workflow-resume'} and not any(
                (args.operation_dir / filename).is_file() for filename in ('operation.json', 'deployment.json')):
            raise ContractError('operator_home_operation_unknown')
        if args.command in {'workflow-status', 'workflow-resume'}:
            from modules.operator_home import select_operation
            select_operation(operation_root(repo, getattr(args, 'operator_home', None)), operation=args.operation_id,
                environment=args.environment, target=args.target, line=args.line, pr_number=args.pr)
    elif args.command in {'workflow-status', 'workflow-resume'}:
        from modules.operator_home import select_operation
        home = getattr(args, 'operator_home', None)
        args.operation_dir = operation_path(repo, select_operation(operation_root(repo, home),
            environment=args.environment, target=args.target, line=args.line, pr_number=args.pr), home)
    else:
        args.operation_dir = None
    if args.command in {'workflow-resume', 'workflow-deploy-existing', 'workflow-publish',
                        'workflow-publish-deploy', 'deploy-apply', 'release-rollback',
                        'release-retention', 'release-promote'} and args.operation_dir is not None:
        from modules.operator_abandon import ensure_resumable
        ensure_resumable(repo, args.operation_dir, getattr(args, 'operator_home', None))
        if args.command == 'workflow-resume' and not (args.operation_dir / 'operation.json').is_file():
            raise UsageError('child deployment resume requires adw:deploy:apply with its recorded release/configuration inputs')


def main(argv: list[str] | None = None) -> int:
    supplied = sys.argv[1:] if argv is None else argv
    for flag, replacement in REMOVED_FLAGS.items():
        if any(item == flag or item.startswith(flag + '=') for item in supplied):
            print(json_result(status='unsupported', reason=flag + ' was removed; operations live in the operator home'
                              ' and are selected with ' + replacement))
            return EXIT_USAGE
    args = parser().parse_args(argv)
    if args.command in {'quality-export', 'quality-import', 'quality-verify', 'quality-leaves', 'context-describe'}:
        from modules.quality_tasks import dispatch
        return dispatch(args)
    if args.command == 'workflows-sync':
        from modules.workflows_sync import sync as sync_workflows
        try:
            result = sync_workflows(args.repo_root, check=args.check)
            print(json_result(**result))
            return 21 if result['status'] == 'blocked' else 0
        except (ContractError, OSError):
            print(json_result(status='blocked', reason='workflow_sync_failed'))
            return 21
    if args.command == "rehearsal":
        return _rehearsal(args)
    task = args.capability if args.command in {"probe", "e2e"} else REMOTE_TASKS.get(args.command)
    if task is None:
        return _dispatch(args)
    from modules import task_evidence
    try:
        identifier = task_evidence.run_id()
    except ContractError as exc:
        print(json_result(status="blocked", reason=str(exc)))
        return EXIT_CONTRACT
    started = task_evidence.now()
    tee = _Tee(sys.stdout)
    with contextlib.redirect_stdout(tee):
        code = _dispatch(args)
    result = None
    for line in reversed(tee.copy.getvalue().splitlines()):
        try:
            result = json.loads(line)
            break
        except json.JSONDecodeError:
            continue
    try:
        task_evidence.record(args.repo_root.resolve(), task=task, identifier=identifier, started_at=started,
                             exit_code=code, result=result if isinstance(result, dict) else None,
                             environment=getattr(args, "environment", None), target=getattr(args, "target", None))
    except (ContractError, OSError, ValueError) as exc:
        # Keep the operation's own outcome: a completed remote write must not look retryable.
        print(f"WARNING: ADW evidence record not written: {exc}", file=sys.stderr)
    return code


def _rehearsal(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone
    from modules.rehearsal import Rehearsal, parse_pairs
    try:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            raise ContractError("rehearsal is a human operator command")
        repo = args.repo_root.resolve()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = args.output or repo / "handover" / f"rehearsal-{stamp}"
        report = Rehearsal(repo, load_adapter(project_dir(repo) / 'pzagent-adapter.json'),
                           lanes=parse_pairs(args.lane, "--lane"), ref=args.ref,
                           transports=parse_pairs(args.hotfix_transport, "--hotfix-transport"),
                           release_refs=parse_pairs(args.release_ref, '--release-ref'),
                           billable=args.billable, rollback=not args.no_rollback, output=output).run()
    except ContractError as exc:
        print(json_result(status="blocked", reason=str(exc)))
        return EXIT_CONTRACT
    failed = [step["name"] for step in report["steps"] if not step["ok"]]
    print(json_result(status="ok" if not failed else "failed", report=str(output / "report.md"),
                      checks=len(report["steps"]), failed=failed))
    return 0 if not failed else EXIT_OPERATION


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == 'context-sync' and os.environ.get('GITHUB_ACTIONS') != 'true':
        # Private provider retrieval uses the same operator credential loader as every human task.
        from modules.operator_credentials import resolve, credentials, REGISTRY
        try:
            values = resolve(args.repo_root.resolve(), mode='human', keys=REGISTRY - {'REGISTRY_TOKEN'})
        except ContractError as exc:
            print(json_result(status='blocked', reason=str(exc)))
            return EXIT_CONTRACT
        with credentials(values, REGISTRY - {'REGISTRY_TOKEN'}):
            return _main(args)
    # Reject before credentials, build or transfer; persistence enforces the same pattern.
    if args.command == 'hotfix-apply' and args.run_id is not None and not IDENTIFIER.fullmatch(args.run_id):
        print(json_result(status='unsupported', reason='hotfix run ID must match ^[a-z][a-z0-9-]{0,62}$'))
        return EXIT_USAGE
    if args.command.startswith('context-') or args.command == 'local-clean':
        return _main(args)
    from modules.execution import execution
    from modules.operator_credentials import resolve, credentials, DOKPLOY, REGISTRY, SSH, KUBE, bootstrap_keys, kubernetes_bootstrap_keys, CLOUDFLARE, CLUSTER_ONLY
    from modules.operator_registry import authentication
    try:
        with ExitStack() as stack:
            stack.enter_context(execution(args.execution_mode))
            if args.command in {'provider-servers', 'provider-provision', 'provider-deprovision', 'provider-examine', 'provider-claim',
                                'provider-journal-rebuild', 'release-pointers-retire', 'provider-domains',
                                'provider-env-apply', 'data-import', 'secrets-show'} and args.execution_mode != 'human' \
                    and not (args.command == 'secrets-show' and args.offline):
                raise ContractError('provider_lifecycle_operator_only')
            if args.command.startswith('workflow-') and args.execution_mode != 'human':
                raise ContractError('local workflow commands require human mode; CI composes its own jobs')
            if args.command in {'release-rollback', 'release-promote'} and args.execution_mode != 'human':
                raise ContractError('operator release mutation requires human mode; use the existing CI publisher policy')
            candidate = project_dir(args.repo_root.resolve()) / 'pzagent-context-development.json'
            if candidate.exists():
                local_simulation = (os.environ.get('ACT', '').lower() == 'true'
                                    and bool(os.environ.get('LAB_RUN')))
                check_consumer(args.repo_root.resolve(),
                               development=args.execution_mode == 'human' or local_simulation,
                               simulation=local_simulation)
            _operator_paths(args)
            offline_abandon = False
            if args.command == 'workflow-abandon':
                from modules.operator_abandon import tree, classification
                from modules.operator_state import journals
                offline_abandon = not args.superseded_by and classification(tree(journals(args.repo_root.resolve(), getattr(args, 'operator_home', None)), args.operation_dir)) == {
                    'classification': 'none', 'publication': 'none'}
            offline_workflow = (args.command == 'workflow-status' or offline_abandon
                                or (args.command in {'workflow-doctor', 'secrets-show'} and args.offline)
                                or args.command == 'secrets-examples')
            adapter_path = project_dir(args.repo_root.resolve()) / 'pzagent-adapter.json'
            if not offline_workflow and args.execution_mode == 'human' and adapter_path.is_file():
                # Probe origins from the vault URL templates; an explicit environment value wins.
                from modules.probe_profile import probe_environment
                probe_commands = {'probe', 'e2e', 'validate-deployment', 'deploy-apply', 'config-plan', 'config-apply',
                    'provider-domains', 'hotfix-apply', 'hotfix-restore', 'release-rollback',
                    'workflow-deploy-existing', 'workflow-publish-deploy', 'workflow-resume', 'workflow-doctor'}
                stack.enter_context(probe_environment(load_adapter(adapter_path),
                    environment=getattr(args, 'environment', None), target=getattr(args, 'target', None),
                    use_templates=args.command in probe_commands))
            registry_commands = {'deploy-apply', 'release-inspect', 'workflow-deploy-existing', 'workflow-resume', 'release-rollback',
                                 'release-publish', 'workflow-publish', 'workflow-publish-deploy', 'release-retention',
                                 'release-pointers-handover', 'release-pointers-retire', 'release-pointers-orphans'}
            source_resume = False
            if args.command == 'workflow-resume' and args.operation_dir:
                from modules.operator_state import read
                operation_record = args.operation_dir / 'operation.json'
                source_resume = operation_record.is_file() and read(operation_record).get('workflow') == 'source-line'
                if source_resume:
                    registry_commands.discard('workflow-resume')
            if args.command == 'release-rollback' and args.scope == 'release-line':
                registry_commands.discard('release-rollback')
            if args.command == 'hotfix-apply' and args.transport == 'registry':
                registry_commands.add('hotfix-apply')
            allowed = set() if offline_workflow else DOKPLOY | SSH | KUBE
            if args.command == 'workflow-doctor' and not offline_workflow:
                allowed |= REGISTRY
            if args.command in {'provider-servers', 'provider-domains', 'provider-env-apply', 'data-import',
                                'secrets-show'}:
                allowed = DOKPLOY | {'PZ_ADW_PROFILE_ROOT'}
            if args.command == 'provider-provision':
                adapter = load_adapter(project_dir(args.repo_root.resolve()) / 'pzagent-adapter.json')
                group = adapter.get('targets', {}).get(args.environment)
                if not group:
                    raise ContractError('provider_environment_undeclared')
                selected = group.get('items', {}).get(args.target or group.get('default'))
                if not selected:
                    raise ContractError('provider_target_unsupported')
                if selected.get('provider') == 'kubernetes':
                    binding = adapter['providers']['kubernetes']['bindings'][selected['provider_binding']]
                    allowed |= {key for key in kubernetes_bootstrap_keys(args.profile_root, binding['context_alias']) - CLOUDFLARE - CLUSTER_ONLY
                                if not key.endswith('_EMAIL')}
            if args.command in {'cluster-up', 'cluster-teardown'}:
                allowed = KUBE
                if args.command == 'cluster-up':
                    allowed |= bootstrap_keys(args.profile_root)
            if args.command == 'probe' and args.capability == 'adw:deploy:status':
                # Authentication happens inside the identity read, after health,
                # so an unreachable registry still yields the combined report.
                allowed |= REGISTRY
            if args.command == 'workflow-abandon':
                # No-write retirement stays offline. Authenticate lazily only
                # if the trusted guard actually needs live observations.
                allowed |= REGISTRY
            if args.command == 'release-retention' and args.execution_mode == 'ci':
                allowed = set()
            if args.command in registry_commands:
                allowed |= REGISTRY
            if args.command in {'config-plan', 'config-apply'} and args.ref:
                allowed |= REGISTRY
            if source_resume or args.command in {'release-promote', 'release-prove-merged-branch'} or (args.command == 'release-rollback' and args.scope == 'release-line'):
                allowed |= REGISTRY
            registry_only = {'release-promote', 'release-prove-merged-branch', 'release-publish',
                'release-inspect', 'release-retention', 'release-pointers-handover',
                'release-pointers-retire', 'release-pointers-orphans', 'workflow-publish'}
            if source_resume or args.command in registry_only or (args.command == 'release-rollback' and args.scope == 'release-line'):
                allowed &= REGISTRY
            if args.command == 'provider-provision':
                if selected.get('provider') == 'kubernetes':
                    allowed -= DOKPLOY | SSH
                else:
                    allowed = DOKPLOY | {'PZ_ADW_PROFILE_ROOT'}
            elif args.command != 'secrets-show' and getattr(args, 'environment', None) and adapter_path.is_file():
                # The secrets overview spans the environment's Dokploy and Kubernetes targets.
                adapter = load_adapter(adapter_path)
                group = adapter.get('targets', {}).get(args.environment, {})
                selected_target = group.get('items', {}).get(getattr(args, 'target', None) or group.get('default'), {})
                if selected_target.get('provider') == 'kubernetes':
                    allowed -= DOKPLOY | SSH
                elif selected_target.get('provider') == 'dokploy':
                    allowed -= KUBE - {'PZ_ADW_PROFILE_ROOT'}
            # Resolve only after the command's grant is known. In particular a
            # server inventory must not decrypt registry, DNS or cluster keys.
            values = {} if offline_workflow else resolve(args.repo_root.resolve(),
                mode=args.execution_mode, profile_root=getattr(args, 'profile_root', None), keys=allowed)
            if getattr(args, 'operator_home', None) is not None and not offline_workflow:
                values['PZ_ADW_PROFILE_ROOT'] = str(args.profile_root)
            stack.enter_context(credentials(values, allowed))
            if args.command in registry_commands:
                stack.enter_context(authentication(values))
            if args.command == 'workflow-doctor' and not offline_workflow:
                try:
                    stack.enter_context(authentication(values))
                except ContractError:
                    pass  # Each identity read then reports the registry as unavailable for its target.
            return _main(args)
    except (ContractError, OSError, ValueError, KeyError, TypeError) as exc:
        reason = str(exc) if isinstance(exc, ContractError) else 'required local tool or file is unavailable'
        print(json_result(status='blocked', reason=reason))
        return EXIT_CONTRACT


if __name__ == "__main__":
    raise SystemExit(main())

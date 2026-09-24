#!/usr/bin/env python3
"""Single bounded CLI for the vendored pz ADW runtime."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.adapter import load as load_adapter
from modules.common import (
    ContractError, EXIT_CONTRACT, EXIT_OPERATION, EXIT_USAGE, UsageError,
    json_result,
)
from modules.context_sync import check_consumer, sync, trusted_freshness
from modules.hooks import HookFailure, invoke as invoke_hook, request as hook_request
from modules.remote_config import config_apply, config_plan, config_pull
from modules.remote_probe import run as run_probe
from modules.remote_deploy import deploy
from modules.hotfix import apply as apply_hotfix, restore as restore_hotfix
from modules.remote_validation import run_e2e, validate_deployment


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)
    check = sub.add_parser("context-check")
    check.add_argument("--repo-root", type=Path, default=Path("."))
    check.add_argument("--strict-freshness", action="store_true")
    check.add_argument("--lookup-freshness", action="store_true")
    update = sub.add_parser("context-sync")
    update.add_argument("--repo-root", type=Path, default=Path("."))
    update.add_argument("--source", required=True)
    update.add_argument("--bundle-sha256", required=True)
    update.add_argument("--allow-downgrade", action="store_true")
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
    hotfix.add_argument("--transport", choices=["registry", "ssh-docker"], required=True)
    hotfix.add_argument("--ssh-alias")
    hotfix.add_argument("--profile-root", type=Path, required=True)
    hotfix.add_argument("--run-id", required=True)
    restore = sub.add_parser("hotfix-restore")
    restore.add_argument("--repo-root", type=Path, default=Path("."))
    restore.add_argument("--environment", required=True)
    restore.add_argument("--target")
    restore.add_argument("--approval-file", type=Path, required=True)
    restore.add_argument("--profile-root", type=Path, required=True)
    restore.add_argument("--artifact", type=Path, required=True)
    return root


def _invoke(args: argparse.Namespace) -> dict:
    repo = args.repo_root.resolve()
    adapter = load_adapter(repo / ".hermes/pzagent-adapter.json")
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


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "context-check":
            result = check_consumer(
                args.repo_root.resolve(),
                freshness_lookup=trusted_freshness if (args.strict_freshness or args.lookup_freshness) else None,
                strict_freshness=args.strict_freshness,
            )
        elif args.command == "context-sync":
            result = sync(
                args.repo_root.resolve(), args.source,
                bundle_sha256=args.bundle_sha256,
                allow_downgrade=args.allow_downgrade,
            )
        elif args.command == "config-pull":
            repo = args.repo_root.resolve()
            result = config_pull(
                repo, load_adapter(repo / ".hermes/pzagent-adapter.json"),
                environment=args.environment, requested_target=args.target,
                profile_root=args.profile_root,
            )
        elif args.command == "config-plan":
            repo = args.repo_root.resolve()
            result = config_plan(
                repo, load_adapter(repo / ".hermes/pzagent-adapter.json"),
                environment=args.environment, requested_target=args.target,
                profile_root=args.profile_root,
            )
        elif args.command == "config-apply":
            repo = args.repo_root.resolve()
            result = config_apply(
                repo, load_adapter(repo / ".hermes/pzagent-adapter.json"),
                environment=args.environment, requested_target=args.target,
                approval_path=args.approval_file,
                profile_root=args.profile_root,
            )
        elif args.command == "probe":
            repo = args.repo_root.resolve()
            result = run_probe(
                repo, load_adapter(repo / ".hermes/pzagent-adapter.json"),
                capability=args.capability, environment=args.environment,
                requested_target=args.target, profile_root=args.profile_root,
            )
        elif args.command == "deploy-apply":
            repo = args.repo_root.resolve()
            result = deploy(
                repo, load_adapter(repo / ".hermes/pzagent-adapter.json"),
                environment=args.environment, requested_target=args.target,
                approval_path=args.approval_file, profile_root=args.profile_root,
                release_kind=args.release_kind,
                release_source_sha=args.release_source_sha,
                manifest_path=args.release_manifest,
                manifest_reference=args.manifest_reference,
                expected_pointers_path=args.expected_pointers,
            )
        elif args.command == "e2e":
            repo = args.repo_root.resolve()
            result = run_e2e(repo, load_adapter(repo / ".hermes/pzagent-adapter.json"), capability=args.capability, environment=args.environment, requested_target=args.target, approval_path=args.approval_file)
        elif args.command == "validate-deployment":
            repo = args.repo_root.resolve()
            result = validate_deployment(repo, load_adapter(repo / ".hermes/pzagent-adapter.json"), environment=args.environment, requested_target=args.target, approval_path=args.approval_file, profile_root=args.profile_root)
        elif args.command == "hotfix-apply":
            repo = args.repo_root.resolve()
            result = apply_hotfix(
                repo, load_adapter(repo / ".hermes/pzagent-adapter.json"),
                environment=args.environment, requested_target=args.target,
                approval_path=args.approval_file, profile_root=args.profile_root,
                run_id=args.run_id,
                transport=args.transport, ssh_alias=args.ssh_alias,
            )
        elif args.command == "hotfix-restore":
            repo = args.repo_root.resolve()
            result = restore_hotfix(repo, load_adapter(repo / ".hermes/pzagent-adapter.json"), environment=args.environment, requested_target=args.target, approval_path=args.approval_file, profile_root=args.profile_root, artifact_path=args.artifact)
        else:
            result = _invoke(args)
        print(json_result(**result))
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


if __name__ == "__main__":
    raise SystemExit(main())

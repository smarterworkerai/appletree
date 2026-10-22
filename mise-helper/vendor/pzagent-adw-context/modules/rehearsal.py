"""Repeatable delivery rehearsal against preview lanes, rendered as a client-ready report.

The rehearsal only drives the public `mise run adw:*` / `pz:*` tasks. Write steps are
restricted to hotfix-capable (preview) lanes; refusal checks run without credentials,
so even a regressed guard cannot reach a provider.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import ContractError
from .operator_credentials import KEYS
from .release_manifest import DIGEST_REF

REFUSAL_SECONDS = 30
# A refusal only counts when it comes from the guard under test, never from absent credentials.
CREDENTIAL_FAILURE = re.compile(r"missing DOKPLOY|credential|kubeconfig|kubernetes_context_profile", re.IGNORECASE)
BOGUS_DIGEST = "sha256:" + "0" * 64


class _StopRehearsal(RuntimeError):
    pass


class Rehearsal:
    def __init__(self, repo: Path, adapter: dict, *, lanes: dict[str, str], ref: str,
                 transports: dict[str, str], billable: bool, rollback: bool, output: Path, runner=None,
                 release_refs: dict[str, str] | None = None):
        self.repo, self.adapter, self.ref = repo, adapter, ref
        self.billable, self.rollback, self.output = billable, rollback, output
        self.runner = runner or subprocess.run
        self.steps: list[dict[str, Any]] = []
        self.environments = list(adapter["environments"])
        self.capabilities = adapter["capabilities"]
        preview = set(adapter["hotfix"]["supported_environments"])
        self.lanes, self.selected_targets = {}, {}
        aliases = {}
        for lane, kind in lanes.items():
            if lane in self.environments:
                environment = lane
                target = adapter['targets'][environment]['default']
            else:
                matches = [(env, lane) for env, group in adapter['targets'].items()
                           if lane in group.get('items', {})]
                if len(matches) != 1:
                    raise ContractError('rehearsal_lane_target_ambiguous')
                environment, target = matches[0]
            group = adapter['targets'][environment]
            if environment in self.lanes or target is None or ('items' in group and group['items'][target]['mode'] != 'active'):
                raise ContractError('rehearsal_lane_target_not_active')
            self.lanes[environment] = kind
            self.selected_targets[environment] = target
            aliases[lane] = environment
            aliases[environment] = environment
        if not self.lanes or set(self.lanes) - preview:
            raise ContractError("rehearsal lanes must be hotfix-capable preview environments")
        unknown = set(self.lanes.values()) - set(adapter["release_kinds"])
        if unknown:
            raise ContractError("rehearsal lane release kind is unknown")
        self.transports, self.release_refs = {}, {}
        for values, normalized in ((transports, self.transports), (release_refs or {}, self.release_refs)):
            for lane, value in values.items():
                if lane not in aliases or aliases[lane] in normalized:
                    raise ContractError('rehearsal_lane_option_ambiguous')
                normalized[aliases[lane]] = value
        for environment, kind in self.lanes.items():
            transport = self.transports.get(environment) or _default_transport(adapter, environment, self.selected_targets[environment])
            target = adapter['targets'][environment].get('items', {}).get(self.selected_targets[environment], {})
            if target.get('provider') == 'kubernetes' and transport != 'registry':
                raise ContractError('rehearsal_kubernetes_registry_transport_required')
            reference = self.release_refs.get(environment)
            if reference is not None:
                match = DIGEST_REF.fullmatch(reference)
                if not match or match['repo'] != adapter['release_kinds'][kind]['manifest_package']:
                    raise ContractError('rehearsal_release_reference_invalid')

    # -- execution ---------------------------------------------------------
    def task(self, name: str, task: str, *args: str, expect: str = "pass", credentials: bool = True,
             env: dict[str, str] | None = None, check=None, reason: str | None = None) -> dict[str, Any]:
        environment = dict(os.environ)
        args = list(args)
        selected_environment = (args[args.index('--environment') + 1] if '--environment' in args
                                else args[0] if args and args[0] in self.selected_targets else None)
        if selected_environment in self.selected_targets and '--target' not in args:
            target = self.selected_targets[selected_environment]
            if target != self.adapter['targets'][selected_environment]['default']:
                args += ['--target', target]
        command = ["mise", "run", task, "--", *args] if args else ["mise", "run", task]
        with tempfile.NamedTemporaryFile("w", suffix=".env") as empty:
            if not credentials:
                for key in KEYS:
                    environment.pop(key, None)
                command += ["--env-file", empty.name]
            environment.update(env or {})
            started = time.monotonic()
            completed = self.runner(command, cwd=self.repo, env=environment, text=True,
                                    capture_output=True, check=False)
            seconds = round(time.monotonic() - started, 1)
        result = _last_json(completed.stdout)
        if expect == "refuse":
            why = (result or {}).get("reason") or ""
            ok = (completed.returncode != 0 and seconds <= REFUSAL_SECONDS and not CREDENTIAL_FAILURE.search(why)
                  and (reason is None or re.search(reason, why) is not None))
        else:
            ok = completed.returncode == 0 and (check is None or bool(check(result or {})))
        step = {"name": name, "task": task, "arguments": _public(args), "expect": expect,
                "exit_code": completed.returncode, "seconds": seconds, "ok": ok,
                "status": (result or {}).get("status"), "reason": _bounded((result or {}).get("reason"))}
        self.steps.append(step)
        if not ok:
            raise _StopRehearsal()
        return result or {}

    def fingerprints(self) -> dict[str, dict[str, Any]]:
        """Untouched active targets, including a different target in the same environment."""
        untouched = {}
        for environment in self.environments:
            group = self.adapter['targets'].get(environment, {})
            targets = [name for name, target in group.get('items', {}).items() if target['mode'] == 'active']
            if not targets and 'items' not in group and group.get('default'):
                targets = [group['default']]
            for target in targets:
                if self.selected_targets.get(environment) == target:
                    continue
                label = environment if len(targets) == 1 else environment + '/' + target
                extra = ['--target', target] if environment in self.selected_targets or target != group.get('default') else []
                result = self.task(f"readback {label}", "adw:deploy:config:pull", environment, *extra,
                    check=lambda r: bool(re.fullmatch(r'[0-9a-f]{64}', r.get('definition_sha256', r.get('compose_sha256', ''))))
                    and isinstance(r.get('config_key_count', r.get('environment_key_count')), int))
                untouched[label] = {'definition_sha256': result.get('definition_sha256', result.get('compose_sha256')),
                                    'config_key_count': result.get('config_key_count', result.get('environment_key_count'))}
        return untouched

    def run(self) -> dict[str, Any]:
        started = datetime.now(timezone.utc)
        releases = {}
        stopped = False
        try:
            self.task("contract: describe", "adw:describe")
            self.task("contract: check", "adw:check")
            self.task("contract: context check", "adw:context:check")
            for environment in self.environments:
                group = self.adapter['targets'].get(environment, {})
                if environment in self.selected_targets or group.get('default'):
                    self.task(f"baseline status {environment}", "adw:validate-deployment", environment)
            before = self.fingerprints()
            self.refusals()
            for environment, kind in self.lanes.items():
                releases[environment] = self.lane(environment, kind)
            self.kind_mismatch(releases)
            after = self.fingerprints()
            isolation = {environment: before[environment] == after.get(environment) for environment in before}
            self.steps.append({"name": "lifecycle isolation", "task": None, "arguments": [], "expect": "pass",
                               "exit_code": 0, "seconds": 0, "ok": all(isolation.values()), "status": None,
                               "reason": None, "isolation": isolation})
        except _StopRehearsal:
            stopped = True
        report = {"schema_version": "1.0.0", "repository": self.adapter["repository"]["id"],
                  "ref": self.ref, "lanes": self.lanes, "started_at": _iso(started),
                  "finished_at": _iso(datetime.now(timezone.utc)), "billable_e2e": self.billable,
                  "releases": releases, "steps": self.steps,
                  "selected_targets": self.selected_targets, "stopped_on_failure": stopped,
                  "passed": all(step["ok"] for step in self.steps)}
        self.output.mkdir(parents=True, exist_ok=True)
        (self.output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (self.output / "report.md").write_text(render(report))
        return report

    # -- scenarios ---------------------------------------------------------
    def refusals(self) -> None:
        preview = self.adapter["hotfix"]["supported_environments"]
        e2e = set(self.capabilities.get("adw:test:e2e:fast", {}).get("environments", []))
        lane = next(iter(self.lanes))
        other = next((e for e in self.environments if e != lane), None)
        for environment in self.environments:
            if environment not in preview:
                self.task(f"refuse hotfix on {environment}", "adw:hotfix:apply", environment,
                          expect="refuse", credentials=False, reason="unsupported for environment")
            if environment not in e2e:
                self.task(f"refuse E2E on {environment}", "adw:test:e2e:fast", environment,
                          expect="refuse", credentials=False, reason="unsupported for environment")
        self.task("refuse unknown environment", "adw:deploy:status", "rehearsal-unknown",
                  expect="refuse", credentials=False, reason="unsupported for environment|unknown")
        if other:
            foreign_group = self.adapter["targets"][other]
            foreign = foreign_group["default"] or next(iter(foreign_group.get("items", {})), None)
            if foreign is not None:
                self.task("refuse foreign target", "adw:health", lane, "--target", foreign,
                          expect="refuse", credentials=False, reason="not allowlisted")
        package = self.adapter["release_kinds"][self.lanes[lane]]["manifest_package"]
        self.task("refuse bogus release digest", "adw:deploy:apply", lane, "--kind", self.lanes[lane],
                  "--release-ref", f"{package}@{BOGUS_DIGEST}", expect="refuse", credentials=False,
                  reason="incomplete|not found|unavailable")
        self.task("refuse missing restore artifact", "adw:hotfix:restore", lane, "--artifact",
                  "handover/rehearsal-missing-restore.json", expect="refuse", credentials=False,
                  reason="unavailable|missing|artifact")
        self.task("refuse unsafe run ID", "adw:deploy:status", lane, expect="refuse", credentials=False,
                  env={"ADW_RUN_ID": "../rehearsal-escape"}, reason="ADW_RUN_ID")

    def kind_mismatch(self, releases: dict[str, dict[str, Any]]) -> None:
        """Deploy a real published release into the wrong kind/lane; it must be refused before writes."""
        published = [(e, r) for e, r in releases.items() if r.get("release_reference")]
        if not published:
            return
        source, release = published[0]
        wrong = next((k for k in self.adapter["release_kinds"] if k != release["kind"]), None)
        if wrong:
            self.task("refuse release kind mismatch", "adw:deploy:apply", source, "--kind", wrong,
                      "--release-ref", release["release_reference"], expect="refuse", credentials=False,
                      reason="does not belong to the selected kind|image-set-differs")
        other = next((e for e, r in published if r["kind"] != release["kind"]), None)
        if other:
            self.task("refuse release into foreign lane", "adw:deploy:apply", other,
                      "--kind", release["kind"], "--release-ref", release["release_reference"],
                      expect="refuse", credentials=False, reason="image-set-differs|does not belong")

    def lane(self, environment: str, kind: str) -> dict[str, Any]:
        if environment in self.release_refs:
            reference = self.release_refs[environment]
            selected = self.task(f"inspect published release {environment}", 'pz:release:inspect',
                '--kind', kind, '--ref', self.ref,
                check=lambda r: r.get('available') is True and r.get('release_reference') == reference)
            published = self.task(f"deploy published release {environment}", 'pz:workflow:deploy-existing',
                '--kind', kind, '--release-ref', reference, '--environment', environment, '--sync-config', '--verify')
            published = {**published, 'release_reference': reference, 'source_sha': selected['source_sha']}
        else:
            published = self.task(f"publish and deploy {environment}", "pz:workflow:publish-deploy",
                                  "--kind", kind, "--ref", self.ref, "--environment", environment,
                                  "--sync-config", "--verify")
        reference = published.get("release_reference")
        record = {"kind": kind, "release_reference": reference, "source_sha": published.get("source_sha")}
        if not reference:
            return record
        self.task(f"same-release redeploy {environment}", "pz:workflow:deploy-existing", "--kind", kind,
                  "--release-ref", reference, "--environment", environment, "--verify",
                  check=lambda r: _deploy(r).get("pointers_promoted") is False)
        if self.rollback:
            self.task(f"rollback {environment}", "pz:release:rollback", "--kind", kind,
                      "--environment", environment, "--verify")
            self.task(f"roll forward {environment}", "pz:workflow:deploy-existing", "--kind", kind,
                      "--release-ref", reference, "--environment", environment, "--verify",
                      check=lambda r: _deploy(r).get("artifact_source_sha") == published.get("source_sha"))
        transport = self.transports.get(environment) or _default_transport(self.adapter, environment, self.selected_targets[environment])
        applied = self.task(f"hotfix apply {environment} ({transport})", "adw:hotfix:apply", environment,
                            "--transport", transport)
        artifact = applied.get("restore_artifact")
        if artifact:
            self.task(f"hotfix restore {environment}", "adw:hotfix:restore", environment, "--artifact", artifact)
        if self.billable and environment in self.capabilities.get("adw:test:e2e:fast", {}).get("environments", []):
            self.task(f"live E2E {environment}", "adw:test:e2e:fast", environment,
                      check=lambda r: r.get("executed", 0) >= 1 and r.get("skipped", 1) == 0)
        self.task(f"final validation {environment}", "adw:validate-deployment", environment)
        return record


def _default_transport(adapter: dict, environment: str | None = None, target: str | None = None) -> str:
    transports = adapter["hotfix"]["transports"]
    if isinstance(transports, dict):
        group = adapter['targets'].get(environment, {})
        selected = group.get('items', {}).get(target or group.get('default'), {})
        transports = transports.get(selected.get('provider'), [])
    if not transports:
        raise ContractError('rehearsal_hotfix_transport_missing')
    return "registry" if "registry" in transports else transports[0]


def _deploy(result: dict) -> dict:
    results = result.get("results") or {}
    return results.get("deploy") or result


def _last_json(stdout: str) -> dict | None:
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _public(args) -> list[str]:
    """Arguments are logical names and digests only; mask anything path-like outside handover."""
    return [a if not a.startswith("/") else "<path>" for a in args]


def _bounded(reason) -> str | None:
    return reason[:200] if isinstance(reason, str) else None


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def render(report: dict) -> str:
    lines = [f"# Delivery rehearsal: {report['repository']}", "",
             f"- Source: `{report['ref']}`",
             f"- Lanes: " + ", ".join(f"`{e}` ({k})" for e, k in report["lanes"].items()),
             f"- Window: {report['started_at']} → {report['finished_at']}",
             f"- Live billable E2E: {'yes' if report['billable_e2e'] else 'not requested'}",
             f"- **Result: {'PASSED' if report['passed'] else 'FAILED'}** "
             f"({sum(s['ok'] for s in report['steps'])}/{len(report['steps'])} checks)", ""]
    if report["releases"]:
        lines += ["## Releases", "", "| Lane | Kind | Immutable release |", "|---|---|---|"]
        for environment, release in report["releases"].items():
            lines.append(f"| `{environment}` | {release['kind']} | `{release.get('release_reference') or 'not published'}` |")
        lines.append("")
    lines += ["## Checks", "", "| Check | Expectation | Exit | Seconds | Result |", "|---|---|---|---|---|"]
    for step in report["steps"]:
        expectation = "refused before provider access" if step["expect"] == "refuse" else "succeeds"
        detail = f" ({step['reason']})" if step.get("reason") and not step["ok"] else ""
        lines.append(f"| {step['name']} | {expectation} | {step['exit_code']} | {step['seconds']} | "
                     f"{'✅' if step['ok'] else '❌'}{detail} |")
    isolation = next((s.get("isolation") for s in report["steps"] if s["name"] == "lifecycle isolation"), {})
    if isolation:
        lines += ["", "## Lifecycle isolation", "",
                  "Configuration of untouched active targets (definition hash and "
                  "configuration key count) was read before and after:", ""]
        lines += [f"- `{e}`: {'unchanged' if same else 'CHANGED'}" for e, same in isolation.items()]
    lines += ["", "Refusal checks run without credentials. Values, endpoints and secrets are never recorded.", ""]
    return "\n".join(lines)


def parse_pairs(values: list[str] | None, label: str) -> dict[str, str]:
    result = {}
    for value in values or []:
        key, sep, item = value.partition("=")
        if not sep or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", key) or not item:
            raise ContractError(f"{label} must be ENV=VALUE")
        result[key] = item
    return result

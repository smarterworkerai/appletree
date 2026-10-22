#!/usr/bin/env python3
"""Thin CI coordinator over the public ``pz:release:*`` ABI."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from .common import project_dir
import re
import subprocess
import tempfile

from . import quality_outputs
from .adapter import load as load_adapter

ROOT = Path.cwd()
FULL_SHA = re.compile(r"[0-9a-f]{40}")


class ContractError(RuntimeError):
    """Closed CI handover validation failure."""


def read(path: Path) -> dict:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ContractError("CI handover JSON must be an object")
    return value


def write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=".handover-", delete=False) as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        temporary = Path(stream.name)
    temporary.replace(path)


def public_task(repo: Path, task: str, *arguments: str) -> dict:
    result = subprocess.run(["mise", "run", task, "--", *arguments], cwd=repo,
                            text=True, capture_output=True, check=False)
    if result.returncode:
        reason = "public release task failed: " + task
        if os.environ.get("LAB_RUN"):
            try:
                detail = json.loads(result.stdout).get("reason", "")
            except (json.JSONDecodeError, AttributeError):
                detail = ""
            # Only fixed identifiers can cross this diagnostic boundary.
            if isinstance(detail, str) and re.fullmatch(r'[a-z][a-z0-9_]{0,127}', detail):
                reason += ": " + detail
        raise ContractError(reason)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ContractError("public release task returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ContractError("public release task returned a non-object")
    return value


def fingerprint(path: Path) -> str:
    # Project recipe ownership stays here; registry lifecycle stays in public pz tasks.
    return quality_outputs.fingerprint(path)


def configuration(repo: Path, adapter: dict, kind: str, platform: str | None = None) -> dict:
    """Read publication settings before registry access; never invent project defaults."""
    platforms = read(project_dir(repo) / 'pz-release.json').get('platforms')
    if (not isinstance(platforms, list) or not platforms
            or any(not isinstance(value, str) or not re.fullmatch(r'[a-z0-9]+/[a-z0-9_]+(?:/[a-z0-9_]+)?', value)
                   for value in platforms)):
        raise ContractError('ci_release_configuration_invalid')
    platform = platform if platform is not None else platforms[0]
    if platform not in platforms:
        raise ContractError('ci_release_configuration_invalid')
    declaration = adapter['release_kinds'][kind]
    packages = [declaration['manifest_package'],
                *(component['package'] for component in declaration['components'].values())]
    registries = {package.split('/', 1)[0] for package in packages}
    if len(registries) != 1:
        raise ContractError('ci_release_configuration_invalid')
    return {'registry': registries.pop(), 'platform': platform}


def selection(repo: Path, source: Path, state_dir: Path, kind: str, sha: str, platform: str) -> dict:
    if not FULL_SHA.fullmatch(sha):
        raise ContractError("CI source requires a full Git SHA")
    if source == state_dir or source in state_dir.parents:
        raise ContractError("CI handover must be outside the selected source")
    observed = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if observed != sha:
        raise ContractError("CI source checkout differs")
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=source, check=True)
    if subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], cwd=source).strip():
        raise ContractError("CI source contains untracked inputs")
    cfg = read(project_dir(repo) / 'pz-release.json')
    if platform not in cfg["platforms"]:
        raise ContractError("CI platform is unsupported")
    inventory = public_task(repo, "pz:release:inspect", "--kind", kind, "--ref", sha,
                            "--detail", "components", "--platform", platform,
                            "--execution-mode", "ci")
    required = {"schema_version", "status", "detail", "kind", "source_sha", "platform", "reused", "missing"}
    if (set(inventory) != required or inventory["status"] != "ok" or inventory["detail"] != "components"
            or inventory["kind"] != kind or inventory["source_sha"] != sha or inventory["platform"] != platform
            or not isinstance(inventory["reused"], dict) or not isinstance(inventory["missing"], list)
            or len(inventory["missing"]) != len(set(inventory["missing"]))
            or set(inventory["reused"]) & set(inventory["missing"])):
        raise ContractError("public component inventory is invalid")
    record = {"schema_version": "1.0.0", "kind": kind, "source_sha": sha, "platform": platform,
              "source_root": str(source), "source_digest": fingerprint(source),
              "recipe_digest": hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest(),
              "reused": inventory["reused"], "missing": sorted(inventory["missing"])}
    path = state_dir / "selection.json"
    if path.exists() and read(path) != record:
        raise ContractError("CI inventory changed; start a fresh job instead of mixing handovers")
    write(path, record)
    return record


def selected(repo: Path, state_dir: Path) -> dict:
    record = read(state_dir / "selection.json")
    cfg = read(project_dir(repo) / 'pz-release.json')
    if (fingerprint(Path(record["source_root"])) != record["source_digest"]
            or hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest() != record["recipe_digest"]):
        raise ContractError("CI source or packaging recipe changed after selection")
    return record


def validate_producer(value: dict, record: dict, repository: str) -> dict:
    required = {"repository", "source_sha", "run_id", "run_attempt", "event", "branch", "pr_number"}
    if (set(value) != required or value["repository"] != repository or value["source_sha"] != record["source_sha"]
            or type(value["run_id"]) is not int or value["run_id"] <= 0
            or type(value["run_attempt"]) is not int or value["run_attempt"] <= 0
            or value["event"] not in {"push", "pull_request", "workflow_dispatch"}
            or not isinstance(value["branch"], str) or not value["branch"]
            or (value["event"] == "pull_request"
                and (type(value["pr_number"]) is not int or value["pr_number"] <= 0))):
        raise ContractError("CI quality producer is invalid")
    return value


def prepare(repo: Path, state_dir: Path, producer: dict, env: dict) -> dict:
    record = selected(repo, state_dir)
    producer = validate_producer(producer, record, env.get("GITHUB_REPOSITORY", ""))
    cfg = read(project_dir(repo) / 'pz-release.json')
    result = {"status": "build-required", "source_sha": record["source_sha"]}
    if not record["missing"]:
        result["status"] = "not-required"
    elif (set(record["missing"]) <= set(cfg.get("quality_exports", {}))
          and (project_dir(Path(record["source_root"])) / "pz-release.json").is_file()
          and read(project_dir(Path(record["source_root"])) / "pz-release.json") == cfg):
        request = {"source_root": record["source_root"], "output_dir": str(state_dir / "build"),
                   "components": record["missing"], "producer": producer}
        completed = subprocess.run(["mise", "run", "pz:quality:import", "--", "--fetch-ci", "--execution-mode", "ci"], cwd=repo,
                                   env=env, input=json.dumps(request), text=True,
                                   capture_output=True, check=False)
        if completed.returncode:
            raise ContractError("quality handover import failed")
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ContractError("quality handover returned invalid JSON") from exc
        if not isinstance(result, dict) or result.get("status") not in {"imported", "build-required"}:
            raise ContractError("quality handover returned an invalid result")
    write(state_dir / "preparation.json", {"schema_version": "1.0.0", **result})
    return result


def package(repo: Path, state_dir: Path) -> dict:
    record = selected(repo, state_dir)
    build_path = state_dir / "build/build.json"
    if record["missing"]:
        build = read(build_path)
        if (build.get("source_sha") != record["source_sha"] or build.get("platform") != record["platform"]
                or set(build.get("components", [])) != set(record["missing"])):
            raise ContractError("CI build handover differs from missing components")
    else:
        write(build_path, {"schema_version": "1.0.0", "source_sha": record["source_sha"],
                           "source_root": record["source_root"], "source_digest": record["source_digest"],
                           "recipe_digest": record["recipe_digest"], "platform": record["platform"],
                           "components": [], "stages": {}})
    result = public_task(repo, "pz:release:package", "--kind", record["kind"],
                         "--build-dir", str(state_dir / "build"),
                         "--package-dir", str(state_dir / "package"), "--execution-mode", "ci")
    package_record = read(state_dir / "package/package.json")
    if (package_record.get("kind") != record["kind"] or package_record.get("source_sha") != record["source_sha"]
            or package_record.get("platform") != record["platform"]
            or set(package_record.get("images", {})) != set(record["missing"])):
        raise ContractError("public package differs from selected work")
    return result


def publish(repo: Path, state_dir: Path, authorization: Path,
            pointer: str | None, expected_digest: str | None) -> dict:
    selected(repo, state_dir)
    arguments = ["--package-dir", str(state_dir / "package"),
                 "--authorization-file", str(authorization), "--execution-mode", "ci"]
    if pointer is not None or expected_digest is not None:
        if not pointer or not expected_digest:
            raise ContractError("publication pointer and expectation must be supplied together")
        arguments.extend(["--publication-pointer", pointer, "--expected-pointer-digest", expected_digest])
    return public_task(repo, "pz:release:publish", *arguments)


def emit(values: dict, env: dict) -> None:
    if env.get("GITHUB_OUTPUT"):
        with open(env["GITHUB_OUTPUT"], "a") as stream:
            for key, value in values.items():
                text = str(value)
                if "\n" in text or "\r" in text:
                    raise ContractError("invalid CI step output")
                stream.write(key + "=" + text + "\n")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("configure", "inventory", "prepare", "package", "publish"))
    args = parser.parse_args(argv)
    env = dict(os.environ)
    if env.get("GITHUB_ACTIONS", "").lower() != "true":
        raise ContractError("CI helper requires Actions; use human workflows locally")
    adapter = load_adapter(project_dir(ROOT) / 'pzagent-adapter.json')
    if env.get("GITHUB_REPOSITORY") != adapter["repository"]["id"]:
        raise ContractError("CI repository differs from project adapter")
    if args.command in {'configure', 'inventory'}:
        settings = configuration(ROOT, adapter, env['PZ_CI_KIND'], env.get('PZ_CI_PLATFORM'))
    if args.command == 'configure':
        emit(settings, env)
        print(json.dumps(settings, sort_keys=True))
        return
    state_dir = Path(env["PZ_CI_STATE_DIR"]).resolve()
    if args.command == "inventory":
        record = selection(ROOT, Path(env["PZ_CI_SOURCE_ROOT"]).resolve(), state_dir,
                           env["PZ_CI_KIND"], env["PZ_CI_SOURCE_SHA"],
                           settings['platform'])
        emit({"missing": json.dumps(record["missing"]),
              "has_missing": str(bool(record["missing"])).lower()}, env)
        print(json.dumps({"missing": record["missing"], "reused": record["reused"]}, sort_keys=True))
    elif args.command == "prepare":
        result = prepare(ROOT, state_dir, json.loads(env["PZ_CI_QUALITY_PRODUCER"]), env)
        emit({"build_required": str(result["status"] == "build-required").lower()}, env)
        print(json.dumps(result, sort_keys=True))
    elif args.command == "package":
        print(json.dumps(package(ROOT, state_dir), sort_keys=True))
    else:
        result = publish(ROOT, state_dir, Path(env["PZ_CI_AUTHORIZATION_FILE"]).resolve(),
                         env.get("PZ_CI_PUBLICATION_POINTER") or None,
                         env.get("PZ_CI_EXPECTED_POINTER_DIGEST") or None)
        print(json.dumps(result, sort_keys=True))

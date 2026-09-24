#!/usr/bin/env python3
"""Deterministic project-local implementations of the ADW quality tasks."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from http.client import RemoteDisconnected
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
QUALITY = ["adw:build", "adw:lint", "adw:static-analysis", "adw:test:unit", "adw:test:integration:fast"]


def run(*args: str, timeout: int = 900) -> None:
    subprocess.run(args, cwd=ROOT, check=True, timeout=timeout)


def ensure_dependencies() -> None:
    if not (ROOT / "node_modules/.package-lock.json").is_file():
        run("npm", "ci")


def install() -> None:
    run("npm", "ci")


def build() -> None:
    ensure_dependencies()
    run("npm", "run", "build")
    required = [ROOT / "dist/index.html"]
    if any(not path.is_file() for path in required):
        raise RuntimeError("production bundle is incomplete")


def lint() -> None:
    run("node", "--check", "src/main.js")
    tracked = subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines()
    bad = [path for path in tracked if path.endswith((".pyc", ".pyo")) or "/__pycache__/" in path]
    if bad:
        raise RuntimeError("generated Python artifacts are tracked")


def static_analysis() -> None:
    package = json.loads((ROOT / "package.json").read_text())
    if package.get("scripts", {}).get("build") != "vite build":
        raise RuntimeError("canonical build script differs")
    for name in ("preview", "demo", "production"):
        compose = (ROOT / f"infra/dokploy/docker-compose.{name}.yml").read_text()
        if "${APPLETREE_IMAGE:?digest-pinned image required}" not in compose:
            raise RuntimeError(f"{name} Compose is not immutable-image ready")
        if re.search(r"^\s*labels:", compose, re.MULTILINE):
            raise RuntimeError("Dokploy Compose must not own routing labels")
    adapter = json.loads((ROOT / ".hermes/pzagent-adapter.json").read_text())
    if adapter["repository"]["id"] != "smarterworkerai/appletree":
        raise RuntimeError("adapter repository identity differs")
    if set(adapter["environments"]) != {"pr-preview", "demo", "production"}:
        raise RuntimeError("adapter environment set differs")


def test_unit() -> None:
    run(sys.executable, "-m", "unittest", "discover", "-s", "mise-helper/tests", "-p", "test_*.py")


def _wait_http(url: str, marker: str, attempts: int = 40) -> None:
    failure: Exception | None = None
    for _ in range(attempts):
        try:
            with urlopen(url, timeout=2) as response:  # nosec B310: fixed loopback URL
                body = response.read(2_000_000).decode("utf-8")
            if response.status == 200 and marker in body:
                return
        except (URLError, TimeoutError, UnicodeDecodeError, RemoteDisconnected, ConnectionResetError) as exc:
            failure = exc
        time.sleep(0.25)
    raise RuntimeError("local integration endpoint did not become healthy") from failure


def integration_fast() -> None:
    build()
    process = subprocess.Popen(
        ["npm", "run", "preview", "--", "--host", "127.0.0.1", "--port", "4173"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        _wait_http("http://127.0.0.1:4173/", "<title>Apple Tree</title>")
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def integration_full() -> None:
    if shutil.which("docker") is None:
        raise RuntimeError("Docker is required for full integration")
    image = "appletree-adw-test:local"
    name = f"appletree-adw-test-{os.getpid()}"
    run("docker", "build", "--tag", image, ".", timeout=1200)
    container = subprocess.check_output(
        ["docker", "run", "--detach", "--rm", "--name", name, "--publish", "127.0.0.1::3333", image],
        cwd=ROOT,
        text=True,
    ).strip()
    try:
        port = subprocess.check_output(["docker", "port", container, "3333/tcp"], cwd=ROOT, text=True).strip().rsplit(":", 1)[1]
        _wait_http(f"http://127.0.0.1:{port}/", '<canvas id="scene"></canvas>')
    finally:
        subprocess.run(["docker", "rm", "--force", container], cwd=ROOT, check=False, stdout=subprocess.DEVNULL)


def aggregate(children: list[str]) -> None:
    for child in children:
        run("mise", "run", child, timeout=1800)


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    operations = {
        "install": install,
        "build": build,
        "lint": lint,
        "static-analysis": static_analysis,
        "test-unit": test_unit,
        "test-integration-fast": integration_fast,
        "test-integration-full": integration_full,
        "verify-minimal": lambda: aggregate(["adw:build"]),
        "verify-full": lambda: aggregate(QUALITY),
    }
    operation = operations.get(sys.argv[1])
    if operation is None:
        return 2
    operation()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

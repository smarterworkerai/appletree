import hashlib
import json
import sys
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
VENDOR = ROOT / "mise-helper/vendor/pzagent-adw-context"
sys.path.insert(0, str(ROOT / "mise-helper"))
sys.path.insert(0, str(VENDOR))

from modules.adapter import load as load_adapter
from modules.context_sync import check_consumer
from modules.hooks import request as hook_request
import pzagent_adapter


class AppletreeAdoptionTest(unittest.TestCase):
    def test_context_integrity_and_precedence(self):
        result = check_consumer(ROOT, mise_version="2026.9.7")
        self.assertEqual(result["verdict"], "current")
        self.assertEqual(result["source_ref"], "9ed89906d75b6ed3e54780ecaa295dc7623c7306")
        config = tomllib.loads((ROOT / "mise.toml").read_text())
        self.assertEqual(config["task_config"]["includes"], [
            "mise-helper/vendor/agentic-delivery/tasks.toml",
            "mise-helper/vendor/pzagent-adw-context/tasks.toml",
            "mise-helper/tasks.toml",
        ])

    def test_every_canonical_capability_has_a_meaningful_default(self):
        adapter = load_adapter(ROOT / ".hermes/pzagent-adapter.json")
        self.assertTrue(adapter["capabilities"])
        self.assertTrue(all(value["status"] == "supported" for value in adapter["capabilities"].values()))
        self.assertEqual(set(adapter["targets"]), {"pr-preview", "demo", "production"})
        self.assertEqual(adapter["hotfix"]["supported_environments"], ["pr-preview"])

    def test_manifest_provenance_matches_exact_files(self):
        manifest = json.loads((ROOT / ".hermes/adw-task-manifest.json").read_text())
        for source in manifest["sources"]:
            digest = hashlib.sha256((ROOT / source["path"]).read_bytes()).hexdigest()
            self.assertEqual(source["checksum"], "sha256:" + digest)
        self.assertEqual(manifest["verification"]["full"], [
            "adw:build", "adw:lint", "adw:static-analysis", "adw:test:unit", "adw:test:integration:fast"
        ])

    def test_closed_describe_and_plan_hooks(self):
        self.assertEqual(pzagent_adapter.dispatch("describe", {"operation": "describe"}), {"profile": "project-adapter"})
        value = hook_request("adw:deploy:config:plan", environment="demo", target="demo-dokploy")
        value.update(source_sha="a" * 40, operation="config-plan")
        self.assertEqual(pzagent_adapter.dispatch("config-plan", value), {"order": "application", "role": "application"})
        with self.assertRaises(ValueError):
            pzagent_adapter.dispatch("config-plan", {**value, "extra": True})

    def test_status_health_and_readiness_are_real_probes(self):
        value = hook_request("adw:readiness", environment="demo", target="demo-dokploy")
        value.update(source_sha="a" * 40, operation="readiness")
        with patch.object(pzagent_adapter, "_request_json", return_value={"composeStatus": "done"}) as provider, patch.object(
            pzagent_adapter, "_fetch", return_value='<title>Apple Tree</title><canvas id="scene"></canvas>'
        ) as http:
            self.assertEqual(pzagent_adapter.dispatch("readiness", value), {"status": "passed"})
        provider.assert_called_once()
        http.assert_called_once_with("https://appletree-demo.smarterworker.cc/")

    def test_runtime_proof_requires_exact_live_image(self):
        image = "ghcr.io/smarterworkerai/appletree@sha256:" + "b" * 64
        value = hook_request("adw:validate-deployment", environment="production", target="production-dokploy", phase="normal-release", expected_images=["APPLETREE_IMAGE=" + image])
        value.update(source_sha="a" * 40, operation="runtime-proof")
        payload = {"composeStatus": "done", "env": "APPLETREE_IMAGE=" + image + "\n"}
        with patch.object(pzagent_adapter, "_request_json", return_value=payload), patch.object(
            pzagent_adapter, "_fetch", return_value='<title>Apple Tree</title><canvas id="scene"></canvas>'
        ):
            self.assertEqual(pzagent_adapter.dispatch("runtime-proof", value), {"images": ["APPLETREE_IMAGE=" + image]})

    def test_e2e_full_fetches_built_assets(self):
        value = hook_request("adw:test:e2e:full", environment="pr-preview", target="pr-preview-dokploy")
        value.update(source_sha="a" * 40, operation="e2e-full")
        html = '<title>Apple Tree</title><canvas id="scene"></canvas><script src="/assets/index.js"></script>'
        with patch.object(pzagent_adapter, "_fetch", side_effect=[html, "javascript"]):
            result = pzagent_adapter.dispatch("e2e-full", value)
        self.assertEqual(result, {"status": "passed", "selected": 2, "executed": 2, "skipped": 0})


if __name__ == "__main__":
    unittest.main()

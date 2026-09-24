import hashlib
import json
import subprocess
import sys
import tomllib
import unittest
from copy import deepcopy
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
        self.assertEqual(adapter["hotfix"]["transports"], ["registry", "ssh-docker"])
        self.assertEqual(adapter["hotfix"]["ssh_aliases"], ["pr-preview"])

    def test_sun_disc_is_a_layered_camera_space_scene_feature(self):
        script = """
import * as THREE from 'three';
import { createSunDisc } from './src/sky.js';
const sun = createSunDisc(THREE);
if (sun.name !== 'sun-disc') throw new Error('sun-name');
if (sun.children.length !== 2) throw new Error('sun-layers');
if (sun.position.x <= 0 || sun.position.y <= 0 || sun.position.z >= 0) throw new Error('sun-position');
if (!sun.children.every(child => child.material.depthTest === false)) throw new Error('sun-depth');
"""
        subprocess.run(
            ["node", "--input-type=module", "--eval", script],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )

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
        with patch.object(pzagent_adapter, "_compose", return_value={"composeStatus": "done"}) as provider, patch.object(
            pzagent_adapter, "_fetch", return_value='<title>Apple Tree</title><canvas id="scene"></canvas>'
        ) as http:
            self.assertEqual(pzagent_adapter.dispatch("readiness", value), {"status": "passed"})
        provider.assert_called_once()
        http.assert_called_once_with("https://appletree-demo.smarterworker.cc/")

    def _runtime_fixture(self):
        image = "ghcr.io/smarterworkerai/appletree@sha256:" + "b" * 64
        request = hook_request("adw:validate-deployment", environment="production", target="production-dokploy", phase="normal-release", expected_images=["APPLETREE_IMAGE=" + image])
        request.update(source_sha="a" * 40, operation="runtime-proof")
        compose = {"composeStatus": "done", "env": "APPLETREE_IMAGE=" + image + "\n", "appName": "appletree-prod", "serverId": "server-1"}
        container = {"containerId": "container-1"}
        config = {"Config": {"Image": image, "Labels": {"com.docker.compose.project": "appletree-prod", "com.docker.compose.service": "appletree"}}, "State": {"Status": "running", "Health": {"Status": "healthy"}}}
        return image, request, compose, container, config

    def test_runtime_proof_inspects_exact_healthy_running_container(self):
        image, request, compose, container, config = self._runtime_fixture()
        with patch.object(pzagent_adapter, "_compose", return_value=compose), patch.object(
            pzagent_adapter, "_provider_json", side_effect=[[container], config]
        ) as provider, patch.object(pzagent_adapter, "_fetch", return_value='<title>Apple Tree</title><canvas id="scene"></canvas>'):
            self.assertEqual(pzagent_adapter.dispatch("runtime-proof", request), {"images": ["APPLETREE_IMAGE=" + image]})
        self.assertEqual(provider.call_count, 2)
        self.assertEqual(
            provider.call_args_list[0].args,
            ("/api/docker.getContainersByAppNameMatch", {"appName": "appletree-prod", "appType": "docker-compose", "serverId": "server-1"}),
        )

    def test_runtime_proof_supports_dokploy_local_runtime_without_server_id(self):
        image, request, compose, container, config = self._runtime_fixture()
        compose.pop("serverId")
        with patch.object(pzagent_adapter, "_compose", return_value=compose), patch.object(
            pzagent_adapter, "_provider_json", side_effect=[[container], config]
        ) as provider, patch.object(pzagent_adapter, "_fetch", return_value='<title>Apple Tree</title><canvas id="scene"></canvas>'):
            self.assertEqual(pzagent_adapter.dispatch("runtime-proof", request), {"images": ["APPLETREE_IMAGE=" + image]})
        self.assertNotIn("serverId", provider.call_args_list[0].args[1])
        self.assertNotIn("serverId", provider.call_args_list[1].args[1])
        self.assertEqual(provider.call_args_list[0].args[1]["appType"], "docker-compose")

    def test_runtime_proof_rejects_stale_duplicate_wrong_label_stopped_and_unhealthy(self):
        image, request, compose, container, config = self._runtime_fixture()
        scenarios = []
        stale = deepcopy(config); stale["Config"]["Image"] = "ghcr.io/smarterworkerai/appletree@sha256:" + "c" * 64; scenarios.append(([container], stale))
        scenarios.append(([container, {"containerId": "container-2"}], [config, config]))
        wrong = deepcopy(config); wrong["Config"]["Labels"]["com.docker.compose.project"] = "other"; scenarios.append(([container], wrong))
        stopped = deepcopy(config); stopped["State"]["Status"] = "exited"; scenarios.append(([container], stopped))
        unhealthy = deepcopy(config); unhealthy["State"]["Health"]["Status"] = "unhealthy"; scenarios.append(([container], unhealthy))
        for listed, inspected in scenarios:
            side_effect = [listed] + (inspected if isinstance(inspected, list) else [inspected])
            with self.subTest(side_effect=side_effect), patch.object(pzagent_adapter, "_compose", return_value=compose), patch.object(
                pzagent_adapter, "_provider_json", side_effect=side_effect
            ), patch.object(pzagent_adapter, "_fetch", return_value='<title>Apple Tree</title><canvas id="scene"></canvas>'):
                with self.assertRaises(pzagent_adapter.Blocked):
                    pzagent_adapter.dispatch("runtime-proof", request)

    def test_e2e_uses_browser_runner_and_validates_counts(self):
        value = hook_request("adw:test:e2e:full", environment="pr-preview", target="pr-preview-dokploy")
        value.update(source_sha="a" * 40, operation="e2e-full")
        completed = subprocess.CompletedProcess([], 0, '{"status":"passed","selected":2,"executed":2,"skipped":0}\n', "")
        with patch.object(pzagent_adapter.subprocess, "run", return_value=completed) as runner:
            result = pzagent_adapter.dispatch("e2e-full", value)
        self.assertEqual(result, {"status": "passed", "selected": 2, "executed": 2, "skipped": 0})
        self.assertIn("browser_e2e.mjs", runner.call_args.args[0][1])

    def test_preview_compose_allows_ssh_loaded_hotfix_images(self):
        preview = (ROOT / "infra/dokploy/docker-compose.preview.yml").read_text()
        self.assertNotIn("pull_policy: always", preview)

    def test_publisher_is_content_exact_and_does_not_move_deployment_pointers(self):
        workflow = (ROOT / ".github/workflows/docker-publish.yml").read_text()
        self.assertIn('test "$remote_id" = "$local_id"', workflow)
        self.assertIn("Immutable release published; deploy-owned pointers remain unchanged.", workflow)
        self.assertNotIn("oras cp", workflow)
        self.assertNotIn("mutable_tag", workflow)
        self.assertNotIn("expected_previous_digest", workflow)


if __name__ == "__main__":
    unittest.main()

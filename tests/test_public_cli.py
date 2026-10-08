import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from xnet.cli import main


class PublicCliTests(unittest.TestCase):
    def test_demo_checks_exact_roundtrip_without_model_or_network(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["demo"]), 0)
        value = json.loads(output.getvalue())
        self.assertTrue(value["source_roundtrip_verified"])
        self.assertEqual(value["model_calls"], 0)
        self.assertEqual(value["network_calls"], 0)
        self.assertEqual(value["authority"], "none")

    def test_machine_capsule_preserves_unicode_and_metadata(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main(["capsule", "--text", "A\n中文", "--ring", "2", "--kind", "decision"])
        value = json.loads(output.getvalue())
        self.assertEqual((value["text"], value["ring"], value["kind"]), ("A\n中文", 2, "decision"))

    def test_invalid_ring_refused(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            main(["capsule", "--text", "source", "--ring", "0"])
        self.assertEqual(caught.exception.code, 2)

    def test_route_command_selects_apple_native_without_launching(self):
        policy = {
            "schema": "xnet.model-ladder-policy.v1", "parameter_ceiling_billion": 14,
            "lanes": [
                {"id": "apple-native", "parameter_class_billion": None,
                 "location": "iphone-platform", "capabilities": ["extract"],
                 "context_tokens": 4096, "available": True,
                 "engine_identity_sha256": "1" * 64},
                {"id": "xnet-4b", "parameter_class_billion": 4,
                 "location": "device-qualified", "capabilities": ["extract", "repair"],
                 "context_tokens": 6400, "available": True,
                 "engine_identity_sha256": "2" * 64},
                {"id": "home-14b", "parameter_class_billion": 14,
                 "location": "home-remote", "capabilities": ["extract", "repair"],
                 "context_tokens": 3500, "available": True,
                 "engine_identity_sha256": "3" * 64},
            ]}
        request = {"schema": "xnet.model-ladder-request.v1", "task_id": "phone-1",
                   "capability": "extract", "context_tokens": 300,
                   "offline_required": True, "source_evidence_sha256": ["a" * 64]}
        with tempfile.TemporaryDirectory() as folder:
            policy_path, request_path = Path(folder) / "policy.json", Path(folder) / "request.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            request_path.write_text(json.dumps(request), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["route", "--policy", str(policy_path),
                                      "--request", str(request_path)]), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["selected_lane"], "apple-native")
            self.assertFalse(result["model_launched"])

    def test_update_inventory_is_local_canonical_and_explicitly_non_mutating(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["updates", "inventory"]), 0)
        value = json.loads(output.getvalue())
        self.assertEqual(value["schema"], "xnet.component-inventory.v1")
        self.assertEqual(
            [row["id"] for row in value["components"]],
            sorted(row["id"] for row in value["components"]),
        )
        by_id = {row["id"]: row for row in value["components"]}
        self.assertEqual(by_id["jcode"]["pinned_version"], "0.91.0")
        self.assertFalse(by_id["xnet"]["update_supported"])

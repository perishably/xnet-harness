"""Independent four-silo controls on temporary local directories only.

These controls exercise the Python controller, not remote cloud upload or actual
model/OpenClaw execution. Shell membrane execution has its own separate tests.
"""
from __future__ import annotations

import json
import hashlib
import hmac
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from adapters.openclaw import make_source_packet
from xnet.oroboros_sphere import SphereController, SphereError, bootstrap_config
from xnet.protocol import canonical, sha256
from xnet.scope import ScopeError


SILO_IDS = ("c_nvme", "d_4tb", "proton", "google")
LANES = ("powershell", "git-bash")


class OroborosSphereTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="xnet sphere controls ")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).absolute()
        self.control_root = self.base / "private controller"
        self.config_path = self.control_root / "config.json"
        self.roots = {name: self.base / f"silo {name}" for name in SILO_IDS}
        for root in self.roots.values():
            root.mkdir()
        self.config = bootstrap_config(self.config_path, self.control_root, self.roots)
        self.controller = SphereController(self.config_path)

    def source(self, *, packet_id="packet-a", task_id="sphere-task-a", text="Public context note: café 🧬\n",
               producer="operator"):
        return make_source_packet(task_id=task_id, producer=producer, kind="note",
                                  text=text, packet_id=packet_id)

    def object_path(self, silo, result):
        pin = result["object_sha256"]
        return self.roots[silo] / "cas" / "sha256" / pin[:2] / f"{pin}.json"

    def silo_snapshot(self):
        return {name: {path.relative_to(root).as_posix(): sha256(path.read_bytes())
                       for path in root.rglob("*") if path.is_file()}
                for name, root in self.roots.items()}

    def assert_fetches(self, packet, *, lane="powershell", controller=None):
        controller = controller or self.controller
        expected = canonical(packet)
        for silo in SILO_IDS:
            with self.subTest(silo=silo, lane=lane):
                returned = controller.fetch(silo, packet["packet_sha256"], lane=lane)
                self.assertEqual(returned, expected)
                self.assertEqual(json.loads(returned), packet)

    def test_four_hops_seal_same_source_and_fetch_from_every_silo(self):
        packet = self.source()
        result = self.controller.cycle(packet, "powershell",
                                       expected_head=self.controller.plan()["head"])
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["idempotent_replay"])
        self.assertEqual(len(result["hops"]), 4)
        self.assertEqual(result["packet_sha256"], packet["packet_sha256"])
        self.assertEqual(result["object_sha256"], sha256(canonical(packet)))
        self.assertFalse(result["provider_upload_verified"])
        for silo in SILO_IDS:
            self.assertEqual(self.object_path(silo, result).read_bytes(), canonical(packet))
        self.assert_fetches(packet)
        verified = self.controller.verify()
        self.assertTrue(verified["ok"], verified["errors"])
        self.assertFalse(verified["errors"])
        self.assertEqual(verified["head"], result["head"])

    def test_restart_and_other_lane_replay_preserve_cycle_and_bytes(self):
        packet = self.source()
        first = self.controller.cycle(packet, "powershell")
        before = self.silo_snapshot()
        prior_cycle = self.controller.plan()["cycle"]
        reopened = SphereController(self.config_path)
        self.assertEqual(reopened.plan()["head"], first["head"])
        second = reopened.cycle(packet, "git-bash", expected_head=first["head"])
        self.assertTrue(second["idempotent_replay"])
        self.assertEqual(second["packet_sha256"], first["packet_sha256"])
        self.assertEqual(reopened.plan()["cycle"], prior_cycle)
        self.assertEqual(self.silo_snapshot(), before)
        self.assert_fetches(packet, lane="git-bash", controller=reopened)
        self.assertTrue(reopened.verify(lane="git-bash")["ok"])

    def test_both_declared_lanes_complete_independent_packets(self):
        for index, lane in enumerate(LANES):
            with self.subTest(lane=lane):
                packet = self.source(packet_id=f"packet-{index}", task_id=f"sphere-task-{index}")
                result = self.controller.cycle(packet, lane,
                                               expected_head=self.controller.plan()["head"])
                self.assertEqual(result["status"], "completed")
                self.assertEqual(len(result["hops"]), 4)
                self.assert_fetches(packet, lane=lane)
        self.assertTrue(self.controller.verify()["ok"])

    def test_stale_head_refused_before_new_silo_writes(self):
        stale = self.controller.plan()["head"]
        self.controller.cycle(self.source(), "powershell", expected_head=stale)
        before = self.silo_snapshot()
        other = self.source(packet_id="packet-b", task_id="sphere-task-b", text="Second public note")
        with self.assertRaises(SphereError):
            self.controller.cycle(other, "git-bash", expected_head=stale)
        self.assertEqual(self.silo_snapshot(), before)
        for silo in SILO_IDS:
            with self.subTest(silo=silo), self.assertRaises(SphereError):
                self.controller.fetch(silo, other["packet_sha256"])

    def test_packet_id_cannot_bind_new_text_or_task(self):
        original = self.source()
        self.controller.cycle(original, "powershell")
        before = self.silo_snapshot()
        conflict = self.source(task_id="different-task", text="Changed public source under same packet ID")
        with self.assertRaises(SphereError):
            self.controller.cycle(conflict, "git-bash", expected_head=self.controller.plan()["head"])
        self.assertEqual(self.silo_snapshot(), before)
        self.assert_fetches(original)
        with self.assertRaises(SphereError):
            self.controller.fetch("google", conflict["packet_sha256"])

    def test_tampered_cloud_copy_is_refused_and_verify_reports_red(self):
        packet = self.source()
        result = self.controller.cycle(packet, "powershell")
        path = self.object_path("google", result)
        corrupted = path.read_bytes() + b"\nTEMPORARY-CONTROL-CORRUPTION"
        path.write_bytes(corrupted)
        with self.assertRaises(SphereError):
            self.controller.fetch("google", packet["packet_sha256"])
        verified = self.controller.verify()
        self.assertFalse(verified["ok"])
        self.assertTrue(verified["errors"])
        self.assertEqual(path.read_bytes(), corrupted)
        self.assertEqual(self.controller.fetch("proton", packet["packet_sha256"]), canonical(packet))

    def test_missing_copy_makes_verify_red_without_unreported_heal(self):
        packet = self.source()
        result = self.controller.cycle(packet, "git-bash")
        missing = self.object_path("proton", result)
        missing.unlink()
        verified = self.controller.verify(lane="git-bash")
        self.assertFalse(verified["ok"])
        self.assertTrue(verified["errors"])
        self.assertFalse(missing.exists())
        with self.assertRaises(SphereError):
            self.controller.fetch("proton", packet["packet_sha256"], lane="git-bash")

    def test_nullclaw_task_cancellation_blocks_cycle_before_silo_writes(self):
        packet = self.source()
        self.controller.nullclaw.cancel(packet["task_id"], "temporary sphere control")
        before = self.silo_snapshot()
        with self.assertRaises((SphereError, PermissionError)):
            self.controller.cycle(packet, "powershell")
        self.assertEqual(self.silo_snapshot(), before)

    def test_nullclaw_lane_containment_blocks_only_that_lane(self):
        self.controller.nullclaw.contain_source("git-bash", "temporary lane containment control")
        packet = self.source()
        before = self.silo_snapshot()
        with self.assertRaises((SphereError, PermissionError)):
            self.controller.cycle(packet, "git-bash")
        self.assertEqual(self.silo_snapshot(), before)
        result = self.controller.cycle(packet, "powershell")
        self.assertEqual(result["status"], "completed")
        with self.assertRaises((SphereError, PermissionError)):
            self.controller.fetch("google", packet["packet_sha256"], lane="git-bash")

    def test_nullclaw_producer_containment_blocks_source(self):
        packet = self.source(producer="model")
        self.controller.nullclaw.contain_source("model", "temporary producer containment control")
        before = self.silo_snapshot()
        with self.assertRaises((SphereError, PermissionError)):
            self.controller.cycle(packet, "powershell")
        self.assertEqual(self.silo_snapshot(), before)

    def test_json_escaping_cannot_exceed_complete_packet_frame_budget(self):
        # Text alone fits 16 KiB, but JSON control escaping expands past 64 KiB.
        packet = self.source(text="\x00" * 16_384)
        self.assertGreater(len(canonical(packet)), 65_536)
        before = self.silo_snapshot()
        with self.assertRaises(SphereError):
            self.controller.cycle(packet, "powershell")
        self.assertEqual(self.silo_snapshot(), before)

    def test_config_tampering_is_refused_on_live_and_reopened_controller(self):
        value = json.loads(self.config_path.read_bytes())
        value["unapproved_authority"] = "execute"
        self.config_path.write_bytes(canonical(value))
        before = self.silo_snapshot()
        with self.assertRaises(SphereError):
            self.controller.plan()
        with self.assertRaises(SphereError):
            SphereController(self.config_path)
        self.assertEqual(self.silo_snapshot(), before)

    def test_unknown_lane_or_silo_never_writes(self):
        before = self.silo_snapshot()
        with self.assertRaises(SphereError):
            self.controller.cycle(self.source(), "arbitrary-shell")
        with self.assertRaises(SphereError):
            self.controller.fetch("other-cloud", "0" * 64)
        self.assertEqual(self.silo_snapshot(), before)

    def test_controller_does_not_start_models_or_network_workers(self):
        packet = self.source()
        with patch("subprocess.run", side_effect=AssertionError("Python controller must not execute workers")), \
                patch("socket.socket", side_effect=AssertionError("Python controller must not start network access")):
            result = self.controller.cycle(packet, "powershell")
            self.assertEqual(result["status"], "completed")
            self.assert_fetches(packet)

    def test_interrupted_transfer_reopens_and_resumes_committed_hops(self):
        packet = self.source()
        original_execute = self.controller.tools.execute
        interrupted = False

        def execute(scope_id, method, target, **fields):
            nonlocal interrupted
            # Match the actual controller-selected destination. Windows temp
            # paths may have short-name/long-name aliases, so comparing the
            # rendered target to the original fixture path can miss this hop.
            if (not interrupted and method == "sphere_transfer"
                    and fields.get("root") == self.controller.roots["proton"]):
                interrupted = True
                raise OSError("temporary fixture drive outage")
            return original_execute(scope_id, method, target, **fields)

        with patch.object(self.controller.tools, "execute", side_effect=execute):
            with self.assertRaisesRegex(OSError, "temporary fixture drive outage"):
                self.controller.cycle(packet, "powershell")
        self.assertTrue(interrupted)
        partial = self.controller.verify()
        self.assertFalse(partial["ok"])
        self.assertEqual(partial["packets"], 1)
        self.assertEqual(partial["completed"], 0)
        self.assertEqual(partial["hops"], 1)
        events = self.controller.ledger.events(packet["task_id"])
        pending = [event for event in events if event["kind"] == "sphere.pending"]
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["payload"]["committed_hops"], 1)
        self.assertFalse(any(event["kind"] == "sphere.completed" for event in events))
        reopened = SphereController(self.config_path)
        result = reopened.cycle(packet, "git-bash", expected_head=reopened.plan()["head"])
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["idempotent_replay"])
        self.assertEqual(len(result["hops"]), 4)
        self.assertEqual(result["hops"][0]["lane"], "powershell")
        self.assertTrue(all(hop["lane"] == "git-bash" for hop in result["hops"][1:]))
        self.assert_fetches(packet, controller=reopened)
        final = reopened.verify()
        self.assertTrue(final["ok"], final["errors"])
        self.assertEqual(final["completed"], 1)
        self.assertEqual(final["hops"], 4)

    def test_empty_controller_is_not_a_successful_verified_loop(self):
        result = self.controller.verify()
        self.assertFalse(result["ok"])
        self.assertEqual(result["packets"], 0)
        self.assertEqual(result["hops"], 0)

    def test_expired_signed_scope_refuses_target_access(self):
        packet = self.source()
        self.controller.cycle(packet, "powershell")
        path = self.controller.scopes.scope_dir / f"{self.controller.scope_id}.json"
        manifest = json.loads(path.read_bytes())
        manifest.pop("signature_hmac_sha256")
        manifest["expires_at"] = 1
        manifest["signature_hmac_sha256"] = hmac.new(
            self.controller.scopes._key(), canonical(manifest), hashlib.sha256
        ).hexdigest()
        path.write_bytes(canonical(manifest))
        before = self.silo_snapshot()
        original_open = Path.open

        def no_target_open(path_obj, *args, **kwargs):
            if any(path_obj.is_relative_to(root) for root in self.roots.values()):
                raise AssertionError("expired scope reached a silo file open")
            return original_open(path_obj, *args, **kwargs)

        new_packet = self.source(packet_id="packet-b", task_id="sphere-task-b")
        with patch.object(Path, "open", new=no_target_open):
            with self.assertRaisesRegex(ScopeError, "expired"):
                self.controller.plan()
            with self.assertRaisesRegex(ScopeError, "expired"):
                self.controller.cycle(new_packet, "git-bash")
            for silo in SILO_IDS:
                with self.subTest(silo=silo), self.assertRaisesRegex(ScopeError, "expired"):
                    self.controller.fetch(silo, packet["packet_sha256"])
            try:
                verified = self.controller.verify()
            except ScopeError as exc:
                self.assertIn("expired", str(exc))
            else:
                self.assertFalse(verified["ok"])
                self.assertTrue(verified["errors"])
                self.assertTrue(all(error["error_type"] == "ScopeError" for error in verified["errors"]))
        self.assertEqual(self.silo_snapshot(), before)

    def test_dependency_drift_refused_on_existing_instance_before_target_writes(self):
        packet = self.source()
        self.controller.cycle(packet, "powershell")
        before = self.silo_snapshot()
        changed_pins = dict(self.config["source_pins"])
        changed_pins["xnet/protocol.py"] = "0" * 64
        next_packet = self.source(packet_id="packet-b", task_id="sphere-task-b")
        # Simulate the observed source-pin change, without editing any source.
        with patch("xnet.oroboros_sphere._source_pins", return_value=changed_pins):
            for name, operation in (
                ("plan", self.controller.plan),
                ("cycle", lambda: self.controller.cycle(next_packet, "git-bash")),
                ("fetch", lambda: self.controller.fetch("google", packet["packet_sha256"])),
                ("verify", self.controller.verify),
            ):
                with self.subTest(operation=name), self.assertRaisesRegex(SphereError, "source"):
                    operation()
        self.assertEqual(self.silo_snapshot(), before)

    def test_virtual_silo_zero_link_metadata_accepts_regular_public_file(self):
        packet = self.source()
        object_hash = sha256(canonical(packet))
        target = self.object_path("google", {"object_sha256": object_hash})
        original_stat = Path.stat
        observed_zero = 0

        class ZeroLinkMetadata:
            """Preserve every real stat attribute except the virtual link count."""
            st_nlink = 0

            def __init__(self, actual):
                self.actual = actual

            def __getattr__(self, name):
                return getattr(self.actual, name)

        def virtual_stat(path_obj, *args, **kwargs):
            nonlocal observed_zero
            actual = original_stat(path_obj, *args, **kwargs)
            if path_obj == target:
                observed_zero += 1
                return ZeroLinkMetadata(actual)
            return actual

        # Only the temporary public Google object receives unknown metadata;
        # controller configuration and private keys retain their real stats.
        with patch.object(Path, "stat", new=virtual_stat):
            result = self.controller.cycle(packet, "powershell")
            self.assertEqual(result["status"], "completed")
            self.assertEqual(len(result["hops"]), 4)
            self.assertTrue(target.is_file())
            self.assertEqual(target.stat().st_nlink, 0)
            self.assertEqual(self.controller.fetch("google", packet["packet_sha256"]), canonical(packet))
            verified = self.controller.verify()
            self.assertTrue(verified["ok"], verified["errors"])
        self.assertGreater(observed_zero, 0)
        self.assertEqual(target.read_bytes(), canonical(packet))

    def test_actual_multiple_hard_links_to_public_file_are_refused(self):
        packet = self.source()
        result = self.controller.cycle(packet, "powershell")
        target = self.object_path("google", result)
        alias = self.base / "temporary hardlink alias.json"
        os.link(target, alias)
        self.assertEqual(target.stat().st_nlink, 2)
        self.assertEqual(alias.stat().st_ino, target.stat().st_ino)
        with self.assertRaisesRegex(SphereError, "hard-linked"):
            self.controller.fetch("google", packet["packet_sha256"])
        verified = self.controller.verify()
        self.assertFalse(verified["ok"])
        self.assertTrue(any("hard-linked" in row["error"] for row in verified["errors"]))
        self.assertEqual(target.read_bytes(), canonical(packet))
        self.assertEqual(alias.read_bytes(), canonical(packet))


if __name__ == "__main__":
    unittest.main()

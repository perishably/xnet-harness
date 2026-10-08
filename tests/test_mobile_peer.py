"""Synthetic phone enrollment proofs; no phone, mesh, server or model is used."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from adapters.mobile import IPhoneContextPeer
from xnet.protocol import canonical, sha256
from xnet_sdk import Client, ContextPeer, XnetError
from test_native_public import BINARY, binary_pin


def proof_bytes(**changes):
    value = {
        "schema": "xnet.phone-browser-capsule-proof.v1",
        "phone_browser_transfer_verified": True,
        "screenshot_receipt_matches": True,
        "hardware_identity_attested": False,
        "authority": "none", "model_calls": 0,
        "source_ip": "192.168.50.2",
        "echo_receipt": {"receipt_hash": "1" * 64},
        "ledger": {"head": "2" * 64},
        "capsule_sha256": "3" * 64, "capsule_bytes": 512,
    }
    value.update(changes)
    return canonical(value)


class MobileEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.context = ContextPeer(object(), task_id="mobile-source-fixture", peer="operator")

    def peer(self, raw=None):
        raw = proof_bytes() if raw is None else raw
        return IPhoneContextPeer(self.context, "phone-fixture", raw, sha256(raw))

    def test_projection_keeps_source_pointers_and_declares_no_compute_or_attestation(self):
        raw = proof_bytes(private_notes="DO_NOT_PROJECT_FAKE_PRIVATE_NOTE")
        peer = self.peer(raw)
        packet = peer.enrollment_packet()
        value = json.loads(packet)
        self.assertEqual(canonical(value), packet)
        self.assertEqual(value["source_proof"]["sha256"], sha256(raw))
        self.assertEqual(value["source_proof"]["capsule_sha256"], "3" * 64)
        self.assertEqual(value["admission_peer"], "operator")
        self.assertFalse(value["device"]["hardware_identity_attested"])
        self.assertFalse(value["readiness"]["phone_compute_enabled"])
        self.assertFalse(value["readiness"]["daily_context_forwarder_enabled"])
        self.assertEqual(value["authority"], "none")
        self.assertEqual(value["model_calls"], 0)
        self.assertNotIn(b"DO_NOT_PROJECT_FAKE_PRIVATE_NOTE", packet)

    def test_exact_caller_selected_pin_rejects_changed_proof(self):
        raw = proof_bytes()
        with self.assertRaisesRegex(ValueError, "caller-selected pin"):
            IPhoneContextPeer(self.context, "phone-fixture", raw + b" ", sha256(raw))

    def test_boolean_and_compute_claim_laundering_are_refused(self):
        cases = (
            {"phone_browser_transfer_verified": 1},
            {"screenshot_receipt_matches": 1},
            {"hardware_identity_attested": True},
            {"model_calls": False}, {"model_calls": 1}, {"authority": "execute"},
        )
        for fields in cases:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.peer(proof_bytes(**fields))

    def test_duplicate_and_nonfinite_json_are_refused_even_with_matching_hash(self):
        raw = proof_bytes()
        duplicate = raw[:-1] + b',"authority":"none"}'
        nonfinite = raw[:-1] + b',"unused":NaN}'
        for value in (duplicate, nonfinite):
            with self.subTest(kind=value[-30:]), self.assertRaises(ValueError):
                self.peer(value)

    def test_public_addresses_hostnames_and_noncanonical_addresses_are_refused(self):
        for address in ("8.8.8.8", "phone.example", "192.168.050.2", "http://192.168.50.2"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.peer(proof_bytes(source_ip=address))

    def test_invalid_pointers_and_boolean_byte_counts_are_refused(self):
        cases = ({"capsule_sha256": "missing"}, {"capsule_bytes": True},
                 {"echo_receipt": {"receipt_hash": "a" * 63}},
                 {"ledger": {"head": "A" * 64}})
        for fields in cases:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.peer(proof_bytes(**fields))

    def test_fixed_packet_is_defensive_and_task_drift_refuses_submission(self):
        peer = self.peer()
        original = peer.enrollment_packet()
        value = json.loads(original)
        value["device"]["mesh_ip"] = "192.168.50.99"
        self.assertEqual(peer.enrollment_packet(), original)
        self.context.task_id = "another-task"
        with self.assertRaisesRegex(ValueError, "identity changed"):
            peer.admit()


@unittest.skipUnless(BINARY.is_file(), "Build native XNET or select XNET_NATIVE_BINARY first")
class MobileNativeEnrollmentTests(unittest.TestCase):
    def test_exact_enrollment_replays_once_and_survives_native_restart(self):
        with tempfile.TemporaryDirectory(prefix="xnet-mobile-enrollment-") as temporary:
            root = Path(temporary) / "XNET"
            raw = proof_bytes()
            with Client(BINARY, root, sha256=binary_pin()) as runtime:
                context = ContextPeer(runtime, task_id="mobile-source-fixture", peer="operator")
                peer = IPhoneContextPeer(context, "phone-fixture", raw, sha256(raw))
                first = peer.admit()
                saved = copy.deepcopy(first["event"])
                replay = peer.admit()
                self.assertTrue(replay["duplicate"])
                self.assertEqual(saved, replay["event"])
                self.assertEqual(context.state()["history_count"], 1)
                self.assertEqual(context.fetch_event(saved).encode(), peer.enrollment_packet())
                with self.assertRaises(XnetError):
                    context.append(peer.event_id, "changed enrollment", kind="raw")
                self.assertTrue(runtime.call("verify")["ok"])
            with Client(BINARY, root, sha256=binary_pin()) as reopened:
                context = ContextPeer(reopened, task_id="mobile-source-fixture", peer="operator")
                self.assertEqual(context.state()["history_count"], 1)
                self.assertEqual(context.history()["events"], [saved])


if __name__ == "__main__":
    unittest.main()

"""Owned-instance source concurrency on temporary local silos; no models."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import threading
from types import MethodType
import unittest
from unittest.mock import patch

from adapters.dojo import sphere_arbitration as adapter
from adapters.openclaw import make_source_packet
from test_jcode_sphere_peer import NativeStandIn
from xnet import oroboros_sphere as original
from xnet.protocol import canonical
from xnet_sdk import ContextPeer


def fresh_sphere(root):
    root = Path(root).absolute()
    silos = {name: root / name for name in original.SILOS}
    for path in silos.values():
        path.mkdir(parents=True)
    config = root / "private" / "config.json"
    original.bootstrap_config(config, config.parent, silos)
    return original.SphereController(config)


class SphereArbitrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="dojo-owned-sphere-gate-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sphere = fresh_sphere(self.root / "one")
        self.binding = adapter.install_serial_cycle(self.sphere)
        for target in ("subprocess.Popen", "subprocess.run", "socket.create_connection"):
            handle = patch(target, side_effect=AssertionError("no process/model/network"))
            handle.start(); self.addCleanup(handle.stop)

    def packet(self, name):
        return make_source_packet(task_id="source-task", packet_id=name, producer="operator",
            kind="note", text="Public authored source: " + name)

    def run_thread(self, function, errors, *, name):
        def run():
            try:
                function()
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=run, name=name)
        thread.start()
        self.addCleanup(lambda: thread.join(timeout=10))
        return thread

    def test_concurrent_default_cycles_choose_head_after_owned_gate(self):
        first_inside, release_first, second_started = (threading.Event() for _ in range(3))
        self.addCleanup(release_first.set)
        actual_lock = original._exclusive_file_lock
        second_state_reads, errors, replies = [], [], []
        actual_state = self.sphere._state
        def state(sphere):
            if threading.current_thread().name == "second-source":
                second_state_reads.append(True)
            return actual_state()
        self.sphere._state = MethodType(state, self.sphere)
        @contextmanager
        def paused_os_lock(path, **kwargs):
            if threading.current_thread().name == "first-source":
                first_inside.set()
                if not release_first.wait(timeout=10):
                    raise TimeoutError("test first source release missing")
            with actual_lock(path, **kwargs):
                yield
        def second():
            second_started.set()
            replies.append(self.sphere.cycle(self.packet("second"), "git-bash"))
        with patch.object(original, "_exclusive_file_lock", paused_os_lock):
            one = self.run_thread(lambda: replies.append(self.sphere.cycle(self.packet("first"), "powershell")), errors, name="first-source")
            self.assertTrue(first_inside.wait(timeout=10))
            two = self.run_thread(second, errors, name="second-source")
            self.assertTrue(second_started.wait(timeout=10))
            self.assertEqual(second_state_reads, [])  # blocked before selecting a head
            release_first.set()
            one.join(timeout=15); two.join(timeout=15)
        self.assertFalse(one.is_alive()); self.assertFalse(two.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(replies), 2)
        self.assertTrue(all(row["status"] == "completed" and not row["idempotent_replay"] for row in replies))
        checked = self.sphere.verify()
        self.assertEqual((checked["completed"], checked["hops"], checked["verified_reads"]), (2, 8, 10))
        self.assertTrue(checked["ok"])

    def test_explicit_stale_head_refuses_without_replay_or_new_admission(self):
        head = self.sphere.plan()["head"]
        with adapter.serialized(self.sphere):
            self.sphere.cycle(self.packet("one"), "powershell", expected_head=head)
        before = self.sphere.ledger.verify_chain()
        with self.assertRaisesRegex(original.SphereError, "stale expected_head"):
            self.sphere.cycle(self.packet("two"), "powershell", expected_head=head)
        self.assertEqual(self.sphere.ledger.verify_chain(), before)
        self.assertEqual(self.sphere.plan()["packets"], 1)
        self.assertEqual(adapter.install_serial_cycle(self.sphere), self.binding)
        other = fresh_sphere(self.root / "other")
        self.assertIs(type(self.sphere), original.SphereController)
        self.assertIs(other.cycle.__func__, original.SphereController.cycle)
        other.cycle(self.packet("retained"), "powershell")
        with self.assertRaisesRegex(ValueError, "fresh sphere"):
            adapter.install_serial_cycle(other)
        self.sphere.cycle = MethodType(original.SphereController.cycle, self.sphere)
        with self.assertRaisesRegex(ValueError, "identity changed"):
            adapter.arbitration_binding(self.sphere)

    def test_jcode_completion_proof_excludes_other_cycle_then_releases_gate(self):
        native = NativeStandIn()
        peer = adapter.SerializedJcodeSpherePeer(self.sphere,
            ContextPeer(native, task_id="source-task", peer="assistant"))
        proof_entered, release_proof, contender_started = (threading.Event() for _ in range(3))
        self.addCleanup(release_proof.set)
        original_proof = peer._completion_proof
        owned_packet = self.packet("owned")
        errors, results = [], {}
        def proof(packet):
            proof_entered.set()
            if not release_proof.wait(timeout=10):
                raise TimeoutError("test proof release missing")
            return original_proof(packet)
        peer._completion_proof = proof
        def contender():
            contender_started.set()
            results["other"] = self.sphere.cycle(self.packet("unrelated"), "git-bash")
        one = self.run_thread(lambda: results.update(admitted=peer.admit(owned_packet)), errors, name="jcode-source")
        self.assertTrue(proof_entered.wait(timeout=10))
        before = self.sphere.ledger.verify_chain()
        two = self.run_thread(contender, errors, name="other-source")
        self.assertTrue(contender_started.wait(timeout=10))
        self.assertNotIn("other", results)
        self.assertEqual(self.sphere.ledger.verify_chain(), before)
        release_proof.set(); one.join(timeout=15); two.join(timeout=15)
        self.assertEqual(errors, [])
        event = results["admitted"]["native"]["event"]
        self.assertEqual(peer.public_context([event])["records"][0]["text"], owned_packet["text"])
        # A later completion is allowed: no source gate stays held by the peer.
        done = threading.Event()
        three = self.run_thread(lambda: (self.sphere.cycle(self.packet("after-proof"), "powershell"), done.set()), errors, name="post-source")
        self.assertTrue(done.wait(timeout=15)); three.join(timeout=5)
        self.assertEqual(errors, [])
        for silo in original.SILOS:
            self.assertEqual(self.sphere.fetch(silo, owned_packet["packet_sha256"]), canonical(owned_packet))


if __name__ == "__main__":
    unittest.main()

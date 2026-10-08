"""Portable native utility tests with synthetic sources and no model inference.

Build `cargo build --manifest-path rust/Cargo.toml -p xnet-cli` first, or
set XNET_NATIVE_BINARY to an explicitly selected freshly built `xnet` binary.
Every runtime belongs to this test and uses a new temporary root. The model,
runner and prompt pins below are synthetic declarations, not attestations.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from xnet_sdk import Client, ContextPeer, XnetError, XnetStartupError


PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = PROJECT / "rust" / "target" / "debug" / (
    "xnet.exe" if os.name == "nt" else "xnet"
)
BINARY = Path(os.environ.get("XNET_NATIVE_BINARY", str(DEFAULT_BINARY))).absolute()


def binary_pin():
    with BINARY.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class PublicPeerLabelsTests(unittest.TestCase):
    def test_only_declared_generic_peer_labels_are_accepted(self):
        borrowed_client = object()
        for label in ("operator", "assistant", "peer"):
            selected = ContextPeer(borrowed_client, task_id="public-task", peer=label)
            self.assertIs(selected.client, borrowed_client)
        for label in ("unknown", "", "OPERATOR", True):
            with self.subTest(label=label), self.assertRaises(XnetError):
                ContextPeer(borrowed_client, task_id="public-task", peer=label)


@unittest.skipUnless(BINARY.is_file(), "Build the Rust utility or set XNET_NATIVE_BINARY")
class NativePublicTests(unittest.TestCase):
    def runtime(self, root):
        return Client(BINARY, root, sha256=binary_pin())

    def test_source_seal_fetch_verify_and_durable_restart(self):
        text = "public exact source\r\nUnicode: café 中文 🧬"
        with tempfile.TemporaryDirectory(prefix="xnet-public-native-") as directory:
            root = Path(directory) / "XNET"
            with self.runtime(root) as runtime:
                health = runtime.call("health")
                self.assertFalse(health["model_required"])
                self.assertFalse(health["jcode_required"])
                self.assertEqual(runtime.call("verify")["receipt_count"], 0)
                sealed = runtime.seal(text)
                self.assertEqual(sealed["digest"], hashlib.sha256(text.encode()).hexdigest())
                self.assertEqual(runtime.fetch(sealed["digest"])["text"], text)
                checked = runtime.call("verify")
                self.assertTrue(checked["ok"])
                self.assertEqual(checked["receipt_count"], 1)
                self.assertEqual(checked["sealed_objects_checked"], 1)
                head = checked["head"]
            with self.runtime(root) as reopened:
                self.assertEqual(reopened.fetch(sealed["digest"])["text"], text)
                self.assertEqual(reopened.call("verify")["head"], head)

    def test_task_history_isolation_handoff_and_acknowledgment_replay(self):
        with tempfile.TemporaryDirectory(prefix="xnet-public-history-") as directory:
            root = Path(directory) / "XNET"
            with self.runtime(root) as runtime:
                first = ContextPeer(runtime, task_id="task-one", peer="operator")
                owner = ContextPeer(runtime, task_id="task-one", peer="assistant")
                other = ContextPeer(runtime, task_id="task-two", peer="peer")
                note = first.append("note-one", "API must preserve empty inputs", kind="fact")
                other.append("note-two", "Separate task source", kind="fact")
                self.assertEqual(first.fetch_event(first.history()["events"][0]),
                                 "API must preserve empty inputs")
                self.assertEqual(other.history()["history_count"], 1)
                with self.assertRaises(XnetError):
                    owner.append("stale-note", "stale writer", expected_head=None)
                owner.bind("session-one", model_sha256="a" * 64,
                           runner_sha256="b" * 64, window=1000, reserve=100)
                # This is a caller-reported synthetic snapshot, not model token measurement.
                owner.occupancy("session-one", revision=1, used=850,
                                prompt_sha256="c" * 64)
                with self.assertRaises(XnetError):
                    owner.prepare("session-one", required_ids=["note-two"])
                plan = owner.prepare("session-one", required_ids=["note-one"])
                self.assertEqual(plan["history_head"], note["history_head"])
                self.assertEqual(owner.state()["pending"]["plan_id"], plan["plan_id"])
                capsule = plan["capsule"]
                self.assertFalse(capsule["work_performed"])
                self.assertEqual(capsule["authority"], "none")
                occurrence = json.loads(capsule["pack"]["records"][0]["text"])
                self.assertEqual(occurrence["text"], "API must preserve empty inputs")
                self.assertEqual(occurrence["task_id"], "task-one")
                self.assertEqual(occurrence["event_id"], "note-one")
                ack = dict(plan_id=plan["plan_id"], new_session_id="session-two",
                           capsule_digest=capsule["seal"]["digest"],
                           prompt_sha256="d" * 64, used=100)
                acknowledged = owner.acknowledge(**ack)
                receipt_count = runtime.call("health")["receipt_count"]
                self.assertEqual(owner.acknowledge(**ack), acknowledged)
                self.assertEqual(runtime.call("health")["receipt_count"], receipt_count)
                self.assertIsNone(acknowledged["pending"])
                self.assertEqual(acknowledged["session"]["session_id"], "session-two")
            with self.runtime(root) as reopened:
                recovered = ContextPeer(reopened, task_id="task-one", peer="assistant").state()
                self.assertEqual(recovered, acknowledged)
                self.assertTrue(reopened.call("verify")["ok"])

    def test_sdk_binary_pin_and_native_peer_validation_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="xnet-public-validation-") as directory:
            root = Path(directory) / "XNET"
            with self.assertRaises(XnetError):
                Client(BINARY, root, sha256="0" * 64)
            self.assertFalse(root.exists())
            with self.runtime(root) as runtime:
                with self.assertRaises(XnetError):
                    runtime.call("context_append", task_id="test", peer="unregistered",
                                 event_id="event", kind="fact", text="public note",
                                 expected_head=None)
                self.assertEqual(runtime.call("health")["receipt_count"], 0)

    def test_corrupt_cas_is_refused_and_not_repaired_implicitly(self):
        with tempfile.TemporaryDirectory(prefix="xnet-public-corruption-") as directory:
            root = Path(directory) / "XNET"
            with self.runtime(root) as runtime:
                sealed = runtime.seal("public original bytes")
                object_path = root / "cas" / sealed["digest"][:2] / sealed["digest"]
                corrupt = b"public original byteZ"
                object_path.write_bytes(corrupt)
                with self.assertRaises(XnetError):
                    runtime.fetch(sealed["digest"])
                with self.assertRaises(XnetError):
                    runtime.call("verify")
                self.assertEqual(object_path.read_bytes(), corrupt)

    def test_existing_legacy_lease_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="xnet-public-legacy-") as directory:
            root = Path(directory) / "XNET"
            root.mkdir()
            lease = root / "audit.writer.lock"
            marker = b"synthetic legacy ownership; inspect before recovery"
            lease.write_bytes(marker)
            with self.assertRaises(XnetStartupError) as refused:
                self.runtime(root)
            self.assertEqual(refused.exception.code, "writer_lease_present")
            self.assertEqual(lease.read_bytes(), marker)
            self.assertFalse((root / "audit.jsonl").exists())

    def test_foreign_storage_is_never_imported_or_modified(self):
        with tempfile.TemporaryDirectory(prefix="xnet-public-separate-") as directory:
            root = Path(directory) / "XNET"
            foreign = root / "ledger" / "xnet.sqlite3"
            foreign.parent.mkdir(parents=True)
            marker = b"synthetic unrelated storage; no real SQLite database"
            foreign.write_bytes(marker)
            with self.runtime(root) as runtime:
                self.assertEqual(runtime.call("health")["receipt_count"], 0)
                runtime.seal("new native stream")
                self.assertEqual(runtime.call("verify")["receipt_count"], 1)
            self.assertEqual(foreign.read_bytes(), marker)


if __name__ == "__main__":
    unittest.main()

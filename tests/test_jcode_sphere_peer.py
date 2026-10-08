"""Real scoped four-silo controls with an inert native gateway stand-in.

The gateway models append/task/FETCH semantics only; root live validation uses
the native binary. These are infrastructure checks, not model solve scores.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from adapters.jcode.sphere_peer import JcodeSpherePeer
from adapters.openclaw import make_source_packet
from xnet.oroboros_sphere import SphereController, SphereError, bootstrap_config
from xnet.protocol import canonical, digest, sha256
from xnet_sdk import ContextPeer, XnetError


class NativeStandIn:
    def __init__(self):
        self.tasks, self.sources, self.fetches = {}, {}, []
        self.closed = False

    def call(self, operation, **args):
        task = args["task_id"]
        events = self.tasks.setdefault(task, [])
        head = events[-1]["event_digest"] if events else None
        if operation == "context_state":
            return {"task_id": task, "history_count": len(events), "history_head": head}
        if operation == "context_history":
            after, limit = args["after"], args["limit"]
            rows = copy.deepcopy(events[after:after + limit])
            return {"task_id": task, "events": rows,
                    "next_after": after + limit if after + limit < len(events) else None}
        if operation != "context_append":
            raise AssertionError("unexpected native operation")
        source = sha256(args["text"].encode("utf-8"))
        for event in events:
            if event["event_id"] == args["event_id"]:
                if (event["peer"], event["kind"], event["source_digest"]) != (
                        args["peer"], args["kind"], source):
                    raise XnetError("context_event_id_conflict")
                return {"event": copy.deepcopy(event), "history_head": head, "duplicate": True}
        if args["expected_head"] != head:
            raise XnetError("context_head_mismatch")
        event = {"seq": len(events), "event_id": args["event_id"], "peer": args["peer"],
                 "kind": args["kind"], "source_digest": source,
                 "event_digest": digest({"task_id": task, "parent": head, "args": args})}
        events.append(event)
        self.sources[source] = args["text"]
        return {"event": copy.deepcopy(event), "history_head": event["event_digest"], "duplicate": False}

    def fetch(self, pin):
        self.fetches.append(pin)
        return {"text": self.sources[pin]}

    def close(self):
        self.closed = True


class JcodeSpherePeerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xnet-jcode-sphere-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).absolute()
        self.silos = {name: self.root / name for name in ("c_nvme", "d_4tb", "proton", "google")}
        for silo in self.silos.values():
            silo.mkdir()
        self.config = self.root / "private" / "config.json"
        bootstrap_config(self.config, self.config.parent, self.silos)
        self.sphere = SphereController(self.config)
        self.native = NativeStandIn()
        self.context = ContextPeer(self.native, task_id="task-one", peer="assistant")
        self.peer = JcodeSpherePeer(self.sphere, self.context)

    def packet(self, *, packet_id="public-a", task_id="task-one", text="Exact public note: café 🧬\r\nKeep ORION-7749."):
        return make_source_packet(task_id=task_id, packet_id=packet_id,
                                  producer="operator", kind="note", text=text)

    def snapshots(self):
        return {
            "sphere": self.sphere.ledger.verify_chain(),
            "native": copy.deepcopy(self.native.tasks),
            "files": {name: {str(path.relative_to(root)): sha256(path.read_bytes())
                             for path in root.rglob("*") if path.is_file()}
                      for name, root in self.silos.items()},
        }

    def test_exact_model_visible_note_and_replay_after_unrelated_packet(self):
        packet = self.packet()
        first = self.peer.admit(packet)
        event = first["native"]["event"]
        envelope = self.context.fetch_event(event)
        for silo in self.silos:
            self.assertEqual(self.sphere.fetch(silo, packet["packet_sha256"]), canonical(packet))
        projection = self.peer.public_context([event])
        self.assertEqual(projection["records"][0]["text"], packet["text"])
        self.assertEqual(projection["records"][0]["source_sha256"], event["source_digest"])
        self.assertEqual(projection["records"][0]["receipt_sha256"],
                         first["sphere"]["completion_receipt_sha256"])
        self.assertEqual(projection["authority"], "none")
        self.assertEqual(projection["model_calls"], 0)
        self.peer.admit(self.packet(packet_id="public-b", text="Separate explicit public source"), "git-bash")
        before = self.snapshots()
        replay = JcodeSpherePeer(SphereController(self.config), self.context).admit(packet, "git-bash")
        self.assertTrue(replay["native"]["duplicate"])
        self.assertTrue(replay["sphere_idempotent_replay"])
        self.assertEqual(replay["sphere"], first["sphere"])
        self.assertEqual(self.context.fetch_event(replay["native"]["event"]), envelope)
        self.assertEqual(self.snapshots(), before)
        self.assertIs(self.peer.context, self.context)
        self.assertIs(self.peer.sphere, self.sphere)
        self.assertFalse(self.native.closed)
        self.assertFalse(hasattr(self.peer, "close"))

    def test_cross_task_refused_before_storage_or_native_mutation(self):
        before = self.snapshots()
        with self.assertRaisesRegex(ValueError, "borrowed native task"):
            self.peer.admit(self.packet(task_id="foreign-task"))
        self.assertEqual(self.snapshots(), before)

    def test_changed_source_under_packet_id_preserves_original(self):
        first = self.peer.admit(self.packet())
        before = self.snapshots()
        with self.assertRaisesRegex(SphereError, "already binds different bytes"):
            self.peer.admit(self.packet(text="Changed source under the original packet ID"))
        self.assertEqual(self.snapshots(), before)
        self.assertIn("ORION-7749", self.peer.public_context([first["native"]["event"]])["records"][0]["text"])

    def test_foreign_or_forged_native_occurrence_is_refused_before_fetch(self):
        first = self.peer.admit(self.packet())
        other_context = ContextPeer(self.native, task_id="other-task", peer="assistant")
        other = JcodeSpherePeer(self.sphere, other_context).admit(
            self.packet(packet_id="other-source", task_id="other-task"))
        forged = copy.deepcopy(first["native"]["event"])
        forged["event_digest"] = "f" * 64
        before = list(self.native.fetches)
        for event in (other["native"]["event"], forged):
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, "not in the borrowed native task"):
                self.peer.public_context([event])
        self.assertEqual(self.native.fetches, before)

    def test_context_budget_refuses_complete_text_without_clipping(self):
        packet = self.packet(text="Exact long source line\n" * 100)
        first = self.peer.admit(packet)
        before = self.snapshots()
        with self.assertRaisesRegex(ValueError, "clipping refused"):
            self.peer.public_context([first["native"]["event"]], max_bytes=128)
        self.assertEqual(self.snapshots(), before)
        self.assertEqual(self.peer.public_context([first["native"]["event"]])["records"][0]["text"], packet["text"])

    def test_forged_completion_receipt_in_native_source_is_rejected(self):
        first = self.peer.admit(self.packet())
        envelope = json.loads(self.context.fetch_event(first["native"]["event"]))
        envelope["sphere"]["completion_receipt_sha256"] = "f" * 64
        fresh_native = NativeStandIn()
        fresh_context = ContextPeer(fresh_native, task_id="task-one", peer="assistant")
        forged = fresh_context.append(first["native"]["event"]["event_id"], canonical(envelope).decode("utf-8"))
        peer = JcodeSpherePeer(self.sphere, fresh_context)
        with self.assertRaisesRegex(ValueError, "completion proof mismatch"):
            peer.public_context([forged["event"]])

    def test_changed_caller_binding_and_cancelled_source_cannot_deliver_context(self):
        first = self.peer.admit(self.packet())
        self.context.task_id = "changed-task"
        with self.assertRaisesRegex(ValueError, "binding changed"):
            self.peer.public_context([first["native"]["event"]])
        self.context.task_id = "task-one"
        self.sphere.nullclaw.cancel("task-one", "owned control fixture")
        with self.assertRaisesRegex(SphereError, "cancellation active"):
            self.peer.public_context([first["native"]["event"]])


if __name__ == "__main__":
    unittest.main()

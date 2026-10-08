"""Real peer and bounded epoch plumbing; fixtures make no model capability claim."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from adapters.jcode.outer_peer import JcodeOuterPeer
from adapters.jcode.sphere_peer import JcodeSpherePeer
from adapters.openclaw import make_source_packet
from test_jcode_sphere_peer import NativeStandIn
import test_learning_epoch as epoch_fixtures
from test_oroboros_session import MODEL, RUNNER, reply
from test_native_public import BINARY as RUST
import hashlib

def pin(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

from xnet.context_callable_identity_v2 import policy
from xnet.generation_usage import normalize_generation_usage
from xnet.oroboros_session import OroborosSession
from xnet.oroboros_outer import OroborosOuter, STAGES, bootstrap_outer
from xnet.oroboros_sphere import SphereController, bootstrap_config
from xnet.protocol import canonical, sha256
from xnet.repair_loop import RepairLoop
from xnet.scaffold_context import ScaffoldContextPreparer
from xnet.scaffold_learning import BASELINE
from xnet_sdk import Client, ContextPeer


def request(stage, payload=None, *, task_id="task-one", scope_id="temporary-test-scope"):
    return {"task_id": task_id, "stage": stage, "scope_id": scope_id,
            "reservation_id": "fixture-outer-reservation", "payload": {} if payload is None else {stage: payload},
            "previous": {}, "previous_sha256": {}, "budgets": {}}


class OuterContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xnet-outer-peer-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.native = NativeStandIn()
        self.context = ContextPeer(self.native, task_id="task-one", peer="assistant")

    def test_disabled_optional_peers_and_source_identity_are_explicit(self):
        outer = JcodeOuterPeer(self.context)
        for stage in ("context", "session", "learn"):
            result = outer.callbacks()[stage](request(stage))
            self.assertEqual(result["status"], "disabled")
            self.assertEqual(result["callback_identity"]["source_sha256"],
                             sha256(Path(result["callback_identity"]["path"]).read_bytes()))
            self.assertIsNone(result["costs"])
            self.assertFalse(result["model_lifecycle_owned"])
            self.assertFalse(result["model_tools_executed"])
        self.assertFalse(self.native.closed)

    def test_exact_public_native_text_and_membership_before_every_fetch(self):
        text = "Public only: café 🧬\r\nKeep ORION-7749."
        event = self.context.append("public-note", text)["event"]
        outer = JcodeOuterPeer(self.context)
        result = outer.context_stage(request("context", {"visibility": "public", "action": "native-select",
                                                        "selected_events": [event]}))
        record = result["result"]["public_context"]["records"][0]
        self.assertEqual(record["text"], text)
        self.assertEqual(record["text_sha256"], sha256(text.encode("utf-8")))
        self.assertEqual(result["status"], "completed")
        other = ContextPeer(self.native, task_id="other-task", peer="assistant")
        foreign = other.append("foreign", "Private foreign source")["event"]
        self.native.fetches.clear()
        with self.assertRaisesRegex(ValueError, "borrowed native task"):
            outer.context_stage(request("context", {"visibility": "public", "action": "native-select",
                                                    "selected_events": [event, foreign]}))
        self.assertEqual(self.native.fetches, [])
        with self.assertRaisesRegex(ValueError, "public context required"):
            outer.context_stage(request("context", {"action": "native-select", "selected_events": [event]}))
        with self.assertRaisesRegex(ValueError, "borrowed task"):
            outer.context_stage(request("context", {}, task_id="other-task"))

    def test_context_clipping_and_peer_drift_are_refused(self):
        event = self.context.append("long-note", "x" * 200)["event"]
        outer = JcodeOuterPeer(self.context)
        value = {"visibility": "public", "action": "native-select", "selected_events": [event], "max_bytes": 128}
        with self.assertRaisesRegex(ValueError, "clipping refused"):
            outer.context_stage(request("context", value))
        self.context.task_id = "other-task"
        self.native.fetches.clear()
        with self.assertRaisesRegex(ValueError, "gateway changed"):
            outer.context_stage(request("context", value))
        self.assertEqual(self.native.fetches, [])

    def test_borrowed_context_callback_replacement_is_refused(self):
        event = self.context.append("public-note", "The admitted source.")["event"]
        outer = JcodeOuterPeer(self.context)
        def forged_fetch(selected):
            return "Different caller bytes"
        self.context.fetch_event = forged_fetch
        with self.assertRaisesRegex(ValueError, "callback identity"):
            outer.context_stage(request("context", {"visibility": "public", "action": "native-select",
                                                    "selected_events": [event]}))
        self.assertEqual(self.native.fetches, [])

    def test_four_silo_admission_public_text_and_exact_replay(self):
        silos = {name: self.root / name for name in ("c_nvme", "d_4tb", "proton", "google")}
        for path in silos.values():
            path.mkdir()
        config = self.root / "private" / "config.json"
        bootstrap_config(config, config.parent, silos)
        sphere = SphereController(config)
        borrowed = JcodeSpherePeer(sphere, self.context)
        outer = JcodeOuterPeer(self.context, sphere_peer=borrowed)
        packet = make_source_packet(task_id="task-one", packet_id="public-one", producer="operator",
                                    kind="note", text="Public measured intent, exact bytes.")
        value = request("context", {"visibility": "public", "action": "sphere-admit", "packet": packet},
                        scope_id=sphere.scope_id)
        first = outer.context_stage(value)
        second = outer.context_stage(value)
        self.assertEqual(first["result"]["public_context"], second["result"]["public_context"])
        self.assertEqual(first["result"]["public_context"]["records"][0]["text"], packet["text"])
        self.assertTrue(second["result"]["admission"]["sphere_idempotent_replay"])
        self.assertEqual(len(self.native.tasks["task-one"]), 1)
        bad_scope = copy.deepcopy(value)
        bad_scope["scope_id"] = "other-scope"
        with self.assertRaisesRegex(ValueError, "sphere scope"):
            outer.context_stage(bad_scope)
        self.assertFalse(self.native.closed)

    def test_direct_outer_context_callback_keeps_separate_signed_scopes(self):
        silos = {name: self.root / name for name in ("c_nvme", "d_4tb", "proton", "google")}
        for path in silos.values():
            path.mkdir()
        control = self.root / "sphere-private"
        bootstrap_config(control / "config.json", control, silos)
        sphere = SphereController(control / "config.json")
        borrowed = JcodeOuterPeer(self.context, sphere_peer=JcodeSpherePeer(sphere, self.context))
        callbacks = {"context": borrowed.context_stage}
        config = bootstrap_outer(self.root / "outer-private", callbacks,
            disabled={stage: "outside this focused context fixture" for stage in STAGES[:-1] if stage != "context"},
            bindings={"stage_scopes": {"context": sphere.scope_id}})
        outer = OroborosOuter(self.root / "outer-private", callbacks)
        packet = make_source_packet(task_id="task-one", packet_id="direct-public", producer="operator",
                                    kind="note", text="Explicit separate authority scopes.")
        outer.enqueue("task-one", {"context": {"visibility": "public", "action": "sphere-admit", "packet": packet}})
        result = outer.run(max_steps=9)
        self.assertEqual(result["state"]["completed_cycles"], 1)
        pin = result["state"]["jobs"][0]["outputs"]["context"]
        receipt = json.loads(outer.ledger.get_evidence(pin))
        self.assertEqual(receipt["scope_id"], config["scope_id"])
        self.assertEqual(receipt["stage_scope_id"], sphere.scope_id)
        self.assertNotEqual(receipt["scope_id"], receipt["stage_scope_id"])
        self.assertTrue(receipt["outer_reservation_id"])
        self.assertEqual(receipt["result"]["public_context"]["records"][0]["text"], packet["text"])


@unittest.skipUnless(RUST.is_file(), "build the existing native context utility first")
class OuterSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xnet-outer-session-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = Client(RUST, self.root / "XNET", sha256=pin(RUST))
        self.addCleanup(self.runtime.close)
        self.context = ContextPeer(self.runtime, task_id="task-one", peer="assistant")
        self.context.append("public-intent", "Public exact task contract.")
        self.session = OroborosSession(self.root / "sessions", self.context,
            model_sha256=MODEL, runner_sha256=RUNNER, window=1000, reserve=100)
        self.session.bind("old-1")
        self.calls, self.fail = [], False

    def fresh(self, plan):
        self.calls.append(copy.deepcopy(plan))
        if self.fail:
            raise TimeoutError("fixture caller outcome uncertain; sensitive prose stays local")
        return reply(plan)

    def value(self, *, used=850, revision=1):
        return request("session", {"snapshot": {"session_id": "old-1", "revision": revision,
            "used": used, "prompt_sha256": sha256(b"real fixture measured absolute prompt")},
            "required_ids": ["public-intent"]})

    def test_absolute_occupancy_and_real_supplied_callback(self):
        outer = JcodeOuterPeer(self.context, session_controller=self.session, open_fresh=self.fresh)
        low = outer.session_stage(self.value(used=450))
        self.assertEqual(low["status"], "completed")
        self.assertEqual(low["result"]["session_status"], "not-due")
        self.assertEqual(self.calls, [])
        high = outer.session_stage(self.value(revision=2))
        self.assertEqual(high["result"]["session_status"], "acknowledged")
        self.assertEqual(high["result"]["snapshot"]["used"], 25)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(high["open_fresh_identity"]["qualname"], "OuterSessionTests.fresh")
        self.assertIsNone(high["costs"])
        self.assertTrue(self.runtime.call("verify")["ok"])

    def test_uncertain_handoff_waits_without_callback_repeat(self):
        self.fail = True
        outer = JcodeOuterPeer(self.context, session_controller=self.session, open_fresh=self.fresh)
        first = outer.session_stage(self.value())
        second = outer.session_stage(self.value())
        self.assertEqual(first["status"], "waiting")
        self.assertEqual(second["status"], "waiting")
        self.assertEqual(first["result"]["plan_id"], second["result"]["plan_id"])
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn("sensitive prose", canonical(first).decode())
        pending = self.context.state()["pending"]
        self.session.reconcile(pending["plan_id"], reply(pending))
        self.assertEqual(len(self.calls), 1)
        self.assertIsNone(self.context.state()["pending"])

    def test_saved_callback_reply_ack_recovery_has_no_new_inference(self):
        outer = JcodeOuterPeer(self.context, session_controller=self.session, open_fresh=self.fresh)
        with patch.object(self.context, "acknowledge", side_effect=ConnectionError("ACK transport lost")):
            first = outer.session_stage(self.value())
        self.assertEqual(first["status"], "waiting")
        recovered = outer.session_stage(self.value())
        self.assertEqual(recovered["status"], "completed")
        self.assertEqual(len(self.calls), 1)

    def test_missing_real_callback_waits_and_callback_replacement_refused(self):
        missing = JcodeOuterPeer(self.context, session_controller=self.session)
        self.assertEqual(missing.session_stage(self.value())["reason"], "open-fresh-not-bound")
        self.assertIsNone(self.context.state()["pending"])
        outer = JcodeOuterPeer(self.context, session_controller=self.session, open_fresh=self.fresh)
        outer.open_fresh = reply
        with self.assertRaisesRegex(ValueError, "callback identity"):
            outer.session_stage(self.value())
        self.assertEqual(self.calls, [])


class OuterEpochTests(unittest.TestCase):
    def setUp(self):
        # Reuse the existing fully pinned inert epoch fixture; no new runner.
        self.fixture = epoch_fixtures.LearningEpochControls(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.context = ContextPeer(NativeStandIn(), task_id="task-one", peer="assistant")
        self.epoch = self.fixture.epoch()

    def test_direct_outer_epoch_callback_uses_selected_epoch_scope(self):
        borrowed = JcodeOuterPeer(self.context, learning_epoch=self.epoch)
        callbacks = {"learn": borrowed.learn_stage}
        epoch_scope = self.epoch.cycle.config["scope_id"]
        config = bootstrap_outer(self.fixture.root / "outer-private", callbacks,
            disabled={stage: "outside this focused epoch fixture" for stage in STAGES[:-1] if stage != "learn"},
            bindings={"stage_scopes": {"learn": epoch_scope}})
        outer = OroborosOuter(self.fixture.root / "outer-private", callbacks)
        outer.enqueue("task-one", {"learn": {"action": "run", "max_stages": 8}})
        result = outer.run(max_steps=9)
        self.assertEqual(result["state"]["completed_cycles"], 1)
        receipt = json.loads(outer.ledger.get_evidence(result["state"]["jobs"][0]["outputs"]["learn"]))
        self.assertEqual(receipt["scope_id"], config["scope_id"])
        self.assertEqual(receipt["stage_scope_id"], epoch_scope)
        self.assertNotEqual(receipt["scope_id"], receipt["stage_scope_id"])
        self.assertEqual(receipt["result"]["completed_stages"], 8)
        self.assertTrue(receipt["outer_reservation_id"])

    def test_bounded_progress_then_sealed_completion_exports_only_public_pointers(self):
        outer = JcodeOuterPeer(self.context, learning_epoch=self.epoch)
        with patch("xnet.learning_epoch.RepairLoop.grade", side_effect=AssertionError("hidden grade called")):
            first = outer.learn_stage(request("learn", {"action": "run", "max_stages": 1}))
            final = outer.learn_stage(request("learn", {"action": "run", "max_stages": 8}))
        self.assertEqual(first["status"], "waiting")
        self.assertEqual(first["result"]["completed_stages"], 1)
        self.assertEqual(final["status"], "completed")
        self.assertEqual(final["result"]["completed_stages"], 8)
        self.assertEqual(final["costs"]["generation_calls"], 7)
        self.assertEqual(final["costs"]["input_tokens"], 630)
        self.assertEqual(len(self.fixture.calls), 6)
        self.assertNotIn(self.epoch.private_originals_sha256, canonical(final).decode())
        self.assertNotIn('"references"', canonical(final).decode())
        self.assertNotIn('"files"', canonical(final).decode())
        before = len(self.fixture.ledger.events())
        repeated = outer.learn_stage(request("learn", {"action": "run", "max_stages": 8}))
        self.assertEqual(repeated, final)
        self.assertEqual(len(self.fixture.ledger.events()), before)

    def test_pending_proposal_waits_before_any_implicit_repeat(self):
        self.fixture.proposal_transport_failure = True
        outer = JcodeOuterPeer(self.context, learning_epoch=self.epoch)
        first = outer.learn_stage(request("learn", {"action": "step"}))
        second = outer.learn_stage(request("learn", {"action": "run", "max_stages": 8}))
        self.assertEqual(first["status"], "waiting")
        self.assertEqual(second["reason"], "epoch-reconciliation-required")
        self.assertEqual(len(self.fixture.proposal_requests), 1)
        self.assertIsNone(first["costs"])
        self.assertEqual(second["result"]["pending"], first["result"]["pending"])

    def test_stop_bounds_scope_and_source_pin_guard(self):
        outer = JcodeOuterPeer(self.context, learning_epoch=self.epoch)
        stopped = outer.learn_stage(request("learn", {"action": "run", "control": "STOP"}))
        self.assertEqual(stopped["status"], "waiting")
        self.assertEqual(stopped["result"]["status"], "stopped")
        self.assertEqual(self.fixture.proposal_requests, [])
        for limit in (0, 9, True):
            with self.assertRaisesRegex(ValueError, "bounded"):
                outer.learn_stage(request("learn", {"action": "run", "max_stages": limit}))
        with self.assertRaisesRegex(ValueError, "learning scope"):
            outer.learn_stage(request("learn", {"action": "run"}, scope_id="different-scope"))
        self.epoch.generate = self.fixture.proposal
        with self.assertRaises(ValueError):
            outer.learn_stage(request("learn", {"action": "status"}))
        self.assertEqual(self.fixture.calls, [])

    def test_selected_real_public_outcome_transfer_uses_existing_host_proof(self):
        ids = [row["task_id"] for row in self.fixture.dataset["splits"]["train"]]
        preparer = ScaffoldContextPreparer(self.epoch.learner, task_ids=ids,
            model_ids=["lite"], mode="practice", scaffold_id=BASELINE)
        loop = RepairLoop(self.fixture.root / "external-public-loop",
            [task for task in self.fixture.tasks if task["task_id"] in ids], self.fixture.models,
            {tid: self.fixture.refs[tid] for tid in ids}, run_identity=self.fixture.identity,
            context_preparer=preparer.prepare, public_context_policy=policy(preparer.policy))
        def generate(value):
            rendered = copy.deepcopy(value)
            rendered["learning_public_context_policy"] = copy.deepcopy(loop.manifest["config"]["public_context_policy"])
            response = self.fixture.generate(rendered)
            response["usage"] = normalize_generation_usage(response["usage"])
            return response
        loop.run_lane("lite", generate)
        boundary = self.fixture.boundary(loop, "lite", ids[0])
        outer = JcodeOuterPeer(self.context, learning_epoch=self.epoch, repair_loops={"practice": loop})
        value = request("learn", {"action": "public-outcome", "loop_id": "practice", "model_id": "lite",
            "repair_task_id": ids[0], "scaffold_id": BASELINE, "boundary_evidence_sha256": boundary})
        with patch.object(loop, "grade", side_effect=AssertionError("hidden grade read")):
            result = outer.learn_stage(value)
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["result"]["hidden_grade_read"])
        self.assertFalse(result["result"]["candidate_source_copied"])
        self.assertEqual(result["result"]["report"]["task_id"], ids[0])
        self.assertEqual(result["result"]["report"]["output_tokens"], 20)
        self.assertNotIn('"files"', canonical(result).decode())
        self.fixture.ledger.get_evidence(result["result"]["public_observation_evidence_sha256"])
        invalid = copy.deepcopy(value)
        invalid["payload"]["learn"]["boundary_evidence_sha256"] = "f" * 64
        with self.assertRaises(Exception):
            outer.learn_stage(invalid)

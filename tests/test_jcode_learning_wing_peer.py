"""Jcode/learning/memory integration controls; no model capability scores.

Synthetic host outcomes exercise actual caller-owned learners, signed memory
scope and next-turn delivery. No generation, network or source execution.
"""
import json
from pathlib import Path
import tempfile
import unittest

from adapters.jcode.learning_wing_peer import JcodeLearningWingPeer
from adapters.jcode.procedural_memory_peer import JcodeProceduralMemoryPeer
from xnet.ledger import Ledger
from xnet.procedural_memory import ProceduralMemory, VALIDATION_SCHEMA
from xnet.protocol import canonical, digest
from xnet.scaffold_learning import BASELINE, PUBLIC_SCHEMA, ScaffoldLearner
from xnet.scope import ScopeAuthority, ScopeError


class JcodeLearningWingPeerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xnet-jcode-learning-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.learner_ledger = Ledger(self.root / "learner")
        self.learner = ScaffoldLearner(
            self.learner_ledger, "jcode-learning", ["practice-one", "practice-two"],
            ["validation-one", "validation-two"], "a" * 64,
        )
        self.peer = JcodeLearningWingPeer(self.learner)
        self.authority = ScopeAuthority(self.root / "authority")
        self.memory_root = self.root / "memory"
        self.memory_scope = self.authority.create(
            program="owned-learning-memory", policy_url="fixture:",
            policy_capture=b"public owned fixture only", fixture=True,
            allowed_assets=["path:" + str(self.memory_root)],
            methods=["memory_read", "memory_write"],
        )
        self.memory = ProceduralMemory(
            Ledger(self.memory_root), "memory-one", "project-one", "a" * 64,
            scope_authority=self.authority, scope_id=self.memory_scope["scope_id"],
        )

    def response(self, *, steps=None, usage=None):
        return {"text": json.dumps({"scaffold_id": "edges", "steps":
                    ["inspect-contract", "check-edge-cases"] if steps is None else steps}),
                "usage": {"input_tokens": 100, "output_tokens": 30} if usage is None else usage}

    def observe(self, task, scaffold, passed, *, no_op=False):
        report = {
            "schema": PUBLIC_SCHEMA, "task_id": task, "scaffold_id": scaffold,
            "verifier_sha256": "a" * 64, "passed": passed, "no_op": no_op,
            "boundary_violation": False, "attempts": 1,
            "output_tokens": 100, "wall_ms": 1000,
        }
        # These CAS records are explicitly synthetic controls, never live
        # repairs, model outputs or an accuracy claim. They exercise the
        # existing caller-attached public-verifier projection boundary.
        pointer = self.learner_ledger.put_evidence(
            canonical({"control_only": True, "task_id": task, "scaffold_id": scaffold}),
            source="synthetic-control-public-verifier", scope_id="control-only",
        )
        proof = {
            "schema": "xnet.scaffold-repair-projection.v1", "visibility": "public",
            "repair_manifest_sha256": pointer, "model_id": "control-lite",
            "model_artifacts": {"model_sha256": "b" * 64, "runner_sha256": "c" * 64},
            "attempts": [{"attempt": 1, "result_sha256": pointer,
                          "output_sha256": pointer, "request_sha256": pointer}],
            "selected_result_sha256": pointer, "public_evaluation_sha256": digest(report),
            "scaffold_exposure_sha256": pointer, "boundary_evidence_sha256": pointer,
            "report": report, "hidden_grade_read": False, "candidate_source_copied": False,
        }
        evidence = self.learner_ledger.put_evidence(
            canonical(proof), source="synthetic-control-public-verifier", scope_id="control-only",
        )
        return self.learner.observe(task, scaffold, report, evidence_sha256=evidence)

    def completed_epoch(self, *, gain=True):
        self.peer.admit(self.response())
        for index, task in enumerate(self.learner.config["train_task_ids"]):
            self.observe(task, BASELINE, bool(index))
            self.observe(task, "edges", gain or bool(index))
        frozen = self.learner.freeze_training()
        for index, task in enumerate(self.learner.config["validation_task_ids"]):
            self.observe(task, BASELINE, bool(index))
            if frozen["body"]["selected_scaffold"] != BASELINE:
                self.observe(task, "edges", gain or bool(index))
        return self.learner.promote()

    def stage(self, **options):
        return self.peer.promote_to_catalog(
            self.memory, session_id="session-one", task_id="fresh-repair", turn_id="old-turn",
            now=100, **options,
        )

    def validation(self, staged):
        body = {
            "schema": VALIDATION_SCHEMA, "project_id": "project-one",
            "memory_id": staged["memory_id"], "stage_sha256": staged["stage_sha256"],
            "source_sha256": staged["source_sha256"], "verifier_sha256": "a" * 64,
            "validation_task_id": "independent-memory-validation", "passed": True,
            "boundary_violation": False, "hidden_cases_used": False,
            "answer_payload_used": False, "independent_public_validation": True,
        }
        return self.memory.ledger.put_evidence(
            canonical(body), source="synthetic-independent-public-verifier",
            scope_id=self.memory_scope["scope_id"],
        )

    def test_borrowed_epoch_stays_caller_owned_and_proposal_is_not_a_win(self):
        self.assertIs(self.peer.current_learner, self.learner)
        self.assertIs(self.peer.current_learner.ledger, self.learner_ledger)
        self.assertIsNone(self.peer.previous_learner)
        before = self.learner.snapshot()
        request = self.peer.proposal_request()
        self.assertIsInstance(request, dict)
        # A seed may provide enum guidance, but cannot invent measured outcomes.
        for task_id in self.learner.config["train_task_ids"]:
            self.assertNotIn(task_id, json.dumps(request))
        self.assertEqual(self.learner.snapshot(), before)
        self.peer.admit(self.response())
        state = self.learner.snapshot()
        self.assertEqual(state["proposals"]["edges"]["steps"],
                         ["inspect-contract", "check-edge-cases"])
        self.assertEqual(state["observation_count"], 0)
        self.assertIsNone(state["promotion"])
        self.assertFalse(state["weights_updated"])

    def test_untrusted_commands_and_invalid_usage_do_not_become_guidance(self):
        before = self.learner.snapshot()
        for response in (
            self.response(steps=["run-arbitrary-command"]),
            self.response(steps=["inspect-contract", "inspect-contract"]),
            self.response(usage={"input_tokens": 100}),
            self.response(usage={"input_tokens": 100, "output_tokens": True}),
            self.response(usage={"input_tokens": 100, "output_tokens": 201}),
        ):
            with self.subTest(response=response), self.assertRaises(ValueError):
                self.peer.admit(response)
        self.assertEqual(self.learner.snapshot(), before)

    def test_next_epoch_request_uses_previous_sealed_public_failures(self):
        self.completed_epoch(gain=False)
        previous_state = self.learner.snapshot()
        next_learner = ScaffoldLearner(
            self.learner_ledger, "jcode-next-epoch", ["new-practice-one", "new-practice-two"],
            ["new-validation-one", "new-validation-two"], "a" * 64,
        )
        next_peer = JcodeLearningWingPeer(next_learner, self.learner)
        request = next_peer.proposal_request()
        rendered = json.dumps(request)
        self.assertTrue("practice-one" in rendered or "validation-one" in rendered)
        self.assertNotIn("new-practice-one", rendered)
        self.assertIs(next_peer.previous_learner, self.learner)
        self.assertEqual(self.learner.snapshot(), previous_state)
        self.assertEqual(next_learner.snapshot()["observation_count"], 0)

    def test_promoted_procedure_waits_for_independent_validation_and_new_turn(self):
        self.assertTrue(self.completed_epoch()["body"]["promoted"])
        staged = self.stage()
        self.assertFalse(staged["active"])
        self.assertFalse(staged["queued"])
        self.assertEqual(self.memory.catalog(), [])
        with self.assertRaises(ValueError):
            self.memory.load(staged["memory_id"])
        active = self.stage(validation_evidence_sha256=self.validation(staged))
        self.assertTrue(active["active"])
        self.assertTrue(active["queued"])
        bridge = JcodeProceduralMemoryPeer(self.memory)
        request = {"task": {"task_id": "fresh-repair"}, "public_feedback": None,
                   "hidden_cases_used": False}
        same_turn = bridge.consume_fresh_user_turn(
            "session-one", request, project_id="project-one", user_turn_id="old-turn", now=101,
        )
        self.assertEqual(same_turn["records"], [])
        fresh_turn = bridge.consume_fresh_user_turn(
            "session-one", request, project_id="project-one", user_turn_id="fresh-turn", now=102,
        )
        self.assertEqual(len(fresh_turn["records"]), 1)
        self.assertIn("empty inputs", fresh_turn["records"][0]["text"])
        self.assertFalse(fresh_turn["work_performed"])
        self.assertEqual(fresh_turn["authority"], "none")

    def test_tied_candidate_retains_baseline_and_cannot_publish_as_learning(self):
        promotion = self.completed_epoch(gain=False)
        self.assertFalse(promotion["body"]["promoted"])
        before = self.memory.verify()
        with self.assertRaises(ValueError):
            self.stage()
        self.assertEqual(self.memory.verify(), before)
        self.assertEqual(self.memory.catalog(), [])

    def test_replay_does_not_multiply_promoted_cards_or_redeliver_same_memory(self):
        self.completed_epoch()
        staged = self.stage()
        evidence = self.validation(staged)
        first = self.stage(validation_evidence_sha256=evidence)
        repeated = self.stage(validation_evidence_sha256=evidence)
        self.assertEqual(first["memory_id"], repeated["memory_id"])
        self.assertEqual(len(self.memory.catalog()), 1)
        consumed = self.memory.consume(
            "session-one", "fresh-repair", project_id="project-one",
            fresh_turn_id="fresh-turn", now=101,
        )
        self.assertEqual(len(consumed), 1)
        self.stage(validation_evidence_sha256=evidence)
        self.assertEqual(self.memory.consume(
            "session-one", "fresh-repair", project_id="project-one",
            fresh_turn_id="another-turn", now=102,
        ), [])
        count = self.learner.snapshot()["observation_count"]
        self.observe("practice-one", BASELINE, False)
        self.assertEqual(self.learner.snapshot()["observation_count"], count)

    def test_other_pending_card_does_not_hide_new_promoted_guidance(self):
        self.completed_epoch()
        staged = self.stage()
        other_source = self.memory.ledger.put_evidence(
            canonical({"public_note": "unrelated carrier marker"}),
            source="owned-public-control", scope_id=self.memory_scope["scope_id"],
        )
        other = self.memory.stage_note(
            "other-card", kind="fact", title="Unrelated note", tags=["public"],
            text="Unrelated carrier marker.", source_sha256=other_source,
            origin_task_id="other-practice",
        )
        self.memory.activate(other["memory_id"], self.validation(other | {"source_sha256": other_source}))
        self.memory.queue("session-one", "fresh-repair", [other["memory_id"]],
                          turn_id="old-turn", now=100)
        published = self.stage(validation_evidence_sha256=self.validation(staged))
        self.assertTrue(published["active"])
        self.assertTrue(published["queued"])
        delivered = self.memory.consume(
            "session-one", "fresh-repair", project_id="project-one",
            fresh_turn_id="fresh-turn", now=101,
        )
        self.assertEqual(delivered, [self.memory.load(staged["memory_id"])])
        self.assertIn("empty inputs", delivered[0]["text"])

    def test_already_active_deduped_card_reports_existing_activation(self):
        self.completed_epoch()
        staged = self.stage()
        self.stage(validation_evidence_sha256=self.validation(staged))
        replay = self.stage()
        self.assertTrue(replay["active"])
        self.assertEqual(replay["memory_id"], staged["memory_id"])
        self.assertEqual(len(self.memory.catalog()), 1)
        self.assertIn("empty inputs", self.memory.load(replay["memory_id"])["text"])

    def test_catalog_writes_still_require_the_callers_signed_scope(self):
        self.completed_epoch()
        denied = self.authority.create(
            program="other-scope", policy_url="fixture:",
            policy_capture=b"other owned root only", fixture=True,
            allowed_assets=["path:" + str(self.root / "other-memory")],
            methods=["memory_read", "memory_write"],
        )
        original_scope = self.memory.scope_id
        before = self.memory.ledger.verify_chain()
        before_cas = sorted(str(path.relative_to(self.memory.ledger.cas_dir))
                            for path in self.memory.ledger.cas_dir.rglob("*") if path.is_file())
        self.memory.scope_id = denied["scope_id"]
        try:
            with self.assertRaises(ScopeError):
                self.stage()
        finally:
            self.memory.scope_id = original_scope
        self.assertEqual(self.memory.ledger.verify_chain(), before)
        self.assertEqual(sorted(str(path.relative_to(self.memory.ledger.cas_dir))
                                for path in self.memory.ledger.cas_dir.rglob("*") if path.is_file()),
                         before_cas)
        self.assertEqual(self.memory.catalog(), [])


if __name__ == "__main__":
    unittest.main()

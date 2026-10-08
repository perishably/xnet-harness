"""Offline public-feedback controls; declared metrics are not live model scores."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from xnet.learning_wing import (admit_proposal, build_proposal_request, incumbent_baseline,
                               public_failure_feed, seal_epoch_trace, seal_run_identity,
                               seed_failure_feed)
from xnet.ledger import Ledger
from xnet.protocol import canonical, digest, make_event, sha256
from xnet.repair_loop import RepairLoop, pilot_battery
from xnet.scaffold_context import ScaffoldContextPreparer, ingest_repair_outcome, public_verifier_identity
from xnet.scaffold_learning import PUBLIC_SCHEMA, ScaffoldLearner


class LearningWingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.ledger = Ledger(self.root / "memory")
        self.learner = ScaffoldLearner(self.ledger, "control-epoch", ["train-one", "train-two"],
                                       ["validate-one", "validate-two"], "a" * 64)

    def tearDown(self):
        self.temp.cleanup()

    def response(self, **changes):
        return {"text": json.dumps({"scaffold_id": "candidate", "steps": ["inspect-contract", "trace-state"]}),
                "usage": {"prompt_tokens": 80, "completion_tokens": 20}} | changes

    def observe(self, task, scaffold, passed):
        report = {"schema": PUBLIC_SCHEMA, "task_id": task, "scaffold_id": scaffold,
                  "verifier_sha256": "a" * 64, "passed": passed, "no_op": False,
                  "boundary_violation": False, "attempts": 1, "output_tokens": 20, "wall_ms": 100}
        pin = self.ledger.put_evidence(canonical({"control_only": True}), source="owned-control",
                                      scope_id="fixture")
        proof = {"schema": "xnet.scaffold-repair-projection.v1", "visibility": "public",
                 "repair_manifest_sha256": pin, "model_id": "lite-control",
                 "model_artifacts": {"model_sha256": pin, "runner_sha256": pin},
                 "attempts": [{"attempt": 1, "result_sha256": pin, "output_sha256": pin, "request_sha256": pin}],
                 "selected_result_sha256": pin, "public_evaluation_sha256": pin,
                 "scaffold_exposure_sha256": pin, "boundary_evidence_sha256": pin,
                 "report": report, "hidden_grade_read": False, "candidate_source_copied": False}
        parent = self.ledger.put_evidence(canonical(proof), source="control-public-verifier", scope_id="fixture")
        return self.learner.observe(task, scaffold, report, evidence_sha256=parent)

    def complete(self, *, gain=False):
        admission = admit_proposal(self.learner, self.response())
        for index, task in enumerate(["train-one", "train-two"]):
            self.observe(task, "baseline", bool(index))
            self.observe(task, "candidate", True if gain else bool(index))
        self.learner.freeze_training()
        for index, task in enumerate(["validate-one", "validate-two"]):
            self.observe(task, "baseline", bool(index))
            if gain:
                self.observe(task, "candidate", True)
        self.learner.promote()
        return admission

    def binding(self):
        path = Path(__file__).absolute()
        pin = sha256(path.read_bytes())
        models = {"lite-control": {"model_sha256": "a" * 64, "runner_sha256": pin}}
        identity = {"schema": "xnet.repair-run-identity.v1", "adapter": {"path": str(path), "sha256": pin},
                    "runner": {"source_revision": "offline-control", "artifacts": [{"path": str(path), "sha256": pin}]},
                    "models": {"lite-control": {"decoding": {"spec_type": "ngram-simple"}, "transport": {"network": False},
                        "tokenizer": {"id": "control", "sha256": None}, "template": {"id": "control", "sha256": None}}},
                    "native": None}
        return seal_run_identity(self.learner, models, identity)["binding_evidence_sha256"]

    def test_cold_start_does_not_invent_failures(self):
        request = build_proposal_request(seed_failure_feed())
        self.assertEqual(request["failure_feed"]["records"], [])
        self.assertEqual(request["max_output_tokens"], 200)
        self.assertFalse(request["weights_updated"])
        poisoned = seed_failure_feed() | {"records": [{"failure": "invented"}]}
        with self.assertRaises(ValueError):
            build_proposal_request(poisoned)

    def test_raw_proposal_is_retained_on_invalid_enum(self):
        response = self.response(text=json.dumps({"scaffold_id": "candidate", "steps": ["call-shell"]}))
        with self.assertRaisesRegex(ValueError, "raw response preserved"):
            admit_proposal(self.learner, response)
        pointer = sha256(canonical(response))
        self.assertEqual(self.ledger.get_evidence(pointer), canonical(response))
        self.assertNotIn("candidate", self.learner.snapshot()["proposals"])

    def test_alias_conflicts_missing_bool_and_budget_are_refused(self):
        usages = [{"input_tokens": 1, "output_tokens": True}, {"input_tokens": 1},
                  {"input_tokens": 1, "output_tokens": 2, "completion_tokens": 3},
                  {"prompt_tokens": 1, "completion_tokens": 201}]
        for usage in usages:
            with self.subTest(usage=usage), self.assertRaises(ValueError):
                admit_proposal(self.learner, self.response(usage=usage))
        self.assertNotIn("candidate", self.learner.snapshot()["proposals"])

    def test_duplicate_json_keys_and_extra_payload_refused(self):
        for text in ('{"scaffold_id":"one","scaffold_id":"two","steps":["trace-state"]}',
                     '{"scaffold_id":"one","steps":["trace-state"],"hidden_report":"answer"}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                admit_proposal(self.learner, self.response(text=text))

    def test_admission_replay_is_idempotent_and_is_not_promotion(self):
        first = admit_proposal(self.learner, self.response())
        count = len(self.ledger.events())
        second = admit_proposal(self.learner, self.response())
        self.assertTrue(second["duplicate"])
        self.assertEqual(first["evidence_sha256"], second["evidence_sha256"])
        self.assertEqual(count, len(self.ledger.events()))
        self.assertIsNone(self.learner.snapshot()["promotion"])

    def test_replay_refuses_mismatched_event_and_cas_record(self):
        admitted = admit_proposal(self.learner, self.response())
        config = self.learner.config
        self.ledger.append(make_event("learning-wing-" + digest(config)[:32],
            config["epoch_id"], "learning-wing-run-identity",
            {"record_sha256": admitted["evidence_sha256"],
             "epoch_config_sha256": digest(config), "record_type": "run-identity"},
            source="learning-wing"))
        with self.assertRaisesRegex(ValueError, "binding differ"):
            admit_proposal(self.learner, self.response(text=json.dumps({
                "scaffold_id": "second", "steps": ["inspect-contract"]})))

    def test_feed_requires_completed_epoch_and_projection(self):
        with self.assertRaisesRegex(ValueError, "finish"):
            public_failure_feed(self.learner)
        self.complete()
        feed = public_failure_feed(self.learner)
        self.assertEqual([row["task_id"] for row in feed["records"]], ["train-one"])
        self.assertNotIn("validate-one", canonical(feed).decode())
        self.assertNotIn("files", canonical(feed).decode())
        self.assertTrue(feed["records"][0]["projection_evidence_sha256"])

    def test_proposal_context_refuses_nested_payload_and_repeat_credit(self):
        self.complete()
        feed = public_failure_feed(self.learner)
        malformed = copy.deepcopy(feed)
        malformed["records"][0]["attempt_pointers"][0]["hidden_report"] = "answer"
        with self.assertRaises(ValueError):
            build_proposal_request(malformed)
        repeated = copy.deepcopy(feed)
        repeated["records"] *= 2
        with self.assertRaisesRegex(ValueError, "repeated"):
            build_proposal_request(repeated)

    def test_incumbent_carries_validated_steps_and_tie_retains_baseline(self):
        self.complete(gain=True)
        inherited = incumbent_baseline(self.learner)
        self.assertTrue(inherited["promoted"])
        self.assertEqual(inherited["steps"], ["inspect-contract", "trace-state"])
        inherited["steps"].clear()
        self.assertEqual(len(incumbent_baseline(self.learner)["steps"]), 2)

    def test_trace_is_idempotent_completed_metadata(self):
        admission = self.complete()
        feed = self.ledger.put_evidence(canonical(seed_failure_feed()), source="control", scope_id="fixture")
        identity = self.binding()
        args = dict(failure_feed_sha256=feed, proposal_evidence_sha256=admission["evidence_sha256"],
                    run_identity_sha256=identity)
        trace = seal_epoch_trace(self.learner, **args)
        count = len(self.ledger.events())
        replay = seal_epoch_trace(self.learner, **args)
        self.assertEqual(trace["evidence_sha256"], replay["evidence_sha256"])
        self.assertTrue(replay["duplicate"])
        self.assertEqual(count, len(self.ledger.events()))
        self.assertFalse(trace["body"]["thinking_transcript_included"])
        self.assertFalse(trace["body"]["snapshot"]["promotion"]["body"]["promoted"])

    def test_trace_rejects_unrelated_source_pointers_and_missing_runtime(self):
        admission = self.complete()
        feed = self.ledger.put_evidence(canonical(seed_failure_feed()), source="control", scope_id="fixture")
        invalid = self.ledger.put_evidence(canonical({"not_identity": True}), source="control", scope_id="fixture")
        with self.assertRaisesRegex(ValueError, "run binding"):
            seal_epoch_trace(self.learner, failure_feed_sha256=feed,
                             proposal_evidence_sha256=admission["evidence_sha256"], run_identity_sha256=invalid)
        with self.assertRaises(ValueError):
            seal_run_identity(self.learner, {}, None)

    def test_real_inert_repair_results_feed_without_hidden_grading(self):
        tasks, references = pilot_battery()
        train, validation = tasks[:2], tasks[2:4]
        models = {"lite-control": {"model_sha256": "a" * 64, "runner_sha256": "b" * 64}}
        refs = {task["task_id"]: references[task["task_id"]] for task in train}
        probe = RepairLoop(self.root / "probe", train, models, refs)
        learner = ScaffoldLearner(self.ledger, "actual-public-controls", [t["task_id"] for t in train],
                                  [t["task_id"] for t in validation], public_verifier_identity(probe, "lite-control"))
        context = ScaffoldContextPreparer(learner, task_ids=[t["task_id"] for t in train],
                                          model_ids=["lite-control"], mode="practice", scaffold_id="baseline")
        loop = RepairLoop(self.root / "real-results", train, models, refs,
                          context_preparer=context.prepare, public_context_policy=context.policy)
        def unchanged(request):
            return {"model_id": request["model_id"], "model_sha256": request["model_sha256"],
                    "text": json.dumps({"files": request["task"]["files"]}),
                    "usage": {"input_tokens": 100, "output_tokens": 20}}
        loop.run_lane("lite-control", unchanged)
        for task in train:
            tid = task["task_id"]
            boundary = {"schema": "xnet.scaffold-boundary-observation.v1",
                        "repair_manifest_sha256": loop.manifest["receipt_sha256"], "model_id": "lite-control",
                        "task_id": tid, "attempt_receipts": [r["receipt_sha256"] for r in loop._rows("lite-control", tid)],
                        "violation": False}
            pin = self.ledger.put_evidence(canonical(boundary), source="owned-control-observer", scope_id="fixture")
            ingest_repair_outcome(learner, loop, "lite-control", tid, "baseline", boundary_evidence_sha256=pin)
        learner.freeze_training()
        for task in validation:
            tid = task["task_id"]
            learner.observe(tid, "baseline", {"schema": PUBLIC_SCHEMA, "task_id": tid, "scaffold_id": "baseline",
                "verifier_sha256": learner.config["verifier_sha256"], "passed": False, "no_op": True,
                "boundary_violation": False, "attempts": 1, "output_tokens": 20, "wall_ms": 100})
        learner.promote()
        feed = public_failure_feed(learner)
        self.assertEqual(len(feed["records"]), 2)
        self.assertTrue(all(row["no_op"] for row in feed["records"]))
        self.assertFalse((loop.root / "score.json").exists())


if __name__ == "__main__":
    unittest.main()

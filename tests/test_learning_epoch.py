"""Real inert repair/learner wiring; fake callbacks are plumbing, not scores."""
import copy
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from xnet.learning_dataset import freeze_learning_dataset
from xnet.learning_cycle import PendingStageError
from xnet.learning_epoch import LearningEpoch
from xnet.ledger import Ledger
from xnet.protocol import canonical, digest, make_event, sha256
from xnet.repair_loop import PendingAttempt, pilot_battery
from xnet.scaffold_learning import BASELINE
from xnet.swe_repair_suite import public_task


class LearningEpochControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ledger = Ledger(self.root / "memory")
        tasks, refs = pilot_battery()
        self.tasks = copy.deepcopy(tasks[:6])
        self.refs = {task["task_id"]: refs[task["task_id"]] for task in self.tasks}
        self.splits = {split: [public_task(task) for task in self.tasks[index:index + 2]]
                       for split, index in (("train", 0), ("validation", 2), ("unseen", 4))}
        provenance = {task["task_id"]: {"kind": "synthetic-authored", "source_manifest_sha256": "a" * 64}
                      for task in self.tasks}
        self.dataset = freeze_learning_dataset(self.splits, provenance)
        def artifact(name, content):
            path = self.root / name
            path.write_bytes(content)
            return {"path": str(path.absolute()), "sha256": sha256(content)}
        self.weights = artifact("model.fixture", b"inert model artifact")
        runner = artifact("runner.fixture", b"inert runner artifact")
        adapter = artifact("adapter.fixture", b"inert adapter artifact")
        self.models = {"lite": {"model_sha256": self.weights["sha256"], "runner_sha256": runner["sha256"]}}
        self.identity = {"schema": "xnet.repair-run-identity.v1", "adapter": adapter,
            "runner": {"source_revision": "fixture-only", "artifacts": [runner]},
            "models": {"lite": {"decoding": {"temperature": 0}, "transport": {"kind": "inert-test"},
                "tokenizer": {"id": "fixture-tokenizer", "sha256": None},
                "template": {"id": "fixture-template", "sha256": None}}}, "native": None}
        self.callback_artifacts = [{"path": str(Path(__file__).absolute()),
                                    "sha256": sha256(Path(__file__).read_bytes())}]
        renderer = Path(__file__).resolve().parents[1] / "adapters" / "kimi" / "learning_prompt.py"
        self.callback_artifacts.append({"path": str(renderer), "sha256": sha256(renderer.read_bytes())})
        self.calls = []
        self.rendered = []
        self.fail_baseline = False
        self.fail_transport = False
        self.proposal_requests = []
        self.proposal_transport_failure = False
        self.boundary_missing = False
        self.mutate_weights = False
        self.generation_clock = None
        self.generation_seconds = {BASELINE: 1.0, "candidate": 1.0}

    def tearDown(self):
        self.tmp.cleanup()

    def proposal(self, request):
        self.proposal_requests.append(copy.deepcopy(request))
        if self.proposal_transport_failure:
            raise RuntimeError("fixture proposal transport interruption")
        return {"text": json.dumps({"scaffold_id": "candidate", "steps": ["inspect-contract", "trace-state"]}),
                "usage": {"prompt_tokens": 30, "completion_tokens": 12}}

    def coach(self, request):
        response = self.proposal(request)
        response |= {"coach_model_id": request["model_id"],
                     "coach_identity_sha256": request["coach_identity_sha256"]}
        if getattr(self, "wrong_coach", False):
            response["coach_model_id"] = "worker-relabeled-as-coach"
        if getattr(self, "mutate_coach_transport", False):
            Path(self.coach_artifact["path"]).write_bytes(b"coach transport changed after completed response")
        return response

    def separate_coach_identity(self):
        path = self.root / "coach-transport.fixture"
        if not path.exists():
            path.write_bytes(b"inert remote coach transport artifact")
        self.coach_artifact = {"path": str(path.absolute()), "sha256": sha256(path.read_bytes())}
        return {"schema": "xnet.learning-coach-identity.v1", "provider": "inert-test-provider",
                "model_id": "luna-fixture", "model_revision": None,
                "transport": {"kind": "recording-fixture", "artifacts": [self.coach_artifact]},
                "decoding": {"temperature": 0, "max_output_tokens": 200}}

    def generate(self, request):
        from adapters.kimi.learning_prompt import render_learning_messages
        self.calls.append(copy.deepcopy(request))
        if self.fail_transport:
            raise RuntimeError("fixture generation transport interruption")
        text = request["public_context"]["records"][0]["text"]
        messages = render_learning_messages(request, lambda value: [
            {"role": "system", "content": "Inert fixture code worker"},
            {"role": "user", "content": canonical(value["task"]).decode()}])
        self.rendered.append(messages)
        for record in request["public_context"]["records"]:
            self.assertTrue(any(record["text"] in row["content"] for row in messages))
        if self.mutate_weights:
            Path(self.weights["path"]).write_bytes(b"inert weights changed during round")
        baseline = "Trace state changes" not in text
        if self.generation_clock is not None:
            self.generation_clock[0] += self.generation_seconds[BASELINE if baseline else "candidate"]
        files = request["base_files"] if self.fail_baseline and baseline else self.refs[request["task"]["task_id"]]
        return {"model_id": "lite", "model_sha256": self.weights["sha256"],
                "text": json.dumps({"files": files}), "usage": {"prompt_tokens": 100, "completion_tokens": 20}}

    @contextmanager
    def measured_fixture_generations(self, *, candidate_seconds=1.0):
        # These callbacks are synthetic, so host I/O pauses must not decide
        # whether this inheritance fixture meets the unchanged cost gate.
        # Replace only the two modules' timer references; evaluator deadlines,
        # filesystem locks and the process-wide time module remain real.
        clock = [100.0]
        self.generation_clock = clock
        self.generation_seconds = {BASELINE: 1.0, "candidate": candidate_seconds}
        timer = SimpleNamespace(monotonic=lambda: clock[0])
        try:
            with patch("xnet.learning_epoch.time", timer), patch("xnet.repair_loop.time", timer):
                yield
        finally:
            self.generation_clock = None

    def boundary(self, loop, model_id, task_id):
        # Explicit test monitor; no production boundary claim is manufactured.
        if self.boundary_missing:
            return "f" * 64
        body = {"schema": "xnet.scaffold-boundary-observation.v1",
            "repair_manifest_sha256": loop.manifest["receipt_sha256"], "model_id": model_id,
            "task_id": task_id, "attempt_receipts": [row["receipt_sha256"] for row in loop._rows(model_id, task_id)],
            "violation": False}
        return self.ledger.put_evidence(canonical(body), source="inert-test-host-observer",
                                      scope_id="temporary-test-scope", metadata={"control_only": True})

    def epoch(self, name="epoch-1", previous=None, root_override=None, **changes):
        args = dict(epoch_id=name, scope_id="temporary-test-scope", dataset=self.dataset,
            dataset_sha256=self.dataset["manifest_sha256"], tasks=self.tasks, references=self.refs,
            full_tasks_sha256=digest({task["task_id"]: task for task in self.tasks}),
            references_sha256=digest(self.refs),
            model_id="lite", models=self.models, run_identity=self.identity, model_artifacts=[self.weights],
            callback_artifacts=self.callback_artifacts, generate=self.generate, propose=self.proposal,
            boundary_observer=self.boundary, previous=previous)
        return LearningEpoch(self.ledger, self.root / name if root_override is None else root_override, **(args | changes))

    def test_tie_full_eight_stage_lifecycle_sealed_trace_reopen_and_fresh_preparer(self):
        epoch = self.epoch()
        with patch("xnet.learning_epoch.RepairLoop.grade", side_effect=AssertionError("hidden model grading called")):
            final = epoch.run()
        self.assertEqual(final["status"], "completed")
        self.assertEqual(len(self.calls), 6)  # train x2 lanes, baseline trial; selected tie skips candidate
        self.assertEqual(len(self.rendered), 6)
        for request in self.calls:
            self.assertIn("learning_public_context_policy", request)
        for path in (epoch.root / "practice-baseline").rglob("reservation.json"):
            self.assertNotIn("learning_public_context_policy", json.loads(path.read_bytes()))
        snapshot = epoch.learner.snapshot()
        self.assertFalse(snapshot["promotion"]["body"]["promoted"])
        self.assertEqual(snapshot["training"]["body"]["selected_scaffold"], BASELINE)
        self.assertEqual(snapshot["observation_count"], 6)
        trace_result = json.loads(self.ledger.get_evidence(final["results"][-1]["body"]["result_sha256"]))
        trace = json.loads(self.ledger.get_evidence(trace_result["trace_evidence_sha256"]))
        self.assertFalse(trace["body"]["general_capability_claim"])
        count = len(self.ledger.events())
        self.assertEqual(self.epoch().run(), final)
        self.assertEqual(len(self.ledger.events()), count)
        self.assertEqual(len(self.calls), 6)
        private = json.loads(self.ledger.get_evidence(epoch.private_originals_sha256))
        self.assertEqual(private["references"], self.refs)
        prep = epoch.active_preparer()
        self.assertEqual(set(prep.policy["tasks"]), {row["task_id"] for row in self.dataset["splits"]["unseen"]})
        with self.assertRaises(ValueError):
            epoch.learner.observe(self.tasks[0]["task_id"], BASELINE, {})

    def test_real_public_failures_feed_next_proposal_and_promoted_steps_inherit(self):
        self.fail_baseline = True
        with self.measured_fixture_generations():
            first = self.epoch()
            self.assertEqual(first.run()["status"], "completed")
        promotion = first.learner.snapshot()["promotion"]["body"]
        self.assertTrue(promotion["promoted"], promotion)
        self.assertTrue(promotion["within_cost"])
        self.assertEqual(promotion["solve_delta"], 2)
        self.assertEqual(promotion["summaries"][BASELINE]["wall_ms"], 4000)
        self.assertEqual(promotion["summaries"]["candidate"]["wall_ms"], 2000)
        second = self.epoch("epoch-2", first.learner)
        self.assertEqual(second.learner.config["baseline_steps"], ["inspect-contract", "trace-state"])
        second.step()
        feed = self.proposal_requests[-1]["failure_feed"]
        self.assertEqual(feed["basis"], "sealed-public-baseline-failures")
        self.assertEqual(len(feed["records"]), 2)
        for row in feed["records"]:
            self.assertTrue(row["no_op"])
            self.assertEqual(row["attempts"], 2)
            self.assertNotIn("files", row)
            self.assertNotIn("hidden", row)
            self.ledger.get_evidence(row["projection_evidence_sha256"])

    def test_measured_synthetic_wall_cost_refuses_expensive_candidate_despite_solve_gain(self):
        self.fail_baseline = True
        with self.measured_fixture_generations(candidate_seconds=10.0):
            epoch = self.epoch()
            self.assertEqual(epoch.run()["status"], "completed")
        promotion = epoch.learner.snapshot()["promotion"]["body"]
        self.assertEqual(promotion["solve_delta"], 2)
        self.assertEqual(promotion["summaries"][BASELINE]["wall_ms"], 4000)
        self.assertEqual(promotion["summaries"]["candidate"]["wall_ms"], 20000)
        self.assertFalse(promotion["within_cost"])
        self.assertFalse(promotion["promoted"])
        self.assertEqual(promotion["active_scaffold"], BASELINE)

    def test_stop_and_lost_proposal_require_confirmed_explicit_recovery(self):
        epoch = self.epoch()
        self.assertEqual(epoch.step(control="STOP")["status"], "stopped")
        self.assertEqual(self.proposal_requests, [])
        self.proposal_transport_failure = True
        with self.assertRaises(PendingStageError):
            epoch.step()
        with self.assertRaises(PendingStageError):
            epoch.step()
        self.assertEqual(len(self.proposal_requests), 1)
        original_request = epoch._find("proposal-request")
        self.assertEqual(original_request["request_sha256"], digest(self.proposal_requests[0]))
        self.assertEqual(json.loads(self.ledger.get_evidence(original_request["request_sha256"])),
                         self.proposal_requests[0])
        proof = self.ledger.put_evidence(b"Fixture operator confirmed completed proposal bytes", source="test-recovery",
                                         scope_id="temporary-test-scope")
        with self.assertRaises(PendingStageError):
            epoch.resume_pending(evidence_sha256=proof, justification="Confirmed pending callback status")
        response = {"text": json.dumps({"scaffold_id": "candidate", "steps": ["inspect-contract", "trace-state"]}),
                    "usage": {"input_tokens": 30, "output_tokens": 12}}
        epoch.recover_proposal(response, elapsed_ms=10, evidence_sha256=proof,
                               justification="Confirmed exact original callback bytes")
        self.assertEqual(epoch._find("proposal-raw")["request_sha256"], original_request["request_sha256"])
        recovered = epoch.resume_pending(evidence_sha256=proof, justification="Confirmed exact original callback bytes")
        self.assertEqual(recovered["completed_stages"], 1)
        self.assertEqual(len(self.proposal_requests), 1)

    def test_nested_repair_pending_refuses_redispatch_on_explicit_resume(self):
        epoch = self.epoch()
        epoch.step()
        self.fail_transport = True
        with self.assertRaises(PendingStageError):
            epoch.step()
        self.assertEqual(len(self.calls), 1)
        proof = self.ledger.put_evidence(b"Fixture nested callback still unresolved", source="test-recovery",
                                         scope_id="temporary-test-scope")
        with self.assertRaises(PendingAttempt):
            epoch.resume_pending(evidence_sha256=proof, justification="Inspected pending nested generation")
        self.assertEqual(len(self.calls), 1)
        with self.assertRaises(ValueError):
            self.epoch(root_override=self.root / "different-root")
        original = epoch.root
        epoch.root = self.root / "mutated-root"
        with self.assertRaises(ValueError):
            epoch.resume_pending(evidence_sha256=proof, justification="Must retain original reservation root")
        epoch.root = original
        self.assertEqual(len(self.calls), 1)

    def test_dataset_original_task_reference_model_and_callback_drift_refused(self):
        changed = copy.deepcopy(self.tasks)
        changed[0]["issue"] += " edited"
        with self.assertRaises(ValueError):
            self.epoch(tasks=changed)
        changed = copy.deepcopy(self.refs)
        changed[self.tasks[0]["task_id"]]["api.py"] += "\n"
        with self.assertRaises(ValueError):
            self.epoch(references=changed)
        epoch = self.epoch()
        epoch.references[self.tasks[0]["task_id"]]["api.py"] += "\n"
        with self.assertRaises(ValueError):
            epoch.step()
        self.assertEqual(self.proposal_requests, [])
        epoch.references = copy.deepcopy(self.refs)
        Path(self.weights["path"]).write_bytes(b"changed weights")
        with self.assertRaises(ValueError):
            epoch.step()
        self.assertEqual(self.proposal_requests, [])

    def test_boundary_missing_and_raw_usage_failure_stay_pending_with_raw_evidence(self):
        epoch = self.epoch()
        epoch.step()
        with patch.object(self, "boundary", return_value="f" * 64):
            # Replacing a borrowed callback's identity is refused; it cannot
            # silently claim a different host monitor under frozen config.
            original = epoch.boundary_observer
            epoch.boundary_observer = self.proposal
            with self.assertRaises(ValueError):
                epoch.step()
            epoch.boundary_observer = original
        self.assertEqual(len(self.calls), 0)
        self.boundary_missing = True
        with self.assertRaises(PendingStageError):
            epoch.step()
        self.assertEqual(epoch.status()["status"], "pending")

        self.assertEqual(len(self.calls), 2)
        self.boundary_missing = False
        epoch = self.epoch("usage-epoch")
        epoch.step()
        with patch("xnet.learning_epoch.normalize_generation_usage", side_effect=ValueError("usage gate refused")):
            with self.assertRaises(PendingStageError):
                epoch.step()
        raws = [event for event in self.ledger.events() if event["source"] == "learning-epoch"
                and event["payload"]["kind"].startswith("generation-")]
        # Two prior known answers await host observation; the new usage-gated
        # answer was also saved raw before its normalized output was refused.
        self.assertEqual(len(raws), 3)
        wrapper = json.loads(self.ledger.get_evidence(raws[0]["payload"]["record_sha256"]))
        self.ledger.get_evidence(wrapper["body"]["response_sha256"])
        self.assertEqual(epoch.status()["status"], "pending")

    def test_auxiliary_replay_refuses_wrong_event_and_wrapper_schema(self):
        for index, (event_kind, schema) in enumerate((("wrong-event-kind", "xnet.learning-epoch-aux.v1"),
                                                     ("learning-epoch-record", "wrong-wrapper-schema"))):
            with self.subTest(index=index):
                epoch = self.epoch("aux-epoch-" + str(index))
                wrapper = {"schema": schema, "private_binding_sha256": epoch._private_pin,
                           "kind": "malformed", "body": {"tokens": 1}}
                pointer = self.ledger.put_evidence(canonical(wrapper), source="inert-forged-control",
                                                  scope_id="temporary-test-scope")
                self.ledger.append(make_event(epoch._task, epoch._scope, event_kind,
                    {"kind": "malformed", "record_sha256": pointer}, source="learning-epoch"))
                with self.assertRaises(ValueError):
                    epoch._find("malformed")

    def test_full_model_round_guard_precedes_any_learning_observation(self):
        epoch = self.epoch()
        epoch.step()
        self.mutate_weights = True
        with self.assertRaises(PendingStageError):
            epoch.step()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(epoch.learner.snapshot()["observation_count"], 0)

    def test_distinct_coach_request_response_and_callback_attribution_replay(self):
        coach_identity = self.separate_coach_identity()
        epoch = self.epoch(coach_identity=coach_identity, propose=self.coach)
        final = epoch.run()
        self.assertEqual(final["status"], "completed")
        request = self.proposal_requests[0]
        self.assertEqual(request["model_id"], "luna-fixture")
        self.assertEqual(request["worker_model_id"], "lite")
        self.assertEqual(request["coach_identity"], coach_identity)
        self.assertEqual(request["coach_identity_sha256"], digest(coach_identity))
        self.assertEqual(request["worker_run_identity_sha256"], digest(self.identity))
        self.assertNotIn("model_sha256", request)
        self.assertNotIn("run_identity", request)
        self.assertNotIn("references", request)
        self.assertTrue(all(row["model_id"] == "lite" for row in self.calls))
        attribution = epoch._find("coach-attribution")
        self.assertFalse(attribution["remote_weights_attested"])
        self.assertIn("coach", attribution["proposal_callback_identity"]["qualname"])
        raw = json.loads(self.ledger.get_evidence(attribution["response_sha256"]))
        self.assertEqual(raw["coach_model_id"], "luna-fixture")
        self.assertEqual(raw["usage"]["completion_tokens"], 12)
        reopened = self.epoch(coach_identity=coach_identity, propose=self.coach)
        self.assertEqual(reopened.status()["status"], "completed")
        self.assertEqual(reopened._find("coach-attribution"), attribution)
        self.assertEqual(len(self.proposal_requests), 1)

    def test_wrong_coach_response_stays_raw_and_pending_without_redispatch(self):
        self.wrong_coach = True
        epoch = self.epoch(coach_identity=self.separate_coach_identity(), propose=self.coach)
        with self.assertRaises(PendingStageError):
            epoch.step()
        raw = epoch._find("proposal-raw")
        response = json.loads(self.ledger.get_evidence(raw["response_sha256"]))
        self.assertEqual(response["coach_model_id"], "worker-relabeled-as-coach")
        with self.assertRaises(PendingStageError):
            epoch.step()
        self.assertEqual(len(self.proposal_requests), 1)
        self.assertEqual(epoch.learner.snapshot()["observation_count"], 0)

    def test_coach_transport_and_identity_drift_refuse_admission_preserve_reply(self):
        identity = self.separate_coach_identity()
        epoch = self.epoch(coach_identity=identity, propose=self.coach)
        identity["model_id"] = "caller-mutated-copy"
        self.assertEqual(epoch.coach_identity["model_id"], "luna-fixture")
        self.mutate_coach_transport = True
        with self.assertRaises(PendingStageError):
            epoch.step()
        self.assertIsNotNone(epoch._find("proposal-raw"))
        self.assertEqual(len(self.proposal_requests), 1)
        self.assertEqual(set(epoch.learner.snapshot()["proposals"]), {BASELINE})
        self.mutate_coach_transport = False
        Path(self.coach_artifact["path"]).write_bytes(b"inert remote coach transport artifact")
        epoch.coach_identity["model_id"] = "different-coach"
        with self.assertRaises(ValueError):
            epoch.status()

    def test_separate_coach_contract_refuses_worker_alias_and_incomplete_identity(self):
        identity = self.separate_coach_identity()
        for change in ({"model_id": "lite"}, {"transport": {"kind": "unpinned"}},
                       {"provider": ""}, {"model_revision": True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.epoch(coach_identity=identity | change, propose=self.coach)


if __name__ == "__main__":
    unittest.main()

"""Public synthetic metrics only; no inference, native execution or answers."""
import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from xnet.ledger import Ledger, LedgerError
from xnet.protocol import canonical, sha256
from xnet.scaffold_learning import (ScaffoldLearner, BASELINE, PUBLIC_SCHEMA, _source_pins,
                                   EFFICIENCY_COST_FIELDS, COST_SCHEMA)


class ScaffoldLearningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = Ledger(Path(self.tmp.name))
        self.train, self.validation = ["train-1", "train-2"], ["val-1", "val-2"]
        self.kwargs = {"epoch_id": "repair-v1", "train_task_ids": self.train,
            "validation_task_ids": self.validation, "verifier_sha256": "a" * 64}
        self.learner = ScaffoldLearner(self.ledger, **self.kwargs)

    def tearDown(self):
        self.tmp.cleanup()

    def report(self, task, scaffold, passed=True, **changes):
        return {"schema": PUBLIC_SCHEMA, "task_id": task, "scaffold_id": scaffold,
            "verifier_sha256": "a" * 64, "passed": passed, "no_op": False,
            "boundary_violation": False, "attempts": 1, "output_tokens": 100,
            "wall_ms": 1000, **changes}

    def observe(self, task, scaffold, passed=True, **changes):
        return self.learner.observe(task, scaffold, self.report(task, scaffold, passed, **changes))

    def training_win(self):
        self.learner.propose("edges", ["inspect-contract", "check-edge-cases"])
        for n, task in enumerate(self.train):
            self.observe(task, BASELINE, bool(n))
            self.observe(task, "edges")
        return self.learner.freeze_training()

    def validation_win(self, **changes):
        for n, task in enumerate(self.validation):
            self.observe(task, BASELINE, bool(n))
            self.observe(task, "edges", **changes)
        return self.learner.promote()

    def test_positive_train_validation_durable_reopen_and_stable_trial(self):
        frozen = self.training_win()
        self.assertEqual(frozen["body"]["selected_scaffold"], "edges")
        trial = self.learner.context_record("trial")
        self.observe(self.validation[0], BASELINE, False)
        self.assertEqual(self.learner.context_record("trial"), trial)
        self.observe(self.validation[0], "edges")
        self.observe(self.validation[1], BASELINE)
        self.observe(self.validation[1], "edges")
        promoted = self.learner.promote()
        self.assertTrue(promoted["body"]["promoted"])
        self.assertEqual(promoted["body"]["solve_delta"], 1)
        self.assertEqual(self.learner.freeze_training(), frozen)
        self.assertEqual(self.learner.validate(), promoted)
        reopened = ScaffoldLearner(self.ledger, **self.kwargs)
        self.assertEqual(reopened.context_record("active"), self.learner.context_record("active"))
        self.assertEqual(reopened.context_record("trial"), trial)
        self.assertEqual(trial["text_sha256"], sha256(trial["text"].encode()))
        self.assertIn("empty inputs", trial["text"])
        self.assertFalse(reopened.snapshot()["weights_updated"])
        self.assertTrue(reopened.verify()["intact"])

    def test_noop_and_boundary_violation_never_earn_reward(self):
        self.learner.propose("edges", ["check-edge-cases"])
        for task in self.train:
            self.observe(task, BASELINE, False)
        self.observe(self.train[0], "edges", no_op=True)
        self.observe(self.train[1], "edges", boundary_violation=True)
        result = self.learner.freeze_training()["body"]
        self.assertEqual(result["selected_scaffold"], BASELINE)
        self.assertEqual(result["summaries"]["edges"]["resolved"], 0)

    def test_splits_labels_and_predeclared_bounds(self):
        changes = [dict(validation_task_ids=self.train), dict(train_task_ids=["only-one"]),
                   dict(train_task_ids=["duplicate", "duplicate"]),
                   dict(epoch_id="../escape"), dict(cost_ratio=True), dict(cost_ratio=5),
                   dict(verifier_sha256="not-a-pin")]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                ScaffoldLearner(self.ledger, **(self.kwargs | change))

    def test_proposals_are_fixed_enums_not_prose_paths_commands_or_mutable_objects(self):
        for values in ([], ["run command"], ["../source.py"], ["inspect-contract"] * 2,
                       list(["inspect-contract", "check-edge-cases", "trace-state", "verify-change",
                             "inspect-feedback", "preserve-interfaces", "check-invariants"])):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.learner.propose("bad", values)
        proposal = self.learner.propose("edges", ["check-edge-cases"])
        proposal["steps"].append("trace-state")
        config = self.learner.config
        config["train_task_ids"].append("injected")
        snapshot = self.learner.snapshot()
        snapshot["proposals"]["edges"]["steps"].append("inspect-feedback")
        self.assertEqual(self.learner.snapshot()["proposals"]["edges"]["steps"], ["check-edge-cases"])
        self.assertEqual(self.learner.config["train_task_ids"], self.train)
        with self.assertRaises(ValueError):
            self.learner.propose("edges", ["trace-state"])

    def test_hidden_free_fields_wrong_bindings_and_bool_as_int_refused(self):
        valid = self.report(self.train[0], BASELINE)
        changes = [{"hidden_report": {}}, {"answer": "secret"}, {"notes": "arbitrary prose"},
                   {"schema": "hidden"}, {"task_id": self.train[1]}, {"scaffold_id": "other"},
                   {"verifier_sha256": "b" * 64}, {"attempts": True}, {"passed": 1},
                   {"output_tokens": -1}, {"wall_ms": 86_400_001}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.learner.observe(self.train[0], BASELINE, valid | change)
        with self.assertRaises(ValueError):
            self.learner.observe(self.train[0], BASELINE, {k: v for k, v in valid.items() if k != "passed"})
        self.assertEqual(self.learner.snapshot()["observation_count"], 0)

    def test_exact_replay_conflicting_duplicate_and_late_reports(self):
        original = self.observe(self.train[0], BASELINE, False)
        self.assertEqual(self.observe(self.train[0], BASELINE, False), original)
        with self.assertRaises(ValueError):
            self.observe(self.train[0], BASELINE, True)
        self.training_win()
        with self.assertRaises(ValueError):
            self.learner.propose("late", ["trace-state"])
        with self.assertRaises(ValueError):
            self.observe("unseen", BASELINE)
        self.validation_win()
        self.assertEqual(self.observe(self.train[0], BASELINE, False), original)
        with self.assertRaises(ValueError):
            self.observe("new-late", BASELINE)

    def test_missing_paired_training_and_validation_refused(self):
        self.learner.propose("edges", ["check-edge-cases"])
        for task in self.train:
            self.observe(task, "edges")
        with self.assertRaises(ValueError):
            self.learner.freeze_training()
        for task in self.train:
            self.observe(task, BASELINE, False)
        self.learner.freeze_training()
        self.observe(self.validation[0], "edges")
        with self.assertRaises(ValueError):
            self.learner.promote()
        with self.assertRaises(ValueError):
            self.observe(self.train[0], "edges", False)

    def test_validation_failure_and_excess_cost_retain_baseline(self):
        for excess in (False, True):
            with self.subTest(excess=excess):
                if excess:
                    self.kwargs["epoch_id"] = "cost-epoch"
                    self.learner = ScaffoldLearner(self.ledger, **self.kwargs)
                self.training_win()
                for n, task in enumerate(self.validation):
                    self.observe(task, BASELINE, bool(n))
                    self.observe(task, "edges", excess or bool(n), output_tokens=201 if excess else 100)
                result = self.learner.promote()["body"]
                self.assertFalse(result["promoted"])
                self.assertEqual(result["active_scaffold"], BASELINE)
                text = self.learner.context_record("active")["text"]
                self.assertNotIn("empty inputs", text)
                self.assertEqual(result["within_cost"], not excess)

    def test_no_training_gain_reverts_even_if_candidate_cheaper(self):
        self.learner.propose("cheap", ["trace-state"])
        for task in self.train:
            self.observe(task, BASELINE)
            self.observe(task, "cheap", output_tokens=1, wall_ms=1)
        self.assertEqual(self.learner.freeze_training()["body"]["selected_scaffold"], BASELINE)
        for task in self.validation:
            self.observe(task, BASELINE)
        result = self.learner.promote()["body"]
        self.assertFalse(result["promoted"])
        self.assertEqual(result["solve_delta"], 0)
        with self.assertRaises(ValueError):
            self.observe(self.validation[0], "cheap")

    def test_validation_boundary_violation_refuses_promotion_despite_positive_gain(self):
        self.validation = ["val-1", "val-2", "val-3"]
        self.kwargs.update(epoch_id="boundary-epoch", validation_task_ids=self.validation)
        self.learner = ScaffoldLearner(self.ledger, **self.kwargs)
        self.training_win()
        for n, task in enumerate(self.validation):
            self.observe(task, BASELINE, False)
            self.observe(task, "edges", boundary_violation=n == 0)
        decision = self.learner.promote()["body"]
        self.assertEqual(decision["solve_delta"], 2)
        self.assertTrue(decision["within_cost"])
        self.assertFalse(decision["clean_boundary"])
        self.assertFalse(decision["promoted"])
        self.assertEqual(decision["active_scaffold"], BASELINE)

    def test_selection_ties_are_deterministic_and_all_candidates_matched(self):
        for name in ("zeta", "alpha", "cheap"):
            self.learner.propose(name, ["check-edge-cases"])
        for task in self.train:
            self.observe(task, BASELINE, False)
            for name in ("zeta", "alpha", "cheap"):
                self.observe(task, name, output_tokens=90 if name == "cheap" else 100)
        self.assertEqual(self.learner.freeze_training()["body"]["selected_scaffold"], "cheap")

    def test_context_unavailable_until_relevant_seal(self):
        for mode in ("trial", "active", "invalid"):
            with self.assertRaises(ValueError):
                self.learner.context_record(mode)
        self.training_win()
        with self.assertRaises(ValueError):
            self.learner.context_record("active")
        self.assertNotIn("report", self.learner.context_record("trial"))

    def test_practice_and_trial_attribute_exact_scaffold_with_stable_receipts(self):
        baseline = self.learner.context_record("practice", scaffold_id=BASELINE)
        self.learner.propose("edges", ["check-edge-cases"])
        practice = self.learner.context_record("practice", scaffold_id="edges")
        self.assertEqual(practice["scaffold_id"], "edges")
        self.assertNotEqual(baseline["source_sha256"], practice["source_sha256"])
        self.assertNotEqual(baseline["record_id"], practice["record_id"])
        for n, task in enumerate(self.train):
            self.observe(task, BASELINE, bool(n))
            self.observe(task, "edges")
        self.learner.freeze_training()
        trial_baseline = self.learner.context_record("trial", scaffold_id=BASELINE)
        trial_selected = self.learner.context_record("trial", scaffold_id="edges")
        self.assertEqual(trial_selected["source_sha256"], trial_baseline["source_sha256"])
        self.assertEqual(trial_selected["receipt_sha256"], trial_baseline["receipt_sha256"])
        self.assertNotEqual(trial_selected["text"], trial_baseline["text"])
        self.assertEqual(self.learner.context_record("practice", scaffold_id="edges"), practice)
        with self.assertRaises(ValueError):
            self.learner.context_record("trial", scaffold_id="other")
        self.validation_win()
        with self.assertRaises(ValueError):
            self.learner.context_record("active", scaffold_id=BASELINE)

    def test_cas_corruption_detected_on_reopen_and_reads(self):
        frozen = self.training_win()
        pin = frozen["evidence_sha256"]
        (self.ledger.cas_dir / pin[:2] / pin).write_bytes(b"corrupted bytes")
        with self.assertRaises(LedgerError):
            self.learner.context_record("trial")
        with self.assertRaises(LedgerError):
            _ = self.learner.config
        with self.assertRaises(LedgerError):
            ScaffoldLearner(self.ledger, **self.kwargs)

    def test_parent_evidence_bound_and_verified_but_not_rendered(self):
        parent = self.ledger.put_evidence(b'{"public_only":true,"verifier":"test"}',
                    source="test-public-verifier", scope_id="synthetic")
        result = self.learner.observe(self.train[0], BASELINE, self.report(self.train[0], BASELINE),
                                      evidence_sha256=parent)
        self.assertEqual(result["body"]["parent_evidence_sha256"], parent)
        self.assertEqual(result["body"]["provenance"], "caller-attached-verifier-evidence")
        with self.assertRaises(ValueError):
            self.learner.observe(self.train[0], BASELINE, self.report(self.train[0], BASELINE))
        (self.ledger.cas_dir / parent[:2] / parent).write_bytes(b"altered")
        with self.assertRaises(LedgerError):
            self.learner.verify()

    def test_changed_config_source_requires_new_epoch(self):
        with self.assertRaises(ValueError):
            ScaffoldLearner(self.ledger, **(self.kwargs | {"cost_ratio": 3}))
        pins = _source_pins()
        pins["scaffold_learning.py"] = "c" * 64
        with patch("xnet.scaffold_learning._source_pins", return_value=pins):
            with self.assertRaises(ValueError):
                self.learner.snapshot()
            with self.assertRaises(ValueError):
                ScaffoldLearner(self.ledger, **self.kwargs)
            fresh = ScaffoldLearner(self.ledger, **(self.kwargs | {"epoch_id": "new-source"}))
            self.assertEqual(fresh.config["source_pins"], pins)

    def test_concurrent_freeze_appends_one_decision(self):
        self.learner.propose("edges", ["check-edge-cases"])
        for task in self.train:
            self.observe(task, BASELINE, False)
            self.observe(task, "edges")
        peer = ScaffoldLearner(self.ledger, **self.kwargs)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(learner.freeze_training) for learner in (self.learner, peer)]
            first, second = [future.result() for future in futures]
        self.assertEqual(first, second)
        self.assertEqual(sum(e["kind"] == "scaffold-training" for e in self.ledger.events()), 1)
        self.assertTrue(self.learner.verify()["intact"])

    def efficiency_learner(self, *, objective="total_tokens", **policy_changes):
        policy = {"schema": "xnet.scaffold-promotion-policy.v1",
                  "mode": "solve-gain-or-equal-quality-cheaper", "objective": objective,
                  "minimum_savings_percent": 20, "cost_categories": list(EFFICIENCY_COST_FIELDS),
                  "coach_accounting": "full-cost-per-candidate-evaluation", **policy_changes}
        self.kwargs |= {"epoch_id": "complete-cost-efficiency", "promotion_policy": policy}
        self.learner = ScaffoldLearner(self.ledger, **self.kwargs)
        self.learner.propose("cheap", ["trace-state"])
        return policy

    def cost_observation(self, task, scaffold, *, passed=True, costs_changes=None, **report_changes):
        cheap = scaffold != BASELINE
        report = self.report(task, scaffold, passed,
                             output_tokens=50 if cheap else 100, wall_ms=500 if cheap else 1000)
        report.update(report_changes)
        costs = dict.fromkeys(EFFICIENCY_COST_FIELDS, 0)
        costs |= {"worker_input_tokens": 50 if cheap else 100,
                  "worker_output_tokens": report["output_tokens"], "worker_wall_ms": report["wall_ms"],
                  "worker_calls": report["attempts"], "grader_calls": 1, "grader_wall_ms": 10}
        if cheap:
            costs |= {"coach_input_tokens": 10, "coach_output_tokens": 5, "coach_wall_ms": 5, "coach_calls": 1}
        costs.update(costs_changes or {})
        body = {"schema": COST_SCHEMA, "task_id": task, "scaffold_id": scaffold,
                "verifier_sha256": "a" * 64, "costs": costs,
                "coach_accounting": self.learner.config["promotion_policy"]["coach_accounting"]}
        pointer = self.ledger.put_evidence(canonical(body), source="independent-inert-cost-fixture", scope_id="fixture")
        return report, costs, pointer

    def observe_cost(self, task, scaffold, **changes):
        report, costs, pointer = self.cost_observation(task, scaffold, **changes)
        return self.learner.observe(task, scaffold, report, costs=costs, cost_evidence_sha256=pointer)

    def test_optin_equal_quality_complete_cost_savings_promotes_and_reopens(self):
        policy = self.efficiency_learner()
        policy["minimum_savings_percent"] = 99  # detached policy does not change an epoch
        for task in self.train:
            self.observe_cost(task, BASELINE)
            self.observe_cost(task, "cheap")
        training = self.learner.freeze_training()
        self.assertEqual(training["body"]["selected_scaffold"], "cheap")
        for task in self.validation:
            self.observe_cost(task, BASELINE)
            self.observe_cost(task, "cheap")
        decision = self.learner.promote()["body"]
        self.assertTrue(decision["promoted"])
        self.assertEqual(decision["solve_delta"], 0)
        self.assertEqual(decision["improvement_kind"], "equal-quality-efficiency")
        self.assertEqual(decision["summaries"]["cheap"]["total_tokens"], 230)
        self.assertEqual(decision["summaries"]["cheap"]["complete_costs"]["coach_calls"], 2)
        reopened = ScaffoldLearner(self.ledger, **(self.kwargs | {"promotion_policy": decision["promotion_policy"]}))
        self.assertEqual(reopened.promote()["body"], decision)

    def test_complete_costs_missing_boolean_unrelated_evidence_and_worker_mismatch_refused(self):
        self.efficiency_learner()
        task = self.train[0]
        report, costs, pointer = self.cost_observation(task, BASELINE)
        with self.assertRaises(ValueError):
            self.learner.observe(task, BASELINE, report)
        for invalid in ({key: value for key, value in costs.items() if key != "coach_input_tokens"},
                        costs | {"worker_input_tokens": True}, costs | {"worker_output_tokens": 1},
                        costs | {"worker_calls": 0}, costs | {"unmeasured_cost": 0}):
            with self.subTest(costs=invalid), self.assertRaises(ValueError):
                self.learner.observe(task, BASELINE, report, costs=invalid, cost_evidence_sha256=pointer)
        unrelated = self.ledger.put_evidence(b'{"passed":true}', source="unrelated", scope_id="fixture")
        with self.assertRaises(ValueError):
            self.learner.observe(task, BASELINE, report, costs=costs, cost_evidence_sha256=unrelated)
        mismatch_report = report | {"wall_ms": 1}
        with self.assertRaises(ValueError):
            self.learner.observe(task, BASELINE, mismatch_report, costs=costs, cost_evidence_sha256=pointer)
        self.learner.observe(task, BASELINE, report, costs=costs, cost_evidence_sha256=pointer)
        (self.ledger.cas_dir / pointer[:2] / pointer).write_bytes(b"cost evidence corrupted after admission")
        with self.assertRaises(LedgerError):
            self.learner.snapshot()

    def test_efficiency_preserves_exact_task_quality_and_refuses_failure_only_reward(self):
        cases = ("traded-solves", "all-failed", "new-noop", "new-boundary")
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                self.kwargs["epoch_id"] = "efficiency-refusal-" + str(index)
                policy = {"schema": "xnet.scaffold-promotion-policy.v1", "mode": "solve-gain-or-equal-quality-cheaper",
                          "objective": "total_tokens", "minimum_savings_percent": 20,
                          "cost_categories": list(EFFICIENCY_COST_FIELDS), "coach_accounting": "measured-full-cost"}
                self.learner = ScaffoldLearner(self.ledger, **(self.kwargs | {"promotion_policy": policy}))
                self.learner.propose("cheap", ["trace-state"])
                for n, task in enumerate(self.train):
                    baseline_pass = n == 0 and case != "all-failed"
                    candidate_pass = (n == 1 if case == "traded-solves" else baseline_pass)
                    self.observe_cost(task, BASELINE, passed=baseline_pass)
                    self.observe_cost(task, "cheap", passed=candidate_pass,
                                      no_op=case == "new-noop" and n == 1,
                                      boundary_violation=case == "new-boundary" and n == 1)
                self.assertEqual(self.learner.freeze_training()["body"]["selected_scaffold"], BASELINE)

    def test_including_coach_tool_and_grader_overhead_can_refuse_apparent_savings(self):
        self.efficiency_learner()
        for task in self.train:
            self.observe_cost(task, BASELINE)
            self.observe_cost(task, "cheap")
        self.learner.freeze_training()
        for task in self.validation:
            self.observe_cost(task, BASELINE)
            self.observe_cost(task, "cheap", costs_changes={"coach_input_tokens": 300,
                "tool_wall_ms": 100, "tool_calls": 1, "grader_wall_ms": 1000})
        decision = self.learner.promote()["body"]
        self.assertFalse(decision["promoted"])
        self.assertEqual(decision["improvement_kind"], "retain-baseline")

    def test_declared_cost_policy_changed_or_partial_refused_and_wall_objective_supported(self):
        policy = self.efficiency_learner(objective="total_wall_ms")
        for change in ({"minimum_savings_percent": True}, {"cost_categories": ["worker_output_tokens"]},
                       {"objective": "tokens-without-coach"}, {"coach_accounting": ""}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                ScaffoldLearner(self.ledger, **(self.kwargs | {"promotion_policy": policy | change}))
        with self.assertRaises(ValueError):
            ScaffoldLearner(self.ledger, **(self.kwargs | {"promotion_policy": policy | {"minimum_savings_percent": 30}}))
        for task in self.train:
            self.observe_cost(task, BASELINE)
            self.observe_cost(task, "cheap")
        self.assertEqual(self.learner.freeze_training()["body"]["selected_scaffold"], "cheap")
        for task in self.validation:
            self.observe_cost(task, BASELINE)
            self.observe_cost(task, "cheap")
        self.assertEqual(self.learner.promote()["body"]["improvement_kind"], "equal-quality-efficiency")


if __name__ == "__main__":
    unittest.main()

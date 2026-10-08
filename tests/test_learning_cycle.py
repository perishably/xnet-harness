"""Temp-ledger controls: inert callbacks, no model, native tool or network."""
import copy
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from xnet.ledger import Ledger, LedgerError
from xnet.learning_cycle import (CONFIG_SCHEMA, STAGES, CycleBusyError,
                                 LearningCycle, LearningCycleError,
                                 PendingStageError, _source_pins)
from xnet.protocol import canonical


class LearningCycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = Ledger(Path(self.tmp.name))
        self.identities = {name + "_sha256": letter * 64 for name, letter in
                           (("manifest", "a"), ("model", "b"), ("adapter", "c"), ("source", "d"))}
        self.config = {"schema": CONFIG_SCHEMA, "epoch_id": "epoch-1", "scope_id": "temporary-test-scope",
            "identities": copy.deepcopy(self.identities), "baseline_sha256": "e" * 64,
            "cost_policy": {"max_token_ratio": 2, "max_wall_ratio": 2}}
        self.cycle = self.reopen()

    def tearDown(self):
        self.tmp.cleanup()

    def reopen(self, **changes):
        return LearningCycle(self.ledger, self.config | changes,
                             identity_reader=lambda: copy.deepcopy(self.identities))

    def evidence(self):
        return self.ledger.put_evidence(b"Confirmed external callback outcome", source="test-observation",
                                       scope_id="temporary-test-scope")

    def pending(self):
        def interrupted(request):
            raise RuntimeError("transport was interrupted")
        with self.assertRaises(PendingStageError) as caught:
            self.cycle.step(interrupted)
        return caught.exception.reservation_id

    def test_all_stages_order_completed_replay_reopen_and_no_duplicate_trace(self):
        calls = []
        def callback(request):
            calls.append(copy.deepcopy(request))
            self.assertEqual(self.cycle.ledger.events(self.cycle._task)[-1]["kind"], "learning-cycle-reserve")
            self.assertEqual(len(request["prior_results"]), request["stage_index"])
            return {"stage": request["stage"], "tokens": request["stage_index"] + 1}
        final = self.cycle.run(callback, max_stages=8)
        self.assertEqual([r["stage"] for r in calls], list(STAGES))
        self.assertEqual(final["status"], "completed")
        self.assertEqual(final["completed_stages"], 8)
        self.assertIsNone(final["next_stage"])
        self.assertFalse(final["weights_updated"])
        count = len(self.ledger.events())
        self.assertEqual(self.cycle.step(None), final)
        self.assertEqual(self.reopen().run(None, max_stages=8), final)
        self.assertEqual(len(self.ledger.events()), count)
        self.assertEqual(sum(e["kind"] == "learning-cycle-complete" for e in self.ledger.events()), 1)
        self.assertEqual(sum(r["stage"] == "trace" for r in calls), 1)

    def test_failure_keeps_reservation_and_refuses_automatic_redispatch(self):
        calls = []
        def broken(request):
            calls.append(request)
            raise RuntimeError("private exception details")
        with self.assertRaises(PendingStageError) as caught:
            self.cycle.step(broken)
        status = self.reopen().status()
        self.assertEqual(status["status"], "pending")
        self.assertEqual(status["pending"]["body"]["reservation_id"], caught.exception.reservation_id)
        self.assertEqual(len(status["failures"]), 1)
        self.assertNotIn("private exception details", canonical(status).decode())
        count = len(self.ledger.events())
        with self.assertRaises(PendingStageError):
            self.reopen().run(broken, max_stages=8)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(self.ledger.events()), count)

    def test_explicit_reconcile_is_idempotent_and_conflicting_replay_refused(self):
        nonce = self.pending()
        evidence = self.evidence()
        args = {"evidence_sha256": evidence, "justification": "Confirmed durable reply before reconciliation"}
        result = {"selected_scaffold": "baseline", "cost_tokens": 10}
        view = self.cycle.reconcile(nonce, result, **args)
        self.assertEqual(view["completed_stages"], 1)
        count = len(self.ledger.events())
        self.assertEqual(self.reopen().reconcile(nonce, result, **args), view)
        self.assertEqual(len(self.ledger.events()), count)
        for change in ({"cost_tokens": 11}, {"selected_scaffold": "candidate"}):
            with self.assertRaises(LearningCycleError):
                self.cycle.reconcile(nonce, result | change, **args)
        with self.assertRaises(LearningCycleError):
            self.cycle.reconcile(nonce, result, **(args | {"justification": "A different claim"}))
        self.assertEqual(len(self.ledger.events()), count)

    def test_reconcile_requires_matching_pending_evidence_and_justification(self):
        nonce = self.pending()
        for evidence, justification, reservation in (("f" * 64, "Known reply stored", nonce),
                (self.evidence(), "short", nonce), (self.evidence(), "Known reply stored", "0" * 32)):
            with self.subTest(reservation=reservation), self.assertRaises((LearningCycleError, FileNotFoundError)):
                self.cycle.reconcile(reservation, {}, evidence_sha256=evidence, justification=justification)
        self.assertEqual(self.cycle.status()["status"], "pending")

    def test_stop_at_every_stage_entry_including_pending_and_completed(self):
        controls = iter(["RUN", "STOP"])
        calls = []
        view = self.cycle.run(lambda request: calls.append(request["stage"]) or {},
                              max_stages=8, control=lambda: next(controls))
        self.assertEqual(calls, ["propose"])
        self.assertEqual(view["status"], "stopped")
        count = len(self.ledger.events())
        self.assertEqual(self.cycle.step(None, control="STOP")["status"], "stopped")
        self.assertEqual(len(self.ledger.events()), count)
        nonce = self.pending()
        self.assertEqual(self.cycle.step(None, control="STOP")["status"], "stopped")
        self.cycle.reconcile(nonce, {}, evidence_sha256=self.evidence(), justification="Confirmed no side effect")
        self.cycle.run(lambda request: {}, max_stages=8)
        count = len(self.ledger.events())
        self.assertEqual(self.cycle.step(None, control="STOP")["status"], "stopped")
        self.assertEqual(len(self.ledger.events()), count)

    def test_bounded_run_and_invalid_control_dispatch_nothing(self):
        for bound in (True, 0, 9, 1.0, "2"):
            with self.subTest(bound=bound), self.assertRaises(LearningCycleError):
                self.cycle.run(lambda request: {}, max_stages=bound)
        for control in (True, "stop", "", None):
            with self.subTest(control=control), self.assertRaises(LearningCycleError):
                self.cycle.step(lambda request: {}, control=control)
        self.assertEqual(self.cycle.status()["completed_stages"], 0)
        self.assertEqual(len(self.ledger.events()), 1)
        self.assertEqual(self.cycle.run(lambda request: {}, max_stages=2)["completed_stages"], 2)

    def test_exact_config_schema_and_types_and_changed_epoch_refused(self):
        changes = ({"epoch_id": "../escape"}, {"schema": "other"}, {"unknown": 1},
                   {"cost_policy": {"max_token_ratio": True, "max_wall_ratio": 2}},
                   {"cost_policy": {"max_token_ratio": 2, "max_wall_ratio": 5}},
                   {"identities": {"manifest_sha256": "a" * 64}}, {"baseline_sha256": "invalid"},
                   {"scope_id": "bad\nlabel"})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(LearningCycleError):
                self.reopen(**change)
        with self.assertRaises(LearningCycleError):
            self.reopen(baseline_sha256="f" * 64)
        self.assertEqual(self.cycle.status()["completed_stages"], 0)

    def test_source_and_identity_drift_refused_before_callback(self):
        calls = []
        pins = _source_pins() | {"learning_cycle.py": "f" * 64}
        with patch("xnet.learning_cycle._source_pins", return_value=pins):
            with self.assertRaises(LearningCycleError):
                self.cycle.step(lambda request: calls.append(request) or {})
        self.identities["adapter_sha256"] = "f" * 64
        with self.assertRaises(LearningCycleError):
            self.cycle.step(lambda request: calls.append(request) or {})
        self.assertEqual(calls, [])
        self.assertEqual(len(self.ledger.events()), 1)

    def test_post_callback_identity_drift_preserves_answer_cas_and_pending(self):
        def changed(request):
            self.identities["adapter_sha256"] = "f" * 64
            return {"answer_pointer": "public-proof-1"}
        with self.assertRaises(PendingStageError) as caught:
            self.cycle.step(changed)
        self.assertIsNotNone(caught.exception.result_sha256)
        self.assertEqual(self.ledger.get_evidence(caught.exception.result_sha256),
                         canonical({"answer_pointer": "public-proof-1"}))
        self.identities["adapter_sha256"] = "c" * 64
        self.assertEqual(self.cycle.status()["status"], "pending")
        self.assertEqual(len(self.cycle.status()["failures"]), 1)

    def test_invalid_portable_callback_result_stays_pending(self):
        values = (None, {"seconds": 1.5}, {"large": 2**63}, {"items": (1, 2)},
                  {1: "key"}, {"string": "x" * 16385}, {"separator": "\u2028"})
        for index, value in enumerate(values):
            with self.subTest(index=index):
                cycle = self.reopen(epoch_id="bad-result-" + str(index))
                with self.assertRaises(PendingStageError):
                    cycle.step(lambda request: value)
                self.assertEqual(cycle.status()["status"], "pending")
                self.assertEqual(cycle.status()["completed_stages"], 0)

    def test_recursive_cycle_and_depth_are_bounded_without_execution(self):
        recursive = []
        recursive.append(recursive)
        with self.assertRaises(PendingStageError):
            self.cycle.step(lambda request: {"recursive": recursive})
        cycle = self.reopen(epoch_id="deep-epoch")
        nested = {"data": 0}
        for _ in range(20):
            nested = {"data": nested}
        with self.assertRaises(PendingStageError):
            cycle.step(lambda request: nested)

    def test_secret_result_is_refused_and_not_written(self):
        with self.assertRaises(PendingStageError):
            self.cycle.step(lambda request: {"authorization": "test-secret-value-that-is-not-a-real-token"})
        self.assertEqual(self.cycle.status()["status"], "pending")
        for path in self.ledger.cas_dir.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"test-secret-value-that-is-not-a-real-token", path.read_bytes())

    def test_detached_config_request_and_receipts_cannot_mutate_authority(self):
        config = self.cycle.config
        config["identities"]["adapter_sha256"] = "f" * 64
        self.config["identities"]["model_sha256"] = "f" * 64
        def callback(request):
            request["stage"] = "trace"
            request["prior_results"].append({"stage": "invented"})
            return {"value": [1]}
        view = self.cycle.step(callback)
        view["results"][0]["body"]["stage"] = "trace"
        self.assertEqual(self.cycle.status()["results"][0]["body"]["stage"], "propose")
        self.assertEqual(self.cycle.config["identities"]["adapter_sha256"], "c" * 64)

    def test_concurrent_writer_refused_while_callback_lease_is_held(self):
        second = self.reopen()
        entered, release = threading.Event(), threading.Event()
        def waiting(request):
            entered.set()
            if not release.wait(10):
                raise RuntimeError("test callback wait expired")
            return {"completed": True}
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.cycle.step, waiting)
            try:
                self.assertTrue(entered.wait(5))
                with self.assertRaises(CycleBusyError):
                    second.step(lambda request: self.fail("concurrent callback dispatched"))
            finally:
                release.set()
            self.assertEqual(future.result(timeout=10)["completed_stages"], 1)
        self.assertEqual(second.status()["completed_stages"], 1)

    def test_cas_corruption_detected_before_next_callback(self):
        view = self.cycle.step(lambda request: {"tokens": 1})
        pin = view["results"][0]["body"]["result_sha256"]
        path = self.ledger.cas_dir / pin[:2] / pin
        path.write_bytes(b'{"tokens":2}')
        with self.assertRaises(LedgerError):
            self.cycle.step(lambda request: self.fail("corrupt state dispatched"))

    def test_completion_commit_failure_recovers_without_repeating_trace(self):
        self.cycle.run(lambda request: {}, max_stages=7)
        original = self.cycle._write
        def failed_completion(kind, body):
            if kind == "complete":
                raise OSError("simulated receipt interruption")
            return original(kind, body)
        calls = []
        with patch.object(self.cycle, "_write", side_effect=failed_completion):
            with self.assertRaises(OSError):
                self.cycle.step(lambda request: calls.append(request["stage"]) or {})
        self.assertEqual(calls, ["trace"])
        self.assertEqual(self.reopen().step(None)["status"], "completed")
        self.assertEqual(len(calls), 1)
        self.assertEqual(sum(e["kind"] == "learning-cycle-complete" for e in self.ledger.events()), 1)

    def test_result_committed_before_observed_error_does_not_corrupt_history(self):
        original = self.cycle._write
        def after_commit(kind, body):
            receipt = original(kind, body)
            if kind == "result":
                raise OSError("simulated interruption after durable commit")
            return receipt
        calls = []
        with patch.object(self.cycle, "_write", side_effect=after_commit):
            view = self.cycle.step(lambda request: calls.append(request["stage"]) or {"saved": True})
        self.assertEqual(calls, ["propose"])
        self.assertEqual(view["completed_stages"], 1)
        self.assertEqual(view["failures"], [])
        self.assertEqual(self.reopen().status(), view)
        self.assertTrue(self.ledger.verify_chain()["intact"])


if __name__ == "__main__":
    unittest.main()

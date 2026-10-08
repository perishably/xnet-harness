"""Bounded durable outer coordinator fixtures; no model or remote service."""
from __future__ import annotations

import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import xnet.oroboros_outer as outer_module
from xnet.oroboros_outer import (OroborosOuter, OuterError, OuterPending, STAGES, bootstrap_outer,
                                inspect_outer_status)
from xnet.protocol import canonical, digest


class BorrowedStageFixture:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.wait = None
        self.outer = None
        self.return_control = None
        self.source_patch = None

    def stage(self, request):
        self.calls.append(copy.deepcopy(request))
        if self.fail == request["stage"]:
            raise ConnectionResetError("fixture callback outcome unknown")
        result = {"status": "waiting" if self.wait == request["stage"] else "completed",
                  "task_id": request["task_id"], "stage": request["stage"],
                  "outer_reservation_id": request["reservation_id"],
                  "fixture_only": True, "model_called": False,
                  "input_sha256": digest(request["payload"])}
        if self.return_control == "source-drift":
            changed = dict(outer_module._pins())
            changed["oroboros_outer.py"] = "f" * 64
            self.source_patch = patch("xnet.oroboros_outer._pins", return_value=changed)
            self.source_patch.start()
        elif self.return_control == "contain":
            self.outer.nullclaw.contain_source("oroboros-outer", "fixture containment after response")
        elif self.return_control == "cancel":
            self.outer.nullclaw.cancel(request["task_id"], "fixture cancellation after response")
        return result


class OroborosOuterControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "private-outer"
        self.peer = BorrowedStageFixture()
        self.callbacks = {stage: self.peer.stage for stage in STAGES[:-1]}
        self.payload = {"operator_input": "deterministic local fixture", "context_only": True}

    def tearDown(self):
        if self.peer.source_patch is not None:
            self.peer.source_patch.stop()
        self.tmp.cleanup()

    def start(self, *, disabled=None, budgets=None, bindings=None):
        disabled = {} if disabled is None else disabled
        callbacks = {key: value for key, value in self.callbacks.items() if key not in disabled}
        self.callbacks = callbacks
        self.config = bootstrap_outer(self.root, callbacks, disabled=disabled,
                                      bindings={"fixture_only": True} if bindings is None else bindings,
                                      budgets=budgets)
        outer = OroborosOuter(self.root, callbacks)
        self.peer.outer = outer
        return outer

    def reopen(self):
        outer = OroborosOuter(self.root, self.callbacks)
        self.peer.outer = outer
        return outer

    def waiting_records(self, outer):
        return [outer._get(event["payload"]["record_sha256"])["body"]
                for event in outer.ledger.events() if event["kind"] == "outer.waiting"]

    def test_exact_input_dedup_same_and_different_id_and_detached_payload(self):
        outer = self.start()
        admitted = outer.enqueue("job-1", self.payload)
        pin = outer.status()["head"]
        self.assertFalse(admitted["idempotent_replay"])
        self.assertEqual(outer.enqueue("job-1", copy.deepcopy(self.payload))["head"], pin)
        duplicate = outer.enqueue("different-id", copy.deepcopy(self.payload))
        self.assertEqual(duplicate["task_id"], "job-1")
        self.assertTrue(duplicate["duplicate_input"])
        self.assertEqual(duplicate["head"], pin)
        with self.assertRaisesRegex(OuterError, "different input"):
            outer.enqueue("job-1", {"operator_input": "changed"})
        self.payload["operator_input"] = "mutated after enqueue"
        outer.step()
        self.assertEqual(self.peer.calls[0]["payload"]["operator_input"], "deterministic local fixture")

    def test_one_nine_stage_cycle_requests_previous_hashes_and_restart_replay(self):
        outer = self.start()
        outer.enqueue("job-1", self.payload)
        result = outer.run(max_steps=9)
        self.assertEqual([row["stage"] for row in result["results"]], list(STAGES))
        self.assertEqual(result["state"]["completed_cycles"], 1)
        self.assertEqual(result["state"]["callback_calls"], 8)
        self.assertEqual(len(self.peer.calls), 8)
        for index, request in enumerate(self.peer.calls):
            self.assertEqual(request["stage"], STAGES[index])
            self.assertEqual(set(request["previous"]), set(STAGES[:index]))
            self.assertEqual(set(request["previous_sha256"]), set(STAGES[:index]))
            for stage, evidence in request["previous"].items():
                self.assertEqual(digest(evidence), request["previous_sha256"][stage])
            self.assertEqual(request["budgets"]["remaining_callback_calls"], 256 - index)
        commit = outer._get(result["state"]["jobs"][0]["outputs"]["commit"])
        self.assertFalse(commit["correctness_claim"])
        self.assertFalse(commit["learning_gain_claim"])
        head = result["state"]["head"]
        replay = self.reopen().run(max_steps=9)
        self.assertEqual(replay["results"][0]["status"], "idle")
        self.assertEqual(replay["state"]["head"], head)
        self.assertEqual(len(self.peer.calls), 8)
        self.assertTrue(self.reopen().enqueue("new-label", self.payload)["idempotent_replay"])

    def test_stop_and_nullclaw_cancel_precede_callback_dispatch(self):
        outer = self.start()
        outer.enqueue("job-1", self.payload)
        head = outer.status()["head"]
        self.assertEqual(outer.step(control="STOP")["status"], "stopped")
        self.assertEqual(outer.status()["head"], head)
        self.assertEqual(outer.run(control="STOP")["results"][0]["status"], "stopped")
        outer.nullclaw.cancel("job-1", "fixture explicit cancellation")
        with self.assertRaisesRegex(OuterError, "cancelled"):
            outer.step()
        self.assertEqual(self.peer.calls, [])
        self.assertEqual(outer.status()["callback_calls"], 0)

    def test_stale_expected_head_prevents_admission_and_step(self):
        outer = self.start()
        first = outer.enqueue("job-1", self.payload)["head"]
        outer.enqueue("job-2", {"operator_input": "second unique fixture"})
        with self.assertRaisesRegex(OuterError, "stale"):
            outer.enqueue("job-3", {"operator_input": "third"}, expected_head=first)
        with self.assertRaisesRegex(OuterError, "stale"):
            outer.step(expected_head=first)
        self.assertEqual(len(outer.status()["jobs"]), 2)
        self.assertEqual(self.peer.calls, [])

    def test_unknown_callback_is_not_repeated_after_restart_and_explicit_recovery(self):
        outer = self.start()
        outer.enqueue("job-1", self.payload)
        self.peer.fail = "intake"
        with self.assertRaises(ConnectionResetError):
            outer.step()
        self.peer.fail = None
        reopened = self.reopen()
        with self.assertRaises(OuterPending):
            reopened.step()
        self.assertEqual(len(self.peer.calls), 1)
        reservation = reopened.status()["jobs"][0]["pending_reservation"]
        result = {"status": "completed", "task_id": "job-1", "stage": "intake",
                  "outer_reservation_id": reservation, "nested_outcome_confirmed": True}
        evidence = reopened._put(result)
        recovered = reopened.reconcile("job-1", result, evidence_sha256=evidence,
                                       justification="Confirmed old fixture callback outcome; no redispatch")
        self.assertEqual(recovered["status"], "reconciled")
        self.assertEqual(reopened.status()["jobs"][0]["stage"], "context")
        reopened.run(max_steps=8)
        self.assertEqual(len(self.peer.calls), 8)  # original intake + seven remaining peers
        self.assertEqual(reopened.status()["completed_cycles"], 1)

    def test_reconcile_rejects_unrelated_evidence_wrong_nonce_and_stale_head(self):
        outer = self.start()
        outer.enqueue("job-1", self.payload)
        self.peer.wait = "intake"
        returned = outer.step()
        self.assertEqual(returned["status"], "waiting")
        nonce = returned["reservation_id"]
        result = {"status": "completed", "task_id": "job-1", "stage": "intake", "outer_reservation_id": nonce}
        unrelated = outer._put({"unrelated": "not the confirmed stage output"})
        with self.assertRaises(OuterError):
            outer.reconcile("job-1", result, evidence_sha256=unrelated, justification="Fixture unrelated proof refused")
        wrong = result | {"outer_reservation_id": "f" * 32}
        with self.assertRaises(OuterError):
            outer.reconcile("job-1", wrong, evidence_sha256=outer._put(wrong), justification="Fixture wrong reservation refused")
        stale = outer.status()["head"]
        outer.enqueue("job-2", {"unique": "new input makes head stale"})
        with self.assertRaisesRegex(OuterError, "stale"):
            outer.reconcile("job-1", result, evidence_sha256=outer._put(result),
                justification="Fixture stale head refused", expected_head=stale)
        self.assertEqual(outer.status()["jobs"][0]["stage"], "intake")
        self.assertEqual(len(self.peer.calls), 1)

    def test_disabled_stage_is_explicit_and_commit_does_not_claim_full_activation(self):
        outer = self.start(disabled={"archive": "provider lifecycle is caller-owned and unavailable in fixture"})
        outer.enqueue("job-1", self.payload)
        result = outer.run(max_steps=9)
        archive = result["results"][7]
        self.assertEqual(archive["status"], "disabled")
        self.assertEqual(archive["stage"], "archive")
        self.assertEqual(result["state"]["disabled_stages"], self.config["disabled"])
        self.assertEqual(len(self.peer.calls), 7)
        commit = outer._get(result["state"]["jobs"][0]["outputs"]["commit"])
        self.assertIn("archive", commit["disabled_stages"])

    def test_source_identity_drift_refuses_dispatch(self):
        outer = self.start()
        outer.enqueue("job-1", self.payload)
        changed = dict(outer_module._pins())
        changed["oroboros_outer.py"] = "f" * 64
        with patch("xnet.oroboros_outer._pins", return_value=changed), self.assertRaisesRegex(OuterError, "drift"):
            outer.step()
        self.assertEqual(self.peer.calls, [])
        self.assertEqual(outer.status()["callback_calls"], 0)

    def test_completed_response_preserved_on_source_drift_during_callback(self):
        outer = self.start()
        outer.enqueue("job-1", self.payload)
        self.peer.return_control = "source-drift"
        with self.assertRaisesRegex(OuterError, "drift"):
            outer.step()
        self.peer.source_patch.stop()
        self.peer.source_patch = None
        records = self.waiting_records(outer)
        self.assertEqual(len(records), 1)
        raw = outer._get(records[0]["response_sha256"])
        self.assertEqual(raw["status"], "completed")
        self.assertEqual(raw["outer_reservation_id"], records[0]["reservation_id"])
        with self.assertRaises(OuterPending):
            self.reopen().step()
        self.assertEqual(len(self.peer.calls), 1)

    def test_completed_response_preserved_on_containment_and_cancel_during_callback(self):
        for index, control in enumerate(("contain", "cancel")):
            with self.subTest(control=control):
                self.root = Path(self.tmp.name) / ("return-" + str(index))
                self.peer.return_control = control
                outer = self.start()
                outer.enqueue("job-1", self.payload)
                with self.assertRaises(OuterError):
                    outer.step()
                records = self.waiting_records(outer)
                self.assertEqual(len(records), 1)
                raw = outer._get(records[0]["response_sha256"])
                self.assertEqual(raw["status"], "completed")
                self.assertEqual(raw["task_id"], "job-1")
        self.assertEqual(len(self.peer.calls), 2)

    def test_signed_config_runtime_mutation_refused_before_dispatch(self):
        outer = self.start(budgets={"max_callback_calls": 1})
        outer.enqueue("job-1", self.payload)
        outer.config["budgets"]["max_callback_calls"] = 4096
        with self.assertRaises(OuterError):
            outer.step()
        self.assertEqual(self.peer.calls, [])

    def test_global_callback_budget_queue_bound_and_wall_run_budget(self):
        outer = self.start(budgets={"max_queue": 1, "max_callback_calls": 1, "max_run_ms": 100})
        outer.enqueue("job-1", self.payload)
        with self.assertRaisesRegex(OuterError, "queue full"):
            outer.enqueue("job-2", {"unique": "queue overflow"})
        result = outer.run(max_steps=9)
        self.assertEqual(result["results"][-1]["status"], "budget_exhausted")
        self.assertEqual(len(self.peer.calls), 1)
        self.assertEqual(self.reopen().step()["status"], "budget_exhausted")
        self.assertEqual(len(self.peer.calls), 1)
        with patch("xnet.oroboros_outer.time.monotonic", side_effect=[0, 0.2]):
            wall = outer.run(max_steps=9)
        self.assertEqual(wall["results"][0]["status"], "budget_exhausted")
        self.assertEqual(wall["results"][0]["reason"], "run wall budget")

    def test_out_of_order_or_unreserved_completion_cannot_replay_as_valid_state(self):
        outer = self.start()
        outer.enqueue("job-1", self.payload)
        result = {"status": "completed", "task_id": "job-1", "stage": "context"}
        outer._write("completed", "job-1", {"stage": "context", "result_sha256": outer._put(result)})
        with self.assertRaisesRegex(OuterError, "out-of-order"):
            outer.status()
        self.assertEqual(self.peer.calls, [])

    def test_forged_reserved_request_must_match_derived_scope_input_parents_and_budget(self):
        changes = [{"schema": "wrong-schema"}, {"scope_id": "another-scope"},
                   {"payload": {"operator_input": "substituted operator input"}},
                   {"previous_sha256": {"imaginary-stage": "f" * 64}},
                   {"previous": {"imaginary-stage": {"status": "completed"}}},
                   {"budgets": {"remaining_callback_calls": 4096}}]
        for index, change in enumerate(changes):
            with self.subTest(change=change):
                self.root = Path(self.tmp.name) / ("forged-request-" + str(index))
                outer = self.start()
                outer.enqueue("job-1", self.payload)
                nonce = "e" * 32
                request = {"schema": "xnet.oroboros-outer-request.v1", "task_id": "job-1", "stage": "intake",
                           "scope_id": outer.scope_id, "stage_scope_id": outer.scope_id, "reservation_id": nonce,
                           "payload": self.payload, "previous_sha256": {}, "previous": {},
                           "budgets": {"remaining_callback_calls": 256}} | change
                outer._write("reserved", "job-1", {"stage": "intake", "reservation_id": nonce,
                    "request_sha256": outer._put(request)})
                with self.assertRaises(OuterError):
                    outer.status()
        self.assertEqual(self.peer.calls, [])

    def test_waiting_response_cas_corruption_is_detected_during_restart_replay(self):
        outer = self.start()
        outer.enqueue("job-1", self.payload)
        self.peer.wait = "intake"
        waiting = outer.step()
        evidence = waiting["response_sha256"]
        path = outer.ledger.cas_dir / evidence[:2] / evidence
        self.assertEqual(digest(json.loads(path.read_bytes())), evidence)
        path.write_bytes(canonical({"status": "completed", "substituted": True}))
        with self.assertRaisesRegex(ValueError, "evidence hash mismatch"):
            self.reopen()
        self.assertEqual(len(self.peer.calls), 1)

    def test_reconciled_replay_rejects_wrong_reservation_or_unrelated_proof(self):
        for index, fault in enumerate(("nonce", "evidence")):
            with self.subTest(fault=fault):
                self.root = Path(self.tmp.name) / ("forged-reconciliation-" + str(index))
                outer = self.start()
                outer.enqueue("job-1", self.payload)
                self.peer.wait = "intake"
                waiting = outer.step()
                nonce = waiting["reservation_id"]
                result = {"status": "completed", "task_id": "job-1", "stage": "intake",
                          "outer_reservation_id": nonce}
                result_pin = outer._put(result)
                unrelated = outer._put({"unrelated": "known object is not the result"})
                proof = {"evidence_sha256": unrelated if fault == "evidence" else result_pin,
                         "justification": "Forged fixture proof must fail replay validation",
                         "reservation_id": "f" * 32 if fault == "nonce" else nonce,
                         "nested_recovery_required": True}
                outer._write("reconciled", "job-1", {"stage": "intake", "reservation_id": nonce,
                    "result_sha256": result_pin, "reconciliation_sha256": outer._put(proof)})
                with self.assertRaises(OuterError):
                    outer.status()
        self.assertEqual(len(self.peer.calls), 2)

    def test_disabled_reason_and_commit_parent_receipts_are_exact_on_replay(self):
        outer = self.start(disabled={"archive": "explicit fixture archive disabled"})
        outer.enqueue("job-1", self.payload)
        outer.run(max_steps=7)
        forged = {"status": "disabled", "task_id": "job-1", "stage": "archive", "reason": "invented reason"}
        outer._write("disabled", "job-1", {"stage": "archive", "result_sha256": outer._put(forged)})
        with self.assertRaises(OuterError):
            outer.status()
        self.root = Path(self.tmp.name) / "forged-commit"
        self.callbacks = {stage: self.peer.stage for stage in STAGES[:-1]}
        outer = self.start()
        outer.enqueue("job-1", self.payload)
        outer.run(max_steps=8)
        forged = {"status": "completed", "stage": "commit", "task_id": "job-1", "stage_receipts": {},
                  "disabled_stages": [], "correctness_claim": False, "learning_gain_claim": False}
        outer._write("completed", "job-1", {"stage": "commit", "result_sha256": outer._put(forged)})
        with self.assertRaises(OuterError):
            outer.status()

    def test_public_recovery_evidence_retains_private_exact_result_without_dispatch_or_advance(self):
        outer = self.start()
        outer.enqueue("job-1", self.payload)
        self.peer.wait = "intake"
        waiting = outer.step()
        result = {"status": "completed", "task_id": "job-1", "stage": "intake",
                  "outer_reservation_id": waiting["reservation_id"], "nested_confirmed": True}
        before = outer.status()
        evidence = outer.retain_reconciliation_evidence(result)
        self.assertEqual(evidence, digest(result))
        self.assertEqual(outer.ledger.get_evidence(evidence), canonical(result))
        self.assertEqual(outer.status(), before)
        self.assertEqual(len(self.peer.calls), 1)
        with outer.ledger._conn() as db:
            row = db.execute("SELECT metadata_json FROM evidence WHERE hash=?", (evidence,)).fetchone()
        metadata = json.loads(row[0])
        self.assertEqual(metadata["visibility"], "private")
        self.assertFalse(metadata["cloud_export"])
        self.assertEqual(outer.retain_reconciliation_evidence(result), evidence)
        outer.reconcile("job-1", result, evidence_sha256=evidence,
                        justification="Confirmed old nested receipt from retained private evidence")
        self.assertEqual(outer.status()["jobs"][0]["stage"], "context")
        self.assertEqual(len(self.peer.calls), 1)

    def test_public_recovery_evidence_requires_known_pending_nonce_and_passes_nullclaw_gate(self):
        outer = self.start()
        outer.enqueue("job-1", self.payload)
        unknown = {"status": "completed", "task_id": "job-1", "stage": "intake", "outer_reservation_id": "f" * 32}
        with self.assertRaises(OuterError):
            outer.retain_reconciliation_evidence(unknown)
        self.peer.wait = "intake"
        waiting = outer.step()
        valid = unknown | {"outer_reservation_id": waiting["reservation_id"]}
        for changed in (valid | {"status": "waiting"}, unknown,
                        valid | {"task_id": "different-job"}, valid | {"stage": "context"}):
            with self.subTest(result=changed), self.assertRaises(OuterError):
                outer.retain_reconciliation_evidence(changed)
        outer.nullclaw.cancel("job-1", "fixture cancellation forbids retained recovery authority")
        with self.assertRaisesRegex(OuterError, "cancelled"):
            outer.retain_reconciliation_evidence(valid)
        self.assertEqual(len(self.peer.calls), 1)

    def test_read_only_inspector_matches_state_without_callbacks_initializers_or_authority_writes(self):
        outer = self.start()
        outer.enqueue("job-1", self.payload)
        outer.step()
        before = outer.status()
        saved = {str(path.relative_to(self.root)): path.read_bytes()
                 for path in self.root.rglob("*") if path.is_file()}
        with patch("xnet.oroboros_outer._callbacks", side_effect=AssertionError("cold callback resolution")), \
             patch("xnet.ledger.Ledger._initialize", side_effect=AssertionError("cold ledger initialization")), \
             patch("xnet.scope.ScopeAuthority.init", side_effect=AssertionError("cold authority initialization")):
            observed = inspect_outer_status(self.root)
        self.assertTrue(observed.pop("inspection_only"))
        self.assertEqual(observed.pop("callbacks_invoked"), 0)
        self.assertEqual(observed, before)
        for name, raw in saved.items():
            self.assertEqual((self.root / name).read_bytes(), raw)
        self.assertEqual(len(self.peer.calls), 1)

    def test_api_inspector_does_not_append_and_refuses_missing_or_tampered_roots(self):
        outer = self.start()
        outer.enqueue("job-1", self.payload)
        with patch("xnet.ledger.Ledger.append", side_effect=AssertionError("inspection mutated the ledger")):
            observed = inspect_outer_status(self.root)
        self.assertTrue(observed["inspection_only"])
        self.assertEqual(observed["callbacks_invoked"], 0)
        self.assertEqual(observed["head"], outer.status()["head"])
        missing = Path(self.tmp.name) / "never-created"
        with self.assertRaises((OSError, OuterError)):
            inspect_outer_status(missing)
        self.assertFalse(missing.exists())
        config_path = self.root / "config.json"
        changed = json.loads(config_path.read_bytes())
        changed["budgets"]["max_callback_calls"] = 4096
        config_path.write_bytes(canonical(changed))
        with self.assertRaisesRegex(OuterError, "signature"):
            inspect_outer_status(self.root)
        self.assertEqual(self.peer.calls, [])

    def test_signed_stage_scope_mapping_passes_borrowed_scope_and_forgery_is_refused(self):
        outer = self.start(bindings={"stage_scopes": {"context": "existing-context-scope"}})
        outer.enqueue("job-1", self.payload)
        outer.step()
        self.assertEqual(self.peer.calls[0]["stage_scope_id"], outer.scope_id)
        outer.step()
        request = self.peer.calls[1]
        self.assertEqual(request["scope_id"], outer.scope_id)
        self.assertEqual(request["stage_scope_id"], "existing-context-scope")
        self.root = Path(self.tmp.name) / "forged-stage-scope"
        outer = self.start(bindings={"stage_scopes": {"intake": "retained-input-scope"}})
        outer.enqueue("job-1", self.payload)
        nonce = "e" * 32
        forged = {"schema": "xnet.oroboros-outer-request.v1", "task_id": "job-1", "stage": "intake",
                  "scope_id": outer.scope_id, "stage_scope_id": "different-source-scope", "reservation_id": nonce,
                  "payload": self.payload, "previous_sha256": {}, "previous": {},
                  "budgets": {"remaining_callback_calls": 256}}
        outer._write("reserved", "job-1", {"stage": "intake", "reservation_id": nonce,
                                           "request_sha256": outer._put(forged)})
        with self.assertRaisesRegex(OuterError, "reserved request"):
            inspect_outer_status(self.root)
        for index, mapping in enumerate(({"commit": "not-a-callback-scope"}, {"unknown": "unbounded-stage"},
                                         {"context": "invalid scope label"})):
            with self.subTest(mapping=mapping), self.assertRaises(OuterError):
                bootstrap_outer(Path(self.tmp.name) / ("invalid-scope-" + str(index)), self.callbacks,
                                bindings={"stage_scopes": mapping})


if __name__ == "__main__":
    unittest.main()

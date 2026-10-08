"""Bounded memory controls; fake typed transport, no model/provider calls."""
import copy
import math
from pathlib import Path
import tempfile
import unittest

from xnet.ledger import Ledger
from xnet.protocol import canonical, digest
from xnet.procedural_memory import (ProceduralMemory, ProceduralContextPreparer,
                                    VALIDATION_SCHEMA, public_context_packet)
from xnet.scope import ScopeAuthority, ScopeError


class ProceduralMemoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ledger = Ledger(self.root / "memory")
        self.authority = ScopeAuthority(self.root / "authority")
        self.scope = self.authority.create(program="owned-memory-control", policy_url="fixture:",
                         policy_capture=b"public owned fixture only", fixture=True,
                         allowed_assets=["path:" + str(self.root / "memory")],
                         methods=["memory_read", "memory_write"])
        self.kwargs = dict(scope_authority=self.authority, scope_id=self.scope["scope_id"])
        self.memory = ProceduralMemory(self.ledger, "epoch-one", "project-one", "a" * 64, **self.kwargs)
        self.source = self.ledger.put_evidence(canonical({"public_note": "check supplied interfaces"}),
                             source="owned-public-input", scope_id=self.scope["scope_id"])

    def tearDown(self):
        self.tmp.cleanup()

    def stage(self, identifier="card-one", **kw):
        defaults = dict(title="Check interfaces", tags=["repair"],
                        steps=["inspect-contract", "preserve-interfaces"],
                        source_sha256=self.source, origin_task_id="practice-one")
        return self.memory.stage_procedure(identifier, **(defaults | kw))

    def validation(self, row, **kw):
        body = {"schema": VALIDATION_SCHEMA, "project_id": "project-one",
                "memory_id": row["memory_id"], "stage_sha256": row["stage_sha256"],
                "source_sha256": self.source, "verifier_sha256": "a" * 64,
                "validation_task_id": "validation-one", "passed": True,
                "boundary_violation": False, "hidden_cases_used": False,
                "answer_payload_used": False, "independent_public_validation": True}
        body.update(kw)
        return self.ledger.put_evidence(canonical(body), source="independent-fixture-validator",
                                        scope_id=self.scope["scope_id"])

    def active(self, identifier="card-one", **kw):
        row = self.stage(identifier, **kw)
        self.memory.activate(row["memory_id"], self.validation(row))
        return row

    def test_staged_is_invisible_until_validation(self):
        row = self.stage()
        self.assertEqual(self.memory.catalog(), [])
        with self.assertRaises(ValueError):
            self.memory.load(row["memory_id"])
        self.memory.activate(row["memory_id"], self.validation(row))
        self.assertEqual(len(self.memory.catalog()), 1)

    def test_noop_selfreport_int_bool_hidden_and_wrong_verifier_refused(self):
        row = self.stage()
        for patch in ({"passed": 1}, {"passed": False}, {"hidden_cases_used": True},
                      {"answer_payload_used": True}, {"boundary_violation": True},
                      {"verifier_sha256": "b" * 64}, {"validation_task_id": "practice-one"},
                      {"independent_public_validation": False}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                self.memory.activate(row["memory_id"], self.validation(row, **patch))

    def test_exact_dedup_does_not_multiply_cards_or_claim_learning(self):
        row = self.active()
        repeated = self.stage("repeat-id")
        self.assertTrue(repeated["duplicate"])
        self.assertEqual(repeated["memory_id"], row["memory_id"])
        self.assertEqual(len(self.memory.catalog()), 1)

    def test_conflicting_id_requires_new_version(self):
        self.stage()
        with self.assertRaises(ValueError):
            self.stage(title="Changed title")

    def test_new_validated_version_supersedes_old_not_before(self):
        self.active()
        row = self.stage("card-two", title="Verify changed behavior", steps=["verify-change"], supersedes="card-one")
        self.assertEqual([item["memory_id"] for item in self.memory.catalog()], ["card-one"])
        self.memory.activate(row["memory_id"], self.validation(row))
        self.assertEqual([item["memory_id"] for item in self.memory.catalog()], ["card-two"])

    def test_only_fixed_procedure_enums_and_public_notes(self):
        for steps in (["run-arbitrary-command"], ["inspect-contract", "inspect-contract"], [[]]):
            with self.assertRaises(ValueError):
                self.stage(steps=steps)
        with self.assertRaises(ValueError):
            self.stage(classification="private")
        with self.assertRaises(ValueError):
            self.memory.stage_note("bad", kind="fact", title="bad", tags=["repair"],
                    text="hidden_cases are here", source_sha256=self.source, origin_task_id="practice-one")

    def test_catalog_discloses_metadata_without_full_card(self):
        self.active()
        row = self.memory.catalog()[0]
        self.assertNotIn("text", row)
        self.assertIn("text", self.memory.load(row["memory_id"]))

    def test_exact_typed_probabilities_no_padding_or_fallback(self):
        self.active()
        self.active("card-two", title="Trace state", steps=["trace-state"])
        def good(request):
            return {"answers": {key: {"type": "noul", "noul": 0.9 if key == "candidate_1" else 0.2}
                                for key in request["candidates"]}}
        self.assertEqual(self.memory.select("state repair", good), ["card-two"])
        self.assertEqual(self.memory.select("none", lambda request: {"answers": {
            key: {"type": "noul", "noul": 0.0} for key in request["candidates"]}}), [])
        for answer in (True, float("nan"), float("inf"), -0.1, 1.1):
            with self.assertRaises(ValueError):
                self.memory.select("query", lambda request: {"answers": {
                    key: {"type": "noul", "noul": answer} for key in request["candidates"]}})
        with self.assertRaises(ValueError):
            self.memory.select("query", lambda request: {"answers": {}})
        with self.assertRaises(RuntimeError):
            self.memory.select("query", lambda request: (_ for _ in ()).throw(RuntimeError("failed")))

    def test_pending_waits_for_next_turn_then_dedup(self):
        self.active()
        self.memory.queue("session", "task", ["card-one"], turn_id="turn-one", now=100)
        self.assertEqual(self.memory.consume("session", "task", project_id="project-one", fresh_turn_id="turn-one", now=101), [])
        self.assertEqual(len(self.memory.consume("session", "task", project_id="project-one", fresh_turn_id="turn-two", now=102)), 1)
        self.memory.queue("session", "task", ["card-one"], turn_id="turn-two", now=103)
        self.assertEqual(self.memory.consume("session", "task", project_id="project-one", fresh_turn_id="turn-three", now=104), [])

    def test_pending_exact_ttl_and_project_task_binding(self):
        self.active()
        for task, project, now in (("task", "project-one", 220), ("other", "project-one", 101),
                                    ("task", "other-project", 101)):
            self.memory.queue("session", "task", ["card-one"], turn_id="turn-one", now=100)
            self.assertEqual(self.memory.consume("session", task, project_id=project, fresh_turn_id="turn-two", now=now), [])

    def test_retired_pending_card_cannot_inject(self):
        self.active()
        self.memory.queue("session", "task", ["card-one"], turn_id="turn-one", now=100)
        self.memory.retire("card-one")
        self.assertEqual(self.memory.consume("session", "task", project_id="project-one", fresh_turn_id="turn-two", now=101), [])

    def test_source_cas_tampering_detected(self):
        self.active()
        path = self.ledger.cas_dir / self.source[:2] / self.source
        path.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.memory.load("card-one")

    def test_restart_replay_preserves_active_and_pending(self):
        self.active()
        self.memory.queue("session", "task", ["card-one"], turn_id="turn-one", now=100)
        restored = ProceduralMemory(self.ledger, "epoch-one", "project-one", "a" * 64, **self.kwargs)
        self.assertEqual(len(restored.consume("session", "task", project_id="project-one", fresh_turn_id="turn-two", now=101)), 1)
        self.assertTrue(restored.verify()["intact"])

    def test_queue_preserves_ranked_order(self):
        self.active()
        self.active("card-two", title="Trace state", steps=["trace-state"])
        self.memory.queue("session", "task", ["card-two", "card-one"], turn_id="turn-one", now=100)
        records = self.memory.consume("session", "task", project_id="project-one", fresh_turn_id="turn-two", now=101)
        self.assertEqual([row["text"] for row in records], [self.memory.load("card-two")["text"], self.memory.load("card-one")["text"]])

    def test_public_bridge_packet_preserves_exact_text(self):
        self.active()
        request = {"task": {"task_id": "task", "issue": "public"}, "public_feedback": None,
                   "hidden_cases_used": False}
        record = self.memory.load("card-one")
        packet = public_context_packet(request, [record])
        self.assertFalse(packet["work_performed"])
        self.assertEqual(packet["records"], [record])
        with self.assertRaises(ValueError):
            public_context_packet(request, [record, record])
        with self.assertRaises(ValueError):
            public_context_packet(request | {"hidden_cases": []}, [record])

    def test_signed_scope_refuses_unallowed_memory_root(self):
        alternate = Ledger(self.root / "other")
        with self.assertRaises(ScopeError):
            ProceduralMemory(alternate, "epoch", "project-one", "a" * 64, **self.kwargs)

    def test_superseded_card_cannot_reactivate(self):
        first = self.active()
        proof = self.validation(first)
        second = self.stage("card-two", title="Trace state", steps=["trace-state"], supersedes="card-one")
        self.memory.activate(second["memory_id"], self.validation(second))
        with self.assertRaises(ValueError):
            self.memory.activate(first["memory_id"], proof)

    def test_frozen_preparer_matches_repair_policy(self):
        self.active()
        preparer = ProceduralContextPreparer(self.memory, task_ids=["task"], model_ids=["lite"],
                                             selected_by_task={"task": ["card-one"]})
        request = {"task": {"task_id": "task", "issue": "public"}, "public_feedback": None,
                   "hidden_cases_used": False, "model_id": "lite"}
        from xnet.repair_loop import _admit_public_context, _public_context_policy
        policy = _public_context_policy(preparer.policy, {"task": None}, {"lite": None})
        admitted = _admit_public_context(preparer.prepare(request), request, policy)
        self.assertEqual(admitted["records"], [self.memory.load("card-one")])
        self.memory.retire("card-one")
        with self.assertRaises(ValueError):
            preparer.prepare(request)

    def test_correction_supersedes_fact_after_validation(self):
        common = dict(tags=["public"], source_sha256=self.source, origin_task_id="practice-one")
        fact = self.memory.stage_note("fact-one", kind="fact", title="Public marker", text="Marker BLUE", **common)
        self.memory.activate(fact["memory_id"], self.validation(fact))
        correction = self.memory.stage_note("fact-two", kind="correction", title="Corrected marker", text="Marker GREEN",
                                             supersedes="fact-one", **common)
        self.memory.activate(correction["memory_id"], self.validation(correction))
        self.assertEqual([row["memory_id"] for row in self.memory.catalog()], ["fact-two"])

    def test_jcode_peer_only_consumes_public_fresh_turn(self):
        from adapters.jcode.procedural_memory_peer import JcodeProceduralMemoryPeer
        self.active()
        peer = JcodeProceduralMemoryPeer(self.memory)
        peer.publish_background_selection("session", "task", ["card-one"], user_turn_id="old", now=100)
        request = {"task": {"task_id": "task"}, "public_feedback": None, "hidden_cases_used": False}
        with self.assertRaises(ValueError):
            peer.consume_fresh_user_turn("session", request | {"hidden_cases": []}, project_id="project-one", user_turn_id="new", now=101)
        packet = peer.consume_fresh_user_turn("session", request, project_id="project-one", user_turn_id="new", now=101)
        self.assertEqual(len(packet["records"]), 1)
        self.assertEqual(packet["authority"], "none")

    def test_hermes_peer_progressive_only_active_procedures(self):
        from adapters.hermes.procedural_memory_peer import HermesProceduralMemoryPeer
        self.active()
        peer = HermesProceduralMemoryPeer(self.memory)
        row = peer.procedure_catalog()[0]
        self.assertNotIn("text", row)
        self.assertIn("text", peer.procedure_view(row["memory_id"]))
        self.memory.retire(row["memory_id"])
        with self.assertRaises(ValueError):
            peer.procedure_view(row["memory_id"])


if __name__ == "__main__":
    unittest.main()

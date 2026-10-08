"""Signed inert fast-epoch controls; trusted bounded AST workers only, no models."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

from adapters.kimi.learning_prompt import render_learning_messages
from xnet import learning_epoch_fast_v4 as fast
from xnet.artifact_integrity_guard_v3 import ArtifactIntegrityError, PATH_METHODS
from xnet.learning_cycle import PendingStageError
from xnet.learning_dataset import freeze_learning_dataset
from xnet.ledger import Ledger
from xnet.protocol import canonical, digest, sha256
from xnet.repair_loop import PendingAttempt, pilot_battery
from xnet.scaffold_learning import BASELINE
from xnet.scope import ScopeAuthority
from xnet.swe_repair_suite import public_task


@unittest.skipUnless(os.name == "nt", "Fast epoch requires actual Windows retained read leases")
class FastEpochControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="xnet-fast-epoch-inert-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).absolute()
        self.repo = Path(__file__).absolute().parents[1]
        self.authority = ScopeAuthority(self.root / "authority")
        renderer = self.repo / "adapters/kimi/learning_prompt.py"
        self.scope = self.authority.create(program="Fast learning epoch local inert controls",
            policy_url="fixture://fast-epoch", policy_capture=b"Fixed local inert fixtures and source reads only",
            allowed_assets=["path:" + str(self.root), "path:" + str(self.repo / "xnet"),
                            "path:" + str(Path(__file__).absolute()), "path:" + str(renderer)],
            excluded_assets=["path:" + str(self.root / "unselected")],
            methods=[*PATH_METHODS, "fixture_write", "fixture_evaluate"], fixture=True, requests_per_minute=600, max_parallel=1)
        self.gate_calls = []
        self.artifact_gate("fixture_write", "path:" + str(self.root / "memory"))
        self.ledger = Ledger(self.root / "memory")
        tasks, references = pilot_battery()
        self.tasks = copy.deepcopy(tasks[:6])
        self.references = {row["task_id"]: references[row["task_id"]] for row in self.tasks}
        splits = {name: [public_task(row) for row in self.tasks[index:index + 2]]
                  for name, index in (("train", 0), ("validation", 2), ("unseen", 4))}
        provenance = {row["task_id"]: {"kind": "synthetic-authored", "source_manifest_sha256": "a" * 64}
                      for row in self.tasks}
        self.dataset = freeze_learning_dataset(splits, provenance)
        self.weights = self.artifact("weights.fixture", b"fixed inert model" * 256)
        self.runner = self.artifact("runner.exe", b"fixed inert runner; never executed" * 256)
        self.adapter = self.artifact("adapter.fixture", b"fixed inert source adapter" * 64)
        self.models = {"lite": {"model_sha256": self.weights["sha256"], "runner_sha256": self.runner["sha256"]}}
        self.identity = {"schema": "xnet.repair-run-identity.v1", "adapter": self.adapter,
            "runner": {"source_revision": "inert-test-only", "artifacts": [self.runner]},
            "models": {"lite": {"decoding": {"temperature": 0}, "transport": {"kind": "inert"},
                "tokenizer": {"id": "fixture", "sha256": None}, "template": {"id": "fixture", "sha256": None}}},
            "native": None}
        self.callbacks = [{"path": str(path), "sha256": sha256(path.read_bytes())}
                          for path in (Path(__file__).absolute(), renderer)]
        self.calls = []; self.proposals = []; self.boundaries = []; self.rendered = []
        self.active_epoch = None
        self.fail_proposal = False; self.fail_generation = False; self.mutate_source = False
        self.try_weight_write = False; self.wrong_usage = False
        evaluator = self.repo / "xnet/swe_repair_evaluator.py"
        worker_command = [sys.executable, "-I", "-S", "-B", str(evaluator.resolve()), "--worker"]
        original_run, original_popen = subprocess.run, subprocess.Popen
        def allow_only_worker(function):
            def execute(command, *args, **kwargs):
                if command != worker_command or kwargs.get("shell"):
                    raise AssertionError("only trusted bounded AST worker process permitted")
                self.artifact_gate("fixture_evaluate", "path:" + str(evaluator))
                return function(command, *args, **kwargs)
            return execute
        for name, replacement in (("subprocess.run", allow_only_worker(original_run)),
                                  ("subprocess.Popen", allow_only_worker(original_popen))):
            handle = patch(name, new=replacement); handle.start(); self.addCleanup(handle.stop)
        handle = patch("socket.create_connection", side_effect=AssertionError("no network in fast epoch control"))
        handle.start(); self.addCleanup(handle.stop)

    def artifact_gate(self, method, target):
        self.authority.gate(self.scope["scope_id"], target, method)
        self.gate_calls.append((method, target))

    def artifact(self, name, raw):
        path = self.root / name
        self.artifact_gate("fixture_write", "path:" + str(path)); path.write_bytes(raw)
        return {"path": str(path), "sha256": sha256(raw)}

    def propose(self, request):
        self.proposals.append(copy.deepcopy(request))
        if self.fail_proposal:
            raise RuntimeError("inert proposal transport uncertain")
        return {"text": json.dumps({"scaffold_id": "candidate", "steps": ["inspect-contract", "trace-state"]}),
                "usage": {"prompt_tokens": 30, "completion_tokens": 12}}

    def generate(self, request):
        self.calls.append({"request": copy.deepcopy(request),
                           "full_checks": self.active_epoch.artifact_integrity_status()["full_boundary_checks"]})
        if self.fail_generation:
            raise RuntimeError("inert generation transport uncertain")
        if self.try_weight_write:
            self.artifact_gate("fixture_write", "path:" + self.weights["path"])
            Path(self.weights["path"]).write_bytes(b"x" * Path(self.weights["path"]).stat().st_size)
        if self.mutate_source:
            self.artifact_gate("fixture_write", "path:" + self.adapter["path"])
            Path(self.adapter["path"]).write_bytes(b"changed inert adapter source")
        messages = render_learning_messages(request, lambda value: [
            {"role": "system", "content": "Inert fixed worker"},
            {"role": "user", "content": canonical(value["task"]).decode()}])
        self.rendered.append(messages)
        for record in request["public_context"]["records"]:
            self.assertTrue(any(record["text"] in row["content"] for row in messages))
        return {"model_id": "lite", "model_sha256": self.weights["sha256"],
                "text": json.dumps({"files": self.references[request["task"]["task_id"]]}),
                "usage": {"prompt_tokens": 100, "completion_tokens": 651 if self.wrong_usage else 20}}

    def boundary(self, loop, model_id, task_id):
        self.boundaries.append(self.active_epoch.artifact_integrity_status()["full_boundary_checks"])
        body = {"schema": "xnet.scaffold-boundary-observation.v1",
            "repair_manifest_sha256": loop.manifest["receipt_sha256"], "model_id": model_id,
            "task_id": task_id, "attempt_receipts": [row["receipt_sha256"] for row in loop._rows(model_id, task_id)],
            "violation": False}
        return self.ledger.put_evidence(canonical(body), source="inert-fast-epoch-observer",
            scope_id=self.scope["scope_id"], metadata={"control_only": True})

    def epoch(self, name="epoch-1", **changes):
        args = dict(epoch_id=name, scope_id=self.scope["scope_id"], dataset=self.dataset,
            dataset_sha256=self.dataset["manifest_sha256"], tasks=self.tasks, references=self.references,
            full_tasks_sha256=digest({row["task_id"]: row for row in self.tasks}),
            references_sha256=digest(self.references), model_id="lite", models=self.models,
            run_identity=self.identity, model_artifacts=[self.weights], callback_artifacts=self.callbacks,
            generate=self.generate, propose=self.propose, boundary_observer=self.boundary,
            artifact_gate=self.artifact_gate)
        epoch = fast.LearningEpoch(self.ledger, self.root / name, **(args | changes))
        self.active_epoch = epoch
        self.addCleanup(epoch._artifact_guard.close)
        return epoch

    def test_constructor_reads_model_once_under_held_lease_before_identity_admission(self):
        from xnet.artifact_integrity_guard_v3 import ArtifactIntegrityGuard
        model_reads = []
        original_hash = ArtifactIntegrityGuard._hash
        original_artifact_hash = fast._artifact_sha256
        def bounded_hash(guard, row, phase, *, role, expected):
            if row["path"] == self.weights["path"]:
                model_reads.append({"phase": phase, "role": role,
                    "held": row["path"] in guard._leases, "bytes": Path(row["path"]).stat().st_size})
            return original_hash(guard, row, phase, role=role, expected=expected)
        def sources_only(path):
            if str(path) == self.weights["path"]:
                raise AssertionError("constructor model bytes must use the held guard only")
            return original_artifact_hash(path)
        with patch.object(ArtifactIntegrityGuard, "_hash", new=bounded_hash), \
                patch("xnet.learning_epoch_fast_v4._artifact_sha256", side_effect=sources_only):
            epoch = self.epoch()
        self.assertEqual(len(model_reads), 1)
        self.assertEqual(model_reads[0]["phase"], "initial")
        self.assertEqual(model_reads[0]["role"], "retained")
        self.assertTrue(model_reads[0]["held"])
        self.assertEqual(epoch.artifact_integrity_status()["full_boundary_checks"], 1)
        self.assertEqual(len(self.calls), 0)
        self.assertEqual(len(self.proposals), 0)
        self.assertEqual(epoch._private_binding["constructor_integrity_policy"], fast.CONSTRUCTOR_POLICY)
        self.assertEqual(epoch._private_binding["fast_v3_predecessor_sha256"], fast.FAST_V3_PREDECESSOR_SHA256)

    def test_constructor_wrong_model_bytes_refuses_before_learner_or_callbacks(self):
        self.artifact_gate("fixture_write", "path:" + self.weights["path"])
        Path(self.weights["path"]).write_bytes(b"X" * Path(self.weights["path"]).stat().st_size)
        with patch("xnet.learning_epoch_fast_v4.ScaffoldLearner", side_effect=AssertionError("learner must not be admitted")):
            with self.assertRaises(ArtifactIntegrityError) as caught:
                self.epoch()
        self.assertEqual(caught.exception.reason, "content-hash-mismatch")
        self.assertEqual(caught.exception.phase, "initial")
        self.assertEqual(len(self.calls), 0)
        self.assertEqual(len(self.proposals), 0)
        with Path(self.weights["path"]).open("r+b"):
            pass  # Failed constructor must release retained handles.

    def test_constructor_exact_declarations_and_declared_model_pin_remain_required(self):
        for rows in ([dict(self.weights, sha256="not-a-pin")],
                     [self.weights, self.weights],
                     [dict(self.weights, path="relative.fixture")],
                     [dict(self.weights, extra=True)]):
            with self.assertRaises((ValueError, ArtifactIntegrityError)):
                self.epoch(model_artifacts=rows)
        with self.assertRaisesRegex(ValueError, "omits declared weights"):
            self.epoch(model_artifacts=[dict(self.weights, sha256="f" * 64)])
        self.assertEqual(len(self.calls), 0)
        self.assertEqual(len(self.proposals), 0)

    def test_constructor_model_hardlink_is_refused_before_learner(self):
        alias = self.root / "model-alias.fixture"
        self.artifact_gate("fixture_write", "path:" + str(alias))
        os.link(self.weights["path"], alias)
        with patch("xnet.learning_epoch_fast_v4.ScaffoldLearner", side_effect=AssertionError("linked model must not admit learner")):
            with self.assertRaises(ArtifactIntegrityError) as caught:
                self.epoch()
        self.assertEqual(caught.exception.reason, "path-unavailable-or-linked")
        self.assertEqual(len(self.calls), 0)
        self.assertEqual(len(self.proposals), 0)

    def test_controller_status_keeps_source_hashes_without_retained_reads(self):
        epoch = self.epoch(); initial = epoch.artifact_integrity_status()
        for _ in range(20):
            self.assertEqual(epoch.status()["status"], "ready")
        after = epoch.artifact_integrity_status()
        self.assertEqual(after["retained_bytes_hashed"], initial["retained_bytes_hashed"])
        self.assertEqual(after["full_boundary_checks"], initial["full_boundary_checks"])
        self.assertGreater(after["source_bytes_hashed"], initial["source_bytes_hashed"])
        self.assertGreater(after["dispatch_checks"], initial["dispatch_checks"])
        epoch._identity()
        explicit = epoch.artifact_integrity_status()
        self.assertEqual(explicit["full_boundary_checks"], initial["full_boundary_checks"] + 1)
        self.assertGreater(explicit["retained_bytes_hashed"], after["retained_bytes_hashed"])

    def test_full_admission_and_post_repair_precede_learning_observations(self):
        epoch = self.epoch(); initial = epoch.artifact_integrity_status()["full_boundary_checks"]
        epoch.step()
        after_proposal = epoch.artifact_integrity_status()["full_boundary_checks"]
        self.assertGreater(after_proposal, initial)
        self.assertIn("candidate", epoch.learner.snapshot()["proposals"])
        epoch.step()
        self.assertEqual(len(self.boundaries), 2)
        self.assertTrue(all(value > max(row["full_checks"] for row in self.calls) for value in self.boundaries))
        self.assertEqual(epoch.learner.snapshot()["observation_count"], 2)

    def test_full_lifecycle_frozen_trace_replay_and_release_cleanup(self):
        epoch = self.epoch()
        with patch("xnet.learning_epoch_fast_v4.RepairLoop.grade", side_effect=AssertionError("hidden scoring prohibited")):
            final = epoch.run()
        self.assertEqual(final["status"], "completed")
        self.assertEqual(len(self.calls), 6)
        self.assertEqual(len(self.rendered), 6)
        self.assertFalse(epoch.learner.snapshot()["promotion"]["body"]["promoted"])
        self.assertEqual(epoch.learner.snapshot()["training"]["body"]["selected_scaffold"], BASELINE)
        self.assertEqual(set(epoch.active_preparer().policy["tasks"]),
                         {row["task_id"] for row in self.dataset["splits"]["unseen"]})
        for record in self.calls:
            self.assertIn("learning_public_context_policy", record["request"])
        for path in (epoch.root / "practice-baseline").rglob("reservation.json"):
            self.assertNotIn("learning_public_context_policy", json.loads(path.read_bytes()))
        count = len(self.ledger.events())
        release = epoch.close_artifact_guard()
        self.assertEqual(release["release_proof"]["phase"], "release")
        self.assertTrue(release["metrics"]["closed"])
        self.assertEqual(epoch.close_artifact_guard(), release)
        reopened = self.epoch()
        self.assertEqual(reopened.run(), final)
        self.assertEqual(len(self.calls), 6)
        self.assertEqual(len(self.ledger.events()), count)

    def test_pending_proposal_and_nested_generation_never_redispatch(self):
        epoch = self.epoch(); self.fail_proposal = True
        for _ in range(2):
            with self.assertRaises(PendingStageError):
                epoch.step()
        self.assertEqual(len(self.proposals), 1)
        proof = self.ledger.put_evidence(b"Inert fixture inspected pending proposal", source="inert-recovery",
                                         scope_id=self.scope["scope_id"])
        response = {"text": json.dumps({"scaffold_id": "candidate", "steps": ["inspect-contract", "trace-state"]}),
                    "usage": {"input_tokens": 30, "output_tokens": 12}}
        epoch.recover_proposal(response, elapsed_ms=10, evidence_sha256=proof,
            justification="Inert exact callback bytes confirmed")
        epoch.resume_pending(evidence_sha256=proof, justification="Inert confirmed proposal outcome")
        self.assertEqual(len(self.proposals), 1)
        self.fail_generation = True
        with self.assertRaises(PendingStageError):
            epoch.step()
        with self.assertRaises(PendingAttempt):
            epoch.resume_pending(evidence_sha256=proof, justification="Inert nested transport remains uncertain")
        self.assertEqual(len(self.calls), 1)

    def test_completed_raw_response_survives_source_refusal(self):
        epoch = self.epoch(); epoch.step(); self.mutate_source = True
        with self.assertRaises(PendingStageError):
            epoch.step()
        self.assertEqual(len(self.calls), 1)
        nonce = self.calls[0]["request"]["nonce"]
        raw = epoch._find("generation-" + nonce)
        response = json.loads(self.ledger.get_evidence(raw["response_sha256"]))
        self.assertEqual(response["model_id"], "lite")
        self.assertEqual(epoch.learner.snapshot()["observation_count"], 0)
        self.assertTrue(epoch.artifact_integrity_status()["poisoned"])
        epoch._artifact_guard.close()

    def test_retained_weight_write_is_blocked_and_no_learning_admitted(self):
        epoch = self.epoch(); epoch.step(); self.try_weight_write = True
        with self.assertRaises(PendingStageError):
            epoch.step()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(sha256(Path(self.weights["path"]).read_bytes()), self.weights["sha256"])
        self.assertEqual(epoch.learner.snapshot()["observation_count"], 0)

    def test_usage_budget_refusal_preserves_raw_output(self):
        epoch = self.epoch(); epoch.step(); self.wrong_usage = True
        with self.assertRaises(PendingStageError):
            epoch.step()
        raw = epoch._find("generation-" + self.calls[0]["request"]["nonce"])
        response = json.loads(self.ledger.get_evidence(raw["response_sha256"]))
        self.assertEqual(response["usage"]["completion_tokens"], 651)
        with self.assertRaises(PendingStageError):
            epoch.step()
        self.assertEqual(len(self.calls), 1)

    def test_refused_scope_precedes_model_or_runner_file_reads(self):
        # Valid source-pinned callback, expired scope rather than a fake no-op gate.
        original = self.authority.gate
        def scope_refused(*args, **kwargs):
            raise PermissionError("inert scope expired")
        with patch.object(self.authority, "gate", new=scope_refused), \
                patch("xnet.learning_epoch_fast_v4._artifact_sha256", side_effect=AssertionError("read before scope")):
            with self.assertRaises(ArtifactIntegrityError) as caught:
                self.epoch()
        self.assertEqual(caught.exception.reason, "scope-refused")
        self.assertEqual(len(self.calls), 0)

    def test_constructor_failure_releases_acquired_read_handles(self):
        with patch("xnet.learning_epoch_fast_v4.ScaffoldLearner", side_effect=ValueError("inert later constructor failure")):
            with self.assertRaisesRegex(ValueError, "later constructor failure"):
                self.epoch()
        self.artifact_gate("fixture_write", "path:" + self.weights["path"])
        # If a retained lease leaked, Windows would refuse this writable open.
        with Path(self.weights["path"]).open("r+b"):
            pass

    def test_binding_and_guard_or_callback_identity_replacement_refuse(self):
        epoch = self.epoch()
        epoch.references[self.tasks[0]["task_id"]]["api.py"] += "\n"
        with self.assertRaises(ValueError):
            epoch.status()
        self.assertEqual(len(self.proposals), 0)
        epoch.references = copy.deepcopy(self.references)
        original = epoch.artifact_gate
        epoch.artifact_gate = self.propose
        with self.assertRaises(ValueError):
            epoch.status()
        epoch.artifact_gate = original
        self.assertEqual(epoch._private_binding["epoch_schema"], fast.FAST_SCHEMA)
        self.assertEqual(epoch._private_binding["artifact_guard_policy"]["protection"], "windows-read-lease")
        self.assertIn("learning_epoch_fast_v4.py", epoch._private_binding["source_pins"])

    def test_borrowed_cas_pin_drift_refuses_before_callback(self):
        class Cas:
            binary_sha256 = "f" * 64
        epoch = self.epoch(); epoch.cas = Cas()
        with self.assertRaisesRegex(ValueError, "requires native artifacts"):
            epoch.step()
        self.assertEqual(len(self.proposals), 0)

    def test_declared_native_cas_binary_pin_drift_refuses(self):
        native = self.artifact("native.fixture", b"inert native binary")
        identity = copy.deepcopy(self.identity)
        identity["native"] = {"binary": native, "sdk_artifacts": [self.adapter]}
        class Cas:
            binary_sha256 = native["sha256"]
        cas = Cas()
        epoch = self.epoch(run_identity=identity, cas=cas)
        cas.binary_sha256 = "f" * 64
        with self.assertRaisesRegex(ValueError, "differs from borrowed CAS"):
            epoch.status()
        self.assertEqual(len(self.proposals), 0)

    def test_guard_inner_code_replacement_refuses_before_admission(self):
        epoch = self.epoch()
        original = epoch._artifact_guard._hash
        epoch._artifact_guard._hash = lambda *args, **kwargs: None
        with self.assertRaises(ValueError):
            epoch.status()
        epoch._artifact_guard._hash = original
        self.assertEqual(len(self.proposals), 0)

    def coach(self):
        binary = self.artifact("codex-inert.exe", b"inert exact coach EXE bytes; never execute" * 512)
        source = self.artifact("coach-inert.py", b"# fixed source-pinned inert coach wrapper\n" * 64)
        identity = {"schema": "xnet.learning-coach-identity.v1", "provider": "inert-coach",
            "model_id": "coach-test-only", "model_revision": None,
            "transport": {"kind": "inert-fixed-exe", "artifacts": [binary, source]},
            "decoding": {"temperature": 0}}
        return identity, binary, source

    def test_coach_exe_leased_status_avoids_reads_and_sources_are_fresh(self):
        coach, binary, source = self.coach()
        epoch = self.epoch(coach_identity=coach)
        policy = epoch._private_binding["artifact_guard_policy"]
        self.assertIn(binary, policy["transport_artifacts"])
        self.assertIn(binary, policy["retained_artifacts"])
        self.assertNotIn(binary, policy["source_artifacts"])
        self.assertIn(source, policy["source_artifacts"])
        initial = epoch.artifact_integrity_status()
        original = fast._artifact_sha256
        def source_only(path):
            if os.path.normcase(str(path)) == os.path.normcase(binary["path"]):
                raise AssertionError("status must not rehash held transport executable")
            return original(path)
        with patch("xnet.learning_epoch_fast_v4._artifact_sha256", side_effect=source_only):
            for _ in range(12):
                epoch.status()
                proof = epoch.verify_transport_artifacts([binary])
                self.assertFalse(proof["metadata_is_cryptographic_proof"])
        after = epoch.artifact_integrity_status()
        self.assertEqual(initial["transport_bytes_hashed"], after["transport_bytes_hashed"])
        self.assertGreater(after["source_bytes_hashed"], initial["source_bytes_hashed"])
        self.assertEqual(after["transport_continuity_checks"], 12)
        epoch._identity()
        explicit = epoch.artifact_integrity_status()
        binary_bytes = Path(binary["path"]).stat().st_size
        self.assertEqual(explicit["transport_bytes_hashed"], initial["transport_bytes_hashed"] + binary_bytes)
        release = epoch.close_artifact_guard()
        self.assertEqual(release["metrics"]["transport_bytes_hashed"], explicit["transport_bytes_hashed"] + binary_bytes)

    def test_coach_transport_source_wins_callback_overlap(self):
        coach, binary, _ = self.coach()
        epoch = self.epoch(coach_identity=coach, callback_artifacts=self.callbacks + [binary])
        policy = epoch._private_binding["artifact_guard_policy"]
        self.assertIn(binary, policy["source_artifacts"])
        self.assertNotIn(binary, policy["retained_artifacts"])
        self.assertNotIn(binary, policy["transport_artifacts"])
        with self.assertRaises(ArtifactIntegrityError) as caught:
            epoch.verify_transport_artifacts([binary])
        self.assertEqual(caught.exception.reason, "unselected-transport-artifact")

    def test_coach_source_changed_with_restored_mtime_still_refuses(self):
        coach, _, source = self.coach(); epoch = self.epoch(coach_identity=coach)
        path = Path(source["path"]); before = path.stat(); raw = path.read_bytes()
        self.artifact_gate("fixture_write", "path:" + str(path))
        path.write_bytes(b"X" + raw[1:])
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        with self.assertRaises(ArtifactIntegrityError) as caught:
            epoch.status()
        self.assertEqual(caught.exception.reason, "content-hash-mismatch")
        self.assertEqual(len(self.proposals), 0)

    def test_coach_declared_pin_drift_cannot_replace_leased_identity(self):
        coach, binary, _ = self.coach(); epoch = self.epoch(coach_identity=coach)
        epoch.coach_identity["transport"]["artifacts"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "binding drift"):
            epoch.status()
        self.assertEqual(len(self.proposals), 0)

    def test_borrowed_transport_code_replacement_and_release_refuse(self):
        coach, binary, _ = self.coach(); epoch = self.epoch(coach_identity=coach)
        original = epoch._artifact_guard.verify_transport_artifacts
        epoch._artifact_guard.verify_transport_artifacts = lambda rows: {"passed": True}
        with self.assertRaisesRegex(ValueError, "code binding drift"):
            epoch.verify_transport_artifacts([binary])
        epoch._artifact_guard.verify_transport_artifacts = original
        epoch.close_artifact_guard()
        with self.assertRaises(ArtifactIntegrityError) as caught:
            epoch.verify_transport_artifacts([binary])
        self.assertEqual(caught.exception.reason, "closed")

    def test_coach_constructor_still_fully_checks_transport_pin(self):
        coach, _, _ = self.coach()
        coach["transport"]["artifacts"][0]["sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "differs from retained pin"):
            self.epoch(coach_identity=coach)
        self.assertEqual(len(self.calls), 0)

    def test_sources_are_not_reclassified_when_a_declaration_overlaps(self):
        identity = copy.deepcopy(self.identity)
        identity["runner"]["artifacts"].append(self.adapter)
        epoch = self.epoch(run_identity=identity)
        policy = epoch._private_binding["artifact_guard_policy"]
        sources = {row["path"] for row in policy["source_artifacts"]}
        retained = {row["path"] for row in policy["retained_artifacts"]}
        self.assertIn(self.adapter["path"], sources)
        self.assertNotIn(self.adapter["path"], retained)


if __name__ == "__main__":
    unittest.main()

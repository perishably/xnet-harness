"""Behavioral checks for bounded, ephemeral Jcode context handoffs."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from xnet.context_ouroboros import (
    ContextOuroboros,
    ContextOuroborosError,
    ContextPolicy,
    SourceRequest,
    validate_triathlon_receipts,
)


class ContextOuroborosTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="xnet-context-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.store = self.root / "XNET"
        self.key = b"context-ouroboros-unit-test-key!!"
        self.continuity = {
            "task_id": "pallets__flask-5014",
            "base_commit": "7ee9ceb71e868944a46e1ff00b506772a53a4f1d",
            "evaluator_contract_sha256": "e" * 64,
        }
        self.source = self.workspace / "module.py"
        self.source.write_text(
            "".join(f"line_{number} = {'x' * 80!r}\n" for number in range(1, 201)),
            encoding="utf-8",
        )

    def loop(self, policy: ContextPolicy | None = None) -> ContextOuroboros:
        return ContextOuroboros(
            store_root=self.store,
            allowed_roots=[self.workspace],
            signing_key=self.key,
            task_id=self.continuity["task_id"],
            scope_id="local-benchmark",
            evaluator_continuity=self.continuity,
            policy=policy,
        )

    def test_overflow_compacts_line_slices_and_replays_from_cas(self) -> None:
        loop = self.loop(
            ContextPolicy(
                max_chars=1_400,
                max_estimated_tokens=350,
                max_slice_chars=500,
                max_lines_per_slice=80,
                max_slices=4,
                max_cycles=4,
            )
        )
        created = loop.start(
            objective="Repair the bounded local task. " * 180,
            concise_state={"observation": "state " * 500},
            source_session_id="jcode-source-session",
            provider_id="local-qwen",
            model_id="qwen3.8-27b-rvn-q4km",
            source_requests=[SourceRequest(self.source, 20, 70)],
            work_output="candidate notes " * 400,
            next_actions=["inspect the narrow constructor", "run the admitted evaluator"],
            contradictions=[{"statement": "No verified contradiction yet", "evidence_hashes": []}],
            handoff_reason="32768-token-context-pressure",
        )
        self.assertTrue(created["compacted"])
        capsule = created["capsule"]
        body = capsule["body"]
        self.assertLessEqual(body["budget"]["used_chars"], 1_400)
        self.assertLessEqual(body["budget"]["used_estimated_tokens"], 350)
        self.assertEqual([row["leg"] for row in body["triathlon_receipts"]], ["SWIM", "BIKE", "RUN"])
        snippet = body["replay_context"]["source_snippets"][0]
        self.assertEqual((snippet["start_line"], snippet["end_line"]), (20, 70))
        self.assertTrue(snippet["text_truncated"])
        self.assertNotIn(str(self.workspace), json.dumps(snippet))
        replayed = loop.verify_file(Path(created["capsule_path"]))
        self.assertEqual(replayed["capsule_sha256"], capsule["capsule_sha256"])
        self.assertEqual(replayed["body"]["replay_context_sha256"], body["replay_context_sha256"])
        manifest = created["handoff_manifest"]
        self.assertEqual(manifest["execution_status"], "not-executed")
        self.assertTrue(manifest["ephemeral_session"])
        self.assertEqual(manifest["history_dependency"], "verified-replay-context-only")
        verified_manifest = loop.verify_manifest_file(Path(created["handoff_manifest_path"]))
        self.assertEqual(verified_manifest["capsule_sha256"], capsule["capsule_sha256"])
        self.assertEqual([row["leg"] for row in verified_manifest["triathlon_receipts"]], ["SWIM", "BIKE", "RUN"])
        for pointer in verified_manifest["triathlon_receipts"]:
            self.assertTrue((self.store / pointer["receipt_path"]).is_file())

    def test_under_budget_is_one_deterministic_cycle(self) -> None:
        loop = self.loop()
        arguments = dict(
            objective="Require a non-empty Blueprint name.",
            concise_state={"status": "test reproduced"},
            source_session_id="jcode-A",
            provider_id="openai",
            model_id="gpt-6.1-sol",
            source_requests=[SourceRequest(self.source, 1, 3)],
            work_output="Narrow constructor validation appears relevant.",
            next_actions=["apply a minimal production change"],
            contradictions=[],
        )
        first = loop.start(**arguments)
        second = loop.start(**arguments)
        self.assertEqual(first["cycles"], 1)
        self.assertFalse(first["compacted"])
        self.assertEqual(first["capsule"]["capsule_sha256"], second["capsule"]["capsule_sha256"])
        self.assertEqual(first["capsule_path"], second["capsule_path"])
        body = first["capsule"]["body"]
        self.assertEqual(body["parent_session_id"], "jcode-A")
        self.assertNotEqual(body["session_id"], body["parent_session_id"])
        self.assertEqual([row["event"] for row in body["lifecycle_events"]], ["exit", "handoff", "restart"])

    def test_policy_rejects_boolean_limits_and_verifier_enforces_its_local_budget(self) -> None:
        for field in (
            "max_chars",
            "max_estimated_tokens",
            "max_slice_chars",
            "max_lines_per_slice",
            "max_slices",
            "max_cycles",
            "max_list_items",
        ):
            values = dict(
                max_chars=12_000,
                max_estimated_tokens=3_000,
                max_slice_chars=2_000,
                max_lines_per_slice=160,
                max_slices=12,
                max_cycles=6,
                max_list_items=12,
            )
            values[field] = True
            with self.subTest(field=field), self.assertRaisesRegex(ContextOuroborosError, "must be integers"):
                ContextPolicy(**values).validate()

        producer = self.loop(ContextPolicy(max_chars=4_000, max_estimated_tokens=1_000))
        created = producer.start(
            objective="bounded task",
            concise_state={"large_state": "x" * 2_500},
            source_session_id="jcode-A",
            provider_id="local-qwen",
            model_id="qwen-local",
        )
        self.assertGreater(created["capsule"]["body"]["budget"]["used_chars"], 1_400)
        stricter_verifier = self.loop(
            ContextPolicy(
                max_chars=1_400,
                max_estimated_tokens=350,
                max_slice_chars=500,
            )
        )
        with self.assertRaisesRegex(ContextOuroborosError, "local replay policy"):
            stricter_verifier.verify_file(Path(created["capsule_path"]))

    def test_tampered_persisted_capsule_fails_closed(self) -> None:
        loop = self.loop()
        created = loop.start(
            objective="bounded task",
            concise_state="clean",
            source_session_id="jcode-A",
            provider_id="local-qwen",
            model_id="qwen-local",
        )
        path = Path(created["capsule_path"])
        tampered = json.loads(path.read_text(encoding="utf-8"))
        tampered["body"]["replay_context"]["objective"] = "tampered objective"
        path.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaisesRegex(ContextOuroborosError, "hash mismatch|signature mismatch"):
            loop.verify_file(path)

    def test_tampered_handoff_manifest_fails_closed(self) -> None:
        loop = self.loop()
        created = loop.start(
            objective="bounded task",
            concise_state="clean",
            source_session_id="jcode-A",
            provider_id="local-qwen",
            model_id="qwen-local",
        )
        path = Path(created["handoff_manifest_path"])
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["model_id"] = "substituted-model"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ContextOuroborosError, "manifest hash mismatch|signature mismatch"):
            loop.verify_manifest_file(path)

    def test_fresh_loop_resumes_without_old_process_state_and_cycles_stay_bounded(self) -> None:
        policy = ContextPolicy(max_cycles=3)
        first_process = self.loop(policy)
        first = first_process.start(
            objective="bounded repair",
            concise_state={"phase": 1},
            source_session_id="jcode-A",
            provider_id="local-qwen",
            model_id="qwen-local",
            contradictions=["candidate behavior differs from requested behavior"],
        )
        # Reconstruct the coordinator as a new object.  Only the signed external
        # capsule, key, policy, and task binding cross this process boundary.
        fresh_process = self.loop(policy)
        second = fresh_process.handoff(
            Path(first["capsule_path"]),
            work_output="constructor site isolated",
            concise_state={"phase": 2},
            next_actions=["make the minimal edit"],
        )
        third_process = self.loop(policy)
        third = third_process.handoff(
            Path(second["capsule_path"]),
            work_output="edit verified by focused test",
            concise_state={"phase": 3},
            next_actions=["close with receipt"],
        )
        bodies = [row["capsule"]["body"] for row in (first, second, third)]
        self.assertEqual([body["cycle_index"] for body in bodies], [1, 2, 3])
        sessions = [body["session_id"] for body in bodies]
        self.assertEqual(len(set(sessions)), 3)
        self.assertEqual(bodies[1]["parent_session_id"], sessions[0])
        self.assertEqual(bodies[2]["parent_session_id"], sessions[1])
        all_receipts = [receipt for body in bodies for receipt in body["triathlon_receipts"]]
        self.assertTrue(validate_triathlon_receipts(all_receipts, self.key)["intact"])
        for body in bodies:
            self.assertLessEqual(body["budget"]["used_chars"], policy.max_chars)
            self.assertLessEqual(body["budget"]["used_estimated_tokens"], policy.max_estimated_tokens)
        with self.assertRaisesRegex(ContextOuroborosError, "maximum context cycles"):
            self.loop(policy).handoff(
                Path(third["capsule_path"]),
                work_output="must not start a fourth cycle",
            )

    def test_evaluator_private_fields_and_paths_are_rejected(self) -> None:
        for forbidden in ("gold_patch", "test_patch"):
            continuity = {**self.continuity, forbidden: "hidden evaluator data"}
            with self.subTest(field=forbidden), self.assertRaisesRegex(ContextOuroborosError, "evaluator-private"):
                ContextOuroboros(
                    store_root=self.store,
                    allowed_roots=[self.workspace],
                    signing_key=self.key,
                    task_id=self.continuity["task_id"],
                    scope_id="local-benchmark",
                    evaluator_continuity=continuity,
                )
        loop = self.loop()
        with self.assertRaisesRegex(ContextOuroborosError, "evaluator-private"):
            loop.start(
                objective="bounded task",
                concise_state={"test_patch": "hidden"},
                source_session_id="jcode-A",
                provider_id="local-qwen",
                model_id="qwen-local",
            )
        private_dir = self.workspace / "evaluator-private"
        private_dir.mkdir()
        private_path = private_dir / "task.test.patch"
        private_path.write_text("hidden evaluator patch", encoding="utf-8")
        with self.assertRaisesRegex(ContextOuroborosError, "evaluator-private"):
            loop.start(
                objective="bounded task",
                concise_state="clean",
                source_session_id="jcode-A",
                provider_id="local-qwen",
                model_id="qwen-local",
                source_requests=[SourceRequest(private_path, 1, 1)],
            )

    def test_triathlon_transition_order_and_scope_escape_fail_closed(self) -> None:
        loop = self.loop()
        created = loop.start(
            objective="bounded task",
            concise_state="clean",
            source_session_id="jcode-A",
            provider_id="local-qwen",
            model_id="qwen-local",
        )
        receipts = [dict(row) for row in created["capsule"]["body"]["triathlon_receipts"]]
        receipts[1]["leg"] = "RUN"
        with self.assertRaisesRegex(ContextOuroborosError, "leg transition"):
            validate_triathlon_receipts(receipts, self.key)
        outside = self.root / "outside.py"
        outside.write_text("outside", encoding="utf-8")
        with self.assertRaisesRegex(ContextOuroborosError, "outside allowed roots"):
            loop.start(
                objective="bounded task",
                concise_state="clean",
                source_session_id="jcode-A",
                provider_id="local-qwen",
                model_id="qwen-local",
                source_requests=[SourceRequest(outside, 1, 1)],
            )

    def test_fifth_petal_tornado_metadata_is_ordered_and_non_executing(self) -> None:
        config_path = Path(__file__).parents[1] / "benchmarks" / "master-blaster" / "v1" / "context-ouroboros.json"
        overlay = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(overlay["role"], "fifth-flower-of-life-petal")
        self.assertEqual(overlay["execution_claim"], "lineage-and-flow-metadata-only")
        self.assertEqual(overlay["tornado_handoff"]["ordered_legs"], ["SWIM", "BIKE", "RUN"])
        self.assertEqual(overlay["tornado_handoff"]["restart_transition"], "RUN-to-SWIM")
        self.assertEqual(overlay["external_memory"]["durable_archive_role"], "drive-backed-master-context-record")
        self.assertEqual(overlay["external_memory"]["archive_mutation"], "append-only-content-addressed-capsules")
        self.assertEqual(overlay["external_memory"]["active_prompt_loading"], "verified-bounded-slices-only")
        self.assertTrue(overlay["jcode_session_policy"]["ephemeral"])
        self.assertEqual(overlay["jcode_session_policy"]["hidden_history_dependency"], "forbidden")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from xnet.inference_promotion import (
    CLASSIFICATIONS,
    DECISION_SCHEMA,
    FLOWER_ROLES,
    FLOWER_SCHEMA,
    METRIC_SCHEMA,
    EvaluatorAuthority,
    InferencePromotionEngine,
    InferencePromotionError,
    PromotionPolicy,
    sign_metric_record,
)


def h(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class InferencePromotionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evaluator_key = b"e" * 32
        self.authority_key = b"p" * 32
        self.policy = PromotionPolicy(
            policy_id="tests.promotion.v1",
            min_records_per_candidate=2,
            min_independent_replays=2,
            min_unique_tasks=1,
            min_cohort_candidates=5,
            correctness_floor_ppm=800_000,
            max_latency_ms=500,
            max_cost_microunits=500,
            outlier_mad_multiplier_milli=2_000,
            promotion_ttl_epochs=2,
        )
        self.evaluator = EvaluatorAuthority(
            evaluator_id="official-evaluator",
            key=self.evaluator_key,
            task_families=frozenset({"math", "code"}),
            evaluator_kinds=frozenset({"official_harness"}),
            capabilities=frozenset({"math_evaluation"}),
        )
        self.engine = InferencePromotionEngine(
            policy=self.policy,
            evaluators=[self.evaluator],
            authority_id="promotion-authority",
            authority_key=self.authority_key,
        )

    def record(
        self,
        *,
        candidate: str,
        task_id: str,
        role: str,
        epoch: int,
        replay: int,
        correctness: int,
        latency: int,
        cost: int,
        output_tokens: int = 100,
        family: str = "math",
        hardware: str = "laptop-a",
        shared_response: str | None = None,
        evaluator_id: str = "official-evaluator",
        evaluator_key: bytes | None = None,
    ) -> dict:
        unique = f"{candidate}:{task_id}:{role}:{epoch}:{replay}"
        return sign_metric_record(
            policy_sha256=self.policy.sha256,
            candidate_id=candidate,
            candidate_config_sha256=h(f"config:{candidate}:{task_id}:{role}"),
            model_id="qwen-local-27b",
            hardware_profile_sha256=h(hardware),
            token_budget=32_768,
            task_id=task_id,
            task_family=family,
            benchmark_id="sealed-benchmark-v1",
            benchmark_manifest_sha256=h("benchmark-manifest"),
            run_id=f"run:{unique}",
            session_id=f"session:{unique}",
            replay_id=f"replay:{unique}",
            declared_role=role,
            evidence_epoch=epoch,
            seven_gates_receipt_sha256=h(f"seven-gates:{epoch}:{replay}"),
            inference_receipt_sha256=h(f"inference:{unique}"),
            prompt_sha256=h(f"prompt:{task_id}"),
            response_sha256=shared_response or h(f"response:{unique}"),
            correctness_ppm=correctness,
            latency_ms=latency,
            cost_microunits=cost,
            output_tokens=output_tokens,
            evaluator_id=evaluator_id,
            evaluator_kind="official_harness",
            evaluation_sha256=h(f"evaluation:{unique}"),
            evaluator_key=evaluator_key or self.evaluator_key,
        )

    def cohort(
        self,
        *,
        task_id: str = "task-1",
        role: str = "solver",
        epoch: int = 1,
        family: str = "math",
        leader_correctness: int = 980_000,
        leader_latency: int = 50,
        leader_cost: int = 50,
        replays: int = 2,
        hardware_overrides: dict[int, str] | None = None,
        shared_leader_response: str | None = None,
    ) -> tuple[list[dict], str]:
        profiles = [
            (leader_correctness, leader_latency, leader_cost),
            (900_000, 100, 100),
            (910_000, 120, 120),
            (920_000, 140, 140),
            (930_000, 160, 160),
        ]
        prefix = f"{task_id}-{role}"
        leader = f"{prefix}-candidate-0"
        records: list[dict] = []
        for candidate_index, (correctness, latency, cost) in enumerate(profiles):
            candidate = f"{prefix}-candidate-{candidate_index}"
            hardware = (hardware_overrides or {}).get(candidate_index, "laptop-a")
            for replay in range(replays):
                records.append(
                    self.record(
                        candidate=candidate,
                        task_id=task_id,
                        role=role,
                        epoch=epoch,
                        replay=replay,
                        correctness=correctness,
                        latency=latency,
                        cost=cost,
                        family=family,
                        hardware=hardware,
                        shared_response=shared_leader_response if candidate_index == 0 else None,
                    )
                )
        return records, leader

    @staticmethod
    def by_candidate(decisions: list[dict]) -> dict[str, dict]:
        return {decision["subject"]["candidate_id"]: decision for decision in decisions}

    def promoted_leader(
        self,
        *,
        task_id: str,
        role: str,
        family: str = "math",
        shared_leader_response: str | None = None,
    ) -> dict:
        first_records, leader = self.cohort(
            task_id=task_id,
            role=role,
            epoch=1,
            family=family,
            shared_leader_response=shared_leader_response,
        )
        first = self.by_candidate(self.engine.evaluate(first_records))[leader]
        second_records, _ = self.cohort(
            task_id=task_id,
            role=role,
            epoch=2,
            family=family,
            shared_leader_response=shared_leader_response,
        )
        return self.by_candidate(
            self.engine.evaluate(second_records, previous_decisions=[first])
        )[leader]

    def test_outlier_501_requires_later_disjoint_replay_card(self) -> None:
        first_records, leader = self.cohort(epoch=1)
        first = self.by_candidate(self.engine.evaluate(first_records))[leader]
        self.assertEqual(first["classification"], "Candidate Outlier")
        self.assertEqual(first["action"], "withhold")
        self.assertEqual(first["verification_tier"], 2)
        self.assertTrue(
            {"accuracy_outlier", "latency_outlier", "cost_outlier", "efficiency_outlier"}
            .issubset(first["tags"])
        )

        second_records, _ = self.cohort(epoch=2)
        second = self.by_candidate(
            self.engine.evaluate(second_records, previous_decisions=[first])
        )[leader]
        self.assertEqual(second["classification"], "Outlier 501")
        self.assertEqual(second["action"], "promote")
        self.assertEqual(second["verification_tier"], 3)
        self.assertIn("high_flyer", second["tags"])
        self.assertIn("abacus_math", second["tags"])
        self.assertEqual(second["previous_decision_sha256"], first["receipt_sha256"])
        self.assertTrue(
            set(first["evidence_record_sha256s"]).isdisjoint(second["evidence_record_sha256s"])
        )
        self.engine.verify_decision(second)

    def test_fast_failure_is_quarantined_and_demotes_leader(self) -> None:
        promoted = self.promoted_leader(task_id="failure-task", role="solver")
        records, leader = self.cohort(
            task_id="failure-task",
            role="solver",
            epoch=3,
            leader_correctness=100_000,
            leader_latency=1,
            leader_cost=1,
        )
        decision = self.by_candidate(
            self.engine.evaluate(records, previous_decisions=[promoted])
        )[leader]
        self.assertEqual(decision["classification"], "Quarantined Anomaly")
        self.assertEqual(decision["verification_tier"], 0)
        self.assertEqual(decision["action"], "demote")
        self.assertIn("correctness_below_floor", decision["reason_codes"])
        self.assertIn("latency_outlier", decision["tags"])
        self.assertNotIn("outlier_501", decision["tags"])

    def test_insufficient_replay_stays_standard(self) -> None:
        records, leader = self.cohort(replays=1)
        decision = self.by_candidate(self.engine.evaluate(records))[leader]
        self.assertEqual(decision["classification"], "Standard")
        self.assertIn("insufficient_records", decision["reason_codes"])
        self.assertIn("insufficient_independent_replays", decision["reason_codes"])
        self.assertNotIn("accuracy_outlier", decision["tags"])

    def test_normalization_separates_hardware_cohorts(self) -> None:
        records, leader = self.cohort(hardware_overrides={0: "different-laptop"})
        decision = self.by_candidate(self.engine.evaluate(records))[leader]
        self.assertEqual(decision["metrics_summary"]["cohort_candidate_count"], 1)
        self.assertEqual(decision["classification"], "Standard")
        self.assertFalse(any(tag.endswith("_outlier") for tag in decision["tags"]))

    def test_tampering_duplicates_and_untrusted_signers_fail_closed(self) -> None:
        records, _ = self.cohort()
        tampered = copy.deepcopy(records[0])
        tampered["metrics"]["correctness_ppm"] -= 1
        with self.assertRaisesRegex(InferencePromotionError, "hash mismatch"):
            self.engine.verify_metric_record(tampered)
        with self.assertRaisesRegex(InferencePromotionError, "duplicate metric receipt"):
            self.engine.evaluate([records[0], records[0]])
        untrusted = self.record(
            candidate="candidate-external",
            task_id="task-1",
            role="solver",
            epoch=1,
            replay=1,
            correctness=900_000,
            latency=100,
            cost=100,
            evaluator_id="unknown-evaluator",
            evaluator_key=b"u" * 32,
        )
        with self.assertRaisesRegex(InferencePromotionError, "not trusted"):
            self.engine.verify_metric_record(untrusted)

    def test_self_certification_and_policy_rebinding_are_rejected(self) -> None:
        with self.assertRaisesRegex(InferencePromotionError, "self-certify"):
            self.record(
                candidate="official-evaluator",
                task_id="task-1",
                role="solver",
                epoch=1,
                replay=1,
                correctness=900_000,
                latency=100,
                cost=100,
            )
        record = self.cohort()[0][0]
        changed_policy = PromotionPolicy(policy_id="tests.changed-policy.v1")
        other_engine = InferencePromotionEngine(
            policy=changed_policy,
            evaluators=[self.evaluator],
            authority_id="other-promotion-authority",
            authority_key=b"q" * 32,
        )
        with self.assertRaisesRegex(InferencePromotionError, "predeclared policy"):
            other_engine.verify_metric_record(record)

    def test_leakage_control_tamper_is_rejected(self) -> None:
        record = self.cohort()[0][0]
        record["leakage_controls"]["evaluator_feedback_consumed"] = True
        with self.assertRaises(InferencePromotionError):
            self.engine.verify_metric_record(record)

    def test_abacus_tag_requires_math_family_and_capability(self) -> None:
        promoted = self.promoted_leader(task_id="code-task", role="solver", family="code")
        self.assertEqual(promoted["classification"], "Outlier 501")
        self.assertNotIn("abacus_math", promoted["tags"])

        no_math_engine = InferencePromotionEngine(
            policy=self.policy,
            evaluators=[
                EvaluatorAuthority(
                    evaluator_id="official-evaluator",
                    key=self.evaluator_key,
                    task_families=frozenset({"math", "code"}),
                    evaluator_kinds=frozenset({"official_harness"}),
                    capabilities=frozenset(),
                )
            ],
            authority_id="promotion-authority-2",
            authority_key=b"r" * 32,
        )
        first_records, leader = self.cohort(task_id="math-no-capability", epoch=1)
        first = self.by_candidate(no_math_engine.evaluate(first_records))[leader]
        second_records, _ = self.cohort(task_id="math-no-capability", epoch=2)
        second = self.by_candidate(
            no_math_engine.evaluate(second_records, previous_decisions=[first])
        )[leader]
        self.assertNotIn("abacus_math", second["tags"])

    def test_promotion_expiry_and_gate_admission(self) -> None:
        promoted = self.promoted_leader(task_id="expiry-task", role="solver")
        gates = promoted["seven_gates_receipt_sha256s"]
        self.engine.verify_active_promotion(
            promoted,
            current_evidence_epoch=3,
            verified_seven_gates_receipt_sha256s=gates,
        )
        with self.assertRaisesRegex(InferencePromotionError, "Seven Gates"):
            self.engine.verify_active_promotion(
                promoted,
                current_evidence_epoch=3,
                verified_seven_gates_receipt_sha256s=[],
            )
        with self.assertRaisesRegex(InferencePromotionError, "expired"):
            self.engine.verify_active_promotion(
                promoted,
                current_evidence_epoch=4,
                verified_seven_gates_receipt_sha256s=gates,
            )
        expired = self.engine.expire(
            promoted,
            current_evidence_epoch=4,
            expiry_evidence_sha256=h("clock-evidence"),
        )
        self.assertEqual(expired["action"], "demote")
        self.assertEqual(expired["classification"], "Quarantined Anomaly")
        self.assertEqual(expired["previous_decision_sha256"], promoted["receipt_sha256"])
        self.engine.verify_decision(expired)

        first_records, leader = self.cohort(task_id="late-card", epoch=1)
        first = self.by_candidate(self.engine.evaluate(first_records))[leader]
        late_records, _ = self.cohort(task_id="late-card", epoch=4)
        late = self.by_candidate(
            self.engine.evaluate(late_records, previous_decisions=[first])
        )[leader]
        self.assertEqual(late["classification"], "Candidate Outlier")
        self.assertEqual(late["action"], "withhold")

    def test_flower_has_four_distinct_reference_only_roles(self) -> None:
        promotions = [
            self.promoted_leader(task_id=f"flower-{role}", role=role)
            for role in FLOWER_ROLES
        ]
        gates = sorted({gate for receipt in promotions for gate in receipt["seven_gates_receipt_sha256s"]})
        flower = self.engine.compose_flower(
            promotions,
            current_evidence_epoch=2,
            verified_seven_gates_receipt_sha256s=gates,
        )
        verified = self.engine.verify_flower(flower)
        self.assertFalse(verified["content_embedded"])
        self.assertFalse(verified["benchmark_feedback_allowed"])
        self.assertEqual([anchor["role"] for anchor in verified["role_anchors"]], list(FLOWER_ROLES))
        self.assertEqual(len({anchor["artifact_sha256"] for anchor in verified["role_anchors"]}), 4)

    def test_flower_rejects_duplicate_artifact_reference(self) -> None:
        shared = h("shared-output-must-not-be-duplicated")
        promotions = [
            self.promoted_leader(
                task_id=f"duplicate-{role}",
                role=role,
                shared_leader_response=shared,
            )
            for role in FLOWER_ROLES
        ]
        gates = sorted({gate for receipt in promotions for gate in receipt["seven_gates_receipt_sha256s"]})
        with self.assertRaisesRegex(InferencePromotionError, "distinct content-addressed"):
            self.engine.compose_flower(
                promotions,
                current_evidence_epoch=2,
                verified_seven_gates_receipt_sha256s=gates,
            )

    def test_decisions_are_deterministic_under_input_reordering(self) -> None:
        records, _ = self.cohort()
        forward = self.engine.evaluate(records)
        reverse = self.engine.evaluate(list(reversed(records)))
        self.assertEqual(forward, reverse)

    def test_schema_files_and_exact_class_names_are_present(self) -> None:
        root = Path(__file__).resolve().parents[1]
        schema_root = root / "benchmarks" / "master-blaster" / "v1"
        metric = json.loads((schema_root / "inference-metric-record.schema.json").read_text(encoding="utf-8"))
        decision = json.loads((schema_root / "inference-promotion-decision.schema.json").read_text(encoding="utf-8"))
        flower = json.loads((schema_root / "inference-flower-manifest.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(metric["properties"]["schema_version"]["const"], METRIC_SCHEMA)
        self.assertEqual(decision["properties"]["schema_version"]["const"], DECISION_SCHEMA)
        self.assertEqual(flower["properties"]["schema_version"]["const"], FLOWER_SCHEMA)
        self.assertEqual(tuple(decision["properties"]["classification"]["enum"]), CLASSIFICATIONS)


if __name__ == "__main__":
    unittest.main()

"""Evidence-gated inference tagging and Flower role promotion.

This module operates on evaluator-signed metric receipts.  It never executes
models, copies model output, or exposes benchmark feedback.  Promotion is a
post-evaluation routing decision over content-addressed references only.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any, Iterable, Mapping, Sequence

from .protocol import canonical, digest


METRIC_SCHEMA = "xnet.inference-metric-record.v1"
DECISION_SCHEMA = "xnet.inference-promotion-decision.v1"
FLOWER_SCHEMA = "xnet.inference-flower-manifest.v1"
FLOWER_ROLES = ("solver", "verifier", "challenger", "synthesizer")
CLASSIFICATIONS = (
    "Standard",
    "Candidate Outlier",
    "Outlier 501",
    "Quarantined Anomaly",
)
ZERO_HASH = "0" * 64

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,127}$")
_METRIC_FIELDS = {"correctness_ppm", "latency_ms", "cost_microunits", "output_tokens"}
_LEAKAGE_CONTROLS = {
    "generation_frozen_before_evaluation": True,
    "evaluator_feedback_consumed": False,
    "private_tests_exposed": False,
    "reference_answer_exposed": False,
    "task_specific_memory_reused": False,
}
_DEMOTION_REASONS = {
    "evaluator_revoked",
    "evidence_invalidated",
    "later_evidence_failed_promotion",
    "leakage_detected",
    "replay_failed",
    "promotion_expired",
    "threshold_regression",
}


class InferencePromotionError(ValueError):
    """Raised when promotion evidence or a decision fails closed."""


def _identifier(field_name: str, value: Any) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise InferencePromotionError(f"invalid {field_name}")
    return value


def _hash(field_name: str, value: Any) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise InferencePromotionError(f"invalid {field_name}")
    return value


def _integer(field_name: str, value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise InferencePromotionError(f"invalid {field_name}")
    return value


def _exact_fields(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise InferencePromotionError(f"{label} fields do not match {label} v1")
    return value


def _validate_key(key: bytes, label: str) -> bytes:
    if not isinstance(key, bytes) or len(key) < 32:
        raise InferencePromotionError(f"{label} key must contain at least 32 bytes")
    return key


def _seal(body: Mapping[str, Any], key: bytes) -> dict[str, Any]:
    receipt_sha256 = digest(body)
    hashed = {**body, "receipt_sha256": receipt_sha256}
    return {
        **hashed,
        "receipt_hmac_sha256": hmac.new(key, canonical(hashed), hashlib.sha256).hexdigest(),
    }


def _verify_seal(receipt: Mapping[str, Any], key: bytes, body_fields: set[str], label: str) -> dict[str, Any]:
    _exact_fields(receipt, body_fields | {"receipt_sha256", "receipt_hmac_sha256"}, label)
    supplied_hash = _hash("receipt_sha256", receipt["receipt_sha256"])
    supplied_hmac = _hash("receipt_hmac_sha256", receipt["receipt_hmac_sha256"])
    body = {name: receipt[name] for name in body_fields}
    expected_hash = digest(body)
    if not hmac.compare_digest(supplied_hash, expected_hash):
        raise InferencePromotionError(f"{label} content hash mismatch")
    expected_hmac = hmac.new(
        key,
        canonical({**body, "receipt_sha256": expected_hash}),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(supplied_hmac, expected_hmac):
        raise InferencePromotionError(f"{label} HMAC mismatch")
    return dict(receipt)


@dataclass(frozen=True)
class PromotionPolicy:
    """Thresholds committed into every evidence and decision receipt."""

    policy_id: str = "xnet.inference-promotion.default-v1"
    min_records_per_candidate: int = 4
    min_independent_replays: int = 2
    min_unique_tasks: int = 1
    min_cohort_candidates: int = 5
    correctness_floor_ppm: int = 900_000
    max_latency_ms: int = 120_000
    max_cost_microunits: int = 10_000_000
    outlier_mad_multiplier_milli: int = 3_000
    promotion_ttl_epochs: int = 2

    def validate(self) -> "PromotionPolicy":
        _identifier("policy_id", self.policy_id)
        _integer("min_records_per_candidate", self.min_records_per_candidate, 1, 1_000_000)
        _integer("min_independent_replays", self.min_independent_replays, 2, 1_000_000)
        _integer("min_unique_tasks", self.min_unique_tasks, 1, 1_000_000)
        _integer("min_cohort_candidates", self.min_cohort_candidates, 3, 1_000_000)
        _integer("correctness_floor_ppm", self.correctness_floor_ppm, 0, 1_000_000)
        _integer("max_latency_ms", self.max_latency_ms, 1, 86_400_000)
        _integer("max_cost_microunits", self.max_cost_microunits, 0, 10**18)
        _integer("outlier_mad_multiplier_milli", self.outlier_mad_multiplier_milli, 1_000, 20_000)
        _integer("promotion_ttl_epochs", self.promotion_ttl_epochs, 1, 10_000)
        return self

    @property
    def document(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": "xnet.inference-promotion-policy.v1",
            "policy_id": self.policy_id,
            "thresholds": {
                "min_records_per_candidate": self.min_records_per_candidate,
                "min_independent_replays": self.min_independent_replays,
                "min_unique_tasks": self.min_unique_tasks,
                "min_cohort_candidates": self.min_cohort_candidates,
                "correctness_floor_ppm": self.correctness_floor_ppm,
                "max_latency_ms": self.max_latency_ms,
                "max_cost_microunits": self.max_cost_microunits,
                "outlier_mad_multiplier_milli": self.outlier_mad_multiplier_milli,
                "promotion_ttl_epochs": self.promotion_ttl_epochs,
            },
            "outlier_method": "median-absolute-deviation",
            "zero_mad_behavior": "no-outlier-tag",
            "use_boundary": "post-evaluation-only",
        }

    @property
    def sha256(self) -> str:
        return digest(self.document)


@dataclass(frozen=True)
class EvaluatorAuthority:
    """Locally trusted evaluator identity and its narrow capabilities."""

    evaluator_id: str
    key: bytes = field(repr=False)
    task_families: frozenset[str] = field(default_factory=frozenset)
    evaluator_kinds: frozenset[str] = field(default_factory=lambda: frozenset({"official_harness"}))
    capabilities: frozenset[str] = field(default_factory=frozenset)

    def validate(self) -> "EvaluatorAuthority":
        _identifier("evaluator_id", self.evaluator_id)
        _validate_key(self.key, "evaluator")
        if not self.task_families or not self.evaluator_kinds:
            raise InferencePromotionError("evaluator authority requires task families and kinds")
        for item in sorted(self.task_families):
            _identifier("evaluator task family", item)
        for item in sorted(self.evaluator_kinds):
            _identifier("evaluator kind", item)
        for item in sorted(self.capabilities):
            _identifier("evaluator capability", item)
        return self


_METRIC_BODY_FIELDS = {
    "schema_version",
    "policy_sha256",
    "candidate_id",
    "candidate_config_sha256",
    "model_id",
    "hardware_profile_sha256",
    "token_budget",
    "task_id",
    "task_family",
    "benchmark_id",
    "benchmark_manifest_sha256",
    "run_id",
    "session_id",
    "replay_id",
    "declared_role",
    "evidence_epoch",
    "seven_gates_receipt_sha256",
    "inference_receipt_sha256",
    "prompt_sha256",
    "response_sha256",
    "metrics",
    "evaluator",
    "leakage_controls",
}


def sign_metric_record(
    *,
    policy_sha256: str,
    candidate_id: str,
    candidate_config_sha256: str,
    model_id: str,
    hardware_profile_sha256: str,
    token_budget: int,
    task_id: str,
    task_family: str,
    benchmark_id: str,
    benchmark_manifest_sha256: str,
    run_id: str,
    session_id: str,
    replay_id: str,
    declared_role: str,
    evidence_epoch: int,
    seven_gates_receipt_sha256: str,
    inference_receipt_sha256: str,
    prompt_sha256: str,
    response_sha256: str,
    correctness_ppm: int,
    latency_ms: int,
    cost_microunits: int,
    output_tokens: int,
    evaluator_id: str,
    evaluator_kind: str,
    evaluation_sha256: str,
    evaluator_key: bytes,
) -> dict[str, Any]:
    """Create an evaluator-signed immutable metric record.

    The caller must protect ``evaluator_key`` as evaluator authority.  A record
    is not trusted until an :class:`InferencePromotionEngine` verifies that
    signer against its independently configured trust registry.
    """

    _validate_key(evaluator_key, "evaluator")
    if declared_role not in FLOWER_ROLES:
        raise InferencePromotionError("invalid declared_role")
    body = {
        "schema_version": METRIC_SCHEMA,
        "policy_sha256": _hash("policy_sha256", policy_sha256),
        "candidate_id": _identifier("candidate_id", candidate_id),
        "candidate_config_sha256": _hash("candidate_config_sha256", candidate_config_sha256),
        "model_id": _identifier("model_id", model_id),
        "hardware_profile_sha256": _hash("hardware_profile_sha256", hardware_profile_sha256),
        "token_budget": _integer("token_budget", token_budget, 1, 10_000_000),
        "task_id": _identifier("task_id", task_id),
        "task_family": _identifier("task_family", task_family),
        "benchmark_id": _identifier("benchmark_id", benchmark_id),
        "benchmark_manifest_sha256": _hash("benchmark_manifest_sha256", benchmark_manifest_sha256),
        "run_id": _identifier("run_id", run_id),
        "session_id": _identifier("session_id", session_id),
        "replay_id": _identifier("replay_id", replay_id),
        "declared_role": declared_role,
        "evidence_epoch": _integer("evidence_epoch", evidence_epoch, 1, 2**63 - 1),
        "seven_gates_receipt_sha256": _hash("seven_gates_receipt_sha256", seven_gates_receipt_sha256),
        "inference_receipt_sha256": _hash("inference_receipt_sha256", inference_receipt_sha256),
        "prompt_sha256": _hash("prompt_sha256", prompt_sha256),
        "response_sha256": _hash("response_sha256", response_sha256),
        "metrics": {
            "correctness_ppm": _integer("correctness_ppm", correctness_ppm, 0, 1_000_000),
            "latency_ms": _integer("latency_ms", latency_ms, 1, 86_400_000),
            "cost_microunits": _integer("cost_microunits", cost_microunits, 0, 10**18),
            "output_tokens": _integer("output_tokens", output_tokens, 1, 10_000_000),
        },
        "evaluator": {
            "evaluator_id": _identifier("evaluator_id", evaluator_id),
            "evaluator_kind": _identifier("evaluator_kind", evaluator_kind),
            "evaluation_sha256": _hash("evaluation_sha256", evaluation_sha256),
        },
        "leakage_controls": dict(_LEAKAGE_CONTROLS),
    }
    if candidate_id == evaluator_id:
        raise InferencePromotionError("candidate may not self-certify")
    return _seal(body, evaluator_key)


def _median(values: Iterable[int | Fraction]) -> Fraction:
    ordered = sorted(Fraction(value) for value in values)
    if not ordered:
        raise InferencePromotionError("cannot summarize an empty metric cohort")
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def _mad(values: Sequence[Fraction]) -> Fraction:
    center = _median(values)
    return _median([abs(value - center) for value in values])


def _rational(value: Fraction) -> dict[str, int]:
    return {"numerator": value.numerator, "denominator": value.denominator}


def _validated_rational(value: Any, label: str, *, minimum: int = 0) -> Fraction:
    item = _exact_fields(value, {"numerator", "denominator"}, label)
    numerator = _integer(f"{label} numerator", item["numerator"], minimum, 10**30)
    denominator = _integer(f"{label} denominator", item["denominator"], 1, 10**18)
    if Fraction(numerator, denominator).numerator != numerator or Fraction(numerator, denominator).denominator != denominator:
        raise InferencePromotionError(f"{label} must be in lowest terms")
    return Fraction(numerator, denominator)


_DECISION_BODY_FIELDS = {
    "schema_version",
    "action",
    "classification",
    "verification_tier",
    "authority_id",
    "policy_sha256",
    "subject",
    "tags",
    "reason_codes",
    "metrics_summary",
    "evidence_record_sha256s",
    "artifact_reference",
    "previous_decision_sha256",
    "issued_evidence_epoch",
    "valid_through_evidence_epoch",
    "seven_gates_receipt_sha256s",
    "seven_gates_required",
    "operational_authority_granted",
    "benchmark_feedback_allowed",
}


class InferencePromotionEngine:
    """Verify evidence, classify robust outliers, and sign routing decisions."""

    def __init__(
        self,
        *,
        policy: PromotionPolicy,
        evaluators: Sequence[EvaluatorAuthority],
        authority_id: str,
        authority_key: bytes,
    ) -> None:
        self.policy = policy.validate()
        self.authority_id = _identifier("authority_id", authority_id)
        self.authority_key = _validate_key(authority_key, "promotion authority")
        authorities: dict[str, EvaluatorAuthority] = {}
        for evaluator in evaluators:
            evaluator.validate()
            if evaluator.evaluator_id in authorities:
                raise InferencePromotionError("duplicate evaluator authority")
            if evaluator.evaluator_id == self.authority_id:
                raise InferencePromotionError("promotion authority must be independent of evaluators")
            authorities[evaluator.evaluator_id] = evaluator
        if not authorities:
            raise InferencePromotionError("at least one trusted evaluator is required")
        self.evaluators = authorities

    def verify_metric_record(self, record: Mapping[str, Any]) -> dict[str, Any]:
        _exact_fields(record, _METRIC_BODY_FIELDS | {"receipt_sha256", "receipt_hmac_sha256"}, "metric record")
        if record.get("schema_version") != METRIC_SCHEMA:
            raise InferencePromotionError("unsupported metric record schema")
        if record.get("policy_sha256") != self.policy.sha256:
            raise InferencePromotionError("metric record was not bound to the predeclared policy")
        evaluator = _exact_fields(
            record.get("evaluator"),
            {"evaluator_id", "evaluator_kind", "evaluation_sha256"},
            "evaluator",
        )
        evaluator_id = _identifier("evaluator_id", evaluator["evaluator_id"])
        authority = self.evaluators.get(evaluator_id)
        if authority is None:
            raise InferencePromotionError("metric record evaluator is not trusted")
        verified = _verify_seal(record, authority.key, _METRIC_BODY_FIELDS, "metric record")
        candidate_id = _identifier("candidate_id", verified["candidate_id"])
        if candidate_id in {evaluator_id, self.authority_id}:
            raise InferencePromotionError("candidate may not self-certify or self-promote")
        task_family = _identifier("task_family", verified["task_family"])
        if task_family not in authority.task_families:
            raise InferencePromotionError("evaluator is not trusted for this task family")
        evaluator_kind = _identifier("evaluator_kind", evaluator["evaluator_kind"])
        if evaluator_kind not in authority.evaluator_kinds:
            raise InferencePromotionError("evaluator kind is not trusted")
        if verified["declared_role"] not in FLOWER_ROLES:
            raise InferencePromotionError("invalid declared_role")
        for name in (
            "policy_sha256",
            "candidate_config_sha256",
            "hardware_profile_sha256",
            "benchmark_manifest_sha256",
            "seven_gates_receipt_sha256",
            "inference_receipt_sha256",
            "prompt_sha256",
            "response_sha256",
        ):
            _hash(name, verified[name])
        for name in ("model_id", "task_id", "benchmark_id", "run_id", "session_id", "replay_id"):
            _identifier(name, verified[name])
        _integer("token_budget", verified["token_budget"], 1, 10_000_000)
        _integer("evidence_epoch", verified["evidence_epoch"], 1, 2**63 - 1)
        metrics = _exact_fields(verified["metrics"], _METRIC_FIELDS, "metrics")
        _integer("correctness_ppm", metrics["correctness_ppm"], 0, 1_000_000)
        _integer("latency_ms", metrics["latency_ms"], 1, 86_400_000)
        _integer("cost_microunits", metrics["cost_microunits"], 0, 10**18)
        _integer("output_tokens", metrics["output_tokens"], 1, 10_000_000)
        _hash("evaluation_sha256", evaluator["evaluation_sha256"])
        leakage = _exact_fields(verified["leakage_controls"], set(_LEAKAGE_CONTROLS), "leakage controls")
        if dict(leakage) != _LEAKAGE_CONTROLS:
            raise InferencePromotionError("benchmark leakage or feedback controls are not sealed")
        return verified

    def _group_key(self, record: Mapping[str, Any]) -> tuple[Any, ...]:
        return (
            record["benchmark_id"],
            record["task_family"],
            record["task_id"],
            record["evaluator"]["evaluator_id"],
            record["evaluator"]["evaluator_kind"],
            record["model_id"],
            record["hardware_profile_sha256"],
            record["token_budget"],
            record["evidence_epoch"],
            record["candidate_id"],
            record["candidate_config_sha256"],
            record["declared_role"],
        )

    @staticmethod
    def _cohort_key(group_key: tuple[Any, ...]) -> tuple[Any, ...]:
        # Exact normalization boundary: benchmark/family/task/evaluator/model/
        # hardware/token budget/evidence epoch. Candidate identity and role are
        # deliberately excluded so like-for-like sessions can be compared.
        return group_key[:9]

    def _summary(self, records: Sequence[Mapping[str, Any]], cohort_size: int) -> dict[str, Any]:
        medians = {
            name: _median([record["metrics"][name] for record in records])
            for name in sorted(_METRIC_FIELDS)
        }
        efficiency_values = [
            Fraction(
                record["metrics"]["correctness_ppm"]
                * record["metrics"]["output_tokens"]
                * 1_000,
                record["metrics"]["latency_ms"],
            )
            for record in records
        ]
        independent_counts = [
            len({record[field] for record in records})
            for field in ("replay_id", "run_id", "session_id", "inference_receipt_sha256")
        ]
        independent_counts.append(len({record["evaluator"]["evaluation_sha256"] for record in records}))
        return {
            "sample_count": len(records),
            "independent_replay_count": min(independent_counts),
            "unique_task_count": len({record["task_id"] for record in records}),
            "cohort_candidate_count": cohort_size,
            "median_correctness_ppm": _rational(medians["correctness_ppm"]),
            "median_latency_ms": _rational(medians["latency_ms"]),
            "median_cost_microunits": _rational(medians["cost_microunits"]),
            "median_output_tokens": _rational(medians["output_tokens"]),
            "median_verified_efficiency": _rational(_median(efficiency_values)),
        }

    @staticmethod
    def _summary_fraction(summary: Mapping[str, Any], name: str) -> Fraction:
        value = summary[name]
        return Fraction(value["numerator"], value["denominator"])

    def _outlier_tags(
        self,
        summary: Mapping[str, Any],
        cohort_summaries: Sequence[Mapping[str, Any]],
    ) -> list[str]:
        if len(cohort_summaries) < self.policy.min_cohort_candidates:
            return []
        tags: list[str] = []
        dimensions = (
            ("median_correctness_ppm", "accuracy_outlier", "accuracy_regression"),
            ("median_latency_ms", "latency_regression", "latency_outlier"),
            ("median_cost_microunits", "cost_regression", "cost_outlier"),
            ("median_verified_efficiency", "efficiency_outlier", "efficiency_regression"),
        )
        multiplier = Fraction(self.policy.outlier_mad_multiplier_milli, 1_000)
        for field_name, high_tag, low_tag in dimensions:
            values = [self._summary_fraction(item, field_name) for item in cohort_summaries]
            center = _median(values)
            deviation = _mad(values)
            if deviation == 0:
                continue
            value = self._summary_fraction(summary, field_name)
            delta = value - center
            if delta >= deviation * multiplier:
                tags.append(high_tag)
            elif -delta >= deviation * multiplier:
                tags.append(low_tag)
        return sorted(tags)

    @staticmethod
    def _representative(records: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
        return sorted(
            records,
            key=lambda record: (
                -record["metrics"]["correctness_ppm"],
                record["metrics"]["latency_ms"],
                record["metrics"]["cost_microunits"],
                record["response_sha256"],
                record["receipt_sha256"],
            ),
        )[0]

    def evaluate(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        previous_decisions: Sequence[Mapping[str, Any]] = (),
    ) -> list[dict[str, Any]]:
        """Classify a sealed evidence epoch and sign chained card decisions.

        A statistical leader first becomes ``Candidate Outlier``.  It can
        advance to ``Outlier 501`` only when a later evidence epoch supplies a
        disjoint, independently replayed evidence card.  A later failure emits
        a signed demotion and returns the subject to the quarantine tier.
        """

        if not records:
            raise InferencePromotionError("at least one metric record is required")
        verified = [self.verify_metric_record(record) for record in records]
        receipt_ids = [record["receipt_sha256"] for record in verified]
        if len(receipt_ids) != len(set(receipt_ids)):
            raise InferencePromotionError("duplicate metric receipt cannot increase evidence weight")
        manifests = {(record["benchmark_id"], record["benchmark_manifest_sha256"]) for record in verified}
        by_benchmark: dict[str, set[str]] = {}
        for benchmark_id, manifest_hash in manifests:
            by_benchmark.setdefault(benchmark_id, set()).add(manifest_hash)
        if any(len(values) != 1 for values in by_benchmark.values()):
            raise InferencePromotionError("benchmark identifier is bound to conflicting manifests")

        previous_by_subject: dict[str, dict[str, Any]] = {}
        for receipt in previous_decisions:
            previous = self.verify_decision(receipt)
            subject_key = digest(previous["subject"])
            if subject_key in previous_by_subject:
                raise InferencePromotionError("multiple previous cards for one subject are ambiguous")
            previous_by_subject[subject_key] = previous

        groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
        for record in verified:
            groups.setdefault(self._group_key(record), []).append(record)

        cohort_groups: dict[tuple[Any, ...], list[tuple[Any, ...]]] = {}
        for key in groups:
            cohort_groups.setdefault(self._cohort_key(key), []).append(key)
        summaries: dict[tuple[Any, ...], dict[str, Any]] = {}
        for key, group_records in groups.items():
            summaries[key] = self._summary(group_records, len(cohort_groups[self._cohort_key(key)]))

        group_state: dict[tuple[Any, ...], dict[str, Any]] = {}
        positive_tags = {"accuracy_outlier", "latency_outlier", "cost_outlier", "efficiency_outlier"}
        regression_tags = {"accuracy_regression", "latency_regression", "cost_regression", "efficiency_regression"}
        for key, group_records in groups.items():
            summary = summaries[key]
            reasons: list[str] = []
            if summary["sample_count"] < self.policy.min_records_per_candidate:
                reasons.append("insufficient_records")
            if summary["independent_replay_count"] < self.policy.min_independent_replays:
                reasons.append("insufficient_independent_replays")
            if summary["unique_task_count"] < self.policy.min_unique_tasks:
                reasons.append("insufficient_unique_tasks")
            tags = ["verified_evidence"]
            replay_eligible = not reasons
            if replay_eligible:
                tags.append("independent_replay_verified")
                cohort = [summaries[item] for item in sorted(cohort_groups[self._cohort_key(key)])]
                tags.extend(self._outlier_tags(summary, cohort))
            correctness = self._summary_fraction(summary, "median_correctness_ppm")
            latency = self._summary_fraction(summary, "median_latency_ms")
            cost = self._summary_fraction(summary, "median_cost_microunits")
            if correctness < self.policy.correctness_floor_ppm:
                reasons.append("correctness_below_floor")
            if latency > self.policy.max_latency_ms:
                reasons.append("latency_above_ceiling")
            if cost > self.policy.max_cost_microunits:
                reasons.append("cost_above_ceiling")
            group_state[key] = {
                "tags": sorted(set(tags)),
                "reasons": sorted(set(reasons)),
                "replay_eligible": replay_eligible,
                "thresholds_pass": not any(
                    reason in {"correctness_below_floor", "latency_above_ceiling", "cost_above_ceiling"}
                    for reason in reasons
                ),
                "positive": bool(positive_tags.intersection(tags)),
                "regression": bool(regression_tags.intersection(tags)),
            }

        # Select one deterministic leader within each strictly normalized
        # cohort. Fast incorrect answers cannot enter this candidate set.
        leaders: set[tuple[Any, ...]] = set()
        for cohort_key, keys in cohort_groups.items():
            eligible = [
                key
                for key in keys
                if group_state[key]["replay_eligible"]
                and group_state[key]["thresholds_pass"]
                and group_state[key]["positive"]
                and not group_state[key]["regression"]
            ]
            if not eligible:
                continue
            leader = sorted(
                eligible,
                key=lambda item: (
                    -self._summary_fraction(summaries[item], "median_correctness_ppm"),
                    -self._summary_fraction(summaries[item], "median_verified_efficiency"),
                    self._summary_fraction(summaries[item], "median_latency_ms"),
                    self._summary_fraction(summaries[item], "median_cost_microunits"),
                    item,
                ),
            )[0]
            leaders.add(leader)

        decisions: list[dict[str, Any]] = []
        for key in sorted(groups):
            (
                benchmark_id,
                task_family,
                task_id,
                evaluator_id,
                evaluator_kind,
                model_id,
                hardware_profile_sha256,
                token_budget,
                evidence_epoch,
                candidate_id,
                config_sha256,
                role,
            ) = key
            group_records = groups[key]
            summary = summaries[key]
            state = group_state[key]
            representative = self._representative(group_records)
            subject = {
                "benchmark_id": benchmark_id,
                "benchmark_manifest_sha256": representative["benchmark_manifest_sha256"],
                "task_family": task_family,
                "task_id": task_id,
                "evaluator_id": evaluator_id,
                "evaluator_kind": evaluator_kind,
                "model_id": model_id,
                "hardware_profile_sha256": hardware_profile_sha256,
                "token_budget": token_budget,
                "candidate_id": candidate_id,
                "candidate_config_sha256": config_sha256,
                "flower_role": role,
            }
            previous = previous_by_subject.get(digest(subject))
            current_refs = {record["receipt_sha256"] for record in group_records}
            previous_refs = set(previous["evidence_record_sha256s"]) if previous else set()
            later_disjoint_card = bool(
                previous
                and previous["issued_evidence_epoch"] < evidence_epoch
                and evidence_epoch <= previous["valid_through_evidence_epoch"]
                and current_refs.isdisjoint(previous_refs)
            )

            hard_failure = (
                not state["thresholds_pass"]
                or "accuracy_regression" in state["tags"]
            )
            if hard_failure:
                classification = "Quarantined Anomaly"
                tier = 0
            elif key in leaders:
                if (
                    previous
                    and previous["classification"] in {"Candidate Outlier", "Outlier 501"}
                    and later_disjoint_card
                ):
                    classification = "Outlier 501"
                    tier = 3
                else:
                    classification = "Candidate Outlier"
                    tier = 2
            elif state["positive"] and state["replay_eligible"]:
                classification = "Candidate Outlier"
                tier = 2
            else:
                classification = "Standard"
                tier = 1

            if classification == "Outlier 501":
                action = "promote"
            elif previous and previous["action"] == "promote":
                action = "demote"
                state["reasons"] = sorted(set(state["reasons"] + ["later_evidence_failed_promotion"]))
            else:
                action = "withhold"

            tags = list(state["tags"])
            if classification == "Outlier 501":
                tags.extend(["high_flyer", "outlier_501"])
                authority = self.evaluators[evaluator_id]
                if task_family == "math" and "math_evaluation" in authority.capabilities:
                    tags.append("abacus_math")
            elif classification == "Quarantined Anomaly":
                tags.append("quarantined_anomaly")
            elif classification == "Candidate Outlier":
                tags.append("candidate_outlier")
            else:
                tags.append("standard")

            body = {
                "schema_version": DECISION_SCHEMA,
                "action": action,
                "classification": classification,
                "verification_tier": tier,
                "authority_id": self.authority_id,
                "policy_sha256": self.policy.sha256,
                "subject": subject,
                "tags": sorted(set(tags)),
                "reason_codes": sorted(set(state["reasons"])),
                "metrics_summary": summary,
                "evidence_record_sha256s": sorted(current_refs),
                "artifact_reference": {
                    "response_sha256": representative["response_sha256"],
                    "source_metric_receipt_sha256": representative["receipt_sha256"],
                },
                "previous_decision_sha256": previous["receipt_sha256"] if previous else ZERO_HASH,
                "issued_evidence_epoch": evidence_epoch,
                "valid_through_evidence_epoch": evidence_epoch + self.policy.promotion_ttl_epochs - 1,
                "seven_gates_receipt_sha256s": sorted(
                    {record["seven_gates_receipt_sha256"] for record in group_records}
                ),
                "seven_gates_required": True,
                "operational_authority_granted": False,
                "benchmark_feedback_allowed": False,
            }
            decisions.append(_seal(body, self.authority_key))
        return decisions

    def verify_decision(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        verified = _verify_seal(receipt, self.authority_key, _DECISION_BODY_FIELDS, "promotion decision")
        if verified.get("schema_version") != DECISION_SCHEMA:
            raise InferencePromotionError("unsupported promotion decision schema")
        if verified.get("authority_id") != self.authority_id:
            raise InferencePromotionError("promotion decision authority mismatch")
        if verified.get("policy_sha256") != self.policy.sha256:
            raise InferencePromotionError("promotion decision policy mismatch")
        if verified.get("action") not in {"promote", "withhold", "demote"}:
            raise InferencePromotionError("invalid promotion action")
        if verified.get("benchmark_feedback_allowed") is not False:
            raise InferencePromotionError("promotion decisions may not feed benchmark generation")
        subject = _exact_fields(
            verified.get("subject"),
            {
                "benchmark_id",
                "benchmark_manifest_sha256",
                "task_family",
                "task_id",
                "evaluator_id",
                "evaluator_kind",
                "model_id",
                "hardware_profile_sha256",
                "token_budget",
                "candidate_id",
                "candidate_config_sha256",
                "flower_role",
            },
            "promotion subject",
        )
        if subject["flower_role"] not in FLOWER_ROLES:
            raise InferencePromotionError("invalid Flower role")
        _hash("benchmark_manifest_sha256", subject["benchmark_manifest_sha256"])
        _hash("candidate_config_sha256", subject["candidate_config_sha256"])
        _hash("hardware_profile_sha256", subject["hardware_profile_sha256"])
        for field_name in (
            "benchmark_id",
            "task_family",
            "task_id",
            "evaluator_id",
            "evaluator_kind",
            "model_id",
            "candidate_id",
        ):
            _identifier(field_name, subject[field_name])
        _integer("token_budget", subject["token_budget"], 1, 10_000_000)
        summary = _exact_fields(
            verified.get("metrics_summary"),
            {
                "sample_count",
                "independent_replay_count",
                "unique_task_count",
                "cohort_candidate_count",
                "median_correctness_ppm",
                "median_latency_ms",
                "median_cost_microunits",
                "median_output_tokens",
                "median_verified_efficiency",
            },
            "metrics summary",
        )
        for field_name in (
            "sample_count",
            "independent_replay_count",
            "unique_task_count",
            "cohort_candidate_count",
        ):
            _integer(field_name, summary[field_name], 1, 1_000_000)
        _validated_rational(summary["median_correctness_ppm"], "median_correctness_ppm")
        _validated_rational(summary["median_latency_ms"], "median_latency_ms")
        _validated_rational(summary["median_cost_microunits"], "median_cost_microunits")
        _validated_rational(summary["median_output_tokens"], "median_output_tokens", minimum=1)
        _validated_rational(summary["median_verified_efficiency"], "median_verified_efficiency")
        artifact = _exact_fields(
            verified.get("artifact_reference"),
            {"response_sha256", "source_metric_receipt_sha256"},
            "artifact reference",
        )
        _hash("response_sha256", artifact["response_sha256"])
        _hash("source_metric_receipt_sha256", artifact["source_metric_receipt_sha256"])
        references = verified.get("evidence_record_sha256s")
        if not isinstance(references, list) or not references or references != sorted(set(references)):
            raise InferencePromotionError("evidence record references must be unique and sorted")
        for reference in references:
            _hash("evidence_record_sha256", reference)
        if artifact["source_metric_receipt_sha256"] not in references:
            raise InferencePromotionError("artifact source is not included in evidence references")
        if not isinstance(verified.get("tags"), list) or verified["tags"] != sorted(set(verified["tags"])):
            raise InferencePromotionError("decision tags must be unique and sorted")
        for tag in verified["tags"]:
            _identifier("decision tag", tag)
        if not isinstance(verified.get("reason_codes"), list) or verified["reason_codes"] != sorted(set(verified["reason_codes"])):
            raise InferencePromotionError("decision reasons must be unique and sorted")
        for reason in verified["reason_codes"]:
            _identifier("decision reason", reason)
        if verified["action"] == "demote" and not _DEMOTION_REASONS.intersection(verified["reason_codes"]):
            raise InferencePromotionError("demotion lacks a predeclared demotion reason")
        _hash("previous_decision_sha256", verified["previous_decision_sha256"])
        classification = verified.get("classification")
        if classification not in CLASSIFICATIONS:
            raise InferencePromotionError("invalid inference classification")
        expected_tier = {
            "Quarantined Anomaly": 0,
            "Standard": 1,
            "Candidate Outlier": 2,
            "Outlier 501": 3,
        }[classification]
        if verified.get("verification_tier") != expected_tier:
            raise InferencePromotionError("classification and verification tier disagree")
        if (verified["action"] == "promote") != (classification == "Outlier 501"):
            raise InferencePromotionError("only Outlier 501 may hold an active promotion")
        if classification == "Outlier 501" and verified["previous_decision_sha256"] == ZERO_HASH:
            raise InferencePromotionError("Outlier 501 requires a prior candidate card")
        if verified["action"] == "demote" and verified["previous_decision_sha256"] == ZERO_HASH:
            raise InferencePromotionError("demotion requires a prior promotion receipt")
        if verified["action"] == "promote" and not {"high_flyer", "outlier_501"}.issubset(verified["tags"]):
            raise InferencePromotionError("Outlier 501 promotion lacks required tags")
        if "abacus_math" in verified["tags"] and subject["task_family"] != "math":
            raise InferencePromotionError("Abacus tag is restricted to math")
        if "abacus_math" in verified["tags"]:
            authority = self.evaluators.get(subject["evaluator_id"])
            if authority is None or "math_evaluation" not in authority.capabilities:
                raise InferencePromotionError("Abacus tag lacks a trusted math evaluator")
        issued = _integer("issued_evidence_epoch", verified.get("issued_evidence_epoch"), 1, 2**63 - 1)
        valid_through = _integer(
            "valid_through_evidence_epoch",
            verified.get("valid_through_evidence_epoch"),
            issued,
            2**63 - 1,
        )
        if valid_through != issued + self.policy.promotion_ttl_epochs - 1:
            raise InferencePromotionError("decision expiry does not match policy")
        gate_refs = verified.get("seven_gates_receipt_sha256s")
        if not isinstance(gate_refs, list) or not gate_refs or gate_refs != sorted(set(gate_refs)):
            raise InferencePromotionError("Seven Gates references must be unique and sorted")
        for gate_ref in gate_refs:
            _hash("seven_gates_receipt_sha256", gate_ref)
        if verified.get("seven_gates_required") is not True:
            raise InferencePromotionError("promotion decision may not bypass Seven Gates")
        if verified.get("operational_authority_granted") is not False:
            raise InferencePromotionError("promotion receipt may not grant operational authority")
        return verified

    def verify_active_promotion(
        self,
        receipt: Mapping[str, Any],
        *,
        current_evidence_epoch: int,
        verified_seven_gates_receipt_sha256s: Sequence[str],
    ) -> dict[str, Any]:
        """Verify that an Outlier 501 card is current and gate-backed."""

        verified = self.verify_decision(receipt)
        if verified["action"] != "promote":
            raise InferencePromotionError("decision is not an active promotion")
        current = _integer("current_evidence_epoch", current_evidence_epoch, 1, 2**63 - 1)
        if current < verified["issued_evidence_epoch"]:
            raise InferencePromotionError("current evidence epoch predates promotion")
        if current > verified["valid_through_evidence_epoch"]:
            raise InferencePromotionError("promotion has expired")
        admitted_gates = set(verified_seven_gates_receipt_sha256s)
        for value in admitted_gates:
            _hash("verified Seven Gates receipt", value)
        if not set(verified["seven_gates_receipt_sha256s"]).issubset(admitted_gates):
            raise InferencePromotionError("promotion Seven Gates receipts were not independently admitted")
        return verified

    def demote(
        self,
        promotion_receipt: Mapping[str, Any],
        *,
        reason_code: str,
        evidence_sha256s: Sequence[str],
        evidence_epoch: int,
    ) -> dict[str, Any]:
        previous = self.verify_decision(promotion_receipt)
        if previous["action"] != "promote":
            raise InferencePromotionError("only a promotion can be demoted")
        if reason_code not in _DEMOTION_REASONS:
            raise InferencePromotionError("demotion reason is not predeclared")
        added = sorted(set(evidence_sha256s))
        if not added:
            raise InferencePromotionError("demotion requires new evidence")
        for value in added:
            _hash("demotion evidence", value)
        epoch = _integer("evidence_epoch", evidence_epoch, 1, 2**63 - 1)
        if epoch < previous["issued_evidence_epoch"]:
            raise InferencePromotionError("demotion evidence predates the promotion")
        body = {
            "schema_version": DECISION_SCHEMA,
            "action": "demote",
            "classification": "Quarantined Anomaly",
            "verification_tier": 0,
            "authority_id": self.authority_id,
            "policy_sha256": self.policy.sha256,
            "subject": previous["subject"],
            "tags": ["quarantined_anomaly"],
            "reason_codes": [reason_code],
            "metrics_summary": previous["metrics_summary"],
            "evidence_record_sha256s": sorted(set(previous["evidence_record_sha256s"] + added)),
            "artifact_reference": previous["artifact_reference"],
            "previous_decision_sha256": previous["receipt_sha256"],
            "issued_evidence_epoch": epoch,
            "valid_through_evidence_epoch": epoch + self.policy.promotion_ttl_epochs - 1,
            "seven_gates_receipt_sha256s": previous["seven_gates_receipt_sha256s"],
            "seven_gates_required": True,
            "operational_authority_granted": False,
            "benchmark_feedback_allowed": False,
        }
        return _seal(body, self.authority_key)

    def expire(
        self,
        promotion_receipt: Mapping[str, Any],
        *,
        current_evidence_epoch: int,
        expiry_evidence_sha256: str,
    ) -> dict[str, Any]:
        previous = self.verify_decision(promotion_receipt)
        current = _integer("current_evidence_epoch", current_evidence_epoch, 1, 2**63 - 1)
        if current <= previous["valid_through_evidence_epoch"]:
            raise InferencePromotionError("promotion has not expired")
        return self.demote(
            previous,
            reason_code="promotion_expired",
            evidence_sha256s=[_hash("expiry_evidence_sha256", expiry_evidence_sha256)],
            evidence_epoch=current,
        )

    def compose_flower(
        self,
        promotions: Sequence[Mapping[str, Any]],
        *,
        current_evidence_epoch: int,
        verified_seven_gates_receipt_sha256s: Sequence[str],
    ) -> dict[str, Any]:
        """Bind four promoted roles by hash without embedding or copying data."""

        current = _integer("current_evidence_epoch", current_evidence_epoch, 1, 2**63 - 1)
        verified = [
            self.verify_active_promotion(
                receipt,
                current_evidence_epoch=current,
                verified_seven_gates_receipt_sha256s=verified_seven_gates_receipt_sha256s,
            )
            for receipt in promotions
        ]
        if len(verified) != len(FLOWER_ROLES) or any(item["action"] != "promote" for item in verified):
            raise InferencePromotionError("Flower requires exactly four active promotions")
        by_role = {item["subject"]["flower_role"]: item for item in verified}
        if set(by_role) != set(FLOWER_ROLES):
            raise InferencePromotionError("Flower requires one distinct promotion for every role")
        policies = {item["policy_sha256"] for item in verified}
        if policies != {self.policy.sha256}:
            raise InferencePromotionError("Flower promotions must share one policy")
        artifacts = [item["artifact_reference"]["response_sha256"] for item in verified]
        sources = [item["artifact_reference"]["source_metric_receipt_sha256"] for item in verified]
        decisions = [item["receipt_sha256"] for item in verified]
        if len(set(artifacts)) != 4 or len(set(sources)) != 4 or len(set(decisions)) != 4:
            raise InferencePromotionError("Flower roles require distinct content-addressed evidence")
        anchors = [
            {
                "role": role,
                "decision_receipt_sha256": by_role[role]["receipt_sha256"],
                "artifact_sha256": by_role[role]["artifact_reference"]["response_sha256"],
                "source_metric_receipt_sha256": by_role[role]["artifact_reference"]["source_metric_receipt_sha256"],
            }
            for role in FLOWER_ROLES
        ]
        body = {
            "schema_version": FLOWER_SCHEMA,
            "authority_id": self.authority_id,
            "policy_sha256": self.policy.sha256,
            "purpose": "post-evaluation-routing",
            "evidence_epoch": current,
            "valid_through_evidence_epoch": min(item["valid_through_evidence_epoch"] for item in verified),
            "content_embedded": False,
            "benchmark_feedback_allowed": False,
            "seven_gates_required": True,
            "operational_authority_granted": False,
            "seven_gates_receipt_sha256s": sorted(
                {gate for item in verified for gate in item["seven_gates_receipt_sha256s"]}
            ),
            "role_anchors": anchors,
        }
        return _seal(body, self.authority_key)

    def verify_flower(self, manifest: Mapping[str, Any]) -> dict[str, Any]:
        body_fields = {
            "schema_version",
            "authority_id",
            "policy_sha256",
            "purpose",
            "evidence_epoch",
            "valid_through_evidence_epoch",
            "content_embedded",
            "benchmark_feedback_allowed",
            "seven_gates_required",
            "operational_authority_granted",
            "seven_gates_receipt_sha256s",
            "role_anchors",
        }
        verified = _verify_seal(manifest, self.authority_key, body_fields, "Flower manifest")
        if verified.get("schema_version") != FLOWER_SCHEMA:
            raise InferencePromotionError("unsupported Flower manifest schema")
        if verified.get("authority_id") != self.authority_id or verified.get("policy_sha256") != self.policy.sha256:
            raise InferencePromotionError("Flower authority or policy mismatch")
        if verified.get("purpose") != "post-evaluation-routing":
            raise InferencePromotionError("Flower may only route post-evaluation evidence")
        if verified.get("content_embedded") is not False or verified.get("benchmark_feedback_allowed") is not False:
            raise InferencePromotionError("Flower must remain reference-only and feedback-disabled")
        epoch = _integer("evidence_epoch", verified.get("evidence_epoch"), 1, 2**63 - 1)
        _integer(
            "valid_through_evidence_epoch",
            verified.get("valid_through_evidence_epoch"),
            epoch,
            2**63 - 1,
        )
        if verified.get("seven_gates_required") is not True or verified.get("operational_authority_granted") is not False:
            raise InferencePromotionError("Flower may not bypass Seven Gates or grant authority")
        gate_refs = verified.get("seven_gates_receipt_sha256s")
        if not isinstance(gate_refs, list) or not gate_refs or gate_refs != sorted(set(gate_refs)):
            raise InferencePromotionError("Flower Seven Gates references must be unique and sorted")
        for gate_ref in gate_refs:
            _hash("seven_gates_receipt_sha256", gate_ref)
        anchors = verified.get("role_anchors")
        if not isinstance(anchors, list) or len(anchors) != 4:
            raise InferencePromotionError("Flower requires four role anchors")
        roles: list[str] = []
        artifacts: list[str] = []
        sources: list[str] = []
        decisions: list[str] = []
        for anchor in anchors:
            _exact_fields(
                anchor,
                {"role", "decision_receipt_sha256", "artifact_sha256", "source_metric_receipt_sha256"},
                "Flower anchor",
            )
            if anchor["role"] not in FLOWER_ROLES:
                raise InferencePromotionError("invalid Flower anchor role")
            roles.append(anchor["role"])
            artifacts.append(_hash("artifact_sha256", anchor["artifact_sha256"]))
            sources.append(_hash("source_metric_receipt_sha256", anchor["source_metric_receipt_sha256"]))
            decisions.append(_hash("decision_receipt_sha256", anchor["decision_receipt_sha256"]))
        if tuple(roles) != FLOWER_ROLES:
            raise InferencePromotionError("Flower anchors are not in canonical role order")
        if any(len(set(values)) != 4 for values in (artifacts, sources, decisions)):
            raise InferencePromotionError("Flower anchor references must be distinct")
        return verified

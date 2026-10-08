import hashlib
import hmac
import json
import unittest
from unittest.mock import patch

from xnet.legions import (
    MAX_WIRE_BYTES,
    MAX_QUANTITY,
    MAX_REPLAY_CAPACITY,
    AcceptedJob,
    Budget,
    CapabilityCard,
    JobCapsule,
    LegionsControl,
    LegionsError,
    ResourceUsage,
    WorkerGate,
    WorkerPolicy,
    sign_result_receipt,
    verify_result_receipt,
)
from xnet.protocol import canonical, sha256


def budget(**changes):
    values = {
        "wall_time_ms": 1_000,
        "cpu_time_ms": 800,
        "memory_bytes": 4_000_000,
        "input_bytes": 20_000,
        "output_bytes": 10_000,
        "tokens": 500,
        "cost_microunits": 25_000,
    }
    values.update(changes)
    return Budget(**values)


class LegionsProtocolTests(unittest.TestCase):
    NOW = 1_700_000_000_000
    KEY = bytes(range(32))
    INPUT = sha256(b"caller-owned input")
    OUTPUT = sha256(b"worker output")

    def setUp(self):
        self.card = CapabilityCard(
            worker_id="worker.alpha",
            task_types=("hash.verify", "model.infer"),
            capabilities=("cpu", "model.local"),
            limits=budget(wall_time_ms=2_000, cpu_time_ms=1_600),
        )
        self.policy = WorkerPolicy(
            allowed_coordinator_ids=("coordinator.friend",),
            allowed_task_types=("model.infer",),
            allowed_capabilities=("cpu", "model.local"),
            maximum_budget=budget(),
        )
        self.job = JobCapsule(
            task_type="model.infer",
            input_sha256s=(self.INPUT,),
            required_capabilities=("cpu", "model.local"),
            budget=budget(),
            coordinator_id="coordinator.friend",
            target_worker_id="worker.alpha",
            expires_at_ms=self.NOW + 10_000,
            nonce="11" * 16,
        )
        self.control = LegionsControl()
        self.gate = WorkerGate(self.card, self.policy, self.control)

    def accept(
        self,
        job=None,
        *,
        control=None,
        authenticated_coordinator_id=None,
        now_ms=None,
    ):
        selected = job or self.job
        gate = self.gate if control is None else WorkerGate(self.card, self.policy, control)
        coordinator = authenticated_coordinator_id or selected.coordinator_id
        return gate.accept(
            selected.to_wire(),
            expected_sha256=selected.sha256,
            authenticated_coordinator_id=coordinator,
            now_ms=self.NOW if now_ms is None else now_ms,
        )

    def receipt(self, accepted):
        usage = ResourceUsage(
            wall_time_ms=100,
            cpu_time_ms=70,
            memory_bytes=2_000_000,
            input_bytes=1_000,
            output_bytes=500,
            tokens=42,
            cost_microunits=1_500,
        )
        with patch("xnet.legions._now_ms", return_value=self.NOW + 110):
            raw = sign_result_receipt(
                accepted,
                output_sha256s=(self.OUTPUT,),
                started_at_ms=self.NOW + 10,
                finished_at_ms=self.NOW + 110,
                usage=usage,
                key=self.KEY,
            )
        return raw, usage

    def test_happy_path_card_job_acceptance_and_signed_result(self):
        card_wire = self.card.to_wire()
        self.assertEqual(card_wire, canonical(json.loads(card_wire)))
        self.assertEqual(
            CapabilityCard.from_wire(card_wire, expected_sha256=self.card.sha256),
            self.card,
        )

        accepted = self.accept()
        raw, usage = self.receipt(accepted)
        with patch("xnet.legions._now_ms", return_value=self.NOW + 110):
            receipt = verify_result_receipt(
                raw,
                expected_sha256=sha256(raw),
                expected_job=self.job,
                expected_worker_id="worker.alpha",
                key=self.KEY,
                control=self.control,
            )
        self.assertEqual(receipt.job_sha256, self.job.sha256)
        self.assertEqual(receipt.output_sha256s, (self.OUTPUT,))
        self.assertEqual(receipt.usage, usage)
        self.assertEqual(receipt.finished_at_ms - receipt.started_at_ms, 100)
        self.assertNotIn(self.KEY.hex(), raw.decode("utf-8"))

    def test_tampered_job_and_receipt_are_refused(self):
        value = json.loads(self.job.to_wire())
        value["task_type"] = "hash.verify"
        tampered_job = canonical(value)
        with self.assertRaises(LegionsError):
            self.gate.accept(
                tampered_job,
                expected_sha256=self.job.sha256,
                authenticated_coordinator_id=self.job.coordinator_id,
                now_ms=self.NOW,
            )

        accepted = self.accept()
        raw, _ = self.receipt(accepted)
        value = json.loads(raw)
        value["output_sha256s"] = [sha256(b"attacker output")]
        body = {
            key: item
            for key, item in value.items()
            if key not in {"receipt_sha256", "hmac_sha256"}
        }
        value["receipt_sha256"] = sha256(canonical(body))
        tampered_receipt = canonical(value)
        with self.assertRaises(LegionsError):
            verify_result_receipt(
                tampered_receipt,
                expected_sha256=sha256(tampered_receipt),
                expected_job=self.job,
                expected_worker_id="worker.alpha",
                key=self.KEY,
                control=self.control,
            )

    def test_expired_job_is_refused_without_consuming_replay_slot(self):
        with self.assertRaises(LegionsError):
            self.gate.accept(
                self.job.to_wire(),
                expected_sha256=self.job.sha256,
                authenticated_coordinator_id=self.job.coordinator_id,
                now_ms=self.job.expires_at_ms,
            )
        accepted = self.accept()
        self.assertEqual(accepted.job_sha256, self.job.sha256)

    def test_task_capability_and_budget_gates_are_all_required(self):
        jobs = (
            JobCapsule(
                task_type="hash.verify",
                input_sha256s=self.job.input_sha256s,
                required_capabilities=self.job.required_capabilities,
                budget=self.job.budget,
                coordinator_id=self.job.coordinator_id,
                target_worker_id=self.job.target_worker_id,
                expires_at_ms=self.job.expires_at_ms,
                nonce="22" * 16,
            ),
            JobCapsule(
                task_type=self.job.task_type,
                input_sha256s=self.job.input_sha256s,
                required_capabilities=("gpu",),
                budget=self.job.budget,
                coordinator_id=self.job.coordinator_id,
                target_worker_id=self.job.target_worker_id,
                expires_at_ms=self.job.expires_at_ms,
                nonce="33" * 16,
            ),
            JobCapsule(
                task_type=self.job.task_type,
                input_sha256s=self.job.input_sha256s,
                required_capabilities=self.job.required_capabilities,
                budget=budget(tokens=501),
                coordinator_id=self.job.coordinator_id,
                target_worker_id=self.job.target_worker_id,
                expires_at_ms=self.job.expires_at_ms,
                nonce="44" * 16,
            ),
        )
        for job in jobs:
            with self.subTest(job=job.nonce), self.assertRaises(LegionsError):
                self.accept(job)

    def test_job_and_result_replay_are_refused(self):
        accepted = self.accept()
        with self.assertRaises(LegionsError):
            self.accept()
        changed_same_nonce = JobCapsule(
            task_type=self.job.task_type,
            input_sha256s=self.job.input_sha256s,
            required_capabilities=self.job.required_capabilities,
            budget=budget(tokens=499),
            coordinator_id=self.job.coordinator_id,
            target_worker_id=self.job.target_worker_id,
            expires_at_ms=self.job.expires_at_ms,
            nonce=self.job.nonce,
        )
        with self.assertRaises(LegionsError):
            self.accept(changed_same_nonce)

        raw, _ = self.receipt(accepted)
        arguments = {
            "expected_sha256": sha256(raw),
            "expected_job": self.job,
            "expected_worker_id": "worker.alpha",
            "key": self.KEY,
            "control": self.control,
        }
        with patch("xnet.legions._now_ms", return_value=self.NOW + 110):
            verify_result_receipt(raw, **arguments)
            with self.assertRaises(LegionsError):
                verify_result_receipt(raw, **arguments)

    def test_receipt_is_bound_to_worker_job_and_key(self):
        accepted = self.accept()
        raw, _ = self.receipt(accepted)
        alternate_job = JobCapsule(
            task_type=self.job.task_type,
            input_sha256s=self.job.input_sha256s,
            required_capabilities=self.job.required_capabilities,
            budget=self.job.budget,
            coordinator_id=self.job.coordinator_id,
            target_worker_id=self.job.target_worker_id,
            expires_at_ms=self.job.expires_at_ms,
            nonce="55" * 16,
        )
        cases = (
            {"expected_job": alternate_job, "expected_worker_id": "worker.alpha", "key": self.KEY},
            {"expected_job": self.job, "expected_worker_id": "worker.beta", "key": self.KEY},
            {"expected_job": self.job, "expected_worker_id": "worker.alpha", "key": b"x" * 32},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(LegionsError):
                verify_result_receipt(
                    raw,
                    expected_sha256=sha256(raw),
                    control=LegionsControl(),
                    **changes,
                )

    def test_revoked_nodes_and_kill_switch_refuse_work_and_results(self):
        revoked_coordinator = LegionsControl()
        revoked_coordinator.revoke_node("coordinator.friend")
        with self.assertRaises(LegionsError):
            self.accept(control=revoked_coordinator)

        killed = LegionsControl()
        killed.kill()
        with self.assertRaises(LegionsError):
            self.accept(control=killed)

        accepted = self.accept()
        raw, _ = self.receipt(accepted)
        self.control.kill()
        with self.assertRaises(LegionsError):
            self.receipt(accepted)
        self.control.restore()
        self.control.revoke_node("worker.alpha")
        with patch("xnet.legions._now_ms", return_value=self.NOW + 110):
            with self.assertRaises(LegionsError):
                verify_result_receipt(
                    raw,
                    expected_sha256=sha256(raw),
                    expected_job=self.job,
                    expected_worker_id="worker.alpha",
                    key=self.KEY,
                    control=self.control,
                )

    def test_mutable_inputs_are_snapshotted_before_policy_use(self):
        coordinator_ids = ["coordinator.friend"]
        task_types = ["model.infer"]
        capabilities = ["cpu"]
        input_hashes = [self.INPUT]
        required_capabilities = ["cpu"]
        card = CapabilityCard("worker.alpha", task_types, capabilities, budget())
        policy = WorkerPolicy(
            coordinator_ids, task_types, capabilities, budget()
        )
        job = JobCapsule(
            task_type="model.infer",
            input_sha256s=input_hashes,
            required_capabilities=required_capabilities,
            budget=budget(),
            coordinator_id="coordinator.friend",
            target_worker_id="worker.alpha",
            expires_at_ms=self.NOW + 10_000,
            nonce="66" * 16,
        )

        coordinator_ids.append("coordinator.attacker")
        task_types.append("unsafe.exec")
        capabilities.append("shell")
        input_hashes.append(sha256(b"later input"))
        required_capabilities.append("shell")

        self.assertEqual(policy.allowed_coordinator_ids, ("coordinator.friend",))
        self.assertEqual(policy.allowed_task_types, ("model.infer",))
        self.assertEqual(policy.allowed_capabilities, ("cpu",))
        self.assertEqual(card.task_types, ("model.infer",))
        self.assertEqual(card.capabilities, ("cpu",))
        self.assertEqual(job.input_sha256s, (self.INPUT,))
        self.assertEqual(job.required_capabilities, ("cpu",))
        attacker_job = JobCapsule(
            task_type="model.infer",
            input_sha256s=(self.INPUT,),
            required_capabilities=("cpu",),
            budget=budget(),
            coordinator_id="coordinator.attacker",
            target_worker_id="worker.alpha",
            expires_at_ms=self.NOW + 10_000,
            nonce="77" * 16,
        )
        with self.assertRaises(LegionsError):
            WorkerGate(card, policy, LegionsControl()).accept(
                attacker_job.to_wire(),
                expected_sha256=attacker_job.sha256,
                authenticated_coordinator_id=attacker_job.coordinator_id,
                now_ms=self.NOW,
            )

    def test_job_is_bound_to_one_target_worker(self):
        alternate_card = CapabilityCard(
            worker_id="worker.beta",
            task_types=self.card.task_types,
            capabilities=self.card.capabilities,
            limits=self.card.limits,
        )
        alternate_gate = WorkerGate(alternate_card, self.policy, LegionsControl())
        with self.assertRaises(LegionsError):
            alternate_gate.accept(
                self.job.to_wire(),
                expected_sha256=self.job.sha256,
                authenticated_coordinator_id=self.job.coordinator_id,
                now_ms=self.NOW,
            )

    def test_authenticated_coordinator_must_match_capsule_identity(self):
        with self.assertRaises(TypeError):
            self.gate.accept(
                self.job.to_wire(),
                expected_sha256=self.job.sha256,
                now_ms=self.NOW,
            )
        with self.assertRaises(LegionsError):
            self.gate.accept(
                self.job.to_wire(),
                expected_sha256=self.job.sha256,
                authenticated_coordinator_id="coordinator.attacker",
                now_ms=self.NOW,
            )
        accepted = self.accept()
        self.assertEqual(accepted.job.coordinator_id, "coordinator.friend")

    def test_replay_capacity_fails_closed_until_expiry_pruning(self):
        control = LegionsControl(replay_capacity=1)
        accepted = self.accept(control=control)
        _, usage = self.receipt(accepted)
        later_job = JobCapsule(
            task_type=self.job.task_type,
            input_sha256s=self.job.input_sha256s,
            required_capabilities=self.job.required_capabilities,
            budget=self.job.budget,
            coordinator_id=self.job.coordinator_id,
            target_worker_id=self.job.target_worker_id,
            expires_at_ms=self.NOW + 20_000,
            nonce="88" * 16,
        )
        with self.assertRaises(LegionsError):
            self.accept(later_job, control=control, now_ms=self.NOW + 111)

        accepted_later = self.accept(
            later_job,
            control=control,
            now_ms=self.job.expires_at_ms,
        )
        with patch(
            "xnet.legions._now_ms", return_value=self.job.expires_at_ms + 110
        ):
            raw = sign_result_receipt(
                accepted_later,
                output_sha256s=(self.OUTPUT,),
                started_at_ms=self.job.expires_at_ms + 10,
                finished_at_ms=self.job.expires_at_ms + 110,
                usage=usage,
                key=self.KEY,
            )
        self.assertTrue(raw)
        for invalid_capacity in (0, MAX_REPLAY_CAPACITY + 1, True):
            with self.subTest(capacity=invalid_capacity), self.assertRaises(LegionsError):
                LegionsControl(replay_capacity=invalid_capacity)

    def test_replay_pruning_refuses_clock_rollback(self):
        control = LegionsControl(replay_capacity=1)
        self.accept(control=control)
        later_job = JobCapsule(
            task_type=self.job.task_type,
            input_sha256s=self.job.input_sha256s,
            required_capabilities=self.job.required_capabilities,
            budget=self.job.budget,
            coordinator_id=self.job.coordinator_id,
            target_worker_id=self.job.target_worker_id,
            expires_at_ms=self.NOW + 20_000,
            nonce="89" * 16,
        )
        with self.assertRaises(LegionsError):
            self.accept(later_job, control=control, now_ms=self.NOW - 1)

    def test_receipt_capacity_prunes_without_reopening_expired_replays(self):
        accepted = self.accept()
        first_raw, _ = self.receipt(accepted)
        later_job = JobCapsule(
            task_type=self.job.task_type,
            input_sha256s=self.job.input_sha256s,
            required_capabilities=self.job.required_capabilities,
            budget=self.job.budget,
            coordinator_id=self.job.coordinator_id,
            target_worker_id=self.job.target_worker_id,
            expires_at_ms=self.NOW + 20_000,
            nonce="99" * 16,
        )
        later_accepted = self.accept(later_job, control=LegionsControl())
        second_raw, _ = self.receipt(later_accepted)
        verifier = LegionsControl(replay_capacity=1)
        with patch("xnet.legions._now_ms", return_value=self.NOW + 110):
            verify_result_receipt(
                first_raw,
                expected_sha256=sha256(first_raw),
                expected_job=self.job,
                expected_worker_id="worker.alpha",
                key=self.KEY,
                control=verifier,
            )
            with self.assertRaises(LegionsError):
                verify_result_receipt(
                    second_raw,
                    expected_sha256=sha256(second_raw),
                    expected_job=later_job,
                    expected_worker_id="worker.alpha",
                    key=self.KEY,
                    control=verifier,
                )

        with patch(
            "xnet.legions._now_ms", return_value=self.job.expires_at_ms
        ):
            with self.assertRaises(LegionsError):
                verify_result_receipt(
                    first_raw,
                    expected_sha256=sha256(first_raw),
                    expected_job=self.job,
                    expected_worker_id="worker.alpha",
                    key=self.KEY,
                    control=verifier,
                )
            verified = verify_result_receipt(
                second_raw,
                expected_sha256=sha256(second_raw),
                expected_job=later_job,
                expected_worker_id="worker.alpha",
                key=self.KEY,
                control=verifier,
            )
        self.assertEqual(verified.job_sha256, later_job.sha256)

    def test_wire_quantities_stay_within_json_safe_integer_range(self):
        self.assertEqual(MAX_QUANTITY, 2**53 - 1)
        with self.assertRaises(LegionsError):
            budget(memory_bytes=MAX_QUANTITY + 1)

    def test_only_one_result_can_be_signed_and_verified_per_job(self):
        accepted = self.accept()
        raw, usage = self.receipt(accepted)
        with patch("xnet.legions._now_ms", return_value=self.NOW + 120):
            with self.assertRaises(LegionsError):
                sign_result_receipt(
                    accepted,
                    output_sha256s=(sha256(b"second output"),),
                    started_at_ms=self.NOW + 20,
                    finished_at_ms=self.NOW + 120,
                    usage=usage,
                    key=self.KEY,
                )

        verifier = LegionsControl()
        with patch("xnet.legions._now_ms", return_value=self.NOW + 110):
            verify_result_receipt(
                raw,
                expected_sha256=sha256(raw),
                expected_job=self.job,
                expected_worker_id="worker.alpha",
                key=self.KEY,
                control=verifier,
            )

        distinct = json.loads(raw)
        distinct["output_sha256s"] = [sha256(b"distinct output")]
        body = {
            key: item
            for key, item in distinct.items()
            if key not in {"receipt_sha256", "hmac_sha256"}
        }
        distinct["receipt_sha256"] = sha256(canonical(body))
        signed = {
            key: item for key, item in distinct.items() if key != "hmac_sha256"
        }
        distinct["hmac_sha256"] = hmac.new(
            self.KEY, canonical(signed), hashlib.sha256
        ).hexdigest()
        distinct_wire = canonical(distinct)
        with patch("xnet.legions._now_ms", return_value=self.NOW + 110):
            with self.assertRaises(LegionsError):
                verify_result_receipt(
                    distinct_wire,
                    expected_sha256=sha256(distinct_wire),
                    expected_job=self.job,
                    expected_worker_id="worker.alpha",
                    key=self.KEY,
                    control=verifier,
                )

        alternate_key = b"z" * 32
        value = json.loads(raw)
        signed = {key: item for key, item in value.items() if key != "hmac_sha256"}
        value["hmac_sha256"] = hmac.new(
            alternate_key, canonical(signed), hashlib.sha256
        ).hexdigest()
        alternate_wire = canonical(value)
        with patch("xnet.legions._now_ms", return_value=self.NOW + 110):
            with self.assertRaises(LegionsError):
                verify_result_receipt(
                    alternate_wire,
                    expected_sha256=sha256(alternate_wire),
                    expected_job=self.job,
                    expected_worker_id="worker.alpha",
                    key=alternate_key,
                    control=verifier,
                )

    def test_result_cannot_be_backdated_after_job_expiry(self):
        accepted = self.accept()
        usage = ResourceUsage(
            wall_time_ms=100,
            cpu_time_ms=70,
            memory_bytes=2_000_000,
            input_bytes=1_000,
            output_bytes=500,
            tokens=42,
            cost_microunits=1_500,
        )
        with patch("xnet.legions._now_ms", return_value=self.job.expires_at_ms):
            with self.assertRaises(LegionsError):
                sign_result_receipt(
                    accepted,
                    output_sha256s=(self.OUTPUT,),
                    started_at_ms=self.NOW + 10,
                    finished_at_ms=self.NOW + 110,
                    usage=usage,
                    key=self.KEY,
                )

    def test_accepted_job_cannot_be_forged_outside_worker_gate(self):
        with self.assertRaises(LegionsError):
            AcceptedJob(
                self.job,
                self.job.sha256,
                "worker.alpha",
                self.NOW,
                LegionsControl(),
            )

        forged = AcceptedJob._issue(
            self.job,
            self.job.sha256,
            "worker.alpha",
            self.NOW,
            LegionsControl(),
        )
        usage = ResourceUsage(100, 70, 1, 1, 1, 1, 1)
        with patch("xnet.legions._now_ms", return_value=self.NOW + 110):
            with self.assertRaises(LegionsError):
                sign_result_receipt(
                    forged,
                    output_sha256s=(self.OUTPUT,),
                    started_at_ms=self.NOW + 10,
                    finished_at_ms=self.NOW + 110,
                    usage=usage,
                    key=self.KEY,
                )

    def test_oversized_wire_is_rejected_before_hashing(self):
        oversized = b"x" * (MAX_WIRE_BYTES + 1)
        with patch("xnet.legions.sha256") as digest:
            with self.assertRaises(LegionsError):
                JobCapsule.from_wire(oversized, expected_sha256="0" * 64)
        digest.assert_not_called()


if __name__ == "__main__":
    unittest.main()

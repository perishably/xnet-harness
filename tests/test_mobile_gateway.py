"""Gateway state-machine tests with a fake dispatcher and no listener/model."""
from __future__ import annotations

import json
import ssl
import unittest

from xnet.mobile_gateway import (
    AppleNativeOutcomeProof,
    GatewayDispatchUncertain,
    GatewayResult,
    MobileGateway,
    MobileGatewayConfig,
    MobileGatewayError,
    TransportContext,
)
from xnet.mobile_pairing import PairingAuthority
from xnet.mobile_protocol import (
    build_pair_request,
    build_request,
    inspect_pair_response,
    inspect_response,
)
from xnet.protocol import canonical, sha256


class Entropy:
    def __init__(self):
        self.value = 10

    def __call__(self, size):
        self.value += 1
        return bytes([self.value]) * size


class MobileGatewayTests(unittest.TestCase):
    def setUp(self):
        self.now = [10_000]
        self.pairing = PairingAuthority(clock=lambda: self.now[0], random_bytes=Entropy())
        self.calls = []

        def dispatch(request):
            self.calls.append(request)
            identity = "d" * 64 if request["route"]["requested_lane"] == "home-4b" else "e" * 64
            return GatewayResult(request["route"]["requested_lane"], identity,
                                 "fixed answer for " + request["input"]["task_id"])

        self.apple_proofs = []

        def verify_apple_outcome(proof):
            self.apple_proofs.append(proof)
            return (type(proof) is AppleNativeOutcomeProof
                    and proof.outcome_sha256 == "c" * 64)

        self.verify_apple_outcome = verify_apple_outcome

        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.config = MobileGatewayConfig("100.64.7.9", 7443, tls, "d" * 64, "e" * 64)
        self.gateway = MobileGateway(self.config, self.pairing, dispatch,
                                     evidence_checker=lambda hce, sources: True,
                                     apple_outcome_checker=self.verify_apple_outcome,
                                     clock=lambda: self.now[0])
        self.transport = TransportContext("100.64.7.10", True)
        invitation = self.pairing.issue()
        response = self.gateway.handle_pair(self.transport, build_pair_request(
            code=invitation.code, device_id="iphone-1", device_name="Felix iPhone"))
        self.credential = inspect_pair_response(response)
        self.authorization = "Bearer " + self.credential["bearer_token"]

    def request(self, sequence=1, request_id="request-1", prompt="Repair it",
                lane="home-4b", prior="c" * 64):
        return build_request(
            request_id=request_id, device_id="iphone-1", sequence=sequence,
            sent_at=self.now[0], task_id="repair-1", prompt=prompt,
            hce_sha256="a" * 64, source_sha256=["b" * 64],
            requested_lane=lane, prior_outcome_sha256=prior)

    def test_config_requires_caller_tls_and_never_accepts_loopback_or_public_bind(self):
        self.assertEqual(self.gateway.listener_contract(),
                         ("100.64.7.9", 7443, self.config.tls_context))
        for address in ("127.0.0.1", "0.0.0.0", "8.8.8.8", "gateway.example"):
            with self.subTest(address=address), self.assertRaises(MobileGatewayError):
                MobileGatewayConfig(address, 7443, ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),
                                    "d" * 64, "e" * 64)
        with self.assertRaises(MobileGatewayError):
            MobileGatewayConfig("100.64.7.9", 7443, None, "d" * 64, "e" * 64)
        with self.assertRaises(MobileGatewayError):
            MobileGatewayConfig("100.64.7.9", 7443,
                                ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), "d" * 64, "e" * 64)
        with self.assertRaises(MobileGatewayError):
            MobileGatewayConfig("100.64.7.9", 7443,
                                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), "d" * 64, "d" * 64)

    def test_request_dispatches_once_and_exact_replay_returns_identical_bytes(self):
        wire = self.request()
        first = self.gateway.handle_request(self.transport, self.authorization, wire)
        replay = self.gateway.handle_request(self.transport, self.authorization, wire)
        self.assertFalse(first.idempotent_replay)
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual(first.wire, replay.wire)
        self.assertEqual(len(self.calls), 1)
        value = inspect_response(first.wire, expected_request_wire=wire)
        self.assertEqual(value["selected_lane"], "home-4b")
        self.assertEqual(value["evidence"]["hce_sha256"], "a" * 64)
        self.assertEqual(value["evidence"]["source_sha256"], ["b" * 64])
        self.assertEqual(value["policy"]["tool_authority"], "none")
        self.assertEqual(len(self.apple_proofs), 1)
        self.assertEqual(self.apple_proofs[0].request_sequence, 1)
        self.assertEqual(self.apple_proofs[0].device_id, "iphone-1")
        self.assertEqual(self.apple_proofs[0].task_id, "repair-1")
        self.assertEqual(self.apple_proofs[0].prompt_sha256, sha256(b"Repair it"))
        self.assertEqual(self.apple_proofs[0].hce_sha256, "a" * 64)
        self.assertEqual(self.apple_proofs[0].source_sha256, ("b" * 64,))

    def test_4b_requires_trusted_exact_immediately_prior_apple_outcome(self):
        no_checker = MobileGateway(
            self.config, self.pairing,
            lambda request: self.fail("dispatcher must not run"),
            evidence_checker=lambda hce, sources: True,
            clock=lambda: self.now[0])
        with self.assertRaisesRegex(MobileGatewayError, "prior Apple-native"):
            no_checker.handle_request(self.transport, self.authorization, self.request())

        with self.assertRaisesRegex(MobileGatewayError, "prior Apple-native"):
            self.gateway.handle_request(
                self.transport, self.authorization, self.request(prior="0" * 64))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.apple_proofs[-1].outcome_sha256, "0" * 64)

    def test_exact_completed_replay_survives_freshness_window(self):
        wire = self.request()
        first = self.gateway.handle_request(self.transport, self.authorization, wire)
        self.now[0] += self.config.maximum_request_age_seconds + 1
        replay = self.gateway.handle_request(self.transport, self.authorization, wire)
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual(replay.wire, first.wire)
        self.assertEqual(len(self.calls), 1)

    def test_14b_requires_matching_immediately_prior_4b_response(self):
        invalid = self.request(lane="home-14b", prior="0" * 64)
        with self.assertRaisesRegex(MobileGatewayError, "prior 4B"):
            self.gateway.handle_request(self.transport, self.authorization, invalid)
        self.assertEqual(self.calls, [])
        four = self.gateway.handle_request(self.transport, self.authorization, self.request())
        changed_prompt = self.request(sequence=2, request_id="request-2", prompt="changed",
                                      lane="home-14b", prior=sha256(four.wire))
        with self.assertRaisesRegex(MobileGatewayError, "prior 4B"):
            self.gateway.handle_request(self.transport, self.authorization, changed_prompt)
        home = self.request(sequence=2, request_id="request-2", lane="home-14b",
                            prior=sha256(four.wire))
        answer = self.gateway.handle_request(self.transport, self.authorization, home)
        self.assertEqual(inspect_response(
            answer.wire, expected_request_wire=home)["selected_lane"], "home-14b")
        self.assertEqual(len(self.calls), 2)

    def test_conflicting_replay_gap_and_request_id_reuse_are_refused(self):
        self.gateway.handle_request(self.transport, self.authorization, self.request())
        with self.assertRaises(MobileGatewayError):
            self.gateway.handle_request(self.transport, self.authorization,
                                        self.request(prompt="changed"))
        with self.assertRaises(MobileGatewayError):
            self.gateway.handle_request(self.transport, self.authorization,
                                        self.request(sequence=3, request_id="request-3"))
        self.gateway.handle_request(self.transport, self.authorization,
                                    self.request(sequence=2, request_id="request-2"))
        with self.assertRaises(MobileGatewayError):
            self.gateway.handle_request(self.transport, self.authorization,
                                        self.request(sequence=3, request_id="request-2"))

    def test_tls_private_peer_fresh_time_device_and_revocation_are_required(self):
        wire = self.request()
        with self.assertRaises(MobileGatewayError):
            self.gateway.handle_request(TransportContext("100.64.7.10", False),
                                        self.authorization, wire)
        with self.assertRaises(MobileGatewayError):
            self.gateway.handle_request(TransportContext("8.8.8.8", True),
                                        self.authorization, wire)
        stale = build_request(request_id="stale", device_id="iphone-1", sequence=1,
            sent_at=self.now[0] - 301, task_id="repair-1", prompt="Repair it",
            hce_sha256="a" * 64, source_sha256=["b" * 64],
            requested_lane="home-4b", prior_outcome_sha256="c" * 64)
        with self.assertRaises(MobileGatewayError):
            self.gateway.handle_request(self.transport, self.authorization, stale)
        other = build_request(request_id="other", device_id="iphone-2", sequence=1,
            sent_at=self.now[0], task_id="repair-1", prompt="Repair it",
            hce_sha256="a" * 64, source_sha256=["b" * 64],
            requested_lane="home-4b", prior_outcome_sha256="c" * 64)
        with self.assertRaises(MobileGatewayError):
            self.gateway.handle_request(self.transport, self.authorization, other)
        self.assertTrue(self.pairing.revoke_device("iphone-1"))
        with self.assertRaises(MobileGatewayError):
            self.gateway.handle_request(self.transport, self.authorization, wire)
        self.assertEqual(self.calls, [])

    def test_uncertain_dispatch_is_not_blindly_replayed_and_can_be_reconciled(self):
        calls = []

        def uncertain(request):
            calls.append(request)
            raise RuntimeError("possibly after dispatch; secret details")

        gateway = MobileGateway(self.config, self.pairing, uncertain,
                                evidence_checker=lambda hce, sources: True,
                                apple_outcome_checker=self.verify_apple_outcome,
                                clock=lambda: self.now[0])
        wire = self.request()
        with self.assertRaisesRegex(GatewayDispatchUncertain, "reconcile") as first:
            gateway.handle_request(self.transport, self.authorization, wire)
        self.assertNotIn("secret details", str(first.exception))
        with self.assertRaises(GatewayDispatchUncertain):
            gateway.handle_request(self.transport, self.authorization, wire)
        self.assertEqual(len(calls), 1)
        pending = gateway.pending_dispatch("iphone-1")
        self.assertEqual(pending.request_sha256, sha256(wire))
        committed = gateway.reconcile_pending(
            device_id="iphone-1", credential_generation=pending.credential_generation,
            request_wire=wire,
            result=GatewayResult("home-4b", "d" * 64, "retained result"))
        replay = gateway.handle_request(self.transport, self.authorization, wire)
        self.assertEqual(committed.wire, replay.wire)
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual(len(calls), 1)

    def test_policy_mutation_is_rejected_before_dispatch(self):
        value = json.loads(self.request())
        value["policy"]["tool_authority"] = "execute"
        with self.assertRaises(MobileGatewayError):
            self.gateway.handle_request(self.transport, self.authorization, canonical(value))
        self.assertEqual(self.calls, [])

    def test_unresolved_hce_or_source_hashes_are_refused_before_dispatch(self):
        gateway = MobileGateway(
            self.config, self.pairing,
            lambda request: self.fail("dispatcher must not run"),
            evidence_checker=lambda hce, sources: False,
            apple_outcome_checker=self.verify_apple_outcome,
            clock=lambda: self.now[0])
        with self.assertRaisesRegex(MobileGatewayError, "not verified"):
            gateway.handle_request(self.transport, self.authorization, self.request())

    def test_reentrant_evidence_check_cannot_duplicate_dispatch(self):
        wire = self.request()
        dispatches = []
        reentered = [False]
        gateway = None

        def checker(hce, sources):
            if not reentered[0]:
                reentered[0] = True
                with self.assertRaises(GatewayDispatchUncertain):
                    gateway.handle_request(self.transport, self.authorization, wire)
            return True

        def dispatch(request):
            dispatches.append(request)
            return GatewayResult("home-4b", "d" * 64, "one answer")

        gateway = MobileGateway(self.config, self.pairing, dispatch,
                                evidence_checker=checker,
                                apple_outcome_checker=self.verify_apple_outcome,
                                clock=lambda: self.now[0])
        reply = gateway.handle_request(self.transport, self.authorization, wire)
        self.assertFalse(reply.idempotent_replay)
        self.assertEqual(len(dispatches), 1)

    def test_revoked_then_repaired_device_gets_a_fresh_sequence_namespace(self):
        self.gateway.handle_request(self.transport, self.authorization, self.request())
        self.assertTrue(self.pairing.revoke_device("iphone-1"))
        invitation = self.pairing.issue()
        response = self.gateway.handle_pair(self.transport, build_pair_request(
            code=invitation.code, device_id="iphone-1", device_name="Felix iPhone"))
        replacement = inspect_pair_response(response)
        fresh = self.request(sequence=1, request_id="fresh-request")
        reply = self.gateway.handle_request(
            self.transport, "Bearer " + replacement["bearer_token"], fresh)
        self.assertFalse(reply.idempotent_replay)
        self.assertEqual(len(self.calls), 2)

    def test_request_identifier_tombstone_survives_response_cache_eviction(self):
        small = MobileGatewayConfig("100.64.7.9", 7443, self.config.tls_context,
                                    "d" * 64, "e" * 64, replay_entries_per_device=1)

        def dispatch(request):
            return GatewayResult("home-4b", "d" * 64, "answer")

        gateway = MobileGateway(small, self.pairing, dispatch,
                                evidence_checker=lambda hce, sources: True,
                                apple_outcome_checker=self.verify_apple_outcome,
                                clock=lambda: self.now[0])
        gateway.handle_request(self.transport, self.authorization,
                               self.request(sequence=1, request_id="same"))
        gateway.handle_request(self.transport, self.authorization,
                               self.request(sequence=2, request_id="other"))
        with self.assertRaisesRegex(MobileGatewayError, "identifier was reused"):
            gateway.handle_request(self.transport, self.authorization,
                                   self.request(sequence=3, request_id="same"))

    def test_revoked_distinct_device_state_is_pruned_before_global_limit(self):
        bounded = MobileGatewayConfig("100.64.7.9", 7443, self.config.tls_context,
                                      "d" * 64, "e" * 64, maximum_gateway_states=1)

        def dispatch(request):
            return GatewayResult("home-4b", "d" * 64, "answer")

        gateway = MobileGateway(bounded, self.pairing, dispatch,
                                evidence_checker=lambda hce, sources: True,
                                apple_outcome_checker=self.verify_apple_outcome,
                                clock=lambda: self.now[0])
        gateway.handle_request(self.transport, self.authorization, self.request())
        self.assertTrue(self.pairing.revoke_device("iphone-1"))
        invitation = self.pairing.issue()
        second_transport = TransportContext("100.64.7.11", True)
        response = gateway.handle_pair(second_transport, build_pair_request(
            code=invitation.code, device_id="iphone-2", device_name="Second iPhone"))
        second = inspect_pair_response(response)
        second_wire = build_request(
            request_id="second-request", device_id="iphone-2", sequence=1,
            sent_at=self.now[0], task_id="repair-2", prompt="Repair it",
            hce_sha256="a" * 64, source_sha256=["b" * 64],
            requested_lane="home-4b", prior_outcome_sha256="c" * 64)
        reply = gateway.handle_request(second_transport,
            "Bearer " + second["bearer_token"], second_wire)
        self.assertFalse(reply.idempotent_replay)

    def test_revoked_uncertain_dispatch_becomes_bounded_local_reconciliation(self):
        bounded = MobileGatewayConfig("100.64.7.9", 7443, self.config.tls_context,
                                      "d" * 64, "e" * 64, maximum_gateway_states=1)

        def dispatch(request):
            if request["device_id"] == "iphone-1":
                raise RuntimeError("uncertain")
            return GatewayResult("home-4b", "d" * 64, "second answer")

        gateway = MobileGateway(bounded, self.pairing, dispatch,
                                evidence_checker=lambda hce, sources: True,
                                apple_outcome_checker=self.verify_apple_outcome,
                                clock=lambda: self.now[0])
        first_wire = self.request()
        with self.assertRaises(GatewayDispatchUncertain):
            gateway.handle_request(self.transport, self.authorization, first_wire)
        first_pending = gateway.pending_dispatch("iphone-1")
        self.assertTrue(self.pairing.revoke_device("iphone-1"))
        invitation = self.pairing.issue()
        second_transport = TransportContext("100.64.7.11", True)
        response = gateway.handle_pair(second_transport, build_pair_request(
            code=invitation.code, device_id="iphone-2", device_name="Second iPhone"))
        second = inspect_pair_response(response)
        second_wire = build_request(
            request_id="second-request", device_id="iphone-2", sequence=1,
            sent_at=self.now[0], task_id="repair-2", prompt="Repair it",
            hce_sha256="a" * 64, source_sha256=["b" * 64],
            requested_lane="home-4b", prior_outcome_sha256="c" * 64)
        gateway.handle_request(second_transport, "Bearer " + second["bearer_token"],
                               second_wire)
        orphan = gateway.pending_dispatch("iphone-1")
        self.assertEqual(orphan, first_pending)
        reconciled = gateway.reconcile_pending(
            device_id="iphone-1", credential_generation=orphan.credential_generation,
            request_wire=first_wire,
            result=GatewayResult("home-4b", "d" * 64, "retained first result"))
        self.assertFalse(reconciled.idempotent_replay)
        self.assertIsNone(gateway.pending_dispatch("iphone-1"))

    def test_multiple_unresolved_credential_generations_are_enumerable(self):
        def uncertain(request):
            raise RuntimeError("uncertain")

        gateway = MobileGateway(self.config, self.pairing, uncertain,
                                evidence_checker=lambda hce, sources: True,
                                apple_outcome_checker=self.verify_apple_outcome,
                                clock=lambda: self.now[0])
        first_wire = self.request()
        with self.assertRaises(GatewayDispatchUncertain):
            gateway.handle_request(self.transport, self.authorization, first_wire)
        first = gateway.pending_dispatch("iphone-1")
        self.assertIsNotNone(first)
        self.assertTrue(self.pairing.revoke_device("iphone-1"))
        invitation = self.pairing.issue()
        pair_response = gateway.handle_pair(self.transport, build_pair_request(
            code=invitation.code, device_id="iphone-1", device_name="Felix iPhone"))
        replacement = inspect_pair_response(pair_response)
        second_wire = self.request(request_id="replacement-request")
        with self.assertRaises(GatewayDispatchUncertain):
            gateway.handle_request(self.transport,
                "Bearer " + replacement["bearer_token"], second_wire)
        pending = gateway.pending_dispatches("iphone-1")
        self.assertEqual(len(pending), 2)
        self.assertEqual(pending[0], first)
        self.assertNotEqual(pending[0].credential_generation,
                            pending[1].credential_generation)
        self.assertIsNone(gateway.pending_dispatch("iphone-1"))
        for item, request_wire in zip(pending, (first_wire, second_wire)):
            selected = gateway.pending_dispatch(
                "iphone-1", credential_generation=item.credential_generation)
            self.assertEqual(selected, item)
            gateway.reconcile_pending(
                device_id="iphone-1", credential_generation=item.credential_generation,
                request_wire=request_wire,
                result=GatewayResult("home-4b", "d" * 64, "retained result"))
        self.assertEqual(gateway.pending_dispatches("iphone-1"), ())


if __name__ == "__main__":
    unittest.main()

import copy
import unittest

from xnet.model_ladder import (ModelLadderError, record_outcome, select_route,
                               validate_policy)
from xnet.protocol import digest


def policy():
    return {
        "schema": "xnet.model-ladder-policy.v1",
        "parameter_ceiling_billion": 14,
        "lanes": [
            {"id": "apple-native", "parameter_class_billion": None,
             "location": "iphone-platform", "capabilities": ["classify", "extract", "summarize", "tag", "tool-select"],
             "context_tokens": 4096, "available": True, "engine_identity_sha256": "1" * 64},
            {"id": "xnet-4b", "parameter_class_billion": 4,
             "location": "device-qualified", "capabilities": ["classify", "extract", "summarize", "tag", "tool-select", "code", "repair", "reason"],
             "context_tokens": 6400, "available": True, "engine_identity_sha256": "2" * 64},
            {"id": "home-14b", "parameter_class_billion": 14,
             "location": "home-remote", "capabilities": ["classify", "extract", "summarize", "tag", "tool-select", "code", "repair", "reason"],
             "context_tokens": 3500, "available": True, "engine_identity_sha256": "3" * 64},
        ],
    }


def request(capability="extract", tokens=500, offline=False):
    return {"schema": "xnet.model-ladder-request.v1", "task_id": "mobile-001",
            "capability": capability, "context_tokens": tokens,
            "offline_required": offline, "source_evidence_sha256": ["a" * 64]}


class ModelLadderTests(unittest.TestCase):
    def test_apple_is_first_for_supported_grounded_work(self):
        route = select_route(policy(), request())
        self.assertEqual(route["selected_lane"], "apple-native")
        self.assertFalse(route["model_launched"])
        self.assertEqual(route["tool_authority"], "none")

    def test_coding_starts_at_four_billion(self):
        route = select_route(policy(), request("repair", 1200))
        self.assertEqual(route["selected_lane"], "xnet-4b")
        outcome = record_outcome(route, status="verified", verifier_evidence_sha256=["b" * 64])
        self.assertTrue(outcome["accepted"])
        self.assertFalse(outcome["model_self_assessment_used"])

    def test_failed_four_billion_can_escalate_to_home_14b(self):
        first = select_route(policy(), request("code", 1000))
        failed = record_outcome(first, status="failed", verifier_evidence_sha256=["c" * 64])
        second = select_route(policy(), request("code", 1000), after_lane="xnet-4b",
                              prior_outcome_sha256=failed["outcome_sha256"])
        self.assertEqual(second["selected_lane"], "home-14b")

    def test_offline_request_never_uses_home_14b(self):
        p = policy()
        p["lanes"][1]["available"] = False
        with self.assertRaisesRegex(ModelLadderError, "no eligible"):
            select_route(p, request("code", 1000, offline=True))

    def test_no_route_above_14b_can_enter_policy(self):
        p = policy()
        p["parameter_ceiling_billion"] = 30
        with self.assertRaisesRegex(ModelLadderError, "14B ceiling"):
            validate_policy(p)

    def test_verified_needs_external_evidence_and_tamper_refuses(self):
        route = select_route(policy(), request())
        with self.assertRaisesRegex(ModelLadderError, "requires independent evidence"):
            record_outcome(route, status="verified", verifier_evidence_sha256=[])
        route["selected_lane"] = "home-14b"
        with self.assertRaisesRegex(ModelLadderError, "hash mismatch"):
            record_outcome(route, status="failed", verifier_evidence_sha256=[])

    def test_policy_uses_exact_types_locations_and_distinct_identities(self):
        cases = []
        wrong_ceiling = policy()
        wrong_ceiling["parameter_ceiling_billion"] = 14.0
        cases.append((wrong_ceiling, "14B ceiling"))
        wrong_parameters = policy()
        wrong_parameters["lanes"][1]["parameter_class_billion"] = 4.0
        cases.append((wrong_parameters, "parameter class"))
        remote_four_b = policy()
        remote_four_b["lanes"][1]["location"] = "home-remote"
        cases.append((remote_four_b, "location"))
        oversized_context = policy()
        oversized_context["lanes"][0]["context_tokens"] = 2**31
        cases.append((oversized_context, "context"))
        unhashable_capability = policy()
        unhashable_capability["lanes"][0]["capabilities"] = [{}]
        cases.append((unhashable_capability, "capabilities"))
        duplicate_identity = policy()
        duplicate_identity["lanes"][2]["engine_identity_sha256"] = "2" * 64
        cases.append((duplicate_identity, "distinct"))
        for candidate, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ModelLadderError, message):
                    validate_policy(candidate)

    def test_request_rejects_non_text_capability_with_domain_error(self):
        candidate = request()
        candidate["capability"] = {}
        with self.assertRaisesRegex(ModelLadderError, "unsupported capability"):
            select_route(policy(), candidate)

    def test_rehashed_route_cannot_expand_authority_or_skip_stop(self):
        route = select_route(policy(), request("code", 1000))
        expanded = copy.deepcopy(route)
        expanded["tool_authority"] = "filesystem"
        expanded_body = dict(expanded)
        expanded_body.pop("route_sha256")
        expanded["route_sha256"] = digest(expanded_body)
        with self.assertRaisesRegex(ModelLadderError, "safety boundary"):
            record_outcome(expanded, status="failed", verifier_evidence_sha256=[])

        continued = copy.deepcopy(route)
        continued["decisions"][0] = {
            "lane": "apple-native", "eligible": True, "reason": "eligible",
        }
        continued_body = dict(continued)
        continued_body.pop("route_sha256")
        continued["route_sha256"] = digest(continued_body)
        with self.assertRaisesRegex(ModelLadderError, "continued after"):
            record_outcome(continued, status="failed", verifier_evidence_sha256=[])


if __name__ == "__main__":
    unittest.main()

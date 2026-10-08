"""Deterministic Apple-native -> 4B -> 14B routing receipts.

The ladder selects a caller-declared engine capability.  It does not launch a
model, infer device eligibility, trust a model's self-assessment, or turn
context into tool authority.  A caller-owned verifier decides whether a result
is accepted; failures can advance only to the next configured rung.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Mapping

from .protocol import digest


POLICY_SCHEMA = "xnet.model-ladder-policy.v1"
REQUEST_SCHEMA = "xnet.model-ladder-request.v1"
ROUTE_SCHEMA = "xnet.model-ladder-route.v1"
OUTCOME_SCHEMA = "xnet.model-ladder-outcome.v1"
LANES = ("apple-native", "xnet-4b", "home-14b")
LOCATIONS = {
    "apple-native": "iphone-platform",
    "xnet-4b": "device-qualified",
    "home-14b": "home-remote",
}
CAPABILITIES = frozenset({
    "classify", "extract", "summarize", "tag", "tool-select",
    "code", "repair", "reason",
})
_DECISION_REASONS = frozenset({
    "eligible", "unavailable", "capability-not-declared",
    "context-does-not-fit", "offline-request-refuses-remote",
})
_MAX_CONTEXT_TOKENS = 2**31 - 1
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_TASK = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}\Z")


class ModelLadderError(ValueError):
    """A routing record or policy crossed its declared boundary."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise ModelLadderError(label + " fields differ from schema")
    return value


def _hashes(values: Any, label: str) -> list[str]:
    if type(values) is not list or len(values) > 128:
        raise ModelLadderError(label + " must be a bounded hash list")
    if any(type(item) is not str or _HASH.fullmatch(item) is None for item in values):
        raise ModelLadderError(label + " contains an invalid SHA-256")
    if len(values) != len(set(values)):
        raise ModelLadderError(label + " contains duplicates")
    return list(values)


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ModelLadderError(label + " must be a lowercase SHA-256")
    return value


def validate_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    policy = _exact(value, {"schema", "parameter_ceiling_billion", "lanes"}, "policy")
    if (policy["schema"] != POLICY_SCHEMA
            or type(policy["parameter_ceiling_billion"]) is not int
            or policy["parameter_ceiling_billion"] != 14):
        raise ModelLadderError("policy must pin the 14B ceiling")
    lanes = policy["lanes"]
    if type(lanes) is not list or len(lanes) != len(LANES):
        raise ModelLadderError("policy lanes must be Apple native, 4B, then 14B")
    result = []
    for expected_id, row in zip(LANES, lanes):
        row = _exact(row, {"id", "parameter_class_billion", "location", "capabilities",
                           "context_tokens", "available", "engine_identity_sha256"}, "lane")
        if row["id"] != expected_id:
            raise ModelLadderError("lane order changed")
        parameters = row["parameter_class_billion"]
        if expected_id == "apple-native":
            if parameters is not None:
                raise ModelLadderError("Apple native is platform-managed, not a declared weight count")
        else:
            required = 4 if expected_id == "xnet-4b" else 14
            if type(parameters) is not int or parameters != required:
                raise ModelLadderError("model rung parameter class changed")
        if row["location"] != LOCATIONS[expected_id] or type(row["available"]) is not bool:
            raise ModelLadderError("invalid lane location or availability")
        if (type(row["context_tokens"]) is not int or type(row["context_tokens"]) is bool
                or not 256 <= row["context_tokens"] <= _MAX_CONTEXT_TOKENS):
            raise ModelLadderError("lane context must be an exact positive integer")
        capabilities = row["capabilities"]
        if (type(capabilities) is not list or not capabilities
                or any(type(item) is not str or item not in CAPABILITIES
                       for item in capabilities)
                or len(capabilities) != len(set(capabilities))):
            raise ModelLadderError("lane capabilities are invalid")
        _hash(row["engine_identity_sha256"], "lane engine identity")
        result.append(copy.deepcopy(row))
    identities = [row["engine_identity_sha256"] for row in result]
    if len(identities) != len(set(identities)):
        raise ModelLadderError("lane engine identities must be distinct")
    return {"schema": POLICY_SCHEMA, "parameter_ceiling_billion": 14, "lanes": result}


def validate_request(value: Mapping[str, Any]) -> dict[str, Any]:
    request = _exact(value, {"schema", "task_id", "capability", "context_tokens",
                             "offline_required", "source_evidence_sha256"}, "request")
    if request["schema"] != REQUEST_SCHEMA:
        raise ModelLadderError("unsupported request schema")
    if type(request["task_id"]) is not str or _TASK.fullmatch(request["task_id"]) is None:
        raise ModelLadderError("invalid task identity")
    if type(request["capability"]) is not str or request["capability"] not in CAPABILITIES:
        raise ModelLadderError("unsupported capability")
    if (type(request["context_tokens"]) is not int or type(request["context_tokens"]) is bool
            or not 0 <= request["context_tokens"] <= 2**31 - 1):
        raise ModelLadderError("invalid context budget")
    if type(request["offline_required"]) is not bool:
        raise ModelLadderError("offline_required must be boolean")
    result = copy.deepcopy(request)
    result["source_evidence_sha256"] = _hashes(request["source_evidence_sha256"], "source evidence")
    return result


def _eligible(row: Mapping[str, Any], request: Mapping[str, Any]) -> tuple[bool, str]:
    if not row["available"]:
        return False, "unavailable"
    if request["capability"] not in row["capabilities"]:
        return False, "capability-not-declared"
    if request["context_tokens"] > row["context_tokens"]:
        return False, "context-does-not-fit"
    if request["offline_required"] and row["location"] == "home-remote":
        return False, "offline-request-refuses-remote"
    return True, "eligible"


def select_route(policy: Mapping[str, Any], request: Mapping[str, Any], *,
                 after_lane: str | None = None,
                 prior_outcome_sha256: str | None = None) -> dict[str, Any]:
    """Select the cheapest eligible rung and seal the deterministic decision."""
    policy_value = validate_policy(policy)
    request_value = validate_request(request)
    start = 0
    if after_lane is not None:
        if after_lane not in LANES:
            raise ModelLadderError("unknown prior lane")
        if type(prior_outcome_sha256) is not str or _HASH.fullmatch(prior_outcome_sha256) is None:
            raise ModelLadderError("escalation requires a prior outcome receipt")
        start = LANES.index(after_lane) + 1
    elif prior_outcome_sha256 is not None:
        raise ModelLadderError("initial route cannot cite a prior outcome")
    decisions = []
    selected = None
    for row in policy_value["lanes"][start:]:
        allowed, reason = _eligible(row, request_value)
        decisions.append({"lane": row["id"], "eligible": allowed, "reason": reason})
        if allowed:
            selected = row
            break
    if selected is None:
        raise ModelLadderError("no eligible lane within the 14B ceiling")
    body = {
        "schema": ROUTE_SCHEMA,
        "policy_sha256": digest(policy_value),
        "request_sha256": digest(request_value),
        "selected_lane": selected["id"],
        "engine_identity_sha256": selected["engine_identity_sha256"],
        "prior_outcome_sha256": prior_outcome_sha256,
        "decisions": decisions,
        "tool_authority": "none",
        "model_launched": False,
    }
    return {**body, "route_sha256": digest(body)}


def validate_route(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate both the digest and the fixed safety semantics of a route."""
    route = _exact(value, {"schema", "policy_sha256", "request_sha256", "selected_lane",
                           "engine_identity_sha256", "prior_outcome_sha256", "decisions",
                           "tool_authority", "model_launched", "route_sha256"}, "route")
    if route["schema"] != ROUTE_SCHEMA:
        raise ModelLadderError("unsupported route schema")
    _hash(route["policy_sha256"], "policy_sha256")
    _hash(route["request_sha256"], "request_sha256")
    _hash(route["engine_identity_sha256"], "engine_identity_sha256")
    supplied = _hash(route["route_sha256"], "route_sha256")
    prior = route["prior_outcome_sha256"]
    if prior is not None:
        _hash(prior, "prior_outcome_sha256")
    if route["selected_lane"] not in LANES:
        raise ModelLadderError("route selected an unknown lane")
    if type(route["tool_authority"]) is not str or type(route["model_launched"]) is not bool:
        raise ModelLadderError("route safety boundary has invalid types")
    decisions = route["decisions"]
    if type(decisions) is not list or not 1 <= len(decisions) <= len(LANES):
        raise ModelLadderError("route decisions must be a bounded nonempty list")
    checked_decisions = []
    for decision in decisions:
        decision = _exact(decision, {"lane", "eligible", "reason"}, "route decision")
        if (decision["lane"] not in LANES or type(decision["eligible"]) is not bool
                or type(decision["reason"]) is not str
                or decision["reason"] not in _DECISION_REASONS):
            raise ModelLadderError("route decision is invalid")
        checked_decisions.append(copy.deepcopy(decision))
    body = copy.deepcopy(route)
    body.pop("route_sha256")
    if digest(body) != supplied:
        raise ModelLadderError("route receipt hash mismatch")
    if route["tool_authority"] != "none" or route["model_launched"] is not False:
        raise ModelLadderError("route safety boundary differs")
    if any((decision["reason"] == "eligible") is not decision["eligible"]
           for decision in checked_decisions):
        raise ModelLadderError("route decision eligibility conflicts with its reason")
    lane_ids = [decision["lane"] for decision in checked_decisions]
    start = LANES.index(lane_ids[0])
    if lane_ids != list(LANES[start:start + len(lane_ids)]):
        raise ModelLadderError("route decisions are not a contiguous ladder suffix")
    if any(decision["eligible"] for decision in checked_decisions[:-1]):
        raise ModelLadderError("route continued after an eligible lane")
    if checked_decisions[-1]["eligible"] is not True:
        raise ModelLadderError("route must end at an eligible lane")
    if route["selected_lane"] != checked_decisions[-1]["lane"]:
        raise ModelLadderError("route selection conflicts with its decisions")
    if (start == 0 and prior is not None) or (start > 0 and prior is None):
        raise ModelLadderError("route escalation receipt boundary differs")
    return {**body, "route_sha256": supplied}


def record_outcome(route: Mapping[str, Any], *, status: str,
                   verifier_evidence_sha256: list[str]) -> dict[str, Any]:
    """Bind an external verifier result to a route; model self-rating is excluded."""
    route = validate_route(route)
    supplied = route["route_sha256"]
    if (type(status) is not str
            or status not in {"verified", "failed", "abstained", "unavailable"}):
        raise ModelLadderError("unsupported verifier outcome")
    evidence = _hashes(verifier_evidence_sha256, "verifier evidence")
    if status == "verified" and not evidence:
        raise ModelLadderError("verified outcome requires independent evidence")
    body = {
        "schema": OUTCOME_SCHEMA,
        "route_sha256": supplied,
        "selected_lane": route["selected_lane"],
        "status": status,
        "verifier_evidence_sha256": evidence,
        "accepted": status == "verified",
        "model_self_assessment_used": False,
    }
    return {**body, "outcome_sha256": digest(body)}

"""Deterministic, signed routing metaphors for bounded XNET coordination.

Rubik faces are a fixed routing matrix, Rock/Paper/Scissors is a three-role
review protocol, and adaptive weights are bounded scheduling hints.  None of
these records grants scope, bypasses Seven Gates, changes the fixed evaluator,
or provides autonomous authority.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Mapping, Sequence

from .protocol import ZERO_HASH, canonical, digest


CUBE_SCHEMA = "xnet.rag-rubik-routing-transition.v1"
ARBITRATION_SCHEMA = "xnet.rag-rps-arbitration-transition.v1"
ADAPTIVE_SCHEMA = "xnet.rag-adaptive-routing-update.v1"
ADAPTIVE_SELECTION_SCHEMA = "xnet.rag-adaptive-route-selection.v1"

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
MOVES = frozenset({"rock", "paper", "scissors"})
ROLES = ("proposer", "challenger", "verifier")
WEIGHT_MIN = 0
WEIGHT_MAX = 1_000
MAX_WEIGHT_DELTA = 40

CUBE_FACES: dict[str, dict[str, str]] = {
    "U": {"role": "operator", "silo": "policy-gate"},
    "D": {"role": "auditor", "silo": "receipt-ledger"},
    "F": {"role": "solver", "silo": "active-task"},
    "B": {"role": "scout", "silo": "prefetch-worker"},
    "L": {"role": "catalog", "silo": "local-rag-catalog"},
    "R": {"role": "queue", "silo": "disposable-prediction-queue"},
}

ROTATION_CYCLES: dict[str, tuple[str, str, str, str]] = {
    "U": ("F", "R", "B", "L"),
    "D": ("F", "L", "B", "R"),
    "F": ("U", "L", "D", "R"),
    "B": ("U", "R", "D", "L"),
    "L": ("U", "B", "D", "F"),
    "R": ("U", "F", "D", "B"),
}


class RoutingProtocolError(ValueError):
    pass


def _hash(value: Any, name: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise RoutingProtocolError(f"{name} must be a SHA-256 hash")
    return value


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise RoutingProtocolError(f"invalid {name}")
    return value


def _key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) < 32:
        raise RoutingProtocolError("routing transition key must contain at least 32 bytes")
    return key


def _exact(value: Mapping[str, Any], fields: set[str], name: str) -> None:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RoutingProtocolError(f"{name} fields are missing or contradictory")


def _signature(body: Mapping[str, Any], key: bytes) -> str:
    return hmac.new(_key(key), canonical(body), hashlib.sha256).hexdigest()


def routing_envelope(
    *,
    worker: str,
    role: str,
    task_id: str,
    artifact: str,
    artifact_hash: str,
    source_silo: str,
    destination_silo: str,
    sequence: int,
    timestamp: int,
    ttl_seconds: int,
    policy: str,
    rationale: str,
    evidence_hashes: Sequence[str],
    allowlisted_tools: Sequence[str],
    budget_unit: str,
    budget_maximum: int,
    budget_used: int,
) -> dict[str, Any]:
    for value, name in ((worker, "worker"), (role, "role"), (task_id, "task_id"), (artifact, "artifact"), (source_silo, "source_silo"), (destination_silo, "destination_silo"), (policy, "policy")):
        _identifier(value, name)
    _hash(artifact_hash, "artifact_hash")
    evidence = sorted({_hash(value, "evidence_hash") for value in evidence_hashes})
    if not evidence or len(evidence) > 64:
        raise RoutingProtocolError("routing evidence hashes must contain 1..64 entries")
    if not isinstance(sequence, int) or sequence < 1 or not isinstance(timestamp, int) or timestamp < 0:
        raise RoutingProtocolError("routing sequence/timestamp is invalid")
    if not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 86400:
        raise RoutingProtocolError("routing TTL must be 1..86400 seconds")
    if not isinstance(rationale, str) or not 1 <= len(rationale) <= 512:
        raise RoutingProtocolError("routing rationale is invalid")
    tools = [_identifier(tool, "allowlisted_tool") for tool in allowlisted_tools]
    if len(tools) != len(set(tools)) or len(tools) > 16:
        raise RoutingProtocolError("routing tool allowlist is invalid")
    _identifier(budget_unit, "budget_unit")
    if not isinstance(budget_maximum, int) or not isinstance(budget_used, int) or not 0 <= budget_used <= budget_maximum <= 1_000_000:
        raise RoutingProtocolError("routing budget is invalid")
    return {
        "who": {"worker": worker, "role": role},
        "what": {"task_id": task_id, "artifact": artifact, "artifact_hash": artifact_hash},
        "where": {"source_silo": source_silo, "destination_silo": destination_silo},
        "when": {"sequence": sequence, "timestamp": timestamp, "ttl_seconds": ttl_seconds, "deadline": timestamp + ttl_seconds},
        "why": {"policy": policy, "rationale": rationale, "evidence_hashes": evidence},
        "how": {"allowlisted_tools": tools, "budget": {"unit": budget_unit, "maximum": budget_maximum, "used": budget_used}},
    }


def validate_routing_envelope(envelope: Mapping[str, Any]) -> dict[str, Any]:
    _exact(envelope, {"who", "what", "where", "when", "why", "how"}, "routing envelope")
    _exact(envelope["who"], {"worker", "role"}, "routing who")
    _exact(envelope["what"], {"task_id", "artifact", "artifact_hash"}, "routing what")
    _exact(envelope["where"], {"source_silo", "destination_silo"}, "routing where")
    _exact(envelope["when"], {"sequence", "timestamp", "ttl_seconds", "deadline"}, "routing when")
    _exact(envelope["why"], {"policy", "rationale", "evidence_hashes"}, "routing why")
    _exact(envelope["how"], {"allowlisted_tools", "budget"}, "routing how")
    _exact(envelope["how"]["budget"], {"unit", "maximum", "used"}, "routing budget")
    rebuilt = routing_envelope(
        worker=envelope["who"]["worker"], role=envelope["who"]["role"],
        task_id=envelope["what"]["task_id"], artifact=envelope["what"]["artifact"], artifact_hash=envelope["what"]["artifact_hash"],
        source_silo=envelope["where"]["source_silo"], destination_silo=envelope["where"]["destination_silo"],
        sequence=envelope["when"]["sequence"], timestamp=envelope["when"]["timestamp"], ttl_seconds=envelope["when"]["ttl_seconds"],
        policy=envelope["why"]["policy"], rationale=envelope["why"]["rationale"], evidence_hashes=envelope["why"]["evidence_hashes"],
        allowlisted_tools=envelope["how"]["allowlisted_tools"], budget_unit=envelope["how"]["budget"]["unit"],
        budget_maximum=envelope["how"]["budget"]["maximum"], budget_used=envelope["how"]["budget"]["used"],
    )
    if dict(envelope) != rebuilt:
        raise RoutingProtocolError("routing envelope contains contradictory timing or normalized fields")
    return rebuilt


def _binding(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact(value, {"task_hash", "source_hashes", "policy_hash", "receipt_hash"}, "cube face binding")
    if not isinstance(value["source_hashes"], list) or not value["source_hashes"]:
        raise RoutingProtocolError("cube source_hashes must be a non-empty list")
    sources = sorted({_hash(item, "source_hash") for item in value["source_hashes"]})
    if len(sources) != len(value["source_hashes"]):
        raise RoutingProtocolError("cube source_hashes must be unique and sorted")
    normalized = {
        "task_hash": _hash(value["task_hash"], "task_hash"),
        "source_hashes": sources,
        "policy_hash": _hash(value["policy_hash"], "policy_hash"),
        "receipt_hash": _hash(value["receipt_hash"], "receipt_hash"),
    }
    if dict(value) != normalized:
        raise RoutingProtocolError("cube face binding is not canonical")
    return normalized


def make_cube_transition(
    *,
    task_id: str,
    sequence: int,
    timestamp: int,
    ttl_seconds: int,
    previous_transition_hash: str = ZERO_HASH,
    rotation: str,
    face_bindings: Mapping[str, Mapping[str, Any]],
    key: bytes,
) -> dict[str, Any]:
    _identifier(task_id, "task_id")
    _hash(previous_transition_hash, "previous_transition_hash")
    if rotation not in ROTATION_CYCLES:
        raise RoutingProtocolError("rotation is outside the fixed routing matrix")
    if set(face_bindings) != set(CUBE_FACES):
        raise RoutingProtocolError("all six fixed cube faces are required")
    bindings = {face: _binding(face_bindings[face]) for face in sorted(CUBE_FACES)}
    state_hash = digest(bindings)
    solved = len({canonical(binding) for binding in bindings.values()}) == 1
    cycle = ROTATION_CYCLES[rotation]
    moves = [
        {
            "from_face": source,
            "from_role": CUBE_FACES[source]["role"],
            "from_silo": CUBE_FACES[source]["silo"],
            "to_face": target,
            "to_role": CUBE_FACES[target]["role"],
            "to_silo": CUBE_FACES[target]["silo"],
        }
        for source, target in zip(cycle, cycle[1:] + cycle[:1])
    ]
    receipts = sorted({binding["receipt_hash"] for binding in bindings.values()})
    envelope = routing_envelope(
        worker="rubik-router", role="coordinator", task_id=task_id,
        artifact="rubik-routing-state", artifact_hash=state_hash,
        source_silo=CUBE_FACES[cycle[0]]["silo"], destination_silo=CUBE_FACES[cycle[1]]["silo"],
        sequence=sequence, timestamp=timestamp, ttl_seconds=ttl_seconds,
        policy="deterministic-rubik-routing-v1", rationale=f"fixed-{rotation}-rotation",
        evidence_hashes=receipts, allowlisted_tools=[], budget_unit="rotations", budget_maximum=1, budget_used=1,
    )
    body = {
        "schema_version": CUBE_SCHEMA,
        "previous_transition_hash": previous_transition_hash,
        "rotation": rotation,
        "faces": {face: dict(values) for face, values in CUBE_FACES.items()},
        "face_bindings": bindings,
        "moves": moves,
        "state_hash": state_hash,
        "solved": solved,
        "routing_envelope": envelope,
    }
    transition_hash = digest(body)
    unsigned = {**body, "transition_hash": transition_hash}
    return {**unsigned, "signature_hmac_sha256": _signature(unsigned, key)}


def verify_cube_transition(record: Mapping[str, Any], key: bytes, *, expected_previous_hash: str | None = None) -> dict[str, Any]:
    fields = {"schema_version", "previous_transition_hash", "rotation", "faces", "face_bindings", "moves", "state_hash", "solved", "routing_envelope", "transition_hash", "signature_hmac_sha256"}
    _exact(record, fields, "cube transition")
    if record["schema_version"] != CUBE_SCHEMA or record["faces"] != CUBE_FACES:
        raise RoutingProtocolError("unsupported cube routing matrix")
    if expected_previous_hash is not None and record["previous_transition_hash"] != expected_previous_hash:
        raise RoutingProtocolError("cube transition chain mismatch")
    task_id = validate_routing_envelope(record["routing_envelope"])["what"]["task_id"]
    rebuilt = make_cube_transition(
        task_id=task_id,
        sequence=record["routing_envelope"]["when"]["sequence"],
        timestamp=record["routing_envelope"]["when"]["timestamp"],
        ttl_seconds=record["routing_envelope"]["when"]["ttl_seconds"],
        previous_transition_hash=record["previous_transition_hash"],
        rotation=record["rotation"], face_bindings=record["face_bindings"], key=key,
    )
    if dict(record) != rebuilt:
        raise RoutingProtocolError("cube transition hash, signature, or state is invalid")
    return {"valid": True, "transition_hash": record["transition_hash"], "solved": record["solved"]}


def _rps_outcome(submissions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    by_move: dict[str, list[Mapping[str, Any]]] = {}
    for submission in submissions:
        by_move.setdefault(submission["move"], []).append(submission)
    winning_move = None
    if len(by_move) == 2:
        present = set(by_move)
        for winner, loser in (("rock", "scissors"), ("scissors", "paper"), ("paper", "rock")):
            if {winner, loser} == present:
                winning_move = winner
                break
    winners = by_move.get(winning_move, []) if winning_move else []
    independently_supported = (
        len(winners) == 2
        and len({item["direction_hash"] for item in winners}) == 1
        and "verifier" in {item["role"] for item in winners}
    )
    if independently_supported:
        return {
            "status": "approved",
            "selected_direction_hash": winners[0]["direction_hash"],
            "supporting_roles": sorted(item["role"] for item in winners),
            "escalation": None,
        }
    return {
        "status": "escalate",
        "selected_direction_hash": None,
        "supporting_roles": [],
        "escalation": {"evaluator": "fixed-evaluator", "gate": "xnet-seven-gates"},
    }


def make_rps_transition(
    *,
    task_id: str,
    sequence: int,
    timestamp: int,
    ttl_seconds: int,
    previous_transition_hash: str,
    routing_transition_hash: str,
    submissions: Sequence[Mapping[str, Any]],
    key: bytes,
) -> dict[str, Any]:
    _identifier(task_id, "task_id")
    _hash(previous_transition_hash, "previous_transition_hash")
    _hash(routing_transition_hash, "routing_transition_hash")
    if not isinstance(submissions, Sequence) or len(submissions) != 3:
        raise RoutingProtocolError("RPS arbitration requires exactly three role submissions")
    normalized: list[dict[str, Any]] = []
    for submission in submissions:
        _exact(submission, {"role", "actor_hash", "direction_hash", "move"}, "RPS submission")
        if submission["role"] not in ROLES or submission["move"] not in MOVES:
            raise RoutingProtocolError("RPS role or move is invalid")
        normalized.append({
            "role": submission["role"], "actor_hash": _hash(submission["actor_hash"], "actor_hash"),
            "direction_hash": _hash(submission["direction_hash"], "direction_hash"), "move": submission["move"],
        })
    normalized.sort(key=lambda item: ROLES.index(item["role"]))
    if [item["role"] for item in normalized] != list(ROLES) or len({item["actor_hash"] for item in normalized}) != 3:
        raise RoutingProtocolError("RPS roles require distinct actors; self-approval is forbidden")
    outcome = _rps_outcome(normalized)
    artifact_hash = digest({"submissions": normalized, "outcome": outcome})
    destination = "active-task" if outcome["status"] == "approved" else "fixed-evaluator"
    envelope = routing_envelope(
        worker="rps-arbiter", role="verifier", task_id=task_id,
        artifact="coding-direction-arbitration", artifact_hash=artifact_hash,
        source_silo="rubik-routing-matrix", destination_silo=destination,
        sequence=sequence, timestamp=timestamp, ttl_seconds=ttl_seconds,
        policy="rps-three-role-arbitration-v1", rationale="independent-propose-challenge-verify",
        evidence_hashes=[routing_transition_hash], allowlisted_tools=[],
        budget_unit="submissions", budget_maximum=3, budget_used=3,
    )
    body = {
        "schema_version": ARBITRATION_SCHEMA,
        "previous_transition_hash": previous_transition_hash,
        "routing_transition_hash": routing_transition_hash,
        "submissions": normalized,
        "outcome": outcome,
        "routing_envelope": envelope,
    }
    transition_hash = digest(body)
    unsigned = {**body, "transition_hash": transition_hash}
    return {**unsigned, "signature_hmac_sha256": _signature(unsigned, key)}


def verify_rps_transition(record: Mapping[str, Any], key: bytes, *, expected_previous_hash: str | None = None) -> dict[str, Any]:
    fields = {"schema_version", "previous_transition_hash", "routing_transition_hash", "submissions", "outcome", "routing_envelope", "transition_hash", "signature_hmac_sha256"}
    _exact(record, fields, "RPS transition")
    if record["schema_version"] != ARBITRATION_SCHEMA:
        raise RoutingProtocolError("unsupported RPS arbitration schema")
    if expected_previous_hash is not None and record["previous_transition_hash"] != expected_previous_hash:
        raise RoutingProtocolError("RPS transition chain mismatch")
    envelope = validate_routing_envelope(record["routing_envelope"])
    rebuilt = make_rps_transition(
        task_id=envelope["what"]["task_id"], sequence=envelope["when"]["sequence"],
        timestamp=envelope["when"]["timestamp"], ttl_seconds=envelope["when"]["ttl_seconds"],
        previous_transition_hash=record["previous_transition_hash"], routing_transition_hash=record["routing_transition_hash"],
        submissions=record["submissions"], key=key,
    )
    if dict(record) != rebuilt:
        raise RoutingProtocolError("RPS transition hash, signature, or outcome is invalid")
    return {"valid": True, "transition_hash": record["transition_hash"], "status": record["outcome"]["status"]}


def _measurement(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "correctness", "evaluator_valid", "coherence_milli", "latency_ms", "tokens_used",
        "cost_units", "freshness_seconds", "health", "failure_count",
    }
    _exact(value, fields, "adaptive measurement")
    if value["correctness"] not in {"verified_correct", "verified_wrong", "unverified"}:
        raise RoutingProtocolError("adaptive correctness must be measured and explicit")
    if not isinstance(value["evaluator_valid"], bool):
        raise RoutingProtocolError("adaptive evaluator validity must be a measured boolean")
    if value["health"] not in {"healthy", "degraded", "unavailable"}:
        raise RoutingProtocolError("adaptive route health is invalid")
    limits = {
        "coherence_milli": 1_000,
        "latency_ms": 86_400_000,
        "tokens_used": 10_000_000,
        "cost_units": 1_000_000,
        "freshness_seconds": 31_536_000,
        "failure_count": 1_000_000,
    }
    for name, maximum in limits.items():
        if not isinstance(value[name], int) or not 0 <= value[name] <= maximum:
            raise RoutingProtocolError(f"adaptive {name} is outside its fixed bound")
    return dict(value)


def _weight_delta(measurement: Mapping[str, Any]) -> int:
    if measurement["correctness"] == "verified_wrong":
        return -min(MAX_WEIGHT_DELTA, 20 + min(20, measurement["failure_count"] * 4))
    if measurement["correctness"] == "unverified":
        return -min(MAX_WEIGHT_DELTA, 10 + min(20, measurement["failure_count"] * 3))
    if not measurement["evaluator_valid"] or measurement["health"] == "unavailable":
        return -MAX_WEIGHT_DELTA
    if measurement["coherence_milli"] < 500:
        return -min(MAX_WEIGHT_DELTA, 20 + (500 - measurement["coherence_milli"]) // 25)
    reward = 16 + max(0, measurement["coherence_milli"] - 800) // 25
    reward -= min(12, measurement["latency_ms"] // 1_000)
    reward -= min(8, measurement["tokens_used"] // 10_000)
    reward -= min(8, measurement["cost_units"] // 100)
    reward -= min(8, measurement["freshness_seconds"] // 86_400)
    reward -= min(20, measurement["failure_count"] * 5)
    if measurement["health"] == "degraded":
        reward -= 12
    return max(-MAX_WEIGHT_DELTA, min(MAX_WEIGHT_DELTA, reward))


def _route_disposition(measurement: Mapping[str, Any], delta: int) -> str:
    if (
        measurement["correctness"] != "verified_correct"
        or not measurement["evaluator_valid"]
        or measurement["health"] == "unavailable"
        or measurement["coherence_milli"] < 500
        or measurement["failure_count"] >= 4
    ):
        return "quarantined"
    if delta < 0 or measurement["health"] == "degraded" or measurement["coherence_milli"] < 800:
        return "decayed"
    return "active"


def make_adaptive_update(
    *,
    task_id: str,
    route_id: str,
    allowed_routes: Sequence[str],
    previous_weight: int,
    measurement: Mapping[str, Any],
    version: int,
    timestamp: int,
    ttl_seconds: int,
    previous_update_hash: str = ZERO_HASH,
    routing_transition_hash: str,
    key: bytes,
) -> dict[str, Any]:
    _identifier(task_id, "task_id")
    route_id = _identifier(route_id, "route_id")
    routes = sorted({_identifier(route, "allowed_route") for route in allowed_routes})
    if route_id not in routes or not routes:
        raise RoutingProtocolError("adaptive update may not expand the fixed route allowlist")
    if not isinstance(previous_weight, int) or not WEIGHT_MIN <= previous_weight <= WEIGHT_MAX:
        raise RoutingProtocolError("previous route weight is outside fixed bounds")
    if not isinstance(version, int) or version < 1:
        raise RoutingProtocolError("adaptive update version is invalid")
    _hash(previous_update_hash, "previous_update_hash")
    _hash(routing_transition_hash, "routing_transition_hash")
    measured = _measurement(measurement)
    requested_delta = _weight_delta(measured)
    new_weight = min(WEIGHT_MAX, max(WEIGHT_MIN, previous_weight + requested_delta))
    delta = new_weight - previous_weight
    if measured["correctness"] != "verified_correct" and delta > 0:
        raise RoutingProtocolError("wrong or unverified results may never gain route weight")
    disposition = _route_disposition(measured, delta)
    constraints = {
        "scope_expansion": False,
        "bypass_gates": False,
        "evaluator": "fixed-evaluator",
        "seven_gates_required": True,
        "weight_min": WEIGHT_MIN,
        "weight_max": WEIGHT_MAX,
        "max_delta": MAX_WEIGHT_DELTA,
    }
    state_hash = digest({"route_id": route_id, "weight": new_weight, "version": version})
    envelope = routing_envelope(
        worker="adaptive-matrix", role="scheduler", task_id=task_id,
        artifact="route-weight-update", artifact_hash=state_hash,
        source_silo="receipt-ledger", destination_silo="rubik-routing-matrix",
        sequence=version, timestamp=timestamp, ttl_seconds=ttl_seconds,
        policy="adaptive-matrix-v1", rationale="bounded-update-from-correctness-coherence-evaluator-latency-token-cost-freshness-health-failures",
        evidence_hashes=[routing_transition_hash], allowlisted_tools=[],
        budget_unit="weight-delta", budget_maximum=MAX_WEIGHT_DELTA, budget_used=abs(delta),
    )
    body = {
        "schema_version": ADAPTIVE_SCHEMA,
        "version": version,
        "previous_update_hash": previous_update_hash,
        "routing_transition_hash": routing_transition_hash,
        "route_id": route_id,
        "route_allowlist_hash": digest(routes),
        "previous_weight": previous_weight,
        "new_weight": new_weight,
        "delta": delta,
        "disposition": disposition,
        "measurement": measured,
        "constraints": constraints,
        "reversible": {"restore_weight": previous_weight, "inverse_delta": -delta},
        "state_hash": state_hash,
        "routing_envelope": envelope,
    }
    update_hash = digest(body)
    unsigned = {**body, "update_hash": update_hash}
    return {**unsigned, "signature_hmac_sha256": _signature(unsigned, key)}


def verify_adaptive_update(
    record: Mapping[str, Any], key: bytes, *, allowed_routes: Sequence[str], expected_previous_hash: str | None = None
) -> dict[str, Any]:
    fields = {"schema_version", "version", "previous_update_hash", "routing_transition_hash", "route_id", "route_allowlist_hash", "previous_weight", "new_weight", "delta", "disposition", "measurement", "constraints", "reversible", "state_hash", "routing_envelope", "update_hash", "signature_hmac_sha256"}
    _exact(record, fields, "adaptive update")
    if record["schema_version"] != ADAPTIVE_SCHEMA:
        raise RoutingProtocolError("unsupported adaptive routing schema")
    if expected_previous_hash is not None and record["previous_update_hash"] != expected_previous_hash:
        raise RoutingProtocolError("adaptive update chain mismatch")
    envelope = validate_routing_envelope(record["routing_envelope"])
    rebuilt = make_adaptive_update(
        task_id=envelope["what"]["task_id"], route_id=record["route_id"], allowed_routes=allowed_routes,
        previous_weight=record["previous_weight"], measurement=record["measurement"], version=record["version"],
        timestamp=envelope["when"]["timestamp"], ttl_seconds=envelope["when"]["ttl_seconds"],
        previous_update_hash=record["previous_update_hash"], routing_transition_hash=record["routing_transition_hash"], key=key,
    )
    if dict(record) != rebuilt:
        raise RoutingProtocolError("adaptive update is not replayable from its measured inputs")
    return {
        "valid": True,
        "update_hash": record["update_hash"],
        "new_weight": record["new_weight"],
        "disposition": record["disposition"],
        "restore_weight": record["reversible"]["restore_weight"],
    }


class AdaptiveMatrix:
    """Choose a route only from verified, bounded, signed metric updates."""

    def __init__(self, *, allowed_routes: Sequence[str], key: bytes):
        routes = sorted({_identifier(route, "allowed_route") for route in allowed_routes})
        if not routes or len(routes) > 64:
            raise RoutingProtocolError("Adaptive Matrix requires 1..64 fixed routes")
        self.allowed_routes = tuple(routes)
        self.key = _key(key)

    def update(self, **kwargs: Any) -> dict[str, Any]:
        if "allowed_routes" in kwargs or "key" in kwargs:
            raise RoutingProtocolError("Adaptive Matrix scope and signing key are fixed at construction")
        return make_adaptive_update(allowed_routes=self.allowed_routes, key=self.key, **kwargs)

    def verify_update(self, record: Mapping[str, Any], *, expected_previous_hash: str | None = None) -> dict[str, Any]:
        return verify_adaptive_update(
            record, self.key, allowed_routes=self.allowed_routes, expected_previous_hash=expected_previous_hash
        )

    def restore_weight(self, record: Mapping[str, Any]) -> int:
        """Return the signed prior weight only after full replay verification."""
        return int(self.verify_update(record)["restore_weight"])

    def choose_route(
        self,
        updates: Sequence[Mapping[str, Any]],
        *,
        timestamp: int,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        if not isinstance(updates, Sequence) or not 1 <= len(updates) <= len(self.allowed_routes):
            raise RoutingProtocolError("Adaptive Matrix selection requires a bounded update set")
        records = [dict(record) for record in updates]
        for record in records:
            self.verify_update(record)
        if len({record["route_id"] for record in records}) != len(records):
            raise RoutingProtocolError("Adaptive Matrix selection has duplicate routes")
        if any(record["route_id"] not in self.allowed_routes for record in records):
            raise RoutingProtocolError("Adaptive Matrix selection expands the route allowlist")
        versions = {record["version"] for record in records}
        transitions = {record["routing_transition_hash"] for record in records}
        task_ids = {record["routing_envelope"]["what"]["task_id"] for record in records}
        if len(versions) != 1 or len(transitions) != 1 or len(task_ids) != 1:
            raise RoutingProtocolError("Adaptive Matrix selection combines contradictory epochs")
        records.sort(key=lambda record: record["route_id"])
        basis = [
            {
                "route_id": record["route_id"],
                "update_hash": record["update_hash"],
                "weight": record["new_weight"],
                "disposition": record["disposition"],
                "measurement": dict(record["measurement"]),
            }
            for record in records
        ]
        eligible = [record for record in records if record["disposition"] != "quarantined"]
        eligible.sort(
            key=lambda record: (
                -record["new_weight"],
                -record["measurement"]["coherence_milli"],
                0 if record["measurement"]["health"] == "healthy" else 1,
                record["measurement"]["failure_count"],
                record["measurement"]["latency_ms"],
                record["measurement"]["tokens_used"],
                record["measurement"]["cost_units"],
                record["measurement"]["freshness_seconds"],
                record["route_id"],
            )
        )
        selected_route = eligible[0]["route_id"] if eligible else None
        status = "selected" if selected_route else "escalate"
        selection_state = {
            "version": next(iter(versions)),
            "routing_transition_hash": next(iter(transitions)),
            "basis": basis,
            "selected_route": selected_route,
            "status": status,
        }
        state_hash = digest(selection_state)
        destination = selected_route or "fixed-evaluator"
        envelope = routing_envelope(
            worker="adaptive-matrix", role="scheduler", task_id=next(iter(task_ids)),
            artifact="route-selection", artifact_hash=state_hash,
            source_silo="receipt-ledger", destination_silo=destination,
            sequence=next(iter(versions)), timestamp=timestamp, ttl_seconds=ttl_seconds,
            policy="adaptive-matrix-v1", rationale="deterministic-selection-from-verified-measured-route-updates",
            evidence_hashes=[record["update_hash"] for record in records], allowlisted_tools=[],
            budget_unit="route-candidates", budget_maximum=len(self.allowed_routes), budget_used=len(records),
        )
        body = {
            "schema_version": ADAPTIVE_SELECTION_SCHEMA,
            "version": next(iter(versions)),
            "routing_transition_hash": next(iter(transitions)),
            "route_allowlist_hash": digest(list(self.allowed_routes)),
            "basis": basis,
            "selected_route": selected_route,
            "status": status,
            "escalation": None if selected_route else {"evaluator": "fixed-evaluator", "gate": "xnet-seven-gates"},
            "state_hash": state_hash,
            "routing_envelope": envelope,
        }
        selection_hash = digest(body)
        unsigned = {**body, "selection_hash": selection_hash}
        return {**unsigned, "signature_hmac_sha256": _signature(unsigned, self.key)}

    def verify_selection(
        self, selection: Mapping[str, Any], updates: Sequence[Mapping[str, Any]]
    ) -> dict[str, Any]:
        fields = {
            "schema_version", "version", "routing_transition_hash", "route_allowlist_hash", "basis",
            "selected_route", "status", "escalation", "state_hash", "routing_envelope", "selection_hash",
            "signature_hmac_sha256",
        }
        _exact(selection, fields, "Adaptive Matrix selection")
        if selection["schema_version"] != ADAPTIVE_SELECTION_SCHEMA:
            raise RoutingProtocolError("unsupported Adaptive Matrix selection schema")
        envelope = validate_routing_envelope(selection["routing_envelope"])
        rebuilt = self.choose_route(
            updates,
            timestamp=envelope["when"]["timestamp"],
            ttl_seconds=envelope["when"]["ttl_seconds"],
        )
        if dict(selection) != rebuilt:
            raise RoutingProtocolError("Adaptive Matrix selection is not replayable from signed updates")
        return {
            "valid": True,
            "selection_hash": selection["selection_hash"],
            "selected_route": selection["selected_route"],
            "status": selection["status"],
        }

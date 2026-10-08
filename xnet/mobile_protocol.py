"""Strict, bounded messages for the private XNET mobile gateway.

The protocol carries source provenance and an explicit user-send assertion.  It
does not carry tool calls, VPN controls, credentials for a model, or a model
endpoint. Apple native inference remains on the phone; the private gateway can
only receive an escalation to its configured home 4B or home 14B rung.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import re
from typing import Any, Mapping

from .protocol import canonical, sha256


PAIR_REQUEST_SCHEMA = "xnet.mobile-pair-request.v1"
PAIR_RESPONSE_SCHEMA = "xnet.mobile-pair-response.v1"
REQUEST_SCHEMA = "xnet.mobile-gateway-request.v1"
RESPONSE_SCHEMA = "xnet.mobile-gateway-response.v1"
ORDERED_LANES = ("apple-native", "home-4b", "home-14b")
REMOTE_LANES = frozenset({"home-4b", "home-14b"})
PARAMETER_CEILING_BILLION = 14

MAX_PAIR_BYTES = 4096
MAX_REQUEST_BYTES = 65536
MAX_RESPONSE_BYTES = 131072
MAX_PROMPT_BYTES = 32768
MAX_OUTPUT_BYTES = 65536
MAX_SOURCES = 32
MAX_SAFE_INTEGER = 2**53 - 1

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_CODE = re.compile(r"[A-Za-z0-9_-]{24,128}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,256}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_RFC1918_V4 = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))
_NETBIRD_SHARED_V4 = ipaddress.ip_network("100.64.0.0/10")
_ULA_V6 = ipaddress.ip_network("fc00::/7")


class MobileProtocolError(ValueError):
    """A mobile message or transport address crossed the fixed contract."""


@dataclass(frozen=True)
class RemoteHomeLaneTranslation:
    """Explicit adapter receipt; it is not a mobile wire lane or an outcome."""

    source_lane: str
    source_location: str
    requested_lane: str
    lane_evidence_sha256: str


def translate_model_lane_for_remote_home(
        lane: str, *, source_location: str, explicit_user_route: bool,
        lane_evidence_sha256: str) -> RemoteHomeLaneTranslation:
    """Translate generic 4B intent only at a caller-selected remote boundary.

    ``xnet-4b`` remains the device-qualified, phone-local BYOM lane.  This
    receipt records a user's separate choice to use the home-host 4B adapter;
    it does not claim that a phone-local outcome came from ``home-4b`` and it
    does not grant authority to send a request.
    """
    if lane != "xnet-4b" or source_location != "device-qualified":
        raise MobileProtocolError("remote-home translation requires the device-qualified xnet-4b lane")
    if explicit_user_route is not True:
        raise MobileProtocolError("remote-home translation requires an explicit user route choice")
    evidence = _hash(lane_evidence_sha256, "lane_evidence_sha256")
    return RemoteHomeLaneTranslation(
        source_lane="xnet-4b", source_location="device-qualified",
        requested_lane="home-4b", lane_evidence_sha256=evidence)


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise MobileProtocolError(label + " fields differ from schema")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise MobileProtocolError(label + " requires a bounded identifier")
    return value


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise MobileProtocolError(label + " requires a lowercase SHA-256")
    return value


def _safe_integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        raise MobileProtocolError(label + " requires a bounded integer")
    return value


def _utf8(value: Any, label: str, *, minimum: int, maximum: int) -> str:
    if type(value) is not str:
        raise MobileProtocolError(label + " requires text")
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise MobileProtocolError(label + " requires valid UTF-8") from exc
    if not minimum <= size <= maximum or "\u2028" in value or "\u2029" in value:
        raise MobileProtocolError(label + " exceeds its UTF-8 byte limit")
    return value


def _display_name(value: Any) -> str:
    name = _utf8(value, "device_name", minimum=1, maximum=128)
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise MobileProtocolError("device_name contains a control character")
    return name


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MobileProtocolError("duplicate JSON field")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise MobileProtocolError("nonfinite JSON value refused")


def _float(value: str) -> None:
    raise MobileProtocolError("floating point JSON is not supported")


def _integer(value: str) -> int:
    # Refuse before ``int`` can hit Python's implementation-specific digit cap.
    if len(value) > 17:
        raise MobileProtocolError("JSON integer exceeds its bound")
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise MobileProtocolError("invalid JSON integer") from exc
    if not -MAX_SAFE_INTEGER <= parsed <= MAX_SAFE_INTEGER:
        raise MobileProtocolError("JSON integer exceeds its bound")
    return parsed


def _bounded_tree(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [1024]
    budget[0] -= 1
    if budget[0] < 0 or depth > 12:
        raise MobileProtocolError("JSON structure exceeds its bound")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise MobileProtocolError("JSON integer exceeds its bound")
        return
    if type(value) is str:
        _utf8(value, "JSON string", minimum=0, maximum=MAX_RESPONSE_BYTES)
        return
    if type(value) is list:
        if len(value) > 64:
            raise MobileProtocolError("JSON array exceeds its bound")
        for item in value:
            _bounded_tree(item, depth=depth + 1, budget=budget)
        return
    if type(value) is dict:
        if len(value) > 64:
            raise MobileProtocolError("JSON object exceeds its bound")
        for key, item in value.items():
            if type(key) is not str:
                raise MobileProtocolError("JSON object key requires text")
            _utf8(key, "JSON object key", minimum=1, maximum=128)
            _bounded_tree(item, depth=depth + 1, budget=budget)
        return
    raise MobileProtocolError("unsupported JSON value")


def load_bounded_json(wire: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    """Decode one bounded object, rejecting duplicate keys and loose numbers."""
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= MAX_RESPONSE_BYTES:
        raise MobileProtocolError("invalid JSON byte ceiling")
    if type(wire) is not bytes or not 1 <= len(wire) <= maximum_bytes:
        raise MobileProtocolError("JSON message exceeds its byte ceiling")
    try:
        text = wire.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_unique_object,
                           parse_constant=_nonfinite, parse_float=_float,
                           parse_int=_integer)
    except MobileProtocolError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise MobileProtocolError("invalid JSON message") from exc
    if type(value) is not dict:
        raise MobileProtocolError("JSON message must be an object")
    _bounded_tree(value)
    return value


def validate_private_mesh_address(value: Any) -> str:
    """Accept a numeric RFC1918, NetBird shared, or IPv6 ULA address only."""
    if type(value) is not str or not value or len(value) > 64 or "%" in value:
        raise MobileProtocolError("a numeric private mesh address is required")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise MobileProtocolError("a numeric private mesh address is required") from exc
    if str(address) != value:
        raise MobileProtocolError("mesh address must use canonical numeric form")
    allowed = ((address.version == 4 and
                (any(address in network for network in _RFC1918_V4)
                 or address in _NETBIRD_SHARED_V4))
               or (address.version == 6 and address in _ULA_V6))
    if (not allowed or address.is_loopback or address.is_unspecified
            or address.is_multicast or address.is_link_local):
        raise MobileProtocolError("mesh address must be private and non-loopback")
    return value


def _policy(value: Any, *, pairing: bool = False) -> dict[str, Any]:
    field = "explicit_user_pair" if pairing else "explicit_user_send"
    expected = {field, "tool_authority", "vpn_control"}
    policy = _exact(value, expected, "policy")
    if policy[field] is not True or policy["tool_authority"] != "none" or policy["vpn_control"] is not False:
        raise MobileProtocolError("mobile policy must require user action and grant no authority")
    return dict(policy)


def build_pair_request(*, code: str, device_id: str, device_name: str) -> bytes:
    _identifier(device_id, "device_id")
    _display_name(device_name)
    if type(code) is not str or _CODE.fullmatch(code) is None:
        raise MobileProtocolError("invalid pairing code")
    return canonical({
        "schema": PAIR_REQUEST_SCHEMA,
        "code": code,
        "device_id": device_id,
        "device_name": device_name,
        "policy": {"explicit_user_pair": True, "tool_authority": "none", "vpn_control": False},
    })


def inspect_pair_request(wire: bytes) -> dict[str, Any]:
    value = _exact(load_bounded_json(wire, maximum_bytes=MAX_PAIR_BYTES),
                   {"schema", "code", "device_id", "device_name", "policy"}, "pair request")
    if value["schema"] != PAIR_REQUEST_SCHEMA:
        raise MobileProtocolError("unsupported pair request schema")
    rebuilt = build_pair_request(code=value["code"], device_id=value["device_id"],
                                 device_name=value["device_name"])
    _policy(value["policy"], pairing=True)
    if rebuilt != wire:
        raise MobileProtocolError("pair request must use canonical JSON")
    return value


def build_pair_response(*, device_id: str, bearer_token: str, expires_at: int) -> bytes:
    _identifier(device_id, "device_id")
    _safe_integer(expires_at, "expires_at", minimum=1)
    if type(bearer_token) is not str or _TOKEN.fullmatch(bearer_token) is None:
        raise MobileProtocolError("invalid bearer token")
    return canonical({
        "schema": PAIR_RESPONSE_SCHEMA,
        "device_id": device_id,
        "bearer_token": bearer_token,
        "expires_at": expires_at,
        "policy": {"tool_authority": "none", "vpn_control": False},
    })


def inspect_pair_response(wire: bytes) -> dict[str, Any]:
    value = _exact(load_bounded_json(wire, maximum_bytes=MAX_PAIR_BYTES),
                   {"schema", "device_id", "bearer_token", "expires_at", "policy"}, "pair response")
    if value["schema"] != PAIR_RESPONSE_SCHEMA:
        raise MobileProtocolError("unsupported pair response schema")
    policy = _exact(value["policy"], {"tool_authority", "vpn_control"}, "pair response policy")
    if policy != {"tool_authority": "none", "vpn_control": False}:
        raise MobileProtocolError("pair response grants forbidden authority")
    rebuilt = build_pair_response(device_id=value["device_id"], bearer_token=value["bearer_token"],
                                  expires_at=value["expires_at"])
    if rebuilt != wire:
        raise MobileProtocolError("pair response must use canonical JSON")
    return value


def _sources(value: Any) -> list[str]:
    if (type(value) is not list or not 1 <= len(value) <= MAX_SOURCES
            or any(type(item) is not str or _HASH.fullmatch(item) is None for item in value)
            or len(value) != len(set(value))):
        raise MobileProtocolError("source_sha256 must contain unique complete hashes")
    return list(value)


def build_request(*, request_id: str, device_id: str, sequence: int, sent_at: int,
                  task_id: str, prompt: str, hce_sha256: str,
                  source_sha256: list[str], requested_lane: str,
                  prior_outcome_sha256: str) -> bytes:
    _identifier(request_id, "request_id")
    _identifier(device_id, "device_id")
    _identifier(task_id, "task_id")
    _safe_integer(sequence, "sequence", minimum=1)
    _safe_integer(sent_at, "sent_at", minimum=1)
    _utf8(prompt, "prompt", minimum=1, maximum=MAX_PROMPT_BYTES)
    _hash(hce_sha256, "hce_sha256")
    sources = _sources(source_sha256)
    _hash(prior_outcome_sha256, "prior_outcome_sha256")
    if type(requested_lane) is not str or requested_lane not in REMOTE_LANES:
        raise MobileProtocolError("gateway lane must be home 4B or home 14B")
    after_lane = ORDERED_LANES[ORDERED_LANES.index(requested_lane) - 1]
    value = {
        "schema": REQUEST_SCHEMA,
        "request_id": request_id,
        "device_id": device_id,
        "sequence": sequence,
        "sent_at": sent_at,
        "route": {
            "ordered_lanes": list(ORDERED_LANES),
            "after_lane": after_lane,
            "requested_lane": requested_lane,
            "parameter_ceiling_billion": PARAMETER_CEILING_BILLION,
            "prior_outcome_sha256": prior_outcome_sha256,
        },
        "input": {
            "task_id": task_id,
            "capability": "code",
            "prompt_utf8": prompt,
            "prompt_sha256": sha256(prompt.encode("utf-8")),
            "hce_sha256": hce_sha256,
            "source_sha256": sources,
        },
        "policy": {"explicit_user_send": True, "tool_authority": "none", "vpn_control": False},
    }
    wire = canonical(value)
    if len(wire) > MAX_REQUEST_BYTES:
        raise MobileProtocolError("gateway request exceeds its byte ceiling")
    return wire


def inspect_request(wire: bytes) -> dict[str, Any]:
    value = _exact(load_bounded_json(wire, maximum_bytes=MAX_REQUEST_BYTES), {
        "schema", "request_id", "device_id", "sequence", "sent_at", "route", "input", "policy",
    }, "gateway request")
    if value["schema"] != REQUEST_SCHEMA:
        raise MobileProtocolError("unsupported gateway request schema")
    route = _exact(value["route"], {"ordered_lanes", "after_lane", "requested_lane",
        "parameter_ceiling_billion", "prior_outcome_sha256"}, "route")
    request_input = _exact(value["input"], {"task_id", "capability", "prompt_utf8", "prompt_sha256",
        "hce_sha256", "source_sha256"}, "input")
    if request_input["capability"] != "code":
        raise MobileProtocolError("mobile gateway supports the bounded code capability only")
    _policy(value["policy"])
    rebuilt = build_request(
        request_id=value["request_id"], device_id=value["device_id"],
        sequence=value["sequence"], sent_at=value["sent_at"],
        task_id=request_input["task_id"], prompt=request_input["prompt_utf8"],
        hce_sha256=request_input["hce_sha256"], source_sha256=request_input["source_sha256"],
        requested_lane=route["requested_lane"],
        prior_outcome_sha256=route["prior_outcome_sha256"],
    )
    if route["ordered_lanes"] != list(ORDERED_LANES) or route["parameter_ceiling_billion"] != 14:
        raise MobileProtocolError("route changed the Apple to 4B to 14B ceiling")
    if request_input["prompt_sha256"] != sha256(request_input["prompt_utf8"].encode("utf-8")):
        raise MobileProtocolError("prompt hash mismatch")
    if rebuilt != wire:
        raise MobileProtocolError("gateway request must use canonical JSON")
    return value


def build_response(request: Mapping[str, Any], *, request_sha256: str,
                   selected_lane: str, model_identity_sha256: str, text: str) -> bytes:
    if type(request) is not dict:
        raise MobileProtocolError("validated request object required")
    # Rebuild and inspect so callers cannot pass an unvalidated lookalike mapping.
    checked = inspect_request(canonical(request))
    _hash(request_sha256, "request_sha256")
    if request_sha256 != sha256(canonical(checked)):
        raise MobileProtocolError("request hash mismatch")
    if selected_lane != checked["route"]["requested_lane"]:
        raise MobileProtocolError("response lane differs from the requested rung")
    _hash(model_identity_sha256, "model_identity_sha256")
    _utf8(text, "output", minimum=1, maximum=MAX_OUTPUT_BYTES)
    value = {
        "schema": RESPONSE_SCHEMA,
        "request_id": checked["request_id"],
        "sequence": checked["sequence"],
        "request_sha256": request_sha256,
        "status": "completed",
        "selected_lane": selected_lane,
        "model_identity_sha256": model_identity_sha256,
        "output": {"utf8": text, "sha256": sha256(text.encode("utf-8"))},
        "evidence": {
            "hce_sha256": checked["input"]["hce_sha256"],
            "source_sha256": list(checked["input"]["source_sha256"]),
        },
        "policy": {"tool_authority": "none", "vpn_control": False},
    }
    wire = canonical(value)
    if len(wire) > MAX_RESPONSE_BYTES:
        raise MobileProtocolError("gateway response exceeds its byte ceiling")
    return wire


def inspect_response(wire: bytes, *, expected_request_wire: bytes) -> dict[str, Any]:
    request = inspect_request(expected_request_wire)
    expected_request_sha256 = sha256(expected_request_wire)
    value = _exact(load_bounded_json(wire, maximum_bytes=MAX_RESPONSE_BYTES), {
        "schema", "request_id", "sequence", "request_sha256", "status", "selected_lane",
        "model_identity_sha256", "output", "evidence", "policy",
    }, "gateway response")
    if value["schema"] != RESPONSE_SCHEMA or value["status"] != "completed":
        raise MobileProtocolError("unsupported gateway response")
    _identifier(value["request_id"], "request_id")
    _safe_integer(value["sequence"], "sequence", minimum=1)
    _hash(value["request_sha256"], "request_sha256")
    if (value["request_sha256"] != expected_request_sha256
            or value["request_id"] != request["request_id"]
            or value["sequence"] != request["sequence"]):
        raise MobileProtocolError("response belongs to another request")
    if type(value["selected_lane"]) is not str or value["selected_lane"] not in REMOTE_LANES:
        raise MobileProtocolError("response selected an unsupported rung")
    _hash(value["model_identity_sha256"], "model_identity_sha256")
    output = _exact(value["output"], {"utf8", "sha256"}, "output")
    text = _utf8(output["utf8"], "output", minimum=1, maximum=MAX_OUTPUT_BYTES)
    if output["sha256"] != sha256(text.encode("utf-8")):
        raise MobileProtocolError("output hash mismatch")
    evidence = _exact(value["evidence"], {"hce_sha256", "source_sha256"}, "evidence")
    _hash(evidence["hce_sha256"], "hce_sha256")
    _sources(evidence["source_sha256"])
    if (value["selected_lane"] != request["route"]["requested_lane"]
            or evidence["hce_sha256"] != request["input"]["hce_sha256"]
            or evidence["source_sha256"] != request["input"]["source_sha256"]):
        raise MobileProtocolError("response route or evidence differs from its request")
    policy = _exact(value["policy"], {"tool_authority", "vpn_control"}, "response policy")
    if policy != {"tool_authority": "none", "vpn_control": False}:
        raise MobileProtocolError("response grants forbidden authority")
    if canonical(value) != wire:
        raise MobileProtocolError("gateway response must use canonical JSON")
    return value

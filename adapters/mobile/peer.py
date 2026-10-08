"""Enroll a hash-bound phone transport proof into caller-owned context.

This adapter does not authenticate phone hardware, receive new phone data,
start a service or runtime, close the borrowed gateway, or enable tool/model
work. The host-selected native peer remains separate from the device label.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re

from xnet.protocol import canonical, digest, sha256
from xnet_sdk.context import ContextPeer

_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PROOF_SCHEMA = "xnet.phone-browser-capsule-proof.v1"


def _pin(value):
    if type(value) is not str or not _HASH.fullmatch(value):
        raise ValueError("exact SHA-256 proof pointer required")
    return value


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate phone proof field")
        result[key] = value
    return result


class IPhoneContextPeer:
    """A source-only enrollment peer with deterministic native occurrence ID.

    The expected proof pin is caller-selected. Its hash validates the selected
    report bytes, not the report's semantic truth or cryptographic device
    identity. Ordinary native append/FETCH/replay controls remain unchanged.
    """
    def __init__(self, context, node_id, proof_bytes, expected_proof_sha256):
        if not isinstance(context, ContextPeer):
            raise ValueError("borrowed caller ContextPeer required")
        if type(node_id) is not str or not _ID.fullmatch(node_id):
            raise ValueError("bounded mobile node ID required")
        if type(proof_bytes) is not bytes or not 1 <= len(proof_bytes) <= 16384:
            raise ValueError("bounded exact phone proof bytes required")
        proof_pin = _pin(expected_proof_sha256)
        if sha256(proof_bytes) != proof_pin:
            raise ValueError("phone proof bytes differ from caller-selected pin")
        try:
            proof = json.loads(proof_bytes.decode("utf-8"), object_pairs_hook=_unique,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite phone proof")))
        except (UnicodeError, RecursionError) as exc:
            raise ValueError("invalid bounded UTF-8 phone proof") from exc
        if (type(proof) is not dict or proof.get("schema") != _PROOF_SCHEMA
                or proof.get("phone_browser_transfer_verified") is not True
                or proof.get("screenshot_receipt_matches") is not True
                or proof.get("hardware_identity_attested") is not False
                or proof.get("authority") != "none"
                or type(proof.get("model_calls")) is not int or proof["model_calls"] != 0):
            raise ValueError("source-only verified phone proof contract required")
        source_ip = proof.get("source_ip")
        try:
            address = ipaddress.IPv4Address(source_ip) if type(source_ip) is str else None
        except ipaddress.AddressValueError as exc:
            raise ValueError("canonical private phone IPv4 data required") from exc
        if address is None or str(address) != source_ip or not address.is_private:
            raise ValueError("canonical private phone IPv4 data required")
        if type(proof.get("echo_receipt")) is not dict or type(proof.get("ledger")) is not dict:
            raise ValueError("phone receipt and chain pointers required")
        echo_pin = _pin(proof["echo_receipt"].get("receipt_hash"))
        chain_pin = _pin(proof["ledger"].get("head"))
        capsule_pin = _pin(proof.get("capsule_sha256"))
        if (type(proof.get("capsule_bytes")) is not int
                or not 1 <= proof["capsule_bytes"] <= 8192):
            raise ValueError("bounded public capsule size required")
        self.context = context
        self._task_id, self._peer = context.task_id, context.peer
        self.node_id = node_id
        source_pins = {
            "adapter_sha256": sha256(Path(__file__).read_bytes()),
            "context_sdk_sha256": sha256((Path(__file__).parents[2] / "xnet_sdk/context.py").read_bytes()),
        }
        envelope = {"schema": "xnet.iphone-context-enrollment.v1",
            "node_id": node_id, "task_id": self._task_id, "admission_peer": self._peer,
            "device": {"kind": "iphone", "mesh_ip": source_ip,
                       "identity_is_declared": True, "hardware_identity_attested": False},
            "role": "context-relay-peer",
            "source_proof": {"schema": _PROOF_SCHEMA, "sha256": proof_pin,
                "echo_receipt_sha256": echo_pin, "ledger_head_sha256": chain_pin,
                "capsule_sha256": capsule_pin, "capsule_bytes": proof["capsule_bytes"],
                "verification": "caller-selected-hash-bound-phone-probe-report"},
            "readiness": {"phone_browser_probe_verified": True,
                "daily_context_forwarder_enabled": False, "phone_compute_enabled": False,
                "additional_phone_nodes_verified": False},
            "source_pins": source_pins, "context_only": True, "work_performed": False,
            "model_calls": 0, "authority": "none"}
        self._packet = canonical(envelope)
        self.event_id = "iphone-enroll-" + digest({"node_id": node_id,
            "task_id": self._task_id, "peer": self._peer, "proof_sha256": proof_pin})[:48]

    def enrollment_packet(self):
        """Return immutable canonical enrollment bytes without submitting them."""
        return self._packet

    def admit(self):
        """Append/replay the fixed enrollment under the caller's current head."""
        if self.context.task_id != self._task_id or self.context.peer != self._peer:
            raise ValueError("borrowed phone context identity changed")
        return self.context.append(self.event_id, self._packet.decode("utf-8"), kind="raw")

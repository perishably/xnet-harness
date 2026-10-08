"""Bounded public source envelopes; no OpenClaw runner or tool execution.

The caller chooses what is public and separately authorizes every storage
operation. Digests detect changed bytes; producer labels do not authenticate a
sender. Known secret patterns are screened, not a complete DLP guarantee.
"""
from __future__ import annotations

import hmac
import re
import time
import uuid
from typing import Any

from xnet.protocol import digest, sha256
from xnet.rag import SECRET_PATTERNS


SCHEMA = "xnet.oroboros-source-packet.v1"
MAX_TEXT_BYTES = 16_384
MAX_TTL_SECONDS = 86_400
MAX_HOPS = 4
_MAX_TIME = 2**63 - 1
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_SHA = re.compile(r"[0-9a-f]{64}")
_PRODUCERS = frozenset({"operator", "model", "peer"})
_KINDS = frozenset({"note", "evidence", "strategy", "proposal"})
_BODY_FIELDS = frozenset({
    "schema", "packet_id", "task_id", "producer", "kind", "classification",
    "text", "text_sha256", "authority", "context_only", "tools",
    "created_at", "expires_at", "max_hops",
})
_FIELDS = _BODY_FIELDS | {"packet_sha256"}
_PRIVATE_KEY = re.compile(rb"(?i)-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY-----")


class SourcePacketError(ValueError):
    """A packet failed the source-only envelope contract."""


def _clock(now: int | None) -> int:
    value = int(time.time()) if now is None else now
    if type(value) is not int or not 0 <= value <= _MAX_TIME:
        raise SourcePacketError("invalid current UTC seconds")
    return value


def _text_bytes(text: Any) -> bytes:
    if type(text) is not str:
        raise SourcePacketError("text must be a plain UTF-8 string")
    # A code-point bound rejects oversized input before allocating UTF-8 bytes.
    if len(text) > MAX_TEXT_BYTES:
        raise SourcePacketError("text exceeds the UTF-8 byte budget")
    try:
        raw = text.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise SourcePacketError("text is not valid UTF-8") from exc
    if len(raw) > MAX_TEXT_BYTES:
        raise SourcePacketError("text exceeds the UTF-8 byte budget")
    return raw


def _checked_body(body: dict[str, Any], now: int) -> dict[str, Any]:
    if (type(body) is not dict or any(type(key) is not str for key in body)
            or set(body) != _BODY_FIELDS):
        raise SourcePacketError("source packet fields do not match the contract")
    for field in ("packet_id", "task_id"):
        if type(body[field]) is not str or _ID.fullmatch(body[field]) is None:
            raise SourcePacketError(f"invalid {field}")
    if type(body["schema"]) is not str or body["schema"] != SCHEMA:
        raise SourcePacketError("invalid source packet schema")
    if type(body["producer"]) is not str or body["producer"] not in _PRODUCERS:
        raise SourcePacketError("invalid producer label")
    if type(body["kind"]) is not str or body["kind"] not in _KINDS:
        raise SourcePacketError("invalid source kind")
    if type(body["classification"]) is not str or body["classification"] != "public":
        raise SourcePacketError("only caller-classified public sources are admitted")
    if type(body["authority"]) is not str or body["authority"] != "none":
        raise SourcePacketError("source packets have no authority")
    if body["context_only"] is not True:
        raise SourcePacketError("source packets must be context only")
    if type(body["tools"]) is not list or len(body["tools"]) != 0:
        raise SourcePacketError("source packets cannot request tools")
    if type(body["max_hops"]) is not int or body["max_hops"] != MAX_HOPS:
        raise SourcePacketError("source packets require exactly four bounded hops")
    created, expires = body["created_at"], body["expires_at"]
    if (type(created) is not int or type(expires) is not int
            or not 0 <= created < expires <= _MAX_TIME
            or expires - created > MAX_TTL_SECONDS):
        raise SourcePacketError("invalid source packet lifetime")
    if created > now:
        raise SourcePacketError("source packet creation time is in the future")
    if now >= expires:
        raise SourcePacketError("source packet expired")
    raw = _text_bytes(body["text"])
    text_pin = body["text_sha256"]
    if (type(text_pin) is not str or _SHA.fullmatch(text_pin) is None
            or not hmac.compare_digest(text_pin, sha256(raw))):
        raise SourcePacketError("source text digest mismatch")
    if _PRIVATE_KEY.search(raw) or any(pattern.search(raw) for pattern in SECRET_PATTERNS):
        raise SourcePacketError("known private-key or credential pattern refused")
    # All fields are now fixed primitive values; never preserve a caller's list.
    return {**body, "tools": []}


def make_source_packet(*, task_id: str, producer: str, kind: str, text: str,
                       packet_id: str | None = None, now: int | None = None,
                       ttl_seconds: int = MAX_TTL_SECONDS) -> dict[str, Any]:
    """Make a pinned public source envelope, without granting action authority."""
    timestamp = _clock(now)
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise SourcePacketError("invalid source packet TTL")
    if packet_id is not None and type(packet_id) is not str:
        raise SourcePacketError("invalid packet_id")
    raw = _text_bytes(text)
    body = {
        "schema": SCHEMA,
        "packet_id": str(uuid.uuid4()) if packet_id is None else packet_id,
        "task_id": task_id,
        "producer": producer,
        "kind": kind,
        "classification": "public",
        "text": text,
        "text_sha256": sha256(raw),
        "authority": "none",
        "context_only": True,
        "tools": [],
        "created_at": timestamp,
        "expires_at": timestamp + ttl_seconds,
        "max_hops": MAX_HOPS,
    }
    checked = _checked_body(body, timestamp)
    return {**checked, "packet_sha256": digest(checked)}


def validate_source_packet(packet: Any, *, now: int | None = None) -> dict[str, Any]:
    """Return an independent validated copy; commands in text stay inert data.

    This gate accepts a plain dict, not serialized JSON. A transport is
    responsible for refusing duplicate JSON keys before calling this function.
    """
    timestamp = _clock(now)
    if (type(packet) is not dict or any(type(key) is not str for key in packet)
            or set(packet) != _FIELDS):
        raise SourcePacketError("source packet fields do not match the contract")
    packet_pin = packet["packet_sha256"]
    if type(packet_pin) is not str or _SHA.fullmatch(packet_pin) is None:
        raise SourcePacketError("invalid source packet digest")
    body = _checked_body({key: value for key, value in packet.items()
                          if key != "packet_sha256"}, timestamp)
    if not hmac.compare_digest(packet_pin, digest(body)):
        raise SourcePacketError("source packet digest mismatch")
    return {**body, "packet_sha256": packet_pin}


def gate_contract() -> dict[str, Any]:
    """Describe what this adapter actually provides; no runner is started."""
    return {
        "schema": "xnet.openclaw-source-gate-contract.v1",
        "packet_schema": SCHEMA,
        "role": "data-adapter-only",
        "OpenClaw_runner_executed": False,
        "tools": False,
        "model_calls": 0,
        "network_calls": 0,
        "storage_mutations": 0,
        "authority": "none",
        "max_text_bytes": MAX_TEXT_BYTES,
        "max_ttl_seconds": MAX_TTL_SECONDS,
        "max_hops": MAX_HOPS,
        "classification_owner": "caller",
        "producer_authentication": False,
        "truth_attested": False,
        "secret_screening": "known patterns only; not complete DLP",
        "scope_enforcement": "caller authorizes storage operations separately",
    }

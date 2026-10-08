"""Versioned wire objects and deterministic hashing."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

VERSION = 1
ZERO_HASH = "0" * 64
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
FIELDS = {"v", "event_id", "task_id", "scope_id", "policy_version", "source", "kind", "time_utc", "payload", "payload_sha256"}


class ProtocolError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    return sha256(canonical(value))


def _portable_json(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int):
        return -(2**63) <= value <= 2**63 - 1
    if isinstance(value, str):
        return "\u2028" not in value and "\u2029" not in value and not any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    if isinstance(value, list):
        return all(_portable_json(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and _portable_json(k) and _portable_json(v) for k, v in value.items())
    return False


def make_event(task_id: str, scope_id: str, kind: str, payload: dict[str, Any], *, source: str = "python", policy_version: str = "xnet-v1", event_id: str | None = None) -> dict[str, Any]:
    return {"v": VERSION, "event_id": event_id or str(uuid.uuid4()), "task_id": task_id, "scope_id": scope_id, "policy_version": policy_version, "source": source, "kind": kind, "time_utc": int(time.time()), "payload": payload, "payload_sha256": digest(payload)}


def validate_event(event: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(event, dict) or set(event) - (FIELDS | {"signature_hmac_sha256"}) or FIELDS - set(event):
        raise ProtocolError("event fields do not match protocol v1")
    if event["v"] != VERSION or isinstance(event["v"], bool):
        raise ProtocolError("unsupported event version")
    for field, limit in (("event_id", 128), ("task_id", 128), ("scope_id", 128), ("policy_version", 64), ("source", 64), ("kind", 64)):
        value = event[field]
        if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 for c in value) or not _portable_json(value):
            raise ProtocolError(f"invalid {field}")
    if not isinstance(event["time_utc"], (str, int)) or isinstance(event["time_utc"], bool):
        raise ProtocolError("invalid time_utc")
    if isinstance(event["time_utc"], int) and event["time_utc"] < 0:
        raise ProtocolError("invalid time_utc")
    if isinstance(event["time_utc"], str):
        try:
            if not UTC_TIMESTAMP.fullmatch(event["time_utc"]):
                raise ValueError()
            parsed = datetime.fromisoformat(event["time_utc"].replace("Z", "+00:00"))
            if parsed.tzinfo != timezone.utc:
                raise ValueError()
        except ValueError as exc:
            raise ProtocolError("time_utc must be RFC3339 UTC") from exc
    if not isinstance(event["payload"], dict) or not _portable_json(event["payload"]) or len(canonical(event["payload"])) > 65536:
        raise ProtocolError("payload must be an object of at most 64 KiB")
    if not isinstance(event["payload_sha256"], str) or not hmac.compare_digest(event["payload_sha256"], digest(event["payload"])):
        raise ProtocolError("payload digest mismatch")
    if "signature_hmac_sha256" in event and (not isinstance(event["signature_hmac_sha256"], str) or not HEX64.fullmatch(event["signature_hmac_sha256"])):
        raise ProtocolError("invalid event signature")
    return event


def sign_event(event: dict[str, Any], key: bytes) -> dict[str, Any]:
    validate_event(event)
    unsigned = {k: v for k, v in event.items() if k != "signature_hmac_sha256"}
    return {**unsigned, "signature_hmac_sha256": hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest()}


def verify_event_signature(event: dict[str, Any], key: bytes) -> bool:
    sig = event.get("signature_hmac_sha256", "")
    unsigned = {k: v for k, v in event.items() if k != "signature_hmac_sha256"}
    return bool(sig) and hmac.compare_digest(sig, hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest())

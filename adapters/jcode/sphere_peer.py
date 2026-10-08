"""Borrowed sphere-to-Jcode context seam; no model or storage lifecycle.

Four-silo readback proves byte identity. It does not attest provider upload,
sender identity or correctness. The caller owns scope, runtime and inference.
"""
from __future__ import annotations

import json
import re

from adapters.openclaw import validate_source_packet
from xnet.oroboros_sphere import SILOS, SphereController
from xnet.protocol import canonical, digest, sha256
from xnet_sdk import ContextPeer


SCHEMA = "xnet.jcode.sphere-source.v1"
_EVENT_FIELDS = {"seq", "event_id", "peer", "kind", "source_digest", "event_digest"}
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate sphere context field")
        result[key] = value
    return result


class JcodeSpherePeer:
    """Pass selected public sphere sources into a caller's native task history.

    Admission is resumable, not atomic across the two siblings: a completed
    sphere transfer can precede a refused native append. Replay uses the same
    event ID and immutable original completion receipt. Nothing is closed here.
    """

    def __init__(self, sphere: SphereController, context: ContextPeer):
        if not isinstance(sphere, SphereController) or not isinstance(context, ContextPeer):
            raise ValueError("borrowed SphereController and ContextPeer required")
        self.sphere, self.context = sphere, context
        self._binding = (context.task_id, context.peer, sphere.scope_id)

    def _bound(self):
        if self._binding != (self.context.task_id, self.context.peer, self.sphere.scope_id):
            raise ValueError("borrowed sphere/context binding changed")

    def _completion_proof(self, packet):
        # plan gates the caller's declared roots; the ledger remains its own
        # authority. Reconstruct the stable receipt rather than snapshotting a
        # global head that changes after other packets are admitted.
        self.sphere.plan()
        chain = self.sphere.ledger.verify_chain()
        events = self.sphere.ledger.events()
        previous = "0" * 64
        admitted, hops, completed = [], [], []
        for seq, event in enumerate(events, 1):
            event_pin = sha256(canonical(event))
            receipt = digest({"seq": seq, "prev_hash": previous, "event_hash": event_pin})
            if (event["task_id"] == packet["task_id"]
                    and event["payload"].get("packet_id") == packet["packet_id"]):
                if event["scope_id"] != self.sphere.scope_id or event["source"] != "sphere":
                    raise ValueError("sphere completion scope/source mismatch")
                if event["kind"] == "sphere.admitted":
                    admitted.append(event)
                elif event["kind"] == "sphere.hop":
                    hops.append(event_pin)
                elif event["kind"] == "sphere.completed":
                    completed.append((event, seq, event_pin, receipt, previous))
            previous = receipt
        if len(events) != chain["events"] or previous != chain["head"]:
            raise ValueError("sphere ledger changed during completion selection")
        object_pin = sha256(canonical(packet))
        if (len(admitted) != 1 or len(completed) != 1 or len(hops) != 4
                or admitted[0]["payload"].get("packet_sha256") != packet["packet_sha256"]
                or admitted[0]["payload"].get("object_sha256") != object_pin
                or completed[0][0]["payload"].get("object_sha256") != object_pin):
            raise ValueError("exact completed four-hop source required")
        _, seq, event_pin, receipt, parent = completed[0]
        return {
            "scope_id": self.sphere.scope_id, "packet_sha256": packet["packet_sha256"],
            "object_sha256": object_pin, "completion_seq": seq,
            "completion_event_sha256": event_pin, "completion_receipt_sha256": receipt,
            "completion_parent_receipt_sha256": parent, "hop_event_sha256": hops,
            "readback_silos": list(SILOS), "provider_upload_verified": False,
        }

    def admit(self, packet, lane="powershell", *, expected_sphere_head=None):
        self._bound()
        checked = validate_source_packet(packet)
        if checked["task_id"] != self.context.task_id:
            raise ValueError("sphere source differs from borrowed native task")
        cycle = self.sphere.cycle(checked, lane, expected_head=expected_sphere_head)
        raw = canonical(checked)
        for silo in SILOS:
            if self.sphere.fetch(silo, checked["packet_sha256"], lane) != raw:
                raise ValueError("exact four-silo readback failed")
        proof = self._completion_proof(checked)
        envelope = {
            "schema": SCHEMA, "task_id": self.context.task_id, "peer": self.context.peer,
            "packet": checked, "sphere": proof, "authority": "none",
            "work_performed": False, "context_only": True, "model_calls": 0,
        }
        text = canonical(envelope).decode("utf-8")
        if len(text.encode("utf-8")) > 65536:
            raise ValueError("native sphere envelope exceeds source bound")
        native = self.context.append("sphere-source-" + proof["object_sha256"], text, kind="raw")
        return {
            "schema": "xnet.jcode.sphere-admission.v1", "native": native, "sphere": proof,
            "sphere_idempotent_replay": cycle["idempotent_replay"],
            "authority": "none", "work_performed": False, "context_only": True,
            "model_calls": 0,
        }

    def public_context(self, selected_events, *, max_bytes=8192, lane="powershell"):
        """Fetch explicitly selected task occurrences as exact model-visible text.

        Native FETCH is root-wide. Membership in this borrowed task's history
        is therefore checked before any source FETCH. Historical source TTL is
        checked at admission time; retrieval grants no new action authority.
        This projection is data for a caller's frozen public-context policy.
        """
        self._bound()
        if (type(selected_events) is not list or not 1 <= len(selected_events) <= 16
                or type(max_bytes) is not int or not 128 <= max_bytes <= 16384):
            raise ValueError("one to sixteen exact events and a bounded context budget required")
        seen, selected = set(), []
        for event in selected_events:
            if (type(event) is not dict or set(event) != _EVENT_FIELDS
                    or type(event["seq"]) is not int or not 0 <= event["seq"] < 2048
                    or type(event["event_id"]) is not str or not _ID.fullmatch(event["event_id"])
                    or event["event_id"] in seen or event["peer"] != self.context.peer
                    or event["kind"] != "raw"
                    or any(type(event[key]) is not str or not _HEX.fullmatch(event[key])
                           for key in ("source_digest", "event_digest"))):
                raise ValueError("exact owned sphere event metadata required")
            page = self.context.history(after=event["seq"], limit=1)
            if page.get("task_id") != self.context.task_id or page.get("events") != [event]:
                raise ValueError("selected event is not in the borrowed native task")
            seen.add(event["event_id"])
            selected.append(event)
        records, text_bytes = [], 0
        fields = {"schema", "task_id", "peer", "packet", "sphere", "authority",
                  "work_performed", "context_only", "model_calls"}
        for event in selected:
            text = self.context.fetch_event(event)
            envelope = json.loads(text, object_pairs_hook=_object)
            if (type(envelope) is not dict or set(envelope) != fields or envelope["schema"] != SCHEMA
                    or envelope["task_id"] != self.context.task_id or envelope["peer"] != self.context.peer
                    or envelope["authority"] != "none" or envelope["work_performed"] is not False
                    or envelope["context_only"] is not True or type(envelope["model_calls"]) is not int
                    or envelope["model_calls"] != 0 or canonical(envelope).decode("utf-8") != text):
                raise ValueError("native sphere source contract mismatch")
            if type(envelope["packet"]) is not dict or "created_at" not in envelope["packet"]:
                raise ValueError("stored source packet required")
            packet = validate_source_packet(envelope["packet"], now=envelope["packet"]["created_at"])
            if packet["task_id"] != self.context.task_id:
                raise ValueError("stored sphere packet task mismatch")
            # Native storage preserves the admitted source, while this selected
            # silo read enforces the current caller scope and NullClaw controls.
            if self.sphere.fetch("c_nvme", packet["packet_sha256"], lane) != canonical(packet):
                raise ValueError("stored public source differs from sphere readback")
            proof = self._completion_proof(packet)
            if (envelope["sphere"] != proof
                    or event["event_id"] != "sphere-source-" + proof["object_sha256"]):
                raise ValueError("stored sphere completion proof mismatch")
            text_bytes += len(packet["text"].encode("utf-8"))
            records.append({
                "record_id": event["event_id"], "kind": "frozen-fetch", "text": packet["text"],
                "source_sha256": event["source_digest"], "text_sha256": packet["text_sha256"],
                "receipt_sha256": proof["completion_receipt_sha256"],
            })
        result = {
            "schema": "xnet.jcode.sphere-public-context.v1", "task_id": self.context.task_id,
            "records": records, "authority": "none", "work_performed": False,
            "context_only": True, "model_calls": 0,
        }
        if text_bytes > max_bytes or len(canonical(result)) > 32768:
            raise ValueError("complete sphere context exceeds budget; clipping refused")
        return result

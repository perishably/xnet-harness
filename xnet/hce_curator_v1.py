"""Optional extraction-only curator seam; inference and authority stay outside.

A model proposes one exact triple. This seam validates framing and source
fidelity, then requires an independently confirmed caller triple before HCE
stamping. Byte verification proves provenance, never semantic correctness.
No callback, model lifecycle, tool execution, storage or implicit curator is
installed here. A caller may persist the returned bytes through its scoped HCE
store and must preserve the intake and reply bytes under their full hashes.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

from .hce_capsule_v1 import (MAX_SOURCE_BYTES, decode_capsule, encode_capsule)
from .protocol import digest, sha256

_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
MAX_REPLY_BYTES = 8192
REFUSAL = b"NOT-A-CAPSULE"


class CuratorError(ValueError):
    pass


def _source(raw, maximum):
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise CuratorError("bounded nonempty exact bytes required")
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise CuratorError("exact valid UTF-8 required") from error


def _pin(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise CuratorError("complete lowercase SHA256 required")


@dataclass(frozen=True)
class CuratorPolicy:
    """Explicit caller topology and kinds; no ring-count or model defaults."""

    rings: tuple[int, ...]
    kinds: tuple[str, ...]
    max_payload_bytes: int

    def __post_init__(self):
        if (type(self.rings) is not tuple or not 1 <= len(self.rings) <= 256
                or any(type(r) is not int or not 1 <= r <= 2147483647 for r in self.rings)
                or len(set(self.rings)) != len(self.rings)):
            raise CuratorError("bounded unique exact caller rings required")
        if (type(self.kinds) is not tuple or not 1 <= len(self.kinds) <= 64
                or any(type(k) is not str or _ID.fullmatch(k) is None for k in self.kinds)
                or len(set(self.kinds)) != len(self.kinds)):
            raise CuratorError("bounded unique lowercase caller kinds required")
        if type(self.max_payload_bytes) is not int or not 1 <= self.max_payload_bytes <= MAX_SOURCE_BYTES:
            raise CuratorError("bounded exact non-bool payload budget required")

    @property
    def sha256(self):
        return digest({"schema": "xnet.curator-policy.v1", "rings": list(self.rings),
                       "kinds": list(self.kinds), "max_payload_bytes": self.max_payload_bytes})


@dataclass(frozen=True)
class CuratorProposal:
    """Exact untrusted source/output plus immutable, source-pinned selection."""

    intake_bytes: bytes
    reply_bytes: bytes
    expected_intake_sha256: str
    policy: CuratorPolicy
    triple: tuple[int, str, str] | None


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise CuratorError("duplicate JSON field refused")
        result[key] = value
    return result


def _nonfinite(value):
    raise CuratorError("nonfinite JSON refused")


def _triple(value, policy):
    if type(value) is not tuple or len(value) != 3:
        raise CuratorError("exact immutable ring/kind/payload triple required")
    ring, kind, payload = value
    if type(ring) is not int or ring not in policy.rings:
        raise CuratorError("exact non-bool ring outside caller topology")
    if type(kind) is not str or kind not in policy.kinds:
        raise CuratorError("kind outside caller contract")
    if type(payload) is not str:
        raise CuratorError("payload must remain exact text, including numeric text")
    try:
        _source(payload.encode("utf-8", "strict"), policy.max_payload_bytes)
    except UnicodeError as error:
        raise CuratorError("invalid payload Unicode") from error
    return value


def parse_curator_proposal(intake_bytes, reply_bytes, *, expected_intake_sha256, policy):
    """Reject coercions, extra fields, embedded JSON and nonliteral refusals.

    A positive payload must occur byte-exact in the intake. This is a necessary
    fidelity check, not proof that the model selected the right ring or payload.
    Outer JSON whitespace is accepted as framing; raw reply bytes remain pinned.
    """
    if type(policy) is not CuratorPolicy:
        raise CuratorError("typed caller policy required")
    intake = _source(intake_bytes, MAX_SOURCE_BYTES)
    reply = _source(reply_bytes, MAX_REPLY_BYTES)
    _pin(expected_intake_sha256)
    if sha256(intake_bytes) != expected_intake_sha256:
        raise CuratorError("intake source pin differs")
    if reply_bytes == REFUSAL:
        triple = None
    else:
        try:
            value = json.loads(reply, object_pairs_hook=_pairs, parse_constant=_nonfinite)
        except (ValueError, TypeError, RecursionError) as error:
            if isinstance(error, CuratorError):
                raise
            raise CuratorError("one complete JSON object or literal refusal required") from error
        if type(value) is not dict or set(value) != {"ring", "kind", "payload"}:
            raise CuratorError("exact curator JSON fields required")
        triple = _triple((value["ring"], value["kind"], value["payload"]), policy)
        if triple[2] not in intake:
            raise CuratorError("payload is absent from exact intake source")
    return CuratorProposal(intake_bytes, reply_bytes, expected_intake_sha256, policy, triple)


def stamp_confirmed_proposal(proposal, *, confirmed_triple, classification):
    """Mechanically stamp after caller confirmation; no automatic promotion.

    The caller owns independent semantic confirmation and explicit public-source
    selection. Hashing the model output alone cannot establish that confirmation.
    A literal negative proposal never creates a capsule.
    """
    if type(proposal) is not CuratorProposal:
        raise CuratorError("typed source-pinned proposal required")
    checked = parse_curator_proposal(proposal.intake_bytes, proposal.reply_bytes,
        expected_intake_sha256=proposal.expected_intake_sha256, policy=proposal.policy)
    if checked != proposal:
        raise CuratorError("proposal fields differ from exact source/output")
    if checked.triple is None:
        raise CuratorError("negative proposal cannot be stamped")
    if type(classification) is not str or classification != "public":
        raise CuratorError("caller must explicitly select public source")
    if _triple(confirmed_triple, checked.policy) != checked.triple:
        raise CuratorError("independently confirmed caller triple differs")
    ring, kind, payload = checked.triple
    payload_bytes = payload.encode("utf-8")
    wire = encode_capsule(payload_bytes, expected_source_sha256=sha256(payload_bytes),
                          ring=ring, kind=kind, classification=classification)
    verified = decode_capsule(wire, expected_sha256=sha256(wire))
    if (verified["ring"], verified["kind"], verified["text"]) != confirmed_triple:
        raise CuratorError("mechanical HCE reconstruction differs")
    receipt = {"schema": "xnet.curator-confirmed-intake.v1",
        "intake_sha256": checked.expected_intake_sha256,
        "reply_sha256": sha256(checked.reply_bytes), "policy_sha256": checked.policy.sha256,
        "payload_sha256": sha256(payload_bytes), "capsule_sha256": sha256(wire),
        "ring": ring, "kind": kind, "classification": classification,
        "semantic_basis": "caller-confirmed-triple", "authority": "none",
        "context_only": True, "work_performed": False,
        "storage_performed": False, "weight_update_performed": False}
    return {"capsule_bytes": wire, "receipt": receipt, "receipt_sha256": digest(receipt)}

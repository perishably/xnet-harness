"""Inactive HALO candidate observations, separate from exact engine policies.

Reported model labels and nominal capacities never identify an active engine.
This data type cannot activate a ContextPinProposal or rotate a session. Exact
caller-attested profiles remain governed by halo_context_v1.HaloPinRegistry.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from .protocol import digest

_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class HaloObservationError(ValueError):
    pass


@dataclass(frozen=True)
class UnboundContextCandidate:
    candidate_id: str
    reported_engine_label: str
    declared_capacity_tokens: int
    review_tokens: int
    reported_good_tokens: int
    evidence_sha256s: tuple[str, ...]
    blockers: tuple[str, ...]

    def __post_init__(self):
        for value in (self.candidate_id, self.reported_engine_label):
            if type(value) is not str or _ID.fullmatch(value) is None:
                raise HaloObservationError("bounded observation identifier required")
        for value in (self.declared_capacity_tokens, self.review_tokens, self.reported_good_tokens):
            if type(value) is not int or not 1 <= value <= 1048576:
                raise HaloObservationError("exact non-bool bounded token counts required")
        if not self.review_tokens < self.reported_good_tokens <= self.declared_capacity_tokens:
            raise HaloObservationError("candidate margin must precede reported good occupancy")
        if (type(self.evidence_sha256s) is not tuple or not 1 <= len(self.evidence_sha256s) <= 16
                or any(type(p) is not str or _HASH.fullmatch(p) is None for p in self.evidence_sha256s)
                or len(set(self.evidence_sha256s)) != len(self.evidence_sha256s)):
            raise HaloObservationError("bounded immutable unique evidence pins required")
        if (type(self.blockers) is not tuple or not 1 <= len(self.blockers) <= 16
                or any(type(b) is not str or not 1 <= len(b) <= 256 for b in self.blockers)):
            raise HaloObservationError("explicit unresolved qualification blockers required")

    def record(self):
        return {"schema": "xnet.halo-unbound-candidate.v1", "candidate_id": self.candidate_id,
            "reported_engine_label": self.reported_engine_label,
            "declared_capacity_tokens": self.declared_capacity_tokens, "review_tokens": self.review_tokens,
            "reported_good_tokens": self.reported_good_tokens, "evidence_sha256s": list(self.evidence_sha256s),
            "blockers": list(self.blockers), "status": "inactive-unbound",
            "purpose": "needle-recall-only", "active": False, "authority": "none",
            "rotation_performed": False}

    @property
    def sha256(self):
        return digest(self.record())

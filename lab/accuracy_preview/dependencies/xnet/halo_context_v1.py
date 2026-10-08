"""Optional HALO context advice bound to one complete caller-owned profile.

This pure library performs no I/O, inference or session rotation. Artifact pins
are caller declarations; the caller must attest the actual loaded configuration
and rendered prompt. A needle-recall proposal is not a reasoning guarantee.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re

from .protocol import digest

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")


class HaloContextError(ValueError):
    pass


def _pin(value):
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise HaloContextError("complete lowercase SHA256 required")
    return value


def _integer(value, minimum=1, maximum=1_048_576):
    if type(value) is not int or not minimum <= value <= maximum:
        raise HaloContextError("bounded exact non-bool token count required")
    return value


@dataclass(frozen=True)
class EngineProfile:
    """Exact frozen identity, not a model name or a context-size label.

    configuration_sha256 pins the caller's complete launch/slot/RoPE/decoding
    contract. Tokenizer/template hashes must identify the actual artifacts or
    exact embedded material, not a label hashed to resemble an artifact pin.
    """

    engine_id: str
    model_sha256: str
    runner_bundle_sha256: str
    tokenizer_sha256: str
    template_sha256: str
    configuration_sha256: str
    capacity_tokens: int
    generation_reserve_tokens: int

    def __post_init__(self):
        if type(self.engine_id) is not str or _ID.fullmatch(self.engine_id) is None:
            raise HaloContextError("bounded engine identifier required")
        for value in (self.model_sha256, self.runner_bundle_sha256,
                      self.tokenizer_sha256, self.template_sha256,
                      self.configuration_sha256):
            _pin(value)
        _integer(self.capacity_tokens)
        _integer(self.generation_reserve_tokens, 0)
        if self.generation_reserve_tokens >= self.capacity_tokens:
            raise HaloContextError("reserve must leave prompt capacity")

    @property
    def sha256(self):
        return digest({"schema": "xnet.halo-engine-profile.v1", **asdict(self)})


@dataclass(frozen=True)
class ContextPinProposal:
    """Source-backed recall margin; only the caller can adopt a policy."""

    profile_sha256: str
    review_tokens: int
    proven_good_tokens: int
    evidence_sha256s: tuple[str, ...]
    purpose: str = "needle-recall-only"

    def __post_init__(self):
        _pin(self.profile_sha256)
        _integer(self.review_tokens)
        _integer(self.proven_good_tokens)
        if self.review_tokens >= self.proven_good_tokens:
            raise HaloContextError("review margin must precede the proven-good point")
        if (type(self.evidence_sha256s) is not tuple
                or not 1 <= len(self.evidence_sha256s) <= 16):
            raise HaloContextError("bounded unique immutable evidence pins required")
        for value in self.evidence_sha256s:
            _pin(value)
        if len(set(self.evidence_sha256s)) != len(self.evidence_sha256s):
            raise HaloContextError("unique evidence pins required")
        if type(self.purpose) is not str or self.purpose != "needle-recall-only":
            raise HaloContextError("this policy does not establish reasoning quality")

    def validate_for(self, profile):
        if type(profile) is not EngineProfile or profile.sha256 != self.profile_sha256:
            raise HaloContextError("pin belongs to a different engine configuration")
        if self.proven_good_tokens + profile.generation_reserve_tokens > profile.capacity_tokens:
            raise HaloContextError("recall point leaves insufficient generation headroom")
        return self


class HaloPinRegistry:
    """In-memory explicit registry; no default engine or implicit activation."""

    def __init__(self):
        self._entries = {}

    def register(self, profile, proposal):
        if type(proposal) is not ContextPinProposal:
            raise HaloContextError("typed context proposal required")
        proposal.validate_for(profile)
        entry = (profile, proposal)
        old = self._entries.get(profile.sha256)
        if old is not None and old != entry:
            raise HaloContextError("frozen policy differs; use a new registry")
        self._entries[profile.sha256] = entry
        return profile.sha256

    def advise(self, *, profile_sha256, observed_profile_sha256,
               rendered_prompt_sha256, measured_prompt_tokens):
        """Return data only from a caller's exact current occupancy report."""
        for value in (profile_sha256, observed_profile_sha256, rendered_prompt_sha256):
            _pin(value)
        _integer(measured_prompt_tokens, 0)
        if observed_profile_sha256 != profile_sha256:
            raise HaloContextError("observed loaded profile differs")
        if profile_sha256 not in self._entries:
            raise HaloContextError("no explicit policy for this profile")
        profile, proposal = self._entries[profile_sha256]
        proposal.validate_for(profile)
        if measured_prompt_tokens + profile.generation_reserve_tokens > profile.capacity_tokens:
            raise HaloContextError("rendered prompt plus reserve exceeds the capacity")
        return {
            "schema": "xnet.halo-context-advice.v1",
            "profile_sha256": profile_sha256,
            "rendered_prompt_sha256": rendered_prompt_sha256,
            "measured_prompt_tokens": measured_prompt_tokens,
            "capacity_tokens": profile.capacity_tokens,
            "generation_reserve_tokens": profile.generation_reserve_tokens,
            "review_tokens": proposal.review_tokens,
            "review_due": measured_prompt_tokens >= proposal.review_tokens,
            "remaining_after_reserve": profile.capacity_tokens
                - measured_prompt_tokens - profile.generation_reserve_tokens,
            "evidence_sha256s": list(proposal.evidence_sha256s),
            "identity_basis": "caller-attested-current-profile",
            "purpose": proposal.purpose,
            "authority": "none",
            "rotation_performed": False,
        }

"""In-memory, single-use pairing for a caller-owned private TLS listener.

Pairing codes and bearer tokens are retained only as SHA-256 digests.  This
module performs no file access, logging, network access, or VPN management.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import secrets
import threading
import time
from typing import Callable

from .mobile_protocol import (
    MobileProtocolError,
    build_pair_request,
    validate_private_mesh_address,
)


class PairingError(ValueError):
    """A pairing code or credential was invalid, expired, or revoked."""


def _secret(random_bytes: Callable[[int], bytes], size: int) -> str:
    raw = random_bytes(size)
    if type(raw) is not bytes or len(raw) != size:
        raise PairingError("credential entropy source returned invalid bytes")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii", errors="strict")).hexdigest()


def _now(clock: Callable[[], float]) -> int:
    value = clock()
    if type(value) not in (int, float) or isinstance(value, bool) or value < 0:
        raise PairingError("clock returned an invalid time")
    return int(value)


@dataclass(frozen=True, repr=False)
class PairingInvitation:
    code: str
    expires_at: int

    def __repr__(self) -> str:
        return f"PairingInvitation(code=<redacted>, expires_at={self.expires_at})"


@dataclass(frozen=True, repr=False)
class PairingCredential:
    device_id: str
    device_name: str
    bound_address: str
    bearer_token: str
    issued_at: int
    expires_at: int

    def __repr__(self) -> str:
        return ("PairingCredential(device_id=%r, device_name=%r, bound_address=%r, "
                "bearer_token=<redacted>, issued_at=%r, expires_at=%r)" %
                (self.device_id, self.device_name, self.bound_address,
                 self.issued_at, self.expires_at))


@dataclass(frozen=True)
class PairedPrincipal:
    device_id: str
    device_name: str
    bound_address: str
    issued_at: int
    expires_at: int
    generation: int


@dataclass
class _CodeRecord:
    digest: str
    expires_at: int


@dataclass
class _TokenRecord:
    digest: str
    principal: PairedPrincipal


class PairingAuthority:
    """Bounded volatile pairing state with address-bound, revocable tokens."""

    def __init__(self, *, clock: Callable[[], float] = time.time,
                 random_bytes: Callable[[int], bytes] = secrets.token_bytes,
                 code_ttl_seconds: int = 300, token_ttl_seconds: int = 86400,
                 maximum_pending_codes: int = 16, maximum_devices: int = 64):
        for value, label, high in (
            (code_ttl_seconds, "code TTL", 3600),
            (token_ttl_seconds, "token TTL", 31 * 86400),
            (maximum_pending_codes, "pending code limit", 256),
            (maximum_devices, "device limit", 1024),
        ):
            if type(value) is not int or not 1 <= value <= high:
                raise PairingError(label + " is outside its bound")
        if not callable(clock) or not callable(random_bytes):
            raise PairingError("clock and entropy source must be callable")
        self._clock = clock
        self._random_bytes = random_bytes
        self._code_ttl = code_ttl_seconds
        self._token_ttl = token_ttl_seconds
        self._maximum_pending = maximum_pending_codes
        self._maximum_devices = maximum_devices
        self._codes: dict[str, _CodeRecord] = {}
        self._tokens: dict[str, _TokenRecord] = {}
        self._device_tokens: dict[str, str] = {}
        self._generation = 0
        self._lock = threading.RLock()

    def _prune(self, now: int) -> None:
        for key, record in tuple(self._codes.items()):
            if record.expires_at <= now:
                del self._codes[key]
        for key, record in tuple(self._tokens.items()):
            if record.principal.expires_at <= now:
                del self._tokens[key]
                if self._device_tokens.get(record.principal.device_id) == key:
                    del self._device_tokens[record.principal.device_id]

    def issue(self) -> PairingInvitation:
        now = _now(self._clock)
        with self._lock:
            self._prune(now)
            if len(self._codes) >= self._maximum_pending:
                raise PairingError("pending pairing code limit reached")
            for _ in range(8):
                code = _secret(self._random_bytes, 24)
                code_digest = _digest(code)
                if code_digest not in self._codes:
                    break
            else:
                raise PairingError("could not allocate a unique pairing code")
            expires_at = now + self._code_ttl
            self._codes[code_digest] = _CodeRecord(code_digest, expires_at)
            return PairingInvitation(code, expires_at)

    def redeem(self, *, code: str, device_id: str, device_name: str,
               bound_address: str) -> PairingCredential:
        # Protocol builders perform the same validation; keep this authority safe
        # for direct host use as well.
        try:
            build_pair_request(code=code, device_id=device_id, device_name=device_name)
            validate_private_mesh_address(bound_address)
        except (MobileProtocolError, UnicodeError) as exc:
            raise PairingError("invalid pairing claim") from exc
        now = _now(self._clock)
        try:
            code_digest = _digest(code)
        except (UnicodeError, ValueError) as exc:
            raise PairingError("invalid pairing claim") from exc
        with self._lock:
            self._prune(now)
            record = self._codes.get(code_digest)
            if record is None or not hmac.compare_digest(record.digest, code_digest):
                raise PairingError("pairing code is invalid, expired, or already used")
            if device_id in self._device_tokens:
                raise PairingError("device is already paired; revoke it before pairing again")
            if len(self._tokens) >= self._maximum_devices:
                raise PairingError("paired device limit reached")
            # Consume only after every claim and capacity check succeeds.
            del self._codes[code_digest]
            token = _secret(self._random_bytes, 32)
            token_digest = _digest(token)
            if token_digest in self._tokens:
                raise PairingError("credential entropy collision")
            self._generation += 1
            principal = PairedPrincipal(device_id, device_name, bound_address,
                                        now, now + self._token_ttl, self._generation)
            self._tokens[token_digest] = _TokenRecord(token_digest, principal)
            self._device_tokens[device_id] = token_digest
            return PairingCredential(device_id, device_name, bound_address, token,
                                     principal.issued_at, principal.expires_at)

    def authenticate(self, bearer_token: str, *, bound_address: str) -> PairedPrincipal:
        try:
            validate_private_mesh_address(bound_address)
            if type(bearer_token) is not str or not 32 <= len(bearer_token) <= 256:
                raise ValueError()
            token_digest = _digest(bearer_token)
        except (MobileProtocolError, UnicodeError, ValueError) as exc:
            raise PairingError("credential is invalid, expired, or revoked") from exc
        now = _now(self._clock)
        with self._lock:
            self._prune(now)
            record = self._tokens.get(token_digest)
            if (record is None or not hmac.compare_digest(record.digest, token_digest)
                    or record.principal.bound_address != bound_address):
                raise PairingError("credential is invalid, expired, revoked, or on another address")
            return record.principal

    def revoke_device(self, device_id: str) -> bool:
        if type(device_id) is not str:
            raise PairingError("device identifier is invalid")
        with self._lock:
            token_digest = self._device_tokens.pop(device_id, None)
            if token_digest is None:
                return False
            self._tokens.pop(token_digest, None)
            return True

    def revoke_token(self, bearer_token: str) -> bool:
        try:
            token_digest = _digest(bearer_token)
        except (UnicodeError, ValueError) as exc:
            raise PairingError("credential is invalid") from exc
        with self._lock:
            record = self._tokens.pop(token_digest, None)
            if record is None:
                return False
            if self._device_tokens.get(record.principal.device_id) == token_digest:
                del self._device_tokens[record.principal.device_id]
            return True

    def active_device_ids(self) -> tuple[str, ...]:
        now = _now(self._clock)
        with self._lock:
            self._prune(now)
            return tuple(sorted(self._device_tokens))

    def generation_active(self, device_id: str, generation: int) -> bool:
        """Let the local gateway prune state after expiry or revocation."""
        if type(device_id) is not str or type(generation) is not int:
            return False
        now = _now(self._clock)
        with self._lock:
            self._prune(now)
            token_digest = self._device_tokens.get(device_id)
            record = None if token_digest is None else self._tokens.get(token_digest)
            return record is not None and record.principal.generation == generation

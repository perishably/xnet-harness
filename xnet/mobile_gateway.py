"""Pure host-side request gate for a caller-owned NetBird TLS listener.

This module deliberately creates no socket and knows no model URL.  A caller
supplies a configured server ``SSLContext``, terminates TLS on the validated
private mesh address, and passes authenticated request bytes here.  The injected
dispatcher is responsible for its selected local model; it receives no tool or
VPN authority from this protocol.
"""
from __future__ import annotations

from collections import OrderedDict
import copy
from dataclasses import dataclass
import re
import ssl
import threading
import time
from typing import Callable

from .mobile_pairing import PairingAuthority, PairingError
from .mobile_protocol import (
    MobileProtocolError,
    build_pair_response,
    build_response,
    inspect_pair_request,
    inspect_request,
    validate_private_mesh_address,
)
from .protocol import sha256


_HASH = re.compile(r"[0-9a-f]{64}\Z")


class MobileGatewayError(ValueError):
    """The private gateway refused a transport, credential, or request."""


class GatewayDispatchUncertain(MobileGatewayError):
    """Dispatch may have started; the same request must not be sent again."""


@dataclass(frozen=True)
class MobileGatewayConfig:
    bind_address: str
    port: int
    tls_context: ssl.SSLContext
    home_4b_model_identity_sha256: str
    home_14b_model_identity_sha256: str
    maximum_request_age_seconds: int = 300
    maximum_future_skew_seconds: int = 30
    replay_entries_per_device: int = 8
    maximum_requests_per_credential: int = 1024
    maximum_gateway_states: int = 64
    maximum_orphaned_pending: int = 64

    def __post_init__(self) -> None:
        try:
            validate_private_mesh_address(self.bind_address)
        except MobileProtocolError as exc:
            raise MobileGatewayError("gateway bind address must be an explicit private mesh IP") from exc
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise MobileGatewayError("gateway port is invalid")
        if not isinstance(self.tls_context, ssl.SSLContext):
            raise MobileGatewayError("caller-provided TLS context is required")
        if self.tls_context.protocol != ssl.PROTOCOL_TLS_SERVER:
            raise MobileGatewayError("TLS context must be configured for a server")
        if self.tls_context.minimum_version < ssl.TLSVersion.TLSv1_2:
            raise MobileGatewayError("TLS 1.2 or newer is required")
        if (type(self.home_4b_model_identity_sha256) is not str
                or _HASH.fullmatch(self.home_4b_model_identity_sha256) is None
                or type(self.home_14b_model_identity_sha256) is not str
                or _HASH.fullmatch(self.home_14b_model_identity_sha256) is None
                or self.home_4b_model_identity_sha256 == self.home_14b_model_identity_sha256):
            raise MobileGatewayError("distinct pinned 4B and 14B model identities are required")
        for value, label, high in (
            (self.maximum_request_age_seconds, "request age", 3600),
            (self.maximum_future_skew_seconds, "future skew", 300),
            (self.replay_entries_per_device, "replay entry limit", 64),
            (self.maximum_requests_per_credential, "credential request limit", 4096),
            (self.maximum_gateway_states, "gateway state limit", 1024),
            (self.maximum_orphaned_pending, "orphaned pending limit", 1024),
        ):
            if type(value) is not int or not 1 <= value <= high:
                raise MobileGatewayError(label + " is outside its bound")


@dataclass(frozen=True)
class TransportContext:
    peer_address: str
    tls_established: bool


@dataclass(frozen=True)
class GatewayResult:
    selected_lane: str
    model_identity_sha256: str
    text: str


@dataclass(frozen=True)
class GatewayReply:
    wire: bytes
    idempotent_replay: bool


@dataclass(frozen=True)
class PendingDispatch:
    device_id: str
    credential_generation: int
    sequence: int
    request_id: str
    request_sha256: str


@dataclass(frozen=True)
class AppleNativeOutcomeProof:
    """Exact lookup key for a trusted, immediately prior Apple outcome."""

    device_id: str
    credential_generation: int
    request_sequence: int
    sent_at: int
    task_id: str
    prompt_sha256: str
    hce_sha256: str
    source_sha256: tuple[str, ...]
    outcome_sha256: str


@dataclass
class _Completed:
    request_id: str
    request_sha256: str
    wire: bytes


@dataclass(frozen=True)
class _Outcome:
    sequence: int
    task_id: str
    selected_lane: str
    prompt_sha256: str
    hce_sha256: str
    source_sha256: tuple[str, ...]


@dataclass
class _DeviceState:
    expires_at: int
    next_sequence: int
    completed: OrderedDict[int, _Completed]
    request_ids: dict[str, int]
    outcomes: dict[str, _Outcome]
    pending: PendingDispatch | None = None


class MobileGateway:
    """Validate pairing and sequential requests without owning a listener.

    For ``home-4b``, ``apple_outcome_checker`` must resolve the supplied digest
    in trusted host storage and return ``True`` only when that record is the
    immediately prior Apple-native outcome for every field in the proof.  A
    digest asserted only by the authenticated phone is not independent proof.
    Omitting the checker therefore leaves ``home-4b`` closed.
    """

    def __init__(self, config: MobileGatewayConfig, pairing: PairingAuthority,
                 dispatcher: Callable[[dict], GatewayResult], *,
                 evidence_checker: Callable[[str, tuple[str, ...]], bool],
                 apple_outcome_checker: Callable[[AppleNativeOutcomeProof], bool] | None = None,
                 clock: Callable[[], float] = time.time):
        if type(config) is not MobileGatewayConfig or type(pairing) is not PairingAuthority:
            raise MobileGatewayError("validated gateway config and pairing authority required")
        if (not callable(dispatcher) or not callable(evidence_checker)
                or (apple_outcome_checker is not None and not callable(apple_outcome_checker))
                or not callable(clock)):
            raise MobileGatewayError("dispatcher, evidence checker, and clock must be callable")
        self.config = config
        self._pairing = pairing
        self._dispatcher = dispatcher
        self._evidence_checker = evidence_checker
        self._apple_outcome_checker = apple_outcome_checker
        self._clock = clock
        self._states: dict[tuple[str, int], _DeviceState] = {}
        self._orphaned_pending: OrderedDict[tuple[str, int], PendingDispatch] = OrderedDict()
        self._lock = threading.RLock()

    def listener_contract(self) -> tuple[str, int, ssl.SSLContext]:
        """Return caller-owned listener inputs; this never opens a socket."""
        return self.config.bind_address, self.config.port, self.config.tls_context

    def _transport(self, transport: TransportContext) -> str:
        if type(transport) is not TransportContext or transport.tls_established is not True:
            raise MobileGatewayError("an established caller-owned TLS transport is required")
        try:
            return validate_private_mesh_address(transport.peer_address)
        except MobileProtocolError as exc:
            raise MobileGatewayError("peer must have an explicit private mesh IP") from exc

    def handle_pair(self, transport: TransportContext, wire: bytes) -> bytes:
        peer_address = self._transport(transport)
        try:
            request = inspect_pair_request(wire)
            credential = self._pairing.redeem(
                code=request["code"], device_id=request["device_id"],
                device_name=request["device_name"], bound_address=peer_address)
            return build_pair_response(device_id=credential.device_id,
                                       bearer_token=credential.bearer_token,
                                       expires_at=credential.expires_at)
        except (MobileProtocolError, PairingError) as exc:
            raise MobileGatewayError("pairing refused") from exc

    @staticmethod
    def _bearer(authorization: str) -> str:
        if (type(authorization) is not str or not authorization.startswith("Bearer ")
                or not 39 <= len(authorization) <= 263
                or authorization.count(" ") != 1):
            raise MobileGatewayError("valid bearer authorization required")
        token = authorization[7:]
        if not token or any(ord(char) > 127 for char in token):
            raise MobileGatewayError("valid bearer authorization required")
        return token

    def _time(self) -> int:
        value = self._clock()
        if type(value) not in (int, float) or isinstance(value, bool) or value < 0:
            raise MobileGatewayError("clock returned an invalid time")
        return int(value)

    def _prune_states(self, now: int) -> None:
        for key, state in tuple(self._states.items()):
            if (state.expires_at <= now
                    or not self._pairing.generation_active(key[0], key[1])):
                if state.pending is not None:
                    self._orphaned_pending[key] = state.pending
                    while len(self._orphaned_pending) > self.config.maximum_orphaned_pending:
                        self._orphaned_pending.popitem(last=False)
                del self._states[key]

    def _expected_model_identity(self, lane: str) -> str:
        if lane == "home-4b":
            return self.config.home_4b_model_identity_sha256
        if lane == "home-14b":
            return self.config.home_14b_model_identity_sha256
        raise MobileProtocolError("dispatcher selected an unsupported lane")

    def handle_request(self, transport: TransportContext, authorization: str,
                       wire: bytes) -> GatewayReply:
        peer_address = self._transport(transport)
        token = self._bearer(authorization)
        try:
            principal = self._pairing.authenticate(token, bound_address=peer_address)
            request = inspect_request(wire)
        except (PairingError, MobileProtocolError) as exc:
            raise MobileGatewayError("authenticated request refused") from exc
        if request["device_id"] != principal.device_id:
            raise MobileGatewayError("request device differs from its credential")
        now = self._time()
        request_digest = sha256(wire)
        sequence = request["sequence"]
        request_id = request["request_id"]
        state_key = (principal.device_id, principal.generation)
        with self._lock:
            self._prune_states(now)
            state = self._states.get(state_key)
            if state is None:
                if len(self._states) >= self.config.maximum_gateway_states:
                    raise MobileGatewayError("gateway state limit reached")
                state = _DeviceState(principal.expires_at, 1, OrderedDict(), {}, {})
                self._states[state_key] = state
            completed = state.completed.get(sequence)
            if completed is not None:
                if (completed.request_id != request_id
                        or not hmac_compare(completed.request_sha256, request_digest)):
                    raise MobileGatewayError("sequence replay differs from its completed request")
                return GatewayReply(completed.wire, True)
            if sequence < state.next_sequence:
                raise MobileGatewayError("sequence is stale and no longer replayable")
            if sequence > state.next_sequence:
                raise MobileGatewayError("request sequence has a gap")
            if state.pending is not None:
                pending = state.pending
                if (pending.sequence == sequence and pending.request_id == request_id
                        and hmac_compare(pending.request_sha256, request_digest)):
                    raise GatewayDispatchUncertain(
                        "matching dispatch is pending or uncertain; reconcile it locally")
                raise MobileGatewayError("another request is pending for this device")
            prior_sequence = state.request_ids.get(request_id)
            if prior_sequence is not None and prior_sequence != sequence:
                raise MobileGatewayError("request identifier was reused at another sequence")
            if (request["sent_at"] < now - self.config.maximum_request_age_seconds
                    or request["sent_at"] > now + self.config.maximum_future_skew_seconds):
                raise MobileGatewayError("request time is outside the accepted window")
            if state.next_sequence > self.config.maximum_requests_per_credential:
                raise MobileGatewayError("credential request limit reached; pair a new credential")
            if request["route"]["requested_lane"] == "home-14b":
                prior = state.outcomes.get(request["route"]["prior_outcome_sha256"])
                if (prior is None or prior.sequence != sequence - 1
                        or prior.selected_lane != "home-4b"
                        or prior.task_id != request["input"]["task_id"]
                        or prior.prompt_sha256 != request["input"]["prompt_sha256"]
                        or prior.hce_sha256 != request["input"]["hce_sha256"]
                        or prior.source_sha256 != tuple(request["input"]["source_sha256"])):
                    raise MobileGatewayError(
                        "14B escalation requires the matching immediately prior 4B response")
            reservation = PendingDispatch(principal.device_id, principal.generation,
                                          sequence, request_id, request_digest)
            state.pending = reservation

        if request["route"]["requested_lane"] == "home-4b":
            proof = AppleNativeOutcomeProof(
                device_id=principal.device_id,
                credential_generation=principal.generation,
                request_sequence=sequence,
                sent_at=request["sent_at"],
                task_id=request["input"]["task_id"],
                prompt_sha256=request["input"]["prompt_sha256"],
                hce_sha256=request["input"]["hce_sha256"],
                source_sha256=tuple(request["input"]["source_sha256"]),
                outcome_sha256=request["route"]["prior_outcome_sha256"],
            )
            try:
                apple_verified = (False if self._apple_outcome_checker is None
                                  else self._apple_outcome_checker(proof))
            except Exception:
                self._clear_reservation(state_key, reservation)
                raise MobileGatewayError("trusted Apple-native outcome lookup failed") from None
            if apple_verified is not True:
                self._clear_reservation(state_key, reservation)
                raise MobileGatewayError(
                    "4B escalation requires the matching immediately prior Apple-native outcome")

        try:
            evidence_verified = self._evidence_checker(
                request["input"]["hce_sha256"],
                tuple(request["input"]["source_sha256"]))
        except Exception:
            self._clear_reservation(state_key, reservation)
            raise MobileGatewayError("host HCE/source lookup failed") from None
        if evidence_verified is not True:
            self._clear_reservation(state_key, reservation)
            raise MobileGatewayError("host HCE/source hashes were not verified")

        try:
            result = self._dispatcher(copy.deepcopy(request))
            response = self._response_for(request, request_digest, result)
        except Exception:
            # The callback may have begun inference.  Preserve the reservation and
            # refuse blind retry; do not leak callback text into the remote error.
            raise GatewayDispatchUncertain(
                "dispatch outcome is uncertain; reconcile it locally before continuing") from None
        return self._commit(state_key, request, request_digest, response)

    def _clear_reservation(self, state_key: tuple[str, int],
                           reservation: PendingDispatch) -> None:
        with self._lock:
            state = self._states.get(state_key)
            if state is not None and state.pending == reservation:
                state.pending = None
            if self._orphaned_pending.get(state_key) == reservation:
                del self._orphaned_pending[state_key]

    def _response_for(self, request: dict, request_digest: str, result: GatewayResult) -> bytes:
        if type(result) is not GatewayResult:
            raise MobileProtocolError("dispatcher must return a GatewayResult")
        expected_identity = self._expected_model_identity(result.selected_lane)
        if not hmac_compare(result.model_identity_sha256, expected_identity):
            raise MobileProtocolError("dispatcher model identity differs from the configured rung")
        return build_response(request, request_sha256=request_digest,
                              selected_lane=result.selected_lane,
                              model_identity_sha256=result.model_identity_sha256,
                              text=result.text)

    def _commit(self, state_key: tuple[str, int], request: dict, request_digest: str,
                response: bytes) -> GatewayReply:
        with self._lock:
            state = self._states.get(state_key)
            if state is None:
                raise GatewayDispatchUncertain("credential generation changed before commit")
            pending = state.pending
            if (pending is None or pending.sequence != request["sequence"]
                    or pending.request_id != request["request_id"]
                    or not hmac_compare(pending.request_sha256, request_digest)):
                raise GatewayDispatchUncertain("pending dispatch changed before commit")
            sequence = request["sequence"]
            state.completed[sequence] = _Completed(request["request_id"], request_digest, response)
            state.request_ids[request["request_id"]] = sequence
            state.outcomes[sha256(response)] = _Outcome(
                sequence, request["input"]["task_id"], request["route"]["requested_lane"],
                request["input"]["prompt_sha256"],
                request["input"]["hce_sha256"], tuple(request["input"]["source_sha256"]))
            state.next_sequence += 1
            state.pending = None
            while len(state.completed) > self.config.replay_entries_per_device:
                state.completed.popitem(last=False)
            return GatewayReply(response, False)

    def pending_dispatches(self, device_id: str) -> tuple[PendingDispatch, ...]:
        """Enumerate non-secret reconciliation metadata for the local host."""
        if type(device_id) is not str:
            raise MobileGatewayError("device identifier is invalid")
        with self._lock:
            matches = [state.pending for key, state in self._states.items()
                       if key[0] == device_id and state.pending is not None]
            matches.extend(pending for key, pending in self._orphaned_pending.items()
                           if key[0] == device_id)
            return tuple(sorted(matches, key=lambda item: item.credential_generation))

    def pending_dispatch(self, device_id: str, *,
                         credential_generation: int | None = None) -> PendingDispatch | None:
        """Select one pending generation, refusing an ambiguous unqualified lookup."""
        matches = self.pending_dispatches(device_id)
        if credential_generation is not None:
            if type(credential_generation) is not int:
                raise MobileGatewayError("credential generation is invalid")
            matches = tuple(item for item in matches
                            if item.credential_generation == credential_generation)
        return matches[0] if len(matches) == 1 else None

    def reconcile_pending(self, *, device_id: str, request_wire: bytes,
                          credential_generation: int,
                          result: GatewayResult) -> GatewayReply:
        """Commit a caller-confirmed result without invoking the dispatcher again."""
        try:
            request = inspect_request(request_wire)
        except MobileProtocolError as exc:
            raise MobileGatewayError("invalid reconciliation request") from exc
        request_digest = sha256(request_wire)
        state_key = (device_id, credential_generation)
        with self._lock:
            state = self._states.get(state_key)
            pending = None if state is None else state.pending
            orphaned = False
            if pending is None:
                pending = self._orphaned_pending.get(state_key)
                orphaned = pending is not None
            if (pending is None or request["device_id"] != device_id
                    or pending.sequence != request["sequence"]
                    or pending.request_id != request["request_id"]
                    or not hmac_compare(pending.request_sha256, request_digest)):
                raise MobileGatewayError("reconciliation does not match the pending dispatch")
        try:
            response = self._response_for(request, request_digest, result)
        except MobileProtocolError as exc:
            raise MobileGatewayError("invalid reconciled result") from exc
        if orphaned:
            with self._lock:
                current = self._orphaned_pending.get(state_key)
                if current != pending:
                    raise MobileGatewayError("orphaned pending dispatch changed")
                del self._orphaned_pending[state_key]
            return GatewayReply(response, False)
        return self._commit(state_key, request, request_digest, response)


def hmac_compare(left: str, right: str) -> bool:
    # Local wrapper keeps credential/request digest comparisons timing-safe.
    import hmac
    return hmac.compare_digest(left, right)

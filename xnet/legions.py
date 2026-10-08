"""Small, transport-free protocol core for opt-in shared compute.

Legions describes work and verifies receipts.  It never discovers peers, opens a
socket, executes a payload, forwards a secret, schedules work, or combines
answers.  The caller owns transport, storage, authentication keys, clocks, and
the actual resource sandbox.
"""
from __future__ import annotations

from dataclasses import dataclass
import heapq
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from typing import Any

from .protocol import canonical, sha256


CAPABILITY_SCHEMA = "xnet.legions-capability-card.v1"
JOB_SCHEMA = "xnet.legions-job-capsule.v1"
RESULT_SCHEMA = "xnet.legions-result-receipt.v1"
MAX_WIRE_BYTES = 65_536
MAX_LIST_ITEMS = 64
MAX_QUANTITY = 2**53 - 1
DEFAULT_REPLAY_CAPACITY = 4_096
MAX_REPLAY_CAPACITY = 65_536

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_NONCE = re.compile(r"[0-9a-f]{32,128}\Z")
_BUDGET_FIELDS = (
    "wall_time_ms",
    "cpu_time_ms",
    "memory_bytes",
    "input_bytes",
    "output_bytes",
    "tokens",
    "cost_microunits",
)


class LegionsError(ValueError):
    """Untrusted wire data or a local admission rule was refused."""


def _identifier(value: Any, label: str = "identifier") -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise LegionsError(f"bounded ASCII {label} required")
    return value


def _hash(value: Any, label: str = "SHA256") -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise LegionsError(f"complete lowercase {label} required")
    return value


def _quantity(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_QUANTITY:
        raise LegionsError(f"bounded nonnegative exact integer {label} required")
    return value


def _items(value: Any, label: str, *, hashes: bool = False) -> tuple[str, ...]:
    if type(value) not in (list, tuple) or not 1 <= len(value) <= MAX_LIST_ITEMS:
        raise LegionsError(f"bounded nonempty {label} required")
    result = tuple(value)
    for item in result:
        (_hash(item, label) if hashes else _identifier(item, label))
    if result != tuple(sorted(result)) or len(set(result)) != len(result):
        raise LegionsError(f"sorted unique {label} required")
    return result


def _pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in rows:
        if key in result:
            raise LegionsError("duplicate JSON field")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise LegionsError("nonfinite JSON number refused")


def _bounded_wire(raw: Any) -> bytes:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_WIRE_BYTES:
        raise LegionsError("bounded canonical JSON bytes required")
    return raw


def _decode(raw: bytes) -> dict[str, Any]:
    _bounded_wire(raw)
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=_nonfinite,
        )
        if type(value) is not dict or canonical(value) != raw:
            raise LegionsError("canonical JSON object required")
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        if isinstance(error, LegionsError):
            raise
        raise LegionsError("malformed canonical JSON") from error


def _pin(raw: bytes, expected_sha256: str) -> None:
    _bounded_wire(raw)
    _hash(expected_sha256, "object SHA256")
    if not hmac.compare_digest(sha256(raw), expected_sha256):
        raise LegionsError("expected object hash differs")


def _key(value: Any) -> bytes:
    if type(value) is not bytes or len(value) < 32:
        raise LegionsError("caller-provided HMAC key must contain at least 32 bytes")
    return value


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


@dataclass(frozen=True, slots=True)
class Budget:
    """Requested ceilings. Enforcement remains the worker sandbox's job."""

    wall_time_ms: int
    cpu_time_ms: int
    memory_bytes: int
    input_bytes: int
    output_bytes: int
    tokens: int
    cost_microunits: int

    def __post_init__(self) -> None:
        for name in _BUDGET_FIELDS:
            _quantity(getattr(self, name), name)

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in _BUDGET_FIELDS}

    def fits(self, ceiling: "Budget") -> bool:
        if type(ceiling) is not Budget:
            raise LegionsError("typed budget ceiling required")
        return all(getattr(self, name) <= getattr(ceiling, name) for name in _BUDGET_FIELDS)

    @classmethod
    def from_dict(cls, value: Any) -> "Budget":
        if type(value) is not dict or set(value) != set(_BUDGET_FIELDS):
            raise LegionsError("exact budget fields required")
        return cls(**{name: value[name] for name in _BUDGET_FIELDS})


@dataclass(frozen=True, slots=True)
class CapabilityCard:
    """Canonical, content-addressed declaration; it grants no authority."""

    worker_id: str
    task_types: tuple[str, ...]
    capabilities: tuple[str, ...]
    limits: Budget

    def __post_init__(self) -> None:
        _identifier(self.worker_id, "worker identity")
        object.__setattr__(self, "task_types", _items(self.task_types, "task types"))
        object.__setattr__(
            self, "capabilities", _items(self.capabilities, "capabilities")
        )
        if type(self.limits) is not Budget:
            raise LegionsError("typed capability limits required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": CAPABILITY_SCHEMA,
            "worker_id": self.worker_id,
            "task_types": list(self.task_types),
            "capabilities": list(self.capabilities),
            "limits": self.limits.to_dict(),
        }

    def to_wire(self) -> bytes:
        return canonical(self.to_dict())

    @property
    def sha256(self) -> str:
        return sha256(self.to_wire())

    @classmethod
    def from_wire(cls, raw: bytes, *, expected_sha256: str | None = None) -> "CapabilityCard":
        if expected_sha256 is not None:
            _pin(raw, expected_sha256)
        value = _decode(raw)
        if set(value) != {"schema", "worker_id", "task_types", "capabilities", "limits"}:
            raise LegionsError("capability card fields differ")
        if value["schema"] != CAPABILITY_SCHEMA:
            raise LegionsError("unsupported capability card schema")
        return cls(
            worker_id=value["worker_id"],
            task_types=_items(value["task_types"], "task types"),
            capabilities=_items(value["capabilities"], "capabilities"),
            limits=Budget.from_dict(value["limits"]),
        )


@dataclass(frozen=True, slots=True)
class JobCapsule:
    """Immutable work description containing hashes, never input contents."""

    task_type: str
    input_sha256s: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    budget: Budget
    coordinator_id: str
    target_worker_id: str
    expires_at_ms: int
    nonce: str

    def __post_init__(self) -> None:
        _identifier(self.task_type, "task type")
        object.__setattr__(
            self,
            "input_sha256s",
            _items(self.input_sha256s, "input hashes", hashes=True),
        )
        object.__setattr__(
            self,
            "required_capabilities",
            _items(self.required_capabilities, "required capabilities"),
        )
        if type(self.budget) is not Budget:
            raise LegionsError("typed job budget required")
        _identifier(self.coordinator_id, "coordinator identity")
        _identifier(self.target_worker_id, "target worker identity")
        _quantity(self.expires_at_ms, "expiry")
        if type(self.nonce) is not str or _NONCE.fullmatch(self.nonce) is None:
            raise LegionsError("32-128 character lowercase hexadecimal nonce required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": JOB_SCHEMA,
            "task_type": self.task_type,
            "input_sha256s": list(self.input_sha256s),
            "required_capabilities": list(self.required_capabilities),
            "budget": self.budget.to_dict(),
            "coordinator_id": self.coordinator_id,
            "target_worker_id": self.target_worker_id,
            "expires_at_ms": self.expires_at_ms,
            "nonce": self.nonce,
        }

    def to_wire(self) -> bytes:
        return canonical(self.to_dict())

    @property
    def sha256(self) -> str:
        return sha256(self.to_wire())

    @classmethod
    def from_wire(cls, raw: bytes, *, expected_sha256: str) -> "JobCapsule":
        _pin(raw, expected_sha256)
        value = _decode(raw)
        fields = {
            "schema", "task_type", "input_sha256s", "required_capabilities",
            "budget", "coordinator_id", "target_worker_id", "expires_at_ms", "nonce",
        }
        if set(value) != fields or value["schema"] != JOB_SCHEMA:
            raise LegionsError("job capsule schema or fields differ")
        return cls(
            task_type=value["task_type"],
            input_sha256s=_items(value["input_sha256s"], "input hashes", hashes=True),
            required_capabilities=_items(
                value["required_capabilities"], "required capabilities"
            ),
            budget=Budget.from_dict(value["budget"]),
            coordinator_id=value["coordinator_id"],
            target_worker_id=value["target_worker_id"],
            expires_at_ms=value["expires_at_ms"],
            nonce=value["nonce"],
        )


def new_nonce() -> str:
    """Return a cryptographically random 128-bit job nonce."""
    return secrets.token_hex(16)


@dataclass(frozen=True, slots=True)
class WorkerPolicy:
    """The worker's explicit opt-in boundary."""

    allowed_coordinator_ids: tuple[str, ...]
    allowed_task_types: tuple[str, ...]
    allowed_capabilities: tuple[str, ...]
    maximum_budget: Budget

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_coordinator_ids",
            _items(self.allowed_coordinator_ids, "allowed coordinator identities"),
        )
        object.__setattr__(
            self,
            "allowed_task_types",
            _items(self.allowed_task_types, "allowed task types"),
        )
        object.__setattr__(
            self,
            "allowed_capabilities",
            _items(self.allowed_capabilities, "allowed capabilities"),
        )
        if type(self.maximum_budget) is not Budget:
            raise LegionsError("typed maximum budget required")


class LegionsControl:
    """Thread-safe local kill switch, revocations, and bounded replay memory.

    Live replay records are retained through job expiry and capped per category.
    Persistence is deliberately left to the embedding application.  A restart
    with a fresh instance also starts fresh replay memory.
    """

    def __init__(self, *, replay_capacity: int = DEFAULT_REPLAY_CAPACITY) -> None:
        if (
            type(replay_capacity) is not int
            or not 1 <= replay_capacity <= MAX_REPLAY_CAPACITY
        ):
            raise LegionsError(
                f"replay capacity must be an integer from 1 to {MAX_REPLAY_CAPACITY}"
            )
        self._replay_capacity = replay_capacity
        self._enabled = True
        self._revoked_nodes: set[str] = set()
        self._revoked_jobs: set[str] = set()
        self._accepted_jobs: dict[str, tuple[str, int, int]] = {}
        self._accepted_nonces: dict[tuple[str, str], int] = {}
        self._completed_jobs: dict[tuple[str, str], int] = {}
        self._verified_receipts: dict[str, int] = {}
        self._verified_jobs: dict[tuple[str, str], int] = {}
        self._expiry_heap: list[tuple[int, int, str, Any]] = []
        self._expiry_sequence = 0
        self._clock_watermark_ms = 0
        self._lock = threading.Lock()

    def _advance_clock(self, now_ms: int) -> None:
        _quantity(now_ms, "control time")
        if now_ms < self._clock_watermark_ms:
            raise LegionsError("Legions control clock moved backwards")
        self._clock_watermark_ms = now_ms

    def _retain(
        self, store_name: str, key: Any, value: Any, expires_at_ms: int
    ) -> None:
        store = getattr(self, store_name)
        if key not in store and len(store) >= self._replay_capacity:
            raise LegionsError("Legions replay memory capacity is exhausted")
        store[key] = value
        self._expiry_sequence += 1
        heapq.heappush(
            self._expiry_heap,
            (expires_at_ms, self._expiry_sequence, store_name, key),
        )

    def _prune_expired(self, now_ms: int) -> None:
        while self._expiry_heap and self._expiry_heap[0][0] <= now_ms:
            expires_at_ms, _, store_name, key = heapq.heappop(self._expiry_heap)
            store = getattr(self, store_name)
            value = store.get(key)
            if value is None:
                continue
            retained_expiry = value[2] if store_name == "_accepted_jobs" else value
            if retained_expiry == expires_at_ms:
                del store[key]

    def kill(self) -> None:
        with self._lock:
            self._enabled = False

    def restore(self) -> None:
        with self._lock:
            self._enabled = True

    def revoke_node(self, node_id: str) -> None:
        with self._lock:
            self._revoked_nodes.add(_identifier(node_id, "node identity"))

    def revoke_job(self, job_sha256: str) -> None:
        with self._lock:
            self._revoked_jobs.add(_hash(job_sha256, "job SHA256"))

    def _live(self, job_sha256: str, worker_id: str, coordinator_id: str) -> None:
        if not self._enabled:
            raise LegionsError("Legions kill switch is active")
        if worker_id in self._revoked_nodes or coordinator_id in self._revoked_nodes:
            raise LegionsError("worker or coordinator is revoked")
        if job_sha256 in self._revoked_jobs:
            raise LegionsError("job is revoked")

    def _accept_once(
        self, job: JobCapsule, worker_id: str, accepted_at_ms: int
    ) -> None:
        with self._lock:
            self._advance_clock(accepted_at_ms)
            self._prune_expired(accepted_at_ms)
            self._live(job.sha256, worker_id, job.coordinator_id)
            nonce_key = (job.coordinator_id, job.nonce)
            if job.sha256 in self._accepted_jobs or nonce_key in self._accepted_nonces:
                raise LegionsError("job or coordinator nonce was already accepted")
            if (
                len(self._accepted_jobs) >= self._replay_capacity
                or len(self._accepted_nonces) >= self._replay_capacity
            ):
                raise LegionsError("Legions replay memory capacity is exhausted")
            self._retain(
                "_accepted_jobs",
                job.sha256,
                (worker_id, accepted_at_ms, job.expires_at_ms),
                job.expires_at_ms,
            )
            self._retain(
                "_accepted_nonces",
                nonce_key,
                job.expires_at_ms,
                job.expires_at_ms,
            )

    def _complete_once(
        self,
        job: JobCapsule,
        worker_id: str,
        accepted_at_ms: int,
        completed_at_ms: int,
    ) -> None:
        with self._lock:
            self._advance_clock(completed_at_ms)
            if completed_at_ms >= job.expires_at_ms:
                self._prune_expired(completed_at_ms)
                raise LegionsError("job capsule expired before result signing")
            self._prune_expired(completed_at_ms)
            self._live(job.sha256, worker_id, job.coordinator_id)
            if self._accepted_jobs.get(job.sha256) != (
                worker_id,
                accepted_at_ms,
                job.expires_at_ms,
            ):
                raise LegionsError("accepted job was not issued by this control state")
            result_key = (job.sha256, worker_id)
            if result_key in self._completed_jobs:
                raise LegionsError("accepted job already produced a result")
            self._retain(
                "_completed_jobs",
                result_key,
                job.expires_at_ms,
                job.expires_at_ms,
            )

    def _verify_once(
        self,
        receipt_sha256: str,
        job: JobCapsule,
        worker_id: str,
        verified_at_ms: int,
    ) -> None:
        with self._lock:
            self._advance_clock(verified_at_ms)
            if verified_at_ms >= job.expires_at_ms:
                self._prune_expired(verified_at_ms)
                raise LegionsError("job capsule expired before receipt verification")
            self._prune_expired(verified_at_ms)
            self._live(job.sha256, worker_id, job.coordinator_id)
            result_key = (job.sha256, worker_id)
            if (
                receipt_sha256 in self._verified_receipts
                or result_key in self._verified_jobs
            ):
                raise LegionsError("job result or receipt was already verified")
            if (
                len(self._verified_receipts) >= self._replay_capacity
                or len(self._verified_jobs) >= self._replay_capacity
            ):
                raise LegionsError("Legions replay memory capacity is exhausted")
            self._retain(
                "_verified_receipts",
                receipt_sha256,
                job.expires_at_ms,
                job.expires_at_ms,
            )
            self._retain(
                "_verified_jobs",
                result_key,
                job.expires_at_ms,
                job.expires_at_ms,
            )


@dataclass(frozen=True, slots=True, init=False)
class AcceptedJob:
    job: JobCapsule
    job_sha256: str
    worker_id: str
    accepted_at_ms: int
    control: LegionsControl

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise LegionsError("accepted jobs can only be issued by WorkerGate")

    @classmethod
    def _issue(
        cls,
        job: JobCapsule,
        job_sha256: str,
        worker_id: str,
        accepted_at_ms: int,
        control: LegionsControl,
    ) -> "AcceptedJob":
        accepted = object.__new__(cls)
        object.__setattr__(accepted, "job", job)
        object.__setattr__(accepted, "job_sha256", job_sha256)
        object.__setattr__(accepted, "worker_id", worker_id)
        object.__setattr__(accepted, "accepted_at_ms", accepted_at_ms)
        object.__setattr__(accepted, "control", control)
        accepted._validate()
        return accepted

    def _validate(self) -> None:
        if type(self.job) is not JobCapsule or type(self.control) is not LegionsControl:
            raise LegionsError("typed accepted job and control state required")
        if not hmac.compare_digest(_hash(self.job_sha256, "job SHA256"), self.job.sha256):
            raise LegionsError("accepted job hash differs")
        _identifier(self.worker_id, "worker identity")
        if self.worker_id != self.job.target_worker_id:
            raise LegionsError("accepted job targets a different worker")
        _quantity(self.accepted_at_ms, "acceptance time")


class WorkerGate:
    """Bind authenticated identity, then apply local policy and safety state."""

    def __init__(
        self, card: CapabilityCard, policy: WorkerPolicy, control: LegionsControl
    ) -> None:
        if type(card) is not CapabilityCard or type(policy) is not WorkerPolicy:
            raise LegionsError("typed card and worker policy required")
        if type(control) is not LegionsControl:
            raise LegionsError("explicit Legions control state required")
        self.card = card
        self.policy = policy
        self.control = control

    def accept(
        self,
        raw: bytes,
        *,
        expected_sha256: str,
        authenticated_coordinator_id: str,
        now_ms: int | None = None,
    ) -> AcceptedJob:
        authenticated_coordinator = _identifier(
            authenticated_coordinator_id, "authenticated coordinator identity"
        )
        job = JobCapsule.from_wire(raw, expected_sha256=expected_sha256)
        now = _now_ms() if now_ms is None else now_ms
        _quantity(now, "current time")
        if now >= job.expires_at_ms:
            raise LegionsError("job capsule is expired")
        if job.coordinator_id != authenticated_coordinator:
            raise LegionsError("job coordinator differs from authenticated coordinator")
        if job.target_worker_id != self.card.worker_id:
            raise LegionsError("job capsule targets a different worker")
        if job.coordinator_id not in self.policy.allowed_coordinator_ids:
            raise LegionsError("coordinator is not allowlisted")
        if (
            job.task_type not in self.policy.allowed_task_types
            or job.task_type not in self.card.task_types
        ):
            raise LegionsError("task type is not allowlisted and advertised")
        required = set(job.required_capabilities)
        if not required.issubset(self.policy.allowed_capabilities) or not required.issubset(
            self.card.capabilities
        ):
            raise LegionsError("required capability is not allowlisted and advertised")
        if not job.budget.fits(self.policy.maximum_budget) or not job.budget.fits(
            self.card.limits
        ):
            raise LegionsError("job budget exceeds worker ceilings")
        self.control._accept_once(job, self.card.worker_id, now)
        return AcceptedJob._issue(job, job.sha256, self.card.worker_id, now, self.control)


@dataclass(frozen=True, slots=True)
class ResourceUsage:
    wall_time_ms: int
    cpu_time_ms: int
    memory_bytes: int
    input_bytes: int
    output_bytes: int
    tokens: int
    cost_microunits: int

    def __post_init__(self) -> None:
        for name in _BUDGET_FIELDS:
            _quantity(getattr(self, name), name)

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in _BUDGET_FIELDS}

    def fits(self, budget: Budget) -> bool:
        return all(getattr(self, name) <= getattr(budget, name) for name in _BUDGET_FIELDS)

    @classmethod
    def from_dict(cls, value: Any) -> "ResourceUsage":
        if type(value) is not dict or set(value) != set(_BUDGET_FIELDS):
            raise LegionsError("exact resource usage fields required")
        return cls(**{name: value[name] for name in _BUDGET_FIELDS})


@dataclass(frozen=True, slots=True)
class ResultReceipt:
    job_sha256: str
    worker_id: str
    output_sha256s: tuple[str, ...]
    started_at_ms: int
    finished_at_ms: int
    usage: ResourceUsage
    receipt_sha256: str
    hmac_sha256: str

    def body(self) -> dict[str, Any]:
        return {
            "schema": RESULT_SCHEMA,
            "signature_algorithm": "hmac-sha256",
            "job_sha256": self.job_sha256,
            "worker_id": self.worker_id,
            "output_sha256s": list(self.output_sha256s),
            "started_at_ms": self.started_at_ms,
            "finished_at_ms": self.finished_at_ms,
            "usage": self.usage.to_dict(),
        }

    def signed_body(self) -> dict[str, Any]:
        return {**self.body(), "receipt_sha256": self.receipt_sha256}

    def to_wire(self) -> bytes:
        return canonical({**self.signed_body(), "hmac_sha256": self.hmac_sha256})


def _receipt_values(
    job: JobCapsule,
    worker_id: str,
    output_sha256s: Any,
    started_at_ms: Any,
    finished_at_ms: Any,
    usage: ResourceUsage,
) -> tuple[str, tuple[str, ...], int, int]:
    worker = _identifier(worker_id, "worker identity")
    outputs = _items(output_sha256s, "output hashes", hashes=True)
    started = _quantity(started_at_ms, "start time")
    finished = _quantity(finished_at_ms, "finish time")
    if finished < started:
        raise LegionsError("finish time precedes start time")
    if finished > job.expires_at_ms:
        raise LegionsError("result finished after job expiry")
    if type(usage) is not ResourceUsage or not usage.fits(job.budget):
        raise LegionsError("reported resource usage exceeds the job budget")
    if usage.wall_time_ms != finished - started:
        raise LegionsError("reported wall time differs from signed timestamps")
    return worker, outputs, started, finished


def sign_result_receipt(
    accepted: AcceptedJob,
    *,
    output_sha256s: tuple[str, ...],
    started_at_ms: int,
    finished_at_ms: int,
    usage: ResourceUsage,
    key: bytes,
) -> bytes:
    """Sign one accepted job result without retaining or serializing the key."""
    if type(accepted) is not AcceptedJob:
        raise LegionsError("typed accepted job required")
    accepted._validate()
    worker, outputs, started, finished = _receipt_values(
        accepted.job,
        accepted.worker_id,
        output_sha256s,
        started_at_ms,
        finished_at_ms,
        usage,
    )
    if started < accepted.accepted_at_ms:
        raise LegionsError("result starts before local job acceptance")
    body = {
        "schema": RESULT_SCHEMA,
        "signature_algorithm": "hmac-sha256",
        "job_sha256": accepted.job_sha256,
        "worker_id": worker,
        "output_sha256s": list(outputs),
        "started_at_ms": started,
        "finished_at_ms": finished,
        "usage": usage.to_dict(),
    }
    receipt_sha256 = sha256(canonical(body))
    signed = {**body, "receipt_sha256": receipt_sha256}
    signature = hmac.new(_key(key), canonical(signed), hashlib.sha256).hexdigest()
    raw = canonical({**signed, "hmac_sha256": signature})
    completed_at_ms = _now_ms()
    if finished > completed_at_ms:
        raise LegionsError("result finish time is in the future")
    accepted.control._complete_once(
        accepted.job,
        accepted.worker_id,
        accepted.accepted_at_ms,
        completed_at_ms,
    )
    return raw


def _decode_receipt(raw: bytes, expected_sha256: str) -> ResultReceipt:
    _pin(raw, expected_sha256)
    value = _decode(raw)
    fields = {
        "schema", "signature_algorithm", "job_sha256", "worker_id",
        "output_sha256s", "started_at_ms", "finished_at_ms", "usage",
        "receipt_sha256", "hmac_sha256",
    }
    if set(value) != fields or value["schema"] != RESULT_SCHEMA:
        raise LegionsError("result receipt schema or fields differ")
    if value["signature_algorithm"] != "hmac-sha256":
        raise LegionsError("unsupported receipt signature algorithm")
    return ResultReceipt(
        job_sha256=_hash(value["job_sha256"], "job SHA256"),
        worker_id=_identifier(value["worker_id"], "worker identity"),
        output_sha256s=_items(value["output_sha256s"], "output hashes", hashes=True),
        started_at_ms=_quantity(value["started_at_ms"], "start time"),
        finished_at_ms=_quantity(value["finished_at_ms"], "finish time"),
        usage=ResourceUsage.from_dict(value["usage"]),
        receipt_sha256=_hash(value["receipt_sha256"], "receipt body SHA256"),
        hmac_sha256=_hash(value["hmac_sha256"], "HMAC SHA256"),
    )


def verify_result_receipt(
    raw: bytes,
    *,
    expected_sha256: str,
    expected_job: JobCapsule,
    expected_worker_id: str,
    key: bytes,
    control: LegionsControl,
) -> ResultReceipt:
    """Authenticate, bind, deadline-check, and consume one receipt."""
    if type(expected_job) is not JobCapsule:
        raise LegionsError("typed expected job required")
    worker = _identifier(expected_worker_id, "expected worker identity")
    if expected_job.target_worker_id != worker:
        raise LegionsError("expected job targets a different worker")
    if type(control) is not LegionsControl:
        raise LegionsError("explicit Legions control state required")
    receipt = _decode_receipt(raw, expected_sha256)
    expected_body_hash = sha256(canonical(receipt.body()))
    if not hmac.compare_digest(receipt.receipt_sha256, expected_body_hash):
        raise LegionsError("receipt body hash differs")
    expected_signature = hmac.new(
        _key(key), canonical(receipt.signed_body()), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(receipt.hmac_sha256, expected_signature):
        raise LegionsError("receipt HMAC differs")
    if not hmac.compare_digest(receipt.job_sha256, expected_job.sha256):
        raise LegionsError("receipt belongs to a different job")
    if receipt.worker_id != worker:
        raise LegionsError("receipt belongs to a different worker")
    _receipt_values(
        expected_job,
        receipt.worker_id,
        receipt.output_sha256s,
        receipt.started_at_ms,
        receipt.finished_at_ms,
        receipt.usage,
    )
    verified_at_ms = _now_ms()
    if receipt.finished_at_ms > verified_at_ms:
        raise LegionsError("result finish time is in the future")
    control._verify_once(
        receipt.receipt_sha256, expected_job, worker, verified_at_ms
    )
    return receipt

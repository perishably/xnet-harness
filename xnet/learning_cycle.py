"""Caller-owned, source-pinned orchestration for one bounded learning epoch.

This utility records stage reservations and results; it does not infer, execute
candidate source, score a task, promote guidance, synchronize drives or schedule
work. The caller's stage callback supplies those separately authorized actions.
Promotion correctness remains the caller's validated learner/evaluator contract.

API: LearningCycle(ledger, config, identity_reader=...). identity_reader returns
the current four declared identity hashes. ``step(callback, control='RUN')``
passes a detached reservation request to callback, which returns a portable dict.
An uncertain callback is NEVER repeated. Reconcile its known outcome with
``reconcile(reservation_id, result, evidence_sha256=..., justification=...)``.
``run(..., max_stages=N)`` is bounded; a control reader can return STOP at each
stage entry. Completed cycles safely replay without dispatching any callback.
Results and requests are inert data in the supplied Ledger's CAS. The caller is
responsible for authenticating its identities and authorizing callback tools.
"""
from __future__ import annotations

import copy
import json
import os
import re
import uuid
from contextlib import contextmanager
from pathlib import Path

from .ledger import Ledger
from .protocol import ZERO_HASH, canonical, digest, make_event, sha256

STAGES = ("propose", "practice-baseline", "practice-candidate", "freeze",
          "trial-baseline", "trial-candidate", "promote", "trace")
CONFIG_SCHEMA = "xnet.learning-cycle-config.v1"
_IDENTITIES = {"manifest_sha256", "model_sha256", "adapter_sha256", "source_sha256"}
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_SECRET_FIELD = re.compile(r"(?:authorization|password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key|client[_-]?secret)\Z", re.I)
_MAX_BYTES = 65536


class LearningCycleError(ValueError):
    """A drifted, invalid or conflicting durable cycle was refused."""


class CycleBusyError(LearningCycleError):
    """Another writer holds the OS lease. Nothing was dispatched."""


class PendingStageError(LearningCycleError):
    """The reserved callback outcome requires explicit reconciliation."""

    def __init__(self, reservation_id, *, result_sha256=None):
        super().__init__("stage outcome is pending; reconcile before continuing")
        self.reservation_id = reservation_id
        self.result_sha256 = result_sha256


def _hash(value):
    if type(value) is not str or not _HASH.fullmatch(value):
        raise LearningCycleError("invalid SHA-256 identity")
    return value


def _label(value):
    if type(value) is not str or not _LABEL.fullmatch(value):
        raise LearningCycleError("invalid bounded cycle label")
    return value


def _portable(value, *, max_bytes=_MAX_BYTES):
    """Exact JSON types, finite bounds and no arbitrary repr/serialization."""
    count = 0

    def visit(item, depth):
        nonlocal count
        count += 1
        if depth > 16 or count > 4096:
            raise LearningCycleError("portable value exceeds structural bounds")
        if item is None or type(item) is bool:
            return
        if type(item) is int and -(2**63) <= item <= 2**63 - 1:
            return
        if type(item) is str:
            if len(item) > 16384 or any(ord(c) in (0x2028, 0x2029) or 0xD800 <= ord(c) <= 0xDFFF for c in item):
                raise LearningCycleError("invalid portable string")
            return
        if type(item) is list:
            for child in item:
                visit(child, depth + 1)
            return
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise LearningCycleError("portable object keys must be strings")
                visit(key, depth + 1)
                visit(child, depth + 1)
            return
        raise LearningCycleError("unsupported portable value type")

    visit(value, 0)
    raw = canonical(value)
    if len(raw) > max_bytes:
        raise LearningCycleError("portable value exceeds byte bound")
    return raw


def _identities(value):
    if type(value) is not dict or set(value) != _IDENTITIES:
        raise LearningCycleError("identity reader must return exactly four pins")
    return {key: _hash(pin) for key, pin in value.items()}


def _config(value):
    fields = {"schema", "epoch_id", "scope_id", "identities", "baseline_sha256", "cost_policy"}
    if type(value) is not dict or set(value) != fields or value["schema"] != CONFIG_SCHEMA:
        raise LearningCycleError("config must match learning-cycle v1 exactly")
    _label(value["epoch_id"])
    scope = value["scope_id"]
    if type(scope) is not str or not 1 <= len(scope) <= 128 or any(ord(c) < 32 for c in scope):
        raise LearningCycleError("invalid declared scope ID")
    _identities(value["identities"])
    _hash(value["baseline_sha256"])
    policy = value["cost_policy"]
    if type(policy) is not dict or set(policy) != {"max_token_ratio", "max_wall_ratio"}:
        raise LearningCycleError("cost policy fields must match exactly")
    if any(type(v) is not int or not 1 <= v <= 4 for v in policy.values()):
        raise LearningCycleError("cost ratios must be exact integers from one to four")
    _portable(value, max_bytes=16384)
    return copy.deepcopy(value)


def _source_pins():
    directory = Path(__file__).parent
    return {name: sha256((directory / name).read_bytes())
            for name in ("learning_cycle.py", "ledger.py", "protocol.py")}


class LearningCycle:
    """One eight-stage epoch, durable exclusively in caller Ledger/CAS.

    Config changes require a new epoch ID in the same Ledger. Neither mutable
    attributes nor returned dictionaries can change the frozen configuration.
    The nonblocking writer lease spans reservation, callback and commit. A
    crashed writer releases the OS lock; its durable reservation stays pending.
    """

    def __init__(self, ledger, config, *, identity_reader):
        if not isinstance(ledger, Ledger) or not callable(identity_reader):
            raise LearningCycleError("caller Ledger and identity reader are required")
        value = _config(config)
        value["controller_source_pins"] = _source_pins()
        self.ledger = ledger
        self._config_bytes = canonical(value)
        self._config_sha = sha256(self._config_bytes)
        self._identity_reader = identity_reader
        self._task = "learning-cycle-" + digest(value["epoch_id"])[:32]
        self._scope = value["scope_id"]
        self._lock = ledger.data_dir / "learning-cycle-locks" / (digest(value["epoch_id"]) + ".lock")
        with self._locked():
            state = self._state()
            if state["epoch"] is None:
                self._write("epoch", value)

    @property
    def config(self):
        self._assert_identity()
        return json.loads(self._config_bytes)

    def _assert_identity(self):
        frozen = json.loads(self._config_bytes)
        if _source_pins() != frozen["controller_source_pins"]:
            raise LearningCycleError("controller source drift; create a new epoch")
        if _identities(self._identity_reader()) != frozen["identities"]:
            raise LearningCycleError("caller identity drift; create a new epoch")

    @contextmanager
    def _locked(self):
        self._lock.parent.mkdir(parents=True, exist_ok=True)
        with self._lock.open("a+b") as handle:
            handle.seek(0, os.SEEK_END)
            if not handle.tell():
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise CycleBusyError("learning cycle already has a writer") from error
            try:
                yield
            finally:
                handle.seek(0)
                if os.name == "nt":
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _cas(self, value, source):
        raw = _portable(value)
        def deny_credential_fields(item):
            if type(item) is dict:
                for key, child in item.items():
                    if _SECRET_FIELD.fullmatch(key):
                        raise LearningCycleError("credential fields are prohibited in cycle records")
                    deny_credential_fields(child)
            elif type(item) is list:
                for child in item:
                    deny_credential_fields(child)
        deny_credential_fields(value)
        return self.ledger.put_evidence(raw, source=source,
                    scope_id=self._scope, metadata={"authority": "none", "config_sha256": self._config_sha})

    def _write(self, kind, body):
        record = {"schema": "xnet.learning-cycle-record.v1", "kind": kind,
                  "config_sha256": self._config_sha, "body": body}
        evidence = self._cas(record, "learning-cycle")
        payload = {"epoch_id": json.loads(self._config_bytes)["epoch_id"],
                   "config_sha256": self._config_sha, "record_sha256": evidence, "record_type": kind}
        event = make_event(self._task, self._scope, "learning-cycle-" + kind, payload,
                    source="learning-cycle", event_id="learning-cycle-" + digest(payload))
        receipt = self.ledger.append(event)
        return {"body": copy.deepcopy(body), "evidence_sha256": evidence,
                "receipt_sha256": receipt["receipt_hash"]}

    def _read(self, pin):
        raw = self.ledger.get_evidence(_hash(pin))
        value = json.loads(raw)
        if _portable(value) != raw:
            raise LearningCycleError("CAS value is not canonical portable JSON")
        return value

    def _state(self):
        self._assert_identity()
        self.ledger.verify_chain()
        state = {"epoch": None, "results": [], "pending": None,
                 "failures": [], "completed": None}
        previous = ZERO_HASH
        for seq, event in enumerate(self.ledger.events(), 1):
            previous = digest({"seq": seq, "prev_hash": previous, "event_hash": digest(event)})
            if event["task_id"] != self._task:
                continue
            payload = event["payload"]
            if (event["source"] != "learning-cycle" or event["scope_id"] != self._scope
                    or set(payload) != {"epoch_id", "config_sha256", "record_sha256", "record_type"}
                    or payload["config_sha256"] != self._config_sha
                    or payload["epoch_id"] != json.loads(self._config_bytes)["epoch_id"]):
                raise LearningCycleError("cycle source/config event conflict")
            record = self._read(payload["record_sha256"])
            kind = payload["record_type"]
            if (set(record) != {"schema", "kind", "config_sha256", "body"}
                    or record["schema"] != "xnet.learning-cycle-record.v1"
                    or record["kind"] != kind or record["config_sha256"] != self._config_sha
                    or event["kind"] != "learning-cycle-" + kind):
                raise LearningCycleError("cycle event/CAS mismatch")
            body = record["body"]
            item = {"body": body, "evidence_sha256": payload["record_sha256"], "receipt_sha256": previous}
            if kind == "epoch" and state["epoch"] is None and not state["results"]:
                if body != json.loads(self._config_bytes):
                    raise LearningCycleError("epoch source/config changed; create a new epoch")
                state["epoch"] = item
                continue
            if state["epoch"] is None or state["completed"] is not None:
                raise LearningCycleError("invalid cycle history order")
            if kind == "reserve" and state["pending"] is None and len(state["results"]) < len(STAGES):
                self._reservation(body, state)
                state["pending"] = item
            elif kind == "failure" and state["pending"] is not None:
                if (type(body) is not dict or set(body) != {"reservation_id", "error_type", "error_sha256", "result_sha256"}
                        or body["reservation_id"] != state["pending"]["body"]["reservation_id"]):
                    raise LearningCycleError("failure does not match reservation")
                _label(body["error_type"])
                _hash(body["error_sha256"])
                if body["result_sha256"] is not None:
                    self._result_value(body["result_sha256"])
                if any(f["body"]["reservation_id"] == body["reservation_id"] for f in state["failures"]):
                    raise LearningCycleError("duplicate failure record")
                state["failures"].append(item)
            elif kind in ("result", "reconcile") and state["pending"] is not None:
                self._result_record(body, state, reconciled=(kind == "reconcile"))
                state["results"].append(item)
                state["pending"] = None
            elif kind == "complete" and len(state["results"]) == len(STAGES) and state["pending"] is None:
                if body != self._completion_body(state):
                    raise LearningCycleError("completion differs from ordered results")
                state["completed"] = item
            else:
                raise LearningCycleError("invalid or duplicate cycle transition")
        return state

    def _reservation(self, body, state):
        if type(body) is not dict or set(body) != {"reservation_id", "stage", "stage_index", "request_sha256"}:
            raise LearningCycleError("invalid reservation schema")
        index = len(state["results"])
        if type(body["stage_index"]) is not int or body["stage_index"] != index or body["stage"] != STAGES[index]:
            raise LearningCycleError("reservation is out of order")
        if type(body["reservation_id"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", body["reservation_id"]):
            raise LearningCycleError("invalid reservation ID")
        request = self._read(body["request_sha256"])
        if request != self._request(body["reservation_id"], state):
            raise LearningCycleError("reservation request differs from durable history")

    def _result_value(self, pin):
        value = self._read(pin)
        if type(value) is not dict:
            raise LearningCycleError("stage result must be a portable object")
        return value

    def _result_record(self, body, state, reconciled):
        fields = {"reservation_id", "stage", "stage_index", "result_sha256"}
        if reconciled:
            fields |= {"evidence_sha256", "justification"}
        if type(body) is not dict or set(body) != fields:
            raise LearningCycleError("invalid stage-result schema")
        pending = state["pending"]["body"]
        if any(body[key] != pending[key] for key in ("reservation_id", "stage", "stage_index")) or type(body["stage_index"]) is not int:
            raise LearningCycleError("result does not match pending reservation")
        self._result_value(body["result_sha256"])
        if reconciled:
            self._reconcile_fields(body["evidence_sha256"], body["justification"])

    def _request(self, nonce, state):
        index = len(state["results"])
        return {"schema": "xnet.learning-cycle-request.v1", "epoch_id": json.loads(self._config_bytes)["epoch_id"],
                "scope_id": self._scope, "config_sha256": self._config_sha,
                "reservation_id": nonce, "stage": STAGES[index], "stage_index": index,
                "prior_results": [{"stage": r["body"]["stage"], "result_sha256": r["body"]["result_sha256"]}
                                  for r in state["results"]]}

    def _completion_body(self, state):
        return {"stages": list(STAGES), "results_sha256": digest([r["body"]["result_sha256"] for r in state["results"]]),
                "weights_updated": False}

    def _complete(self, state):
        if len(state["results"]) == len(STAGES) and state["completed"] is None:
            self._write("complete", self._completion_body(state))
            return self._state()
        return state

    def _view(self, state, *, stopped=False):
        index = len(state["results"])
        return copy.deepcopy({"schema": "xnet.learning-cycle-status.v1", "config_sha256": self._config_sha,
            "epoch_id": json.loads(self._config_bytes)["epoch_id"],
            "status": "stopped" if stopped else ("completed" if index == len(STAGES) else "pending" if state["pending"] else "ready"),
            "next_stage": STAGES[index] if index < len(STAGES) else None,
            "completed_stages": index, "pending": state["pending"], "results": state["results"],
            "failures": state["failures"], "completion": state["completed"], "weights_updated": False})

    def status(self):
        with self._locked():
            return self._view(self._state())

    @staticmethod
    def _control(control):
        value = control() if callable(control) else control
        if type(value) is not str or value not in ("RUN", "STOP"):
            raise LearningCycleError("control must be exactly RUN or STOP")
        return value

    def step(self, callback, *, control="RUN"):
        with self._locked():
            state = self._state()
            if self._control(control) == "STOP":
                return self._view(state, stopped=True)
            if len(state["results"]) == len(STAGES):
                return self._view(self._complete(state))
            if state["pending"] is not None:
                raise PendingStageError(state["pending"]["body"]["reservation_id"])
            if not callable(callback):
                raise LearningCycleError("stage callback must be callable")
            nonce = uuid.uuid4().hex
            request = self._request(nonce, state)
            reservation = {"reservation_id": nonce, "stage": request["stage"], "stage_index": request["stage_index"],
                           "request_sha256": self._cas(request, "learning-cycle-request")}
            self._write("reserve", reservation)
            result_pin = None
            try:
                result = callback(copy.deepcopy(request))
                if type(result) is not dict:
                    raise LearningCycleError("callback must return a portable object")
                result_pin = self._cas(result, "learning-cycle-result")
                self._assert_identity()
                self._write("result", {key: reservation[key] for key in ("reservation_id", "stage", "stage_index")}
                            | {"result_sha256": result_pin})
            except Exception as error:
                # An append may have committed before its caller observed an
                # error. Re-read durable authority before recording a failure;
                # never append a pending failure after a committed result.
                try:
                    recovered = self._state()
                except Exception:
                    recovered = None
                if recovered is not None and any(r["body"]["reservation_id"] == nonce for r in recovered["results"]):
                    return self._view(self._complete(recovered))
                # Only a type and digest are recorded: exception prose can carry secrets.
                error_type = re.sub(r"[^A-Za-z0-9_-]", "_", type(error).__name__)[:64]
                if not error_type or not error_type[0].isalnum():
                    error_type = "CallbackError"
                self._write("failure", {"reservation_id": nonce, "error_type": error_type,
                    "error_sha256": sha256(str(error).encode("utf-8", errors="replace")), "result_sha256": result_pin})
                raise PendingStageError(nonce, result_sha256=result_pin) from error
            return self._view(self._complete(self._state()))

    def _reconcile_fields(self, evidence_sha256, justification):
        self.ledger.get_evidence(_hash(evidence_sha256))
        if type(justification) is not str or not 8 <= len(justification) <= 1024 or not justification.strip():
            raise LearningCycleError("reconciliation requires bounded explicit justification")
        _portable(justification)

    def reconcile(self, reservation_id, result, *, evidence_sha256, justification, control="RUN"):
        with self._locked():
            state = self._state()
            if self._control(control) == "STOP":
                return self._view(state, stopped=True)
            self._reconcile_fields(evidence_sha256, justification)
            if type(result) is not dict:
                raise LearningCycleError("reconciled result must be a portable object")
            result_pin = sha256(_portable(result))
            for old in state["results"]:
                body = old["body"]
                if body["reservation_id"] == reservation_id:
                    if (body.get("result_sha256") == result_pin and body.get("evidence_sha256") == evidence_sha256
                            and body.get("justification") == justification):
                        return self._view(self._complete(state))
                    raise LearningCycleError("conflicting reconciliation of resolved stage")
            if state["pending"] is None or state["pending"]["body"]["reservation_id"] != reservation_id:
                raise LearningCycleError("no matching pending reservation")
            pending = state["pending"]["body"]
            result_pin = self._cas(result, "learning-cycle-result")
            self._write("reconcile", {key: pending[key] for key in ("reservation_id", "stage", "stage_index")}
                        | {"result_sha256": result_pin, "evidence_sha256": evidence_sha256, "justification": justification})
            return self._view(self._complete(self._state()))

    def run(self, callback, *, max_stages, control="RUN"):
        if type(max_stages) is not int or not 1 <= max_stages <= len(STAGES):
            raise LearningCycleError("max_stages must be an exact integer from one to eight")
        for _ in range(max_stages):
            view = self.step(callback, control=control)
            if view["status"] in ("stopped", "completed"):
                return view
        return view

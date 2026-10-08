"""Bounded offline source admission; borrows a gateway and owns no service.

SHA256 pins/peer labels are integrity/provenance, not sender authentication.
Unknown submitted calls stay reserved until explicit history reconciliation.
No input paths, models, tools, network, external mirrors or worker lifecycle.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re

from xnet.brains import _exclusive_file_lock
from xnet.protocol import canonical, digest, sha256
from xnet.relay_log import _no_links
from xnet_sdk import Client
from xnet_sdk.client import API, MAX_FRAME

SCHEMA = "xnet.bridge.export.v1"
MAX_BUNDLE = 262144
MAX_ROWS = 128
MAX_TEXT = 61440
MAX_OBJECT = 65536
ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
PIN = re.compile(r"[0-9a-f]{64}")
FIELDS = {"schema", "task_id", "producer_id", "session_id", "origin", "source", "records",
          "context_only", "work_performed", "authority", "importer_model_calls", "export_sha256"}
ROW_FIELDS = {"event_id", "message_id", "block_index", "role", "kind", "text",
              "text_sha256", "tool_use_id", "is_error"}
REFUSALS = frozenset({"context_head_mismatch", "context_handoff_pending", "context_history_capacity",
                      "context_event_id_conflict", "context_task_capacity", "object_too_large",
                      "context_event_too_large", "invalid_context_id", "invalid_context_peer",
                      "invalid_context_kind", "invalid_context_digest"})


class BridgeValidationError(ValueError):
    def __init__(self, reason):
        self.reasons = [reason]
        super().__init__(reason)


class BridgeError(RuntimeError):
    pass


def _id(value):
    return type(value) is str and ID.fullmatch(value) is not None


def _pin(value):
    return type(value) is str and PIN.fullmatch(value) is not None


def _uint(value):
    return type(value) is int and 0 <= value <= 2**63 - 1


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BridgeValidationError("duplicate-json-key")
        result[key] = value
    return result


def _depth(raw):
    depth = 0
    string = escape = False
    for byte in raw:
        if string:
            if escape:
                escape = False
            elif byte == 92:
                escape = True
            elif byte == 34:
                string = False
        elif byte == 34:
            string = True
        elif byte in (91, 123):
            depth += 1
            if depth > 8:
                raise BridgeValidationError("json-depth-bound")
        elif byte in (93, 125):
            depth -= 1


def _parse(raw):
    if type(raw) is not bytes or len(raw) > MAX_BUNDLE or raw.startswith(b"\xef\xbb\xbf"):
        raise BridgeValidationError("bundle-byte-bound-or-encoding")
    _depth(raw)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(BridgeValidationError("nonfinite-json")))
    except BridgeValidationError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise BridgeValidationError("invalid-utf8-json") from error


@dataclass(frozen=True)
class BridgePolicy:
    task_id: str
    admission_peer: str
    producer_id: str
    source_id: str
    source_sha256: str
    source_bytes: int
    raw_bundle_sha256: str

    def __post_init__(self):
        if not all(_id(value) for value in (self.task_id, self.producer_id, self.source_id)):
            raise BridgeValidationError("invalid-approved-identity")
        if self.admission_peer not in ("operator", "assistant", "peer"):
            raise BridgeValidationError("invalid-approved-peer")
        if not _pin(self.source_sha256) or not _pin(self.raw_bundle_sha256):
            raise BridgeValidationError("approved-source-and-raw-pins-required")
        if not _uint(self.source_bytes) or not 0 < self.source_bytes <= 16 * 1024 * 1024:
            raise BridgeValidationError("approved-source-byte-bound")


@dataclass(frozen=True)
class SourceRow:
    index: int
    event_id: str
    text: str
    source_digest: str


@dataclass(frozen=True)
class ValidatedExport:
    raw: bytes
    export_sha256: str
    rows: tuple[SourceRow, ...]
    rejected: tuple[str, ...]  # canonical, immutable per-row diagnostics
    manifest_text: str
    manifest_id: str


def _request_fits(policy, event_id, text):
    request = {"api": API, "id": "0" * 32, "request": {
        "op": "context_append", "task_id": policy.task_id, "peer": policy.admission_peer,
        "event_id": event_id, "kind": "raw", "text": text, "expected_head": "0" * 64}}
    return len(text.encode("utf-8")) <= MAX_OBJECT and len(canonical(request)) + 1 <= MAX_FRAME


def validate_bridge_export(raw_bytes: bytes, *, policy: BridgePolicy) -> ValidatedExport:
    """Full envelope validation plus prevalidation of all rows, without writes.

    Envelope/policy corruption rejects the whole bundle. Individual invalid
    rows are quarantined; eligible rows remain immutable and ordered.
    """
    if not isinstance(policy, BridgePolicy):
        raise BridgeValidationError("approved-policy-required")
    value = _parse(raw_bytes)
    if sha256(raw_bytes) != policy.raw_bundle_sha256:
        raise BridgeValidationError("raw-bundle-pin-mismatch")
    if type(value) is not dict or set(value) != FIELDS:
        raise BridgeValidationError("bundle-field-schema")
    if (value["schema"] != SCHEMA or value["task_id"] != policy.task_id
            or value["producer_id"] != policy.producer_id or not _id(value["session_id"])):
        raise BridgeValidationError("bundle-identity-mismatch")
    if (value["context_only"] is not True or value["work_performed"] is not False
            or value["authority"] != "none" or type(value["importer_model_calls"]) is not int
            or value["importer_model_calls"] != 0):
        raise BridgeValidationError("bundle-authority-refused")
    source = value["source"]
    if (type(source) is not dict or set(source) != {"id", "sha256", "bytes"}
            or source != {"id": policy.source_id, "sha256": policy.source_sha256,
                          "bytes": policy.source_bytes} or type(source["bytes"]) is not int):
        raise BridgeValidationError("authorized-source-mismatch")
    origin = value["origin"]
    if (type(origin) is not dict or set(origin) != {"hemisphere", "system", "agent_id", "authenticated"}
            or origin["hemisphere"] != "wsl" or origin["system"] not in ("openclaw", "nullclaw")
            or not _id(origin["agent_id"]) or origin["authenticated"] is not False):
        raise BridgeValidationError("origin-schema-or-authentication-claim")
    records = value["records"]
    if type(records) is not list or not 1 <= len(records) <= MAX_ROWS:
        raise BridgeValidationError("row-count-bound")
    body = {key: item for key, item in value.items() if key != "export_sha256"}
    try:
        if (not _pin(value["export_sha256"]) or digest(body) != value["export_sha256"]
                or len(canonical(value)) > MAX_BUNDLE):
            raise BridgeValidationError("canonical-export-pin-or-bound")
    except (UnicodeError, ValueError, TypeError, OverflowError) as error:
        if isinstance(error, BridgeValidationError):
            raise
        raise BridgeValidationError("nonportable-canonical-export") from error
    rows, rejected, seen = [], [], set()
    for index, row in enumerate(records):
        reason = None
        event_id = row.get("event_id") if type(row) is dict else None
        if type(row) is not dict or set(row) != ROW_FIELDS:
            reason = "row-field-schema"
        elif (not _id(row["message_id"]) or not _uint(row["block_index"])
              or row["role"] not in ("user", "assistant") or row["kind"] not in ("note", "tool-result")):
            reason = "row-identity-or-kind"
        elif type(row["text"]) is not str or not _pin(row["text_sha256"]):
            reason = "row-text-or-hash-type"
        else:
            try:
                encoded = row["text"].encode("utf-8")
                if len(encoded) > MAX_TEXT or sha256(encoded) != row["text_sha256"]:
                    reason = "row-text-hash-or-bound"
            except UnicodeError:
                reason = "row-text-not-portable"
        if reason is None:
            identity = {"schema": "xnet.bridge.occurrence-id.v1", "producer_id": policy.producer_id,
                        "task_id": policy.task_id, "session_id": value["session_id"],
                        "message_id": row["message_id"], "block_index": row["block_index"]}
            if event_id != digest(identity) or event_id in seen:
                reason = "row-occurrence-id-or-duplicate"
            elif row["kind"] == "note" and (row["tool_use_id"] is not None or row["is_error"] is not None):
                reason = "note-tool-fields"
            elif row["kind"] == "tool-result":
                try:
                    if (type(row["tool_use_id"]) is not str or not row["tool_use_id"]
                            or len(row["tool_use_id"].encode("utf-8")) > 1024
                            or (row["is_error"] is not None and type(row["is_error"]) is not bool)):
                        reason = "tool-result-fields"
                except UnicodeError:
                    reason = "tool-result-fields"
        if reason is None:
            envelope = {"schema": "xnet.bridge.stored-record.v1", "task_id": policy.task_id,
                        "producer_id": policy.producer_id, "session_id": value["session_id"],
                        "origin": origin, "source_id": source["id"], "context_only": True,
                        "authority": "none", "work_performed": False, "importer_model_calls": 0,
                        **row}
            text = canonical(envelope).decode("utf-8")
            if not _request_fits(policy, event_id, text):
                reason = "native-envelope-or-frame-bound"
        if _pin(event_id):
            seen.add(event_id)
        if reason is None:
            rows.append(SourceRow(index, event_id, text, sha256(text.encode("utf-8"))))
        else:
            rejected.append(canonical({"index": index, "event_id": event_id if _pin(event_id) else None,
                                       "reason": reason, "row_sha256": digest(row)}).decode("utf-8"))
    manifest = {"schema": "xnet.bridge.import-manifest.v1", "task_id": policy.task_id,
                "producer_id": policy.producer_id, "session_id": value["session_id"],
                "source": source, "origin": origin, "raw_bundle_sha256": policy.raw_bundle_sha256,
                "export_sha256": value["export_sha256"], "policy_sha256": digest(asdict(policy)),
                "rows": [{"index": row.index, "event_id": row.event_id,
                          "source_digest": row.source_digest} for row in rows],
                "rejected": [json.loads(item) for item in rejected], "context_only": True,
                "authority": "none", "work_performed": False, "importer_model_calls": 0,
                "producer_authenticated": False, "source_verified": False}
    text = canonical(manifest).decode("utf-8")
    manifest_id = "bridge-import-" + digest(manifest)
    if not _request_fits(policy, manifest_id, text):
        raise BridgeValidationError("native-manifest-or-frame-bound")
    return ValidatedExport(raw_bytes, value["export_sha256"], tuple(rows), tuple(rejected), text, manifest_id)


def _sealed(body):
    return {**body, "receipt_sha256": digest(body)}


def _read(path):
    _no_links(path, regular_file=True)
    if path.stat().st_size > MAX_BUNDLE:
        raise BridgeError("journal-byte-bound")
    value = _parse(path.read_bytes())
    if type(value) is not dict or "receipt_sha256" not in value:
        raise BridgeError("invalid-journal-receipt")
    body = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if value["receipt_sha256"] != digest(body):
        raise BridgeError("journal-integrity-failed")
    return value


def _write(path, body):
    _no_links(path, regular_file=True)
    value = _sealed(body)
    raw = canonical(value)
    if len(raw) > MAX_BUNDLE:
        raise BridgeError("journal-byte-bound")
    if path.exists():
        if _read(path) != value:
            raise BridgeError("immutable-journal-conflict")
        return value
    path.parent.mkdir(parents=True, exist_ok=True)
    _no_links(path.parent)
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return value


class BridgeImporter:
    """One approved artifact/root. Never creates or closes the borrowed gateway.

    ``simulated=True`` is explicit offline dependency injection and is recorded
    in every receipt. Production requires an existing pinned native Client.
    Local hashes are not independent authenticated external checkpoints.
    """
    def __init__(self, gateway, journal_root: Path, *, policy: BridgePolicy, simulated=False):
        if not isinstance(policy, BridgePolicy) or type(simulated) is not bool:
            raise BridgeError("approved-policy-required")
        if not simulated and not isinstance(gateway, Client):
            raise BridgeError("production-requires-borrowed-native-client")
        path = Path(journal_root)
        if not path.is_absolute():
            raise BridgeError("absolute-journal-root-required")
        _no_links(path)
        self.gateway, self.root, self.policy, self.simulated = gateway, path, policy, simulated
        self.root.mkdir(parents=True, exist_ok=True)
        self.sources = self._source_pins()
        self.gateway_identity = self._gateway_identity()
        self.config = {"schema": "xnet.bridge.controller.v1", "policy": asdict(policy),
                       "sources": self.sources, "gateway_identity": self.gateway_identity,
                       "simulation": simulated, "gateway_owned": False, "authority": "none"}
        with self._lock():
            manifest = self.root / "controller.json"
            if not manifest.exists() and any(item.name != "admission.lock" for item in self.root.iterdir()):
                raise BridgeError("nonempty-unbound-controller-root")
            self.controller = _write(manifest, self.config)

    def _source_pins(self):
        from xnet_sdk import client, context
        from xnet import brains, protocol, relay_log, repair_loop
        return {str(Path(module.__file__).absolute()): sha256(Path(module.__file__).read_bytes())
                for module in (client, context, brains, protocol, relay_log, repair_loop)} | {
                    str(Path(__file__).absolute()): sha256(Path(__file__).read_bytes())}

    def _gateway_identity(self):
        if self.simulated:
            return {"kind": "explicit-fake-gateway", "attested": False}
        _no_links(self.gateway.root)
        # Cargo can legitimately hardlink an ordinary release artifact. Journal
        # files still require one link; binaries use the existing artifact seam.
        _no_links(self.gateway.binary)
        if not self.gateway.root.is_dir() or not self.gateway.binary.is_file():
            raise BridgeError("gateway-storage-unavailable")
        from xnet.repair_loop import _artifact_sha256
        actual = _artifact_sha256(self.gateway.binary)
        if actual != self.gateway.binary_sha256:
            raise BridgeError("gateway-binary-pin-changed")
        return {"root": str(self.gateway.root), "binary": str(self.gateway.binary), "binary_sha256": actual,
                "kind": "borrowed-native-client", "attested": False}

    def _check(self):
        _no_links(self.root)
        if not self.root.is_dir() or self._source_pins() != self.sources:
            raise BridgeError("controller-storage-or-source-changed")
        if self._gateway_identity() != self.gateway_identity or _read(self.root / "controller.json") != self.controller:
            raise BridgeError("controller-or-gateway-identity-changed")

    def _lock(self):
        _no_links(self.root / "admission.lock")
        return _exclusive_file_lock(self.root / "admission.lock", timeout=1)

    def _state(self):
        value = self.gateway.call("context_state", task_id=self.policy.task_id)
        if (type(value) is not dict or value.get("task_id") != self.policy.task_id
                or not _uint(value.get("history_count")) or value["history_count"] > 2048
                or (value.get("history_head") is not None and not _pin(value["history_head"]))):
            raise BridgeError("native-state-binding")
        return value

    def _history(self):
        state = self._state()
        events, after = {}, 0
        for _ in range(65):
            page = self.gateway.call("context_history", task_id=self.policy.task_id, after=after, limit=32)
            if (type(page) is not dict or page.get("task_id") != self.policy.task_id
                    or page.get("history_head") != state["history_head"]
                    or page.get("history_count") != state["history_count"]
                    or type(page.get("events")) is not list or len(page["events"]) > 32):
                raise BridgeError("native-history-snapshot-binding")
            for event in page["events"]:
                fields = {"seq", "event_id", "peer", "kind", "source_digest", "event_digest"}
                if (type(event) is not dict or set(event) != fields or not _uint(event["seq"])
                        or event["seq"] != len(events)
                        or not _id(event["event_id"]) or event["event_id"] in events
                        or event["peer"] not in ("operator", "assistant", "peer")
                        or event["kind"] not in ("raw", "decision", "fact", "open-item")
                        or not _pin(event["source_digest"]) or not _pin(event["event_digest"])):
                    raise BridgeError("native-history-event-binding")
                events[event["event_id"]] = event
            next_after = page.get("next_after")
            if next_after is None:
                expected_head = next(reversed(events.values()))["event_digest"] if events else None
                if (len(events) != state["history_count"] or state["history_head"] != expected_head
                        or self._state() != state):
                    raise BridgeError("native-history-snapshot-changed")
                return state, events
            if not _uint(next_after) or next_after != len(events) or next_after <= after:
                raise BridgeError("native-history-cursor-binding")
            after = next_after
        raise BridgeError("native-history-page-bound")

    def _audit(self):
        value = self.gateway.call("verify")
        if (type(value) is not dict or value.get("ok") is not True
                or value.get("external_checkpoint_verified") is not False
                or not _uint(value.get("receipt_count")) or value["receipt_count"] > 100000
                or (value.get("head") is not None and not _pin(value["head"]))):
            raise BridgeError("native-audit-binding")
        return {key: value[key] for key in ("ok", "receipt_count", "head", "external_checkpoint_verified")}

    def _event(self, row, event):
        if (event["event_id"] != row.event_id or event["peer"] != self.policy.admission_peer
                or event["kind"] != "raw" or event["source_digest"] != row.source_digest):
            raise BridgeError("native-occurrence-conflict")
        stored = self.gateway.call("fetch", digest=row.source_digest)
        if (type(stored) is not dict or stored.get("digest") != row.source_digest
                or stored.get("text") != row.text or sha256(stored["text"].encode("utf-8")) != row.source_digest):
            raise BridgeError("native-exact-source-binding")
        return event

    def _result(self, status, outcomes, audit=None, *, declared=None):
        outcomes = list(outcomes)
        if declared is not None:
            present = {item.get("index") for item in outcomes}
            for row in declared.rows:
                if row.index not in present:
                    outcomes.append({"index": row.index, "event_id": row.event_id,
                                     "source_digest": row.source_digest, "status": "not-attempted",
                                     "reason": "admission-stopped"})
            for encoded in declared.rejected:
                item = json.loads(encoded)
                if item["index"] not in present:
                    outcomes.append({**item, "status": "quarantined"})
        body = {"schema": "xnet.bridge.admission.v1", "import_id": self.policy.raw_bundle_sha256,
                "controller_sha256": self.controller["receipt_sha256"], "status": status,
                "task_id": self.policy.task_id, "admission_peer": self.policy.admission_peer,
                "raw_bundle_sha256": self.policy.raw_bundle_sha256, "outcomes": outcomes,
                "audit": audit, "simulation": self.simulated, "producer_authenticated": False,
                "source_verified": False, "external_checkpoint_verified": False,
                "work_performed": False, "context_only": True, "authority": "none", "model_calls": 0}
        if declared is not None:
            body.update(export_sha256=declared.export_sha256, eligible_rows=len(declared.rows),
                        quarantined_rows=len(declared.rejected), declared_rows=len(declared.rows) + len(declared.rejected))
        path = self.root / "receipts"
        path.mkdir(exist_ok=True)
        _no_links(path)
        previous = sorted(path.glob("*.json"))
        if len(previous) >= 512:
            raise BridgeError("receipt-capacity")
        old = _read(previous[-1]) if previous else None
        if old and all(old.get(key) == item for key, item in body.items()):
            return old
        body["previous_receipt_sha256"] = old["receipt_sha256"] if old else None
        return _write(path / f"{len(previous):04d}.json", body)

    def ingest(self, raw_bytes: bytes):
        with self._lock():
            self._check()
            try:
                validated = validate_bridge_export(raw_bytes, policy=self.policy)
            except BridgeValidationError as error:
                observed = sha256(raw_bytes) if type(raw_bytes) is bytes and len(raw_bytes) <= MAX_BUNDLE else None
                quarantine = _write(self.root / "quarantine" / "bundle.json", {
                    "schema": "xnet.bridge.quarantine.v1", "expected_raw_sha256": self.policy.raw_bundle_sha256,
                    "observed_raw_sha256": observed, "reasons": error.reasons,
                    "controller_sha256": self.controller["receipt_sha256"]})
                return {"request_replayed": False, "receipt": self._result("rejected-bundle", [quarantine])}
            return self._run(validated, reconcile=False)

    def reconcile(self, import_id: str):
        if import_id != self.policy.raw_bundle_sha256:
            raise BridgeError("reconciliation-import-binding")
        with self._lock():
            self._check()
            raw_path = self.root / "export.json"
            _no_links(raw_path, regular_file=True)
            if raw_path.stat().st_size > MAX_BUNDLE:
                raise BridgeError("stored-export-byte-bound")
            return self._run(validate_bridge_export(raw_path.read_bytes(), policy=self.policy), reconcile=True)

    def _run(self, validated, *, reconcile):
        raw_path = self.root / "export.json"
        _no_links(raw_path, regular_file=True)
        if raw_path.exists():
            if raw_path.stat().st_size > MAX_BUNDLE or raw_path.read_bytes() != validated.raw:
                raise BridgeError("stored-export-changed")
        else:
            with raw_path.open("xb") as handle:
                handle.write(validated.raw); handle.flush(); os.fsync(handle.fileno())
        for item in validated.rejected:
            row = json.loads(item)
            _write(self.root / "quarantine" / f"row-{row['index']:04d}.json", {
                "schema": "xnet.bridge.row-quarantine.v1", **row,
                "raw_bundle_sha256": self.policy.raw_bundle_sha256,
                "controller_sha256": self.controller["receipt_sha256"]})
        manifest = SourceRow(-1, validated.manifest_id, validated.manifest_text,
                             sha256(validated.manifest_text.encode("utf-8")))
        work = (manifest, *validated.rows)
        audit = self._audit()
        state, history = self._history()
        # Verify every existing selected source before the first native write.
        # A definite occurrence conflict is a row rejection; integrity drift is
        # a controller failure, never an excuse to keep importing other rows.
        for row in work:
            if row.event_id not in history:
                continue
            try:
                self._event(row, history[row.event_id])
            except BridgeError as error:
                if str(error) != "native-occurrence-conflict":
                    raise
        completion_path = self.root / "completion.json"
        if completion_path.exists():
            completion = _read(completion_path)
            if completion.get("controller_sha256") != self.controller["receipt_sha256"]:
                raise BridgeError("completion-controller-binding")
            receipts = sorted((self.root / "receipts").glob("*.json"))
            if not 1 <= len(receipts) <= 512:
                raise BridgeError("completion-receipt-bound")
            found, previous = None, None
            for path in receipts:
                saved = _read(path)
                if saved.get("previous_receipt_sha256") != previous:
                    raise BridgeError("receipt-chain-binding")
                previous = saved["receipt_sha256"]
                if previous == completion.get("receipt_sha256_binding"):
                    found = saved
            if (found is None or found.get("controller_sha256") != self.controller["receipt_sha256"]
                    or found.get("raw_bundle_sha256") != self.policy.raw_bundle_sha256):
                raise BridgeError("completion-receipt-binding")
            historical = {item.get("index"): item for item in found["outcomes"] if "source_digest" in item}
            for row in work:
                directory = self.root / "rows" / ("manifest" if row.index == -1 else f"{row.index:04d}")
                outcome = _read(directory / "outcome.json")
                if (outcome != historical.get(row.index) or outcome.get("event_id") != row.event_id
                        or outcome.get("source_digest") != row.source_digest):
                    raise BridgeError("completed-row-binding")
                if outcome["status"] in ("admitted", "replayed", "reconciled"):
                    actual = history.get(row.event_id)
                    if actual is None or self._event(row, actual) != outcome["event"]:
                        raise BridgeError("completed-row-history-binding")
            return {"request_replayed": True, "receipt": found, "completion": completion,
                    "current_verification": {"audit": audit, "history_head": state["history_head"],
                                             "history_count": state["history_count"]}}
        outcomes = []
        newly_called = False
        for row in work:
            self._check()
            directory = self.root / "rows" / ("manifest" if row.index == -1 else f"{row.index:04d}")
            reservation_path, outcome_path = directory / "reservation.json", directory / "outcome.json"
            if outcome_path.exists():
                outcome = _read(outcome_path)
                if (outcome.get("event_id") != row.event_id or outcome.get("source_digest") != row.source_digest
                        or outcome.get("controller_sha256") != self.controller["receipt_sha256"]):
                    raise BridgeError("row-outcome-binding")
                if outcome["status"] in ("admitted", "replayed", "reconciled"):
                    actual = history.get(row.event_id)
                    if actual is None or self._event(row, actual) != outcome["event"]:
                        raise BridgeError("committed-row-history-binding")
                outcomes.append(outcome)
                if outcome["status"] == "refused" and outcome.get("reason") in REFUSALS:
                    return {"request_replayed": True,
                            "receipt": self._result("native-refused", outcomes, audit, declared=validated)}
                continue
            if reservation_path.exists():
                reservation = _read(reservation_path)
                if (reservation.get("event_id") != row.event_id or reservation.get("source_digest") != row.source_digest
                        or reservation.get("controller_sha256") != self.controller["receipt_sha256"]):
                    raise BridgeError("row-reservation-binding")
                if not reconcile or row.event_id not in history:
                    pending = {"index": row.index, "event_id": row.event_id, "status": "pending-reconciliation",
                               "reservation_sha256": reservation["receipt_sha256"]}
                    return {"request_replayed": not newly_called,
                            "receipt": self._result("pending-reconciliation", [*outcomes, pending], audit, declared=validated)}
                event = self._event(row, history[row.event_id])
                outcome = self._row_outcome(directory, row, "reconciled", event,
                                            reservation_sha256=reservation["receipt_sha256"])
                outcomes.append(outcome)
                continue
            if row.event_id in history:
                try:
                    event = self._event(row, history[row.event_id])
                    outcome = self._row_outcome(directory, row, "replayed", event)
                except BridgeError as error:
                    if str(error) != "native-occurrence-conflict":
                        raise
                    outcome = self._row_outcome(directory, row, "refused", None, reason="native-occurrence-conflict")
                    _write(self.root / "quarantine" / f"conflict-{row.index + 1:04d}.json", {
                        "event_id": row.event_id, "source_digest": row.source_digest,
                        "reason": "native-occurrence-conflict", "raw_bundle_sha256": self.policy.raw_bundle_sha256})
                outcomes.append(outcome)
                continue
            if state.get("pending") is not None:
                outcomes.append(self._row_outcome(directory, row, "refused", None, reason="context_handoff_pending"))
                continue
            current = self._state()
            request = {"task_id": self.policy.task_id, "peer": self.policy.admission_peer,
                       "event_id": row.event_id, "kind": "raw", "text": row.text,
                       "expected_head": current["history_head"]}
            reservation = _write(reservation_path, {"schema": "xnet.bridge.row-reservation.v1",
                "index": row.index, "event_id": row.event_id, "source_digest": row.source_digest,
                "request_sha256": digest(request), "expected_head": current["history_head"],
                "controller_sha256": self.controller["receipt_sha256"]})
            newly_called = True
            try:
                returned = self.gateway.call("context_append", **request)
                if (type(returned) is not dict or set(returned) != {"event", "history_head", "duplicate"}
                        or type(returned["duplicate"]) is not bool or not _pin(returned["history_head"])):
                    raise BridgeError("native-append-response-binding")
                state, history = self._history()
                event = history.get(row.event_id)
                if event is None or event != returned["event"]:
                    raise BridgeError("native-append-history-binding")
                if (not returned["duplicate"] and returned["history_head"] != event["event_digest"]
                        or returned["duplicate"] and returned["history_head"] not in
                        {item["event_digest"] for item in history.values()}):
                    raise BridgeError("native-append-head-binding")
                self._event(row, event)
                outcome = self._row_outcome(directory, row, "replayed" if returned["duplicate"] else "admitted", event,
                                            reservation_sha256=reservation["receipt_sha256"])
            except Exception as error:
                code = str(error) if str(error) in REFUSALS else None
                if code is not None:
                    outcome = self._row_outcome(directory, row, "refused", None, reason=code,
                                                reservation_sha256=reservation["receipt_sha256"])
                    outcomes.append(outcome)
                    return {"request_replayed": False,
                            "receipt": self._result("native-refused", outcomes, self._audit(), declared=validated)}
                _write(directory / "uncertain.json", {"schema": "xnet.bridge.uncertain-call.v1",
                    "event_id": row.event_id, "source_digest": row.source_digest,
                    "reservation_sha256": reservation["receipt_sha256"], "reason": type(error).__name__,
                    "raw_bundle_sha256": self.policy.raw_bundle_sha256})
                pending = {"index": row.index, "event_id": row.event_id, "status": "pending-reconciliation",
                           "reservation_sha256": reservation["receipt_sha256"]}
                return {"request_replayed": False,
                        "receipt": self._result("pending-reconciliation", [*outcomes, pending], audit, declared=validated)}
            outcomes.append(outcome)
        rejected = [json.loads(item) | {"status": "quarantined"} for item in validated.rejected]
        audit = self._audit()
        current = self._state()
        status = "partial-complete" if rejected or any(item["status"] == "refused" for item in outcomes) else "complete"
        receipt = self._result(status, [*outcomes, *rejected], audit, declared=validated)
        completion = _write(self.root / "completion.json", {"schema": "xnet.bridge.completion.v1",
            "receipt_sha256_binding": receipt["receipt_sha256"], "history_head": current["history_head"],
            "history_count": current["history_count"], "controller_sha256": self.controller["receipt_sha256"]})
        return {"request_replayed": not newly_called, "receipt": receipt, "completion": completion}

    def _row_outcome(self, directory, row, status, event, **extra):
        return _write(directory / "outcome.json", {"schema": "xnet.bridge.row-outcome.v1",
            "index": row.index, "event_id": row.event_id, "source_digest": row.source_digest,
            "controller_sha256": self.controller["receipt_sha256"], "status": status, "event": event, **extra})

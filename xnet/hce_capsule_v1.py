"""Optional source-only HCE codec and borrowed, scoped Ledger/CAS adapter.

Faces are deterministic plain text, not translations or executable instructions.
Full canonical capsule identities bind metadata as well as exact source bytes.
The caller selects public sources, display language, context budget and policy.
This module creates no authority, runner, rotation rule, mutable global index or
language default. A hash proves bytes, not authorship or permission.
"""
from __future__ import annotations

import json
import re
from .ledger import Ledger
from .protocol import canonical, make_event, sha256
from .relay_log import RelayLogError, _no_links

SCHEMA = "xnet.hce-capsule.v1"
INDEX_SCHEMA = "xnet.hce-index.v1"
RECEIPT_SCHEMA = "xnet.hce-source-receipt.v1"
MAX_SOURCE_BYTES = 65536
MAX_WIRE_BYTES = 262144
MAX_INDEX_ROWS = 64
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_CAPSULE_FIELDS = {"schema", "ring", "kind", "classification", "source_sha256", "text"}
_REF_FIELDS = {"ring", "kind", "classification", "source_sha256", "capsule_sha256", "receipt_sha256"}


class HceError(ValueError):
    """Malformed, mismatched or unverified source-only data is refused."""


def _checked_no_links(path, *, regular_file=False):
    """Keep the existing link refusal while exposing this adapter's API error."""
    try:
        _no_links(path, regular_file=regular_file)
    except RelayLogError as error:
        raise HceError("HCE filesystem path failed the existing no-links check") from error


def _hash(value):
    if type(value) is not str or not _HASH.fullmatch(value):
        raise HceError("complete lowercase SHA256 required")
    return value


def _identity(ring, kind, classification):
    if type(ring) is not int or not 1 <= ring <= 2147483647:
        raise HceError("positive exact integer ring required")
    if type(kind) is not str or not _ID.fullmatch(kind) or len(kind) > 64:
        raise HceError("bounded kind identifier required")
    if type(classification) is not str or classification != "public":
        raise HceError("explicit caller-selected public classification required")


def _source(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_SOURCE_BYTES:
        raise HceError("bounded nonempty source bytes required")
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise HceError("exact valid UTF-8 source required") from error


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise HceError("duplicate JSON field")
        result[key] = value
    return result


def _nonfinite(value):
    raise HceError("nonfinite JSON value refused")


def _parse(raw, expected_sha256):
    _hash(expected_sha256)
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_WIRE_BYTES:
        raise HceError("bounded canonical wire bytes required")
    if sha256(raw) != expected_sha256:
        raise HceError("expected full wire hash differs")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                           parse_constant=_nonfinite)
        if type(value) is not dict or canonical(value) != raw:
            raise HceError("canonical JSON object required; normalization forbidden")
        return value
    except (UnicodeError, ValueError, RecursionError, TypeError) as error:
        if isinstance(error, HceError):
            raise
        raise HceError("malformed canonical UTF-8 JSON") from error


def encode_capsule(source_bytes, *, expected_source_sha256, ring, kind, classification):
    """Lossless canonical JSON; no normalization, shortening or implicit language."""
    _identity(ring, kind, classification)
    _hash(expected_source_sha256)
    text = _source(source_bytes)
    if sha256(source_bytes) != expected_source_sha256:
        raise HceError("original source pin differs")
    raw = canonical({"schema": SCHEMA, "ring": ring, "kind": kind,
        "classification": classification, "source_sha256": expected_source_sha256, "text": text})
    if len(raw) > MAX_WIRE_BYTES:
        raise HceError("escaped canonical capsule exceeds wire budget")
    return raw


def decode_capsule(raw, *, expected_sha256):
    value = _parse(raw, expected_sha256)
    if set(value) != _CAPSULE_FIELDS or value["schema"] != SCHEMA:
        raise HceError("capsule schema fields differ")
    _identity(value["ring"], value["kind"], value["classification"])
    _hash(value["source_sha256"])
    if type(value["text"]) is not str:
        raise HceError("capsule text must be exact UTF-8")
    try:
        raw_text = value["text"].encode("utf-8", "strict")
    except UnicodeError as error:
        raise HceError("invalid capsule Unicode") from error
    _source(raw_text)
    if sha256(raw_text) != value["source_sha256"]:
        raise HceError("capsule source backpointer differs")
    return value


def render_face(capsule, *, face):
    """Return a derived plain-text face. HTML consumers must escape plain text."""
    try:
        raw = canonical(capsule)
    except (UnicodeError, ValueError, TypeError) as error:
        raise HceError("invalid capsule") from error
    value = decode_capsule(raw, expected_sha256=sha256(raw))
    if type(face) is not str or face not in ("machine", "zh", "en"):
        raise HceError("explicit known display face required")
    if face == "machine":
        return raw.decode("utf-8")
    # JSON string escaping preserves delimiters, quotes and control characters.
    text = json.dumps(value["text"], ensure_ascii=False, allow_nan=False)
    kind = json.dumps(value["kind"], ensure_ascii=False, allow_nan=False)
    if face == "zh":
        return f'{value["ring"]}号环 | 类型 {kind} | 源SHA256 {value["source_sha256"]} | 原文 {text}'
    return f'Ring {value["ring"]} | kind {kind} | source SHA256 {value["source_sha256"]} | original text {text}'


def _reference(value):
    if type(value) is not dict or set(value) != _REF_FIELDS:
        raise HceError("exact full-hash capsule reference required")
    _identity(value["ring"], value["kind"], value["classification"])
    for name in ("source_sha256", "capsule_sha256", "receipt_sha256"):
        _hash(value[name])
    return dict(value)


class HceCapsuleStore:
    """Borrow the caller's initialized Ledger and mandatory scope gate.

    gate(method, 'path:...') must admit each CAS or ledger operation. The caller
    owns its scopes and source-pinned callback. All writes are new CAS objects
    or append-only receipts; expected full pins must come from the caller.
    """

    def __init__(self, ledger, *, scope_gate, scope_id, task_id):
        if not isinstance(ledger, Ledger) or not callable(scope_gate):
            raise HceError("existing Ledger and caller scope gate required")
        if any(type(value) is not str or not _ID.fullmatch(value) for value in (scope_id, task_id)):
            raise HceError("explicit scope and task identifiers required")
        if not ledger.cas_dir.is_absolute() or not ledger.db_path.is_absolute():
            raise HceError("caller Ledger paths must be absolute")
        self.ledger, self.scope_gate = ledger, scope_gate
        self.scope_id, self.task_id = scope_id, task_id

    def _gate(self, method, path):
        self.scope_gate(method, "path:" + str(path))

    def _put(self, raw, label):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_WIRE_BYTES:
            raise HceError("bounded CAS write required")
        # Admit both filesystem domains before the Ledger performs any I/O.
        self._gate("hce_cas_write", self.ledger.cas_dir)
        self._gate("hce_ledger_append", self.ledger.db_path.parent)
        _checked_no_links(self.ledger.cas_dir)
        _checked_no_links(self.ledger.db_path, regular_file=True)
        expected_pin = sha256(raw)
        path = self.ledger.cas_dir / expected_pin[:2] / expected_pin
        _checked_no_links(path, regular_file=True)
        if path.exists() and path.lstat().st_nlink != 1:
            raise HceError("single-link CAS destination required")
        pin = self.ledger.put_evidence(raw, source=label, scope_id=self.scope_id,
                                       metadata={"classification": "public", "authority": "none"})
        if pin != expected_pin:
            raise HceError("caller CAS write identity differs")
        if self._get(pin) != raw:
            raise HceError("caller CAS exact write readback differs")
        return pin

    def _get(self, pin):
        _hash(pin)
        path = self.ledger.cas_dir / pin[:2] / pin
        self._gate("hce_cas_read", path)
        try:
            _checked_no_links(path, regular_file=True)
            before = path.lstat()
            if before.st_nlink != 1 or not 0 < before.st_size <= MAX_WIRE_BYTES:
                raise HceError("bounded single-link CAS source required")
            raw = self.ledger.get_evidence(pin)
        except (OSError, ValueError) as error:
            if isinstance(error, HceError):
                raise
            raise HceError("CAS source missing or integrity check failed") from error
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_WIRE_BYTES or sha256(raw) != pin:
            raise HceError("bounded full-hash CAS source differs")
        return raw

    def _append(self, kind, payload):
        self._gate("hce_ledger_append", self.ledger.db_path.parent)
        _checked_no_links(self.ledger.db_path, regular_file=True)
        return self.ledger.append(make_event(self.task_id, self.scope_id, kind, payload, source="hce-source-adapter"))

    def _witness(self, kind, payload):
        self._gate("hce_ledger_read", self.ledger.db_path.parent)
        _checked_no_links(self.ledger.db_path, regular_file=True)
        self.ledger.verify_chain()
        self._gate("hce_ledger_read", self.ledger.db_path.parent)
        events = self.ledger.events(self.task_id)
        if not any(event["scope_id"] == self.scope_id and event["source"] == "hce-source-adapter"
                   and event["kind"] == kind and event["payload"] == payload for event in events):
            raise HceError("caller ledger provenance witness missing")

    def store(self, source_bytes, *, expected_source_sha256, ring, kind, classification):
        raw = encode_capsule(source_bytes, expected_source_sha256=expected_source_sha256,
                             ring=ring, kind=kind, classification=classification)
        source_pin = self._put(source_bytes, "hce-original-public-source")
        capsule_pin = self._put(raw, "hce-canonical-public-capsule")
        body = {"schema": RECEIPT_SCHEMA, "scope_id": self.scope_id, "task_id": self.task_id,
            "ring": ring, "kind": kind, "classification": classification,
            "source_sha256": source_pin, "capsule_sha256": capsule_pin}
        receipt_pin = self._put(canonical(body), "hce-source-only-intake-receipt")
        self._append("hce.source-only", {"receipt_sha256": receipt_pin})
        return {key: body[key] for key in _REF_FIELDS - {"receipt_sha256"}} | {"receipt_sha256": receipt_pin}

    def fetch(self, reference):
        ref = _reference(reference)
        receipt = _parse(self._get(ref["receipt_sha256"]), ref["receipt_sha256"])
        expected = {"schema": RECEIPT_SCHEMA, "scope_id": self.scope_id, "task_id": self.task_id,
                    **{key: ref[key] for key in _REF_FIELDS - {"receipt_sha256"}}}
        if receipt != expected:
            raise HceError("capsule reference scope, source or receipt differs")
        capsule = decode_capsule(self._get(ref["capsule_sha256"]), expected_sha256=ref["capsule_sha256"])
        if any(capsule[key] != ref[key] for key in ("ring", "kind", "classification", "source_sha256")):
            raise HceError("capsule/index metadata differs")
        if self._get(ref["source_sha256"]) != capsule["text"].encode("utf-8"):
            raise HceError("exact original source reconstruction differs")
        self._witness("hce.source-only", {"receipt_sha256": ref["receipt_sha256"]})
        return capsule

    def store_index(self, references):
        if type(references) is not list or not 1 <= len(references) <= MAX_INDEX_ROWS:
            raise HceError("bounded explicit index references required")
        rows = [_reference(row) for row in references]
        if len({row["capsule_sha256"] for row in rows}) != len(rows):
            raise HceError("duplicate capsule index identity")
        for row in rows:
            self.fetch(row)
        rows.sort(key=lambda row: (row["ring"], row["capsule_sha256"]))
        pin = self._put(canonical({"schema": INDEX_SCHEMA, "classification": "public",
            "scope_id": self.scope_id, "task_id": self.task_id, "records": rows}), "hce-immutable-public-index")
        self._append("hce.index-only", {"index_sha256": pin})
        return pin

    def fetch_ring(self, *, expected_index_sha256, ring):
        _identity(ring, "index", "public")
        index = _parse(self._get(expected_index_sha256), expected_index_sha256)
        if (set(index) != {"schema", "classification", "scope_id", "task_id", "records"}
                or index["schema"] != INDEX_SCHEMA or index["classification"] != "public"
                or index["scope_id"] != self.scope_id or index["task_id"] != self.task_id
                or type(index["records"]) is not list or not 1 <= len(index["records"]) <= MAX_INDEX_ROWS):
            raise HceError("index schema/scope differs")
        rows = [_reference(row) for row in index["records"]]
        if (rows != sorted(rows, key=lambda row: (row["ring"], row["capsule_sha256"]))
                or len({row["capsule_sha256"] for row in rows}) != len(rows)):
            raise HceError("index order or duplicate identity differs")
        self._witness("hce.index-only", {"index_sha256": expected_index_sha256})
        # Verify every row before using its ring metadata as a selection filter.
        verified = [(row["ring"], self.fetch(row)) for row in rows]
        return [capsule for selected_ring, capsule in verified if selected_ring == ring]

    def context_record(self, reference, *, record_id, face, max_bytes):
        if type(record_id) is not str or not _ID.fullmatch(record_id):
            raise HceError("explicit context record identifier required")
        if type(max_bytes) is not int or not 1 <= max_bytes <= 16384:
            raise HceError("exact caller context byte budget required")
        ref = _reference(reference)
        text = render_face(self.fetch(ref), face=face)
        raw = text.encode("utf-8")
        if len(raw) > max_bytes:
            raise HceError("context budget exceeded; clipping forbidden")
        text_pin = sha256(raw)
        receipt = {"schema": "xnet.hce-context-receipt.v1", "classification": "public",
            "scope_id": self.scope_id, "task_id": self.task_id, "reference": ref,
            "record_id": record_id, "face": face, "text_sha256": text_pin,
            "authority": "none", "context_only": True}
        pin = self._put(canonical(receipt), "hce-public-context-selection")
        self._append("hce.context-only", {"receipt_sha256": pin})
        record = {"record_id": record_id, "kind": "rag-slice", "text": text,
            "source_sha256": ref["source_sha256"], "text_sha256": text_pin, "receipt_sha256": pin}
        selection = {key: value for key, value in record.items() if key != "text"}
        selection["classification"] = "public"
        return {"classification": "public", "selection": selection, "record": record}

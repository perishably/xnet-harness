"""XNET-owned source-only facts and on-demand procedure cards.

Patterns adapted from Jcode typed recall and Hermes progressive disclosure;
neither upstream agent, provider nor executor is embedded. Public validation is
caller-owned. Hashes prove bytes/provenance, not that a note is semantically true.
"""
from __future__ import annotations

import copy
import json
import math
from pathlib import Path
import re
import time

from .brains import _exclusive_file_lock
from .ledger import Ledger
from .protocol import canonical, digest, make_event, sha256
from .relay_log import _no_links
from .scope import ScopeAuthority
from .scaffold_learning import STEP_TEXT

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE = "procedural-memory"
VALIDATION_SCHEMA = "xnet.procedural-public-validation.v1"
METHODS = ("memory_read", "memory_write")


def _label(value):
    if type(value) is not str or not _ID.fullmatch(value):
        raise ValueError("explicit bounded label required")
    return value


def _pin(value):
    if type(value) is not str or not _HASH.fullmatch(value):
        raise ValueError("SHA-256 pointer required")
    return value


def _text(value, maximum):
    if type(value) is not str or not value.strip() or len(value.encode("utf-8", "strict")) > maximum:
        raise ValueError("exact UTF-8 text exceeds its bound")
    if any(ord(char) < 32 and char not in "\n\t" for char in value):
        raise ValueError("control characters are not memory content")
    # Known grader/payload marker rejection is an additional guard, not DLP or
    # proof that arbitrary caller-classified prose contains no secret/answer.
    if any(marker in value.lower() for marker in
           ("hidden_cases", "hidden_report", "reference_bundle", "gold_patch", "repaired_source")):
        raise ValueError("grader data markers are forbidden in memory")
    return value


def _pins():
    root = Path(__file__).parent
    return {name: sha256((root / name).read_bytes()) for name in
            ("procedural_memory.py", "scaffold_learning.py", "ledger.py", "protocol.py", "scope.py")}


def _compatible_kind(left, right):
    return left == right or left in ("fact", "correction") and right in ("fact", "correction")


class ProceduralMemory:
    """Caller-scoped append-only memory with staged-to-validated activation.

    The caller supplies a signed scope, source CAS and independent public
    verifier evidence. A model's self-report is not a validator. Reads/writes
    use only the fixed METHODS, do not invoke tools or update model weights.
    """
    def __init__(self, ledger, epoch_id, project_id, verifier_sha256, *, scope_authority, scope_id):
        if not isinstance(ledger, Ledger) or not isinstance(scope_authority, ScopeAuthority):
            raise ValueError("caller Ledger and signed ScopeAuthority required")
        self.ledger, self.scope = ledger, scope_authority
        self.scope_id = scope_id
        self.root = ledger.data_dir.absolute()
        _no_links(self.root)
        self._task = "procedural-" + digest([epoch_id, project_id])[:32]
        self._config = {"schema": "xnet.procedural-memory-epoch.v1", "epoch_id": _label(epoch_id),
                        "project_id": _label(project_id), "verifier_sha256": _pin(verifier_sha256),
                        "scope_id": scope_id, "source_pins": _pins(), "weights_updated": False,
                        "external_Jev_called": False, "external_Hermes_executed": False,
                        "authority": "none", "threshold": 0.8, "pending_ttl_seconds": 120}
        self._config_pin = digest(self._config)
        self._lock_path = self.root / "procedural-locks" / (digest(self._task) + ".lock")
        self._gate("memory_write")
        with self._lock():
            state = self._state(allow_empty=True)
            if state["config"] is None:
                self._write("epoch", self._config)
            elif state["config"] != self._config:
                raise ValueError("memory source/config changed; use a new epoch")

    def _lock(self):
        _no_links(self._lock_path)
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        return _exclusive_file_lock(self._lock_path, timeout=1)

    def _gate(self, method):
        self.scope.gate(self.scope_id, "path:" + str(self.root), method, network=False)

    def _write(self, kind, body):
        self._gate("memory_write")
        wrapper = {"schema": "xnet.procedural-record.v1", "config_sha256": self._config_pin,
                   "kind": kind, "body": body}
        pointer = self.ledger.put_evidence(canonical(wrapper), source=_SOURCE,
                    scope_id=self.scope_id, metadata={"classification": "public", "authority": "none"})
        payload = {"record_sha256": pointer, "config_sha256": self._config_pin, "record_type": kind}
        receipt = self.ledger.append(make_event(self._task, self.scope_id, "memory-" + kind,
                                    payload, source=_SOURCE))
        return {"evidence_sha256": pointer, "receipt_sha256": receipt["receipt_hash"]}

    def _state(self, allow_empty=False):
        self._gate("memory_read")
        if _pins() != self._config["source_pins"] or digest(self._config) != self._config_pin:
            raise ValueError("memory implementation changed; use a new epoch")
        self.ledger.verify_chain()
        state = {"config": None, "cards": {}, "pending": {}, "consumed": {}}
        for event in self.ledger.events(self._task):
            payload = event["payload"]
            if (event["source"] != _SOURCE or event["scope_id"] != self.scope_id
                    or payload.get("config_sha256") != self._config_pin):
                raise ValueError("memory epoch/event binding mismatch")
            wrapper = json.loads(self.ledger.get_evidence(payload["record_sha256"]))
            kind = payload["record_type"]
            if (set(wrapper) != {"schema", "config_sha256", "kind", "body"}
                    or wrapper["schema"] != "xnet.procedural-record.v1"
                    or wrapper["config_sha256"] != self._config_pin or wrapper["kind"] != kind):
                raise ValueError("memory event/evidence binding mismatch")
            body = wrapper["body"]
            if kind == "epoch" and state["config"] is None:
                state["config"] = body
            elif kind == "stage":
                identifier = body["memory_id"]
                if identifier in state["cards"]:
                    raise ValueError("duplicate memory stage")
                state["cards"][identifier] = {"card": body, "active": False,
                                               "stage_sha256": payload["record_sha256"],
                                               "validation_sha256": None}
            elif kind == "activate":
                card = state["cards"].get(body["memory_id"])
                if card is None or card["stage_sha256"] != body["stage_sha256"]:
                    raise ValueError("activation does not refer to its staged card")
                self.ledger.get_evidence(body["validation_sha256"])
                card["active"] = True
                card["validation_sha256"] = body["validation_sha256"]
                previous = card["card"]["supersedes"]
                if previous is not None:
                    old = state["cards"].get(previous)
                    if old is None or not _compatible_kind(old["card"]["kind"], card["card"]["kind"]):
                        raise ValueError("supersession target missing or wrong kind")
                    old["active"] = False
            elif kind == "retire":
                if body["memory_id"] not in state["cards"]:
                    raise ValueError("retirement target missing")
                state["cards"][body["memory_id"]]["active"] = False
            elif kind == "pending":
                state["pending"][body["session_id"]] = body
            elif kind == "consume":
                state["pending"].pop(body["session_id"], None)
                state["consumed"].setdefault(body["session_id"], set()).update(body["memory_ids"])
            elif kind == "discard":
                state["pending"].pop(body["session_id"], None)
            elif kind != "corroborate":
                raise ValueError("unknown memory record transition")
        if not allow_empty and state["config"] != self._config:
            raise ValueError("memory epoch missing or changed")
        return state

    @property
    def config(self):
        self._state()
        return copy.deepcopy(self._config)

    def _stage(self, memory_id, *, kind, title, tags, text, steps, source_sha256,
               origin_task_id, supersedes=None, classification="public", hidden_cases_used=False):
        _label(memory_id); _label(origin_task_id); _pin(source_sha256)
        if classification != "public" or hidden_cases_used is not False:
            raise ValueError("only caller-classified public input may be staged")
        title = _text(title, 128)
        if (type(tags) not in (list, tuple) or not 1 <= len(tags) <= 4
                or any(type(tag) is not str or not _ID.fullmatch(tag) or len(tag) > 32 for tag in tags)
                or len(set(tags)) != len(tags)):
            raise ValueError("one to four unique bounded tags required")
        text = _text(text, 2048 if kind == "procedure" else 512)
        source = self.ledger.get_evidence(source_sha256)
        if not source or len(source) > 65536:
            raise ValueError("bounded existing source CAS required")
        card = {"schema": "xnet.procedural-card.v1", "memory_id": memory_id,
                "project_id": self._config["project_id"], "kind": kind, "title": title,
                "tags": list(tags), "text": text, "steps": steps, "source_sha256": source_sha256,
                "origin_task_id": origin_task_id, "supersedes": _label(supersedes) if supersedes else None,
                "classification": "public", "authority": "none", "context_only": True,
                "tools": [], "hidden_cases_used": False, "text_sha256": sha256(text.encode("utf-8"))}
        with self._lock():
            state = self._state()
            old = state["cards"].get(memory_id)
            if old:
                if old["card"] != card:
                    raise ValueError("conflicting memory ID; stage a new version")
                return {"memory_id": memory_id, "stage_sha256": old["stage_sha256"], "duplicate": True}
            content = {key: card[key] for key in ("kind", "title", "tags", "text", "steps", "supersedes")}
            for identifier, prior in state["cards"].items():
                if {key: prior["card"][key] for key in content} == content:
                    self._write("corroborate", {"memory_id": identifier, "source_sha256": source_sha256,
                                               "origin_task_id": origin_task_id})
                    return {"memory_id": identifier, "stage_sha256": prior["stage_sha256"], "duplicate": True}
            if supersedes and (supersedes not in state["cards"] or
                               not _compatible_kind(state["cards"][supersedes]["card"]["kind"], kind)):
                raise ValueError("supersession requires an existing same-kind card")
            receipt = self._write("stage", card)
            return {"memory_id": memory_id, "stage_sha256": receipt["evidence_sha256"], "duplicate": False}

    def stage_procedure(self, memory_id, *, title, tags, steps, source_sha256, origin_task_id, **options):
        if (type(steps) not in (list, tuple) or not 1 <= len(steps) <= 6
                or any(type(step) is not str or step not in STEP_TEXT for step in steps)
                or len(set(steps)) != len(steps)):
            raise ValueError("procedure cards require one to six fixed scaffold enums")
        text = "Procedure guidance; source only, no tool authority.\n" + "\n".join(
            str(n) + ". " + STEP_TEXT[step] for n, step in enumerate(steps, 1))
        return self._stage(memory_id, kind="procedure", title=title, tags=tags, steps=list(steps),
                           text=text, source_sha256=source_sha256, origin_task_id=origin_task_id, **options)

    def stage_note(self, memory_id, *, kind, title, tags, text, source_sha256, origin_task_id, **options):
        if kind not in ("fact", "correction"):
            raise ValueError("notes are facts or corrections, not candidate answers")
        return self._stage(memory_id, kind=kind, title=title, tags=tags, text=text, steps=[],
                           source_sha256=source_sha256, origin_task_id=origin_task_id, **options)

    def activate(self, memory_id, validation_evidence_sha256):
        with self._lock():
            state = self._state()
            item = state["cards"].get(_label(memory_id))
            if item is None:
                raise ValueError("staged memory is missing")
            evidence = json.loads(self.ledger.get_evidence(_pin(validation_evidence_sha256)))
            fields = {"schema", "project_id", "memory_id", "stage_sha256", "source_sha256",
                      "verifier_sha256", "validation_task_id", "passed", "boundary_violation",
                      "hidden_cases_used", "answer_payload_used", "independent_public_validation"}
            if (type(evidence) is not dict or set(evidence) != fields
                    or evidence["schema"] != VALIDATION_SCHEMA
                    or evidence["project_id"] != self._config["project_id"]
                    or evidence["memory_id"] != memory_id or evidence["stage_sha256"] != item["stage_sha256"]
                    or evidence["source_sha256"] != item["card"]["source_sha256"]
                    or evidence["verifier_sha256"] != self._config["verifier_sha256"]
                    or evidence["passed"] is not True or evidence["boundary_violation"] is not False
                    or evidence["hidden_cases_used"] is not False or evidence["answer_payload_used"] is not False
                    or evidence["independent_public_validation"] is not True
                    or _label(evidence["validation_task_id"]) == item["card"]["origin_task_id"]):
                raise ValueError("independent public validation evidence required")
            if item["active"]:
                if item["validation_sha256"] != validation_evidence_sha256:
                    raise ValueError("active validation identity changed")
                return {"active": True, "duplicate": True}
            if item["validation_sha256"] is not None:
                raise ValueError("retired or superseded memory cannot reactivate; stage a new version")
            return {"active": True, "duplicate": False, **self._write("activate", {
                "memory_id": memory_id, "stage_sha256": item["stage_sha256"],
                "validation_sha256": validation_evidence_sha256})}

    def retire(self, memory_id):
        with self._lock():
            state = self._state()
            if _label(memory_id) not in state["cards"]:
                raise ValueError("unknown memory")
            return self._write("retire", {"memory_id": memory_id})

    def catalog(self):
        state = self._state()
        rows = [{"memory_id": identifier, "kind": item["card"]["kind"], "title": item["card"]["title"],
                 "tags": item["card"]["tags"], "card_sha256": item["stage_sha256"]}
                for identifier, item in sorted(state["cards"].items()) if item["active"]]
        if len(rows) > 24 or len(canonical(rows)) > 8192:
            raise ValueError("catalog exceeds one bounded batch; explicit caller partition required")
        return rows

    def load(self, memory_id):
        state = self._state()
        item = state["cards"].get(_label(memory_id))
        if item is None or not item["active"]:
            raise ValueError("only active memory may be loaded")
        self.ledger.get_evidence(item["card"]["source_sha256"])
        return {"record_id": "memory-" + digest([self._task, memory_id])[:32], "kind": "rag-slice",
                "text": item["card"]["text"], "source_sha256": item["stage_sha256"],
                "text_sha256": item["card"]["text_sha256"],
                "receipt_sha256": item["validation_sha256"]}

    def select(self, query, transport, *, threshold=0.8):
        query = _text(query, 8192)
        if (type(threshold) not in (int, float) or not math.isfinite(threshold)
                or not 0.8 <= threshold <= 1 or not callable(transport)):
            raise ValueError("typed selector and finite threshold in [.8,1] required")
        catalog = self.catalog()
        if not catalog:
            return []
        candidates = {"candidate_" + str(n): row for n, row in enumerate(catalog)}
        request = {"schema": "xnet.typed-memory-selection.v1", "project_id": self._config["project_id"],
                   "query": query, "candidates": candidates, "authority": "none",
                   "deadline_seconds": 60, "provider_claim": "caller-owned; not Jev attestation"}
        if len(canonical(request)) > 65536:
            raise ValueError("typed selection request exceeds bound")
        started = time.monotonic()
        response = transport(copy.deepcopy(request))  # caller enforces transport deadline
        if time.monotonic() - started > 60:
            raise ValueError("typed selection deadline elapsed")
        if (type(response) is not dict or set(response) != {"answers"}
                or type(response["answers"]) is not dict or set(response["answers"]) != set(candidates)
                or len(canonical(response)) > 8192):
            raise ValueError("typed selection answer IDs differ from exact catalog")
        accepted = []
        for identifier, row in candidates.items():
            answer = response["answers"][identifier]
            if (type(answer) is not dict or set(answer) != {"type", "noul"} or answer["type"] != "noul"
                    or type(answer["noul"]) not in (int, float) or not math.isfinite(answer["noul"])
                    or not 0 <= answer["noul"] <= 1):
                raise ValueError("typed selector requires finite noul probabilities")
            if answer["noul"] >= threshold:
                accepted.append((answer["noul"], row["memory_id"]))
        # Any callback/answer failure aborts all selections. No padding/fallback.
        return [identifier for score, identifier in sorted(accepted, key=lambda row: (-row[0], row[1]))[:5]]

    def queue(self, session_id, task_id, memory_ids, *, turn_id, now=None):
        now = int(time.time()) if now is None else now
        for value in (session_id, task_id, turn_id):
            _label(value)
        if (type(now) is not int or now < 0 or type(memory_ids) not in (list, tuple)
                or len(memory_ids) > 5 or any(type(item) is not str for item in memory_ids)
                or len(set(memory_ids)) != len(memory_ids)):
            raise ValueError("bounded queue selection required")
        with self._lock():
            state = self._state()
            snapshots = {}
            for identifier in memory_ids:
                item = state["cards"].get(_label(identifier))
                if item is None or not item["active"]:
                    raise ValueError("pending selection must still be active")
                snapshots[identifier] = item["stage_sha256"]
            if sum(len(state["cards"][identifier]["card"]["text"].encode("utf-8")) for identifier in memory_ids) > 2048:
                raise ValueError("pending complete cards exceed 2 KiB; clipping forbidden")
            return self._write("pending", {"session_id": session_id, "task_id": task_id,
                    "project_id": self._config["project_id"], "turn_id": turn_id,
                    "created_at": now, "expires_at": now + 120, "snapshots": snapshots,
                    "memory_ids": list(memory_ids)})

    def consume(self, session_id, task_id, *, project_id, fresh_turn_id, now=None):
        now = int(time.time()) if now is None else now
        for value in (session_id, task_id, project_id, fresh_turn_id):
            _label(value)
        if type(now) is not int or now < 0:
            raise ValueError("integer queue clock required")
        with self._lock():
            state = self._state()
            pending = state["pending"].get(session_id)
            if pending is None:
                return []
            if (project_id == pending["project_id"] and task_id == pending["task_id"]
                    and pending["turn_id"] == fresh_turn_id and now < pending["expires_at"]):
                return []  # tool results in the same turn do not consume pending memory
            good = (project_id == self._config["project_id"] == pending["project_id"]
                    and task_id == pending["task_id"] and pending["turn_id"] != fresh_turn_id
                    and pending["created_at"] <= now < pending["expires_at"])
            for identifier, snapshot in pending["snapshots"].items():
                item = state["cards"].get(identifier)
                good = good and item is not None and item["active"] and item["stage_sha256"] == snapshot
                if item is not None:
                    self.ledger.get_evidence(item["card"]["source_sha256"])
            if not good:
                self._write("discard", {"session_id": session_id, "reason": "binding-expiry-source-or-fresh-turn"})
                return []
            ids = [identifier for identifier in pending["memory_ids"]
                   if identifier not in state["consumed"].get(session_id, set())]
            records = [self.load(identifier) for identifier in ids]
            self._write("consume", {"session_id": session_id, "memory_ids": ids})
            return records

    def verify(self):
        self._state()
        return self.ledger.verify_chain()


def public_context_packet(request, records):
    """Bridge selected cards into RepairLoop's existing data-only packet schema."""
    if (type(request) is not dict or type(request.get("task")) is not dict
            or request.get("hidden_cases_used") is not False
            or any(key in request or key in request["task"] for key in
                   ("hidden_cases", "hidden_report", "reference_bundle", "reference"))
            or type(records) is not list or len(records) > 5):
        raise ValueError("only selected public request/card records may cross the bridge")
    fields = {"record_id", "kind", "text", "source_sha256", "text_sha256", "receipt_sha256"}
    size = 0
    ids = set()
    for row in records:
        if type(row) is not dict or set(row) != fields or row["kind"] != "rag-slice":
            raise ValueError("exact memory context record required")
        _label(row["record_id"])
        if row["record_id"] in ids:
            raise ValueError("duplicate memory context record")
        ids.add(row["record_id"])
        for key in ("source_sha256", "text_sha256", "receipt_sha256"):
            _pin(row[key])
        _text(row["text"], 2048)
        raw = row["text"].encode("utf-8")
        size += len(raw)
        if sha256(raw) != row["text_sha256"]:
            raise ValueError("memory context exact text hash mismatch")
    if size > 2048:
        raise ValueError("complete selected memory exceeds 2 KiB")
    return {"schema": "xnet.repair-public-context.v1", "task_id": _label(request["task"]["task_id"]),
            "input_sha256": digest({"task": request["task"], "public_feedback": request["public_feedback"]}),
            "records": copy.deepcopy(records), "authority": "none", "work_performed": False,
            "hidden_cases_used": False, "context_only": True}


class ProceduralContextPreparer:
    """Freeze caller-selected cards per task in RepairLoop's existing seam.

    Selection happens before this object is frozen. It never performs inference
    during preparation. An existing RAG/source preparer may be composed without
    gaining tool authority. Runtime card/source checks refuse retired or changed
    content; no replacement/fallback is selected after freeze.
    """
    def __init__(self, memory, *, task_ids, model_ids, selected_by_task,
                 max_bytes=2048, base_preparer=None, base_policy=None):
        from . import brains, ledger, protocol, relay_log, repair_loop, scaffold_learning, scope
        from .repair_loop import _artifact_sha256, _public_context_callable, _verify_public_context_artifacts
        for values, maximum in ((task_ids, 50), (model_ids, 16)):
            if (type(values) not in (list, tuple) or not 1 <= len(values) <= maximum
                    or any(type(value) is not str or not _ID.fullmatch(value) for value in values)
                    or len(set(values)) != len(values)):
                raise ValueError("unique bounded task/model enums required")
        if (type(selected_by_task) is not dict or set(selected_by_task) != set(task_ids)
                or type(max_bytes) is not int or not 128 <= max_bytes <= 16384
                or (base_preparer is None) != (base_policy is None)):
            raise ValueError("complete frozen per-task selection and explicit byte budget required")
        self._memory, self._config = memory, memory.config
        self._selected = copy.deepcopy(selected_by_task)
        self._base = base_preparer
        self._base_policy = copy.deepcopy(base_policy)
        self._base_identity = None
        self._records = {}
        for task, identifiers in self._selected.items():
            if (type(identifiers) not in (list, tuple) or len(identifiers) > 5
                    or any(type(value) is not str or not _ID.fullmatch(value) for value in identifiers)
                    or len(set(identifiers)) != len(identifiers)):
                raise ValueError("bounded exact selected card IDs required")
            self._records[task] = [memory.load(identifier) for identifier in identifiers]
            if sum(len(record["text"].encode("utf-8")) for record in self._records[task]) > 2048:
                raise ValueError("complete selected cards exceed 2 KiB")
        artifacts = {}
        if base_policy is not None:
            if (base_policy.get("schema") != "xnet.repair-public-context-policy.v1"
                    or set(base_policy.get("tasks", {})) != set(task_ids)
                    or set(base_policy.get("model_ids", [])) != set(model_ids)):
                raise ValueError("base context must cover the same exact task/model enum")
            _verify_public_context_artifacts(base_policy)
            self._base_identity = _public_context_callable(base_preparer, base_policy)
            artifacts = {row["path"]: dict(row) for row in base_policy["preparer_artifacts"]}
        paths = [Path(__file__).absolute()] + [Path(module.__file__).absolute() for module in
                   (brains, ledger, protocol, relay_log, repair_loop, scaffold_learning, scope)]
        for path in paths:
            _no_links(path, regular_file=True)
            row = {"path": str(path), "sha256": _artifact_sha256(path)}
            if str(path) in artifacts and artifacts[str(path)] != row:
                raise ValueError("conflicting context implementation pins")
            artifacts[str(path)] = row
        selections = {}
        for task in task_ids:
            rows = copy.deepcopy(base_policy["tasks"][task]) if base_policy else []
            rows += [{key: value for key, value in record.items() if key != "text"} |
                     {"classification": "public"} for record in self._records[task]]
            if len(rows) > 16 or len({row["record_id"] for row in rows}) != len(rows):
                raise ValueError("expanded or duplicate public context record IDs")
            selections[task] = rows
        self._policy = {"schema": "xnet.repair-public-context-policy.v1",
                        "preparer_id": "procedure-memory-" + digest(self._records)[:24],
                        "preparer_artifacts": list(artifacts.values()), "tasks": selections,
                        "model_ids": list(model_ids), "max_bytes": max_bytes}
        self._freeze = digest([self._policy, self._records, self._selected, self._config])

    @property
    def policy(self):
        return copy.deepcopy(self._policy)

    def prepare(self, request):
        from .repair_loop import _admit_public_context, _public_context_callable, _verify_public_context_artifacts
        if (digest([self._policy, self._records, self._selected, self._config]) != self._freeze
                or self._memory.config != self._config):
            raise ValueError("frozen procedural context changed; use a new run root")
        _verify_public_context_artifacts(self._policy)
        if (type(request) is not dict or type(request.get("task")) is not dict
                or request["task"].get("task_id") not in self._selected
                or request.get("model_id") not in self._policy["model_ids"]):
            raise ValueError("unselected context task/model")
        task = request["task"]["task_id"]
        current = [self._memory.load(identifier) for identifier in self._selected[task]]
        if current != self._records[task]:
            raise ValueError("selected card/source changed after freeze")
        packet = public_context_packet(request, current)
        if self._base is not None:
            if _public_context_callable(self._base, self._base_policy) != self._base_identity:
                raise ValueError("base context callback identity changed")
            original = self._base(copy.deepcopy(request))
            admitted = _admit_public_context(original, request, self._base_policy)
            packet["records"] = copy.deepcopy(admitted["records"]) + packet["records"]
        _admit_public_context(packet, request, self._policy)
        return packet

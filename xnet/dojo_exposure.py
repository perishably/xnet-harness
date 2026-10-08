"""Cumulative finite dojo exposure authority, separate from model lifecycle.

Reserve a deterministic epoch, commit ``expose`` before every borrowed model
callback, and retire holdouts only after the caller seals actual evaluation.
Exposure is conservative even when a callback fails or its response is lost.
An idempotent exposure receipt does NOT authorize inference redispatch. Model
reservation/reconciliation remains the caller's responsibility.

Families and declared near-duplicate groups are excluded cumulatively. This
does not establish semantic novelty, evaluator independence, or physical ACLs.
The SQLite append chain detects local edits; retain its head externally to
detect rollback or wholesale replacement by a writer controlling this root.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import re
import sqlite3

from .dojo_curriculum import (SPLITS, make_selection,
                              verify_dojo_curriculum, verify_selection)
from .learning_dataset import freeze_learning_dataset, verify_learning_dataset
from .protocol import canonical, digest, sha256
from .relay_log import _no_links


SCHEMA = "xnet.dojo-exposure.v1"
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MAX_EVENTS = 10000
_ZERO = "0" * 64


class DojoExposureError(ValueError):
    pass


class CurriculumExhausted(DojoExposureError):
    """No complete fresh validation/unseen allocation remains. Stop inference."""


def _label(value, field):
    if type(value) is not str or not _LABEL.fullmatch(value):
        raise DojoExposureError(field + " must be a bounded exact label")
    return value


def _hash(value, field):
    if type(value) is not str or not _HASH.fullmatch(value):
        raise DojoExposureError(field + " must be an exact SHA256")
    return value


def _counts(practice, validation, unseen):
    result = dict(zip(SPLITS, (practice, validation, unseen)))
    if any(type(value) is not int or not 2 <= value <= 50 for value in result.values()):
        raise DojoExposureError("each requested split requires two to fifty tasks")
    return result


class DojoExposure:
    """One source-bound cumulative ledger for this finite public curriculum.

    ``plan_epoch`` returns public ``selection`` and ``dataset``. Explicit
    ``dojo_curriculum.private_selection(plan['selection'])`` supplies the local
    full tasks/references expected by LearningEpoch. Its public ``train`` split
    is called ``practice`` here. Holdout reservations never recycle implicitly.
    """

    def __init__(self, root, curriculum, *, curriculum_sha256):
        self.root = Path(root).absolute()
        _no_links(self.root)
        self.curriculum = verify_dojo_curriculum(curriculum, expected_sha256=curriculum_sha256)
        self._curriculum_pin = curriculum_sha256
        self.rows = {row["task_id"]: row for row in self.curriculum["rows"]}
        self.root.mkdir(parents=True, exist_ok=True)
        _no_links(self.root)
        self.path = self.root / "exposure.sqlite3"
        self.config_path = self.root / "config.json"
        sources = Path(__file__).parent
        self.config = {"schema": SCHEMA, "root": str(self.root), "curriculum_sha256": curriculum_sha256,
            "source_pins": {name: sha256((sources / name).read_bytes()) for name in
                ("dojo_exposure.py", "dojo_curriculum.py", "learning_dataset.py", "protocol.py", "relay_log.py")},
            "max_events": _MAX_EVENTS, "semantic_novelty_proven": False,
            "exposure_policy": "persist before callback; uncertain callbacks remain exposed",
            "holdout_policy": "reserved/exposed content, family and declared near-duplicate groups never recycle as holdouts"}
        self._config_pin = digest(self.config)
        data = canonical(self.config)
        try:
            descriptor = os.open(self.config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            _no_links(self.config_path, regular_file=True)
            if self.config_path.read_bytes() != data:
                raise DojoExposureError("exposure root/source/curriculum binding changed")
        else:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        with self._transaction() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, body TEXT NOT NULL, previous_sha256 TEXT NOT NULL, receipt_sha256 TEXT NOT NULL UNIQUE)")
            self._state(connection)

    def _identity(self):
        _no_links(self.root)
        _no_links(self.config_path, regular_file=True)
        if self.config_path.read_bytes() != canonical(self.config) or digest(self.config) != self._config_pin:
            raise DojoExposureError("exposure configuration changed")
        verify_dojo_curriculum(self.curriculum, expected_sha256=self._curriculum_pin)
        sources = Path(__file__).parent
        for name, pin in self.config["source_pins"].items():
            if sha256((sources / name).read_bytes()) != pin:
                raise DojoExposureError("exposure implementation changed; preserve the prior root")
        for path in (self.path, Path(str(self.path) + "-journal"), Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
            if path.exists():
                _no_links(path, regular_file=True)

    @contextmanager
    def _transaction(self):
        self._identity()
        connection = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _append(self, connection, state, kind, body):
        if state["event_count"] >= _MAX_EVENTS:
            raise DojoExposureError("finite exposure event budget exhausted")
        value = {"schema": SCHEMA, "seq": state["event_count"] + 1, "kind": kind,
                 "body": copy.deepcopy(body), "previous_sha256": state["head_sha256"],
                 "config_sha256": self._config_pin}
        receipt = digest(value)
        connection.execute("INSERT INTO events VALUES (?,?,?,?,?)", (value["seq"], kind,
            canonical(body).decode("utf-8"), state["head_sha256"], receipt))
        return {**value, "receipt_sha256": receipt}

    def _dataset(self, selection, state):
        splits = {("train" if split == "practice" else split):
                  [copy.deepcopy(self.rows[task_id]["public_task"]) for task_id in selection["splits"][split]]
                  for split in SPLITS}
        selected = [task_id for values in selection["splits"].values() for task_id in values]
        provenance = {task_id: {"kind": "synthetic-authored", "source_manifest_sha256": self._curriculum_pin}
                      for task_id in selected}
        clusters = {task_id: self.rows[task_id]["near_duplicate_id"] for task_id in selected}
        return freeze_learning_dataset(splits, provenance, clusters=clusters,
            cluster_provenance={"method_id": "dojo-authored-conservative-groups-v1",
                "source_sha256": self._curriculum_pin, "assignment_sha256": digest(clusters)},
            denied_content_sha256=sorted(state["excluded_content"]),
            denied_cluster_ids=sorted(state["excluded_clusters"]),
            caller_source_sha256=self.config["source_pins"]["dojo_exposure.py"])

    def _exclude(self, state, task_ids):
        for task_id in task_ids:
            row = self.rows[task_id]
            state["excluded_content"].update((row["content_sha256"], row["normalized_content_sha256"]))
            state["excluded_families"].add(row["family_id"])
            state["excluded_clusters"].add(row["near_duplicate_id"])

    def _state(self, connection):
        state = {"event_count": 0, "head_sha256": _ZERO, "plans": {}, "exposures": {},
                 "retired": {}, "excluded_content": set(), "excluded_families": set(),
                 "excluded_clusters": set(), "exhaustion": None}
        raw_rows = connection.execute("SELECT seq,kind,body,previous_sha256,receipt_sha256 FROM events ORDER BY seq").fetchall()
        if len(raw_rows) > _MAX_EVENTS:
            raise DojoExposureError("exposure event bound exceeded")
        for seq, kind, raw, previous, receipt in raw_rows:
            if seq != state["event_count"] + 1 or previous != state["head_sha256"] or len(raw) > 1000000:
                raise DojoExposureError("exposure chain sequence, predecessor or size mismatch")
            body = json.loads(raw)
            value = {"schema": SCHEMA, "seq": seq, "kind": kind, "body": body,
                     "previous_sha256": previous, "config_sha256": self._config_pin}
            if canonical(body).decode("utf-8") != raw or digest(value) != receipt:
                raise DojoExposureError("exposure event byte/hash mismatch")
            if kind == "epoch-planned":
                if set(body) != {"epoch_id", "counts", "selection", "selection_sha256", "dataset", "dataset_sha256"}:
                    raise DojoExposureError("invalid epoch plan fields")
                epoch_id = _label(body["epoch_id"], "epoch_id")
                if epoch_id in state["plans"] or state["exhaustion"] is not None:
                    raise DojoExposureError("duplicate or post-exhaustion epoch")
                selection = verify_selection(body["selection"], curriculum=self.curriculum)
                if (body["selection_sha256"] != selection["selection_sha256"] or
                    body["counts"] != {split: len(selection["splits"][split]) for split in SPLITS}):
                    raise DojoExposureError("epoch selection/count mismatch")
                if canonical(selection) != canonical(self._selection(state, body["counts"])):
                    raise DojoExposureError("epoch differs from deterministic cumulative selection")
                for split in ("validation", "unseen"):
                    for task_id in selection["splits"][split]:
                        row = self.rows[task_id]
                        if (row["family_id"] in state["excluded_families"] or row["near_duplicate_id"] in state["excluded_clusters"] or
                            row["content_sha256"] in state["excluded_content"] or row["normalized_content_sha256"] in state["excluded_content"]):
                            raise DojoExposureError("prior reserved/exposed identity reused as holdout")
                dataset = verify_learning_dataset(body["dataset"], expected_sha256=body["dataset_sha256"])
                if canonical(dataset) != canonical(self._dataset(selection, state)):
                    raise DojoExposureError("epoch dataset differs from cumulative exclusions")
                state["plans"][epoch_id] = {**body, "plan_receipt_sha256": receipt}
                # Reserving excludes future holdouts even if the process stops
                # before inference; uncertainty must not manufacture freshness.
                self._exclude(state, [tid for values in selection["splits"].values() for tid in values])
            elif kind == "task-exposed":
                if set(body) != {"epoch_id", "task_id", "reservation_id", "request_sha256", "request_task_sha256", "attempt", "purpose", "selection_sha256", "original_content_sha256", "family_id", "near_duplicate_id", "before_callback", "redispatch_authorized"}:
                    raise DojoExposureError("invalid exposure fields")
                self._check_exposure(body, state)
                reservation = body["reservation_id"]
                if reservation in state["exposures"]:
                    raise DojoExposureError("duplicate exposure reservation")
                state["exposures"][reservation] = {**body, "receipt_sha256": receipt}
            elif kind == "holdouts-retired":
                if set(body) != {"epoch_id", "selection_sha256", "task_ids", "evaluation_sha256", "practice_only", "evaluation_authenticity_proven"}:
                    raise DojoExposureError("invalid retirement fields")
                self._check_retirement(body, state)
                state["retired"][body["epoch_id"]] = {**body, "receipt_sha256": receipt}
            elif kind == "curriculum-exhausted":
                if set(body) != {"epoch_id", "counts", "reason", "stop_inference"} or state["exhaustion"] is not None:
                    raise DojoExposureError("invalid exhaustion event")
                _label(body["epoch_id"], "epoch_id")
                if (body["reason"] != "insufficient complete fresh split" or body["stop_inference"] is not True or
                    body["counts"] != _counts(**{name: body["counts"].get(name) for name in SPLITS})):
                    raise DojoExposureError("invalid exhaustion policy")
                try:
                    self._selection(state, body["counts"])
                except CurriculumExhausted:
                    pass
                else:
                    raise DojoExposureError("exhaustion event still has a complete fresh selection")
                state["exhaustion"] = {**body, "receipt_sha256": receipt}
            else:
                raise DojoExposureError("unknown exposure event kind")
            state["event_count"], state["head_sha256"] = seq, receipt
        return state

    def _check_exposure(self, body, state):
        epoch_id = _label(body["epoch_id"], "epoch_id")
        _label(body["reservation_id"], "reservation_id")
        _hash(body["request_sha256"], "request_sha256")
        if body["request_task_sha256"] is not None:
            _hash(body["request_task_sha256"], "request_task_sha256")
        if body["attempt"] is not None and (type(body["attempt"]) is not int or body["attempt"] not in (1, 2)):
            raise DojoExposureError("exposure attempt must be one/two or unknown")
        plan = state["plans"].get(epoch_id)
        if (plan is None or body["purpose"] not in SPLITS or
            body["task_id"] not in plan["selection"]["splits"][body["purpose"]]):
            raise DojoExposureError("exposure task/purpose is absent from the exact epoch selection")
        if epoch_id in state["retired"]:
            raise DojoExposureError("retired holdout epoch cannot dispatch more model work")
        row = self.rows[body["task_id"]]
        if (body["selection_sha256"] != plan["selection_sha256"] or body["original_content_sha256"] != row["content_sha256"] or
            body["family_id"] != row["family_id"] or body["near_duplicate_id"] != row["near_duplicate_id"] or
            body["before_callback"] is not True or body["redispatch_authorized"] is not False):
            raise DojoExposureError("exposure identity/policy differs")

    def _check_retirement(self, body, state):
        epoch_id = _label(body["epoch_id"], "epoch_id")
        _hash(body["evaluation_sha256"], "evaluation_sha256")
        plan = state["plans"].get(epoch_id)
        if plan is None or epoch_id in state["retired"]:
            raise DojoExposureError("unknown or already retired epoch")
        holdouts = sorted(plan["selection"]["splits"]["validation"] + plan["selection"]["splits"]["unseen"])
        exposed = {row["task_id"] for row in state["exposures"].values() if row["epoch_id"] == epoch_id}
        if (body["task_ids"] != holdouts or not set(holdouts) <= exposed or
            body["selection_sha256"] != plan["selection_sha256"] or body["practice_only"] is not True or
            body["evaluation_authenticity_proven"] is not False):
            raise DojoExposureError("retirement requires all exact holdouts exposed and a declared evaluation pin")

    def _pick(self, candidates, count, used_families, used_clusters):
        selected = []
        picked_families, picked_clusters = set(), set()
        for row in candidates:
            if row["family_id"] in used_families or row["near_duplicate_id"] in used_clusters:
                continue
            selected.append(row["task_id"])
            picked_families.add(row["family_id"])
            picked_clusters.add(row["near_duplicate_id"])
            if len(selected) == count:
                used_families.update(picked_families)
                used_clusters.update(picked_clusters)
                return selected
        raise CurriculumExhausted("insufficient complete fresh split")

    def _selection(self, state, counts):
        if type(counts) is not dict or set(counts) != set(SPLITS):
            raise DojoExposureError("exact split counts required")
        _counts(counts["practice"], counts["validation"], counts["unseen"])
        fresh = [row for row in self.curriculum["rows"] if
            row["family_id"] not in state["excluded_families"] and row["near_duplicate_id"] not in state["excluded_clusters"] and
            row["content_sha256"] not in state["excluded_content"] and row["normalized_content_sha256"] not in state["excluded_content"]]
        retired_ids = {tid for event in state["retired"].values() for tid in event["task_ids"]}
        practiced_ids = {event["task_id"] for event in state["exposures"].values() if event["purpose"] == "practice"}
        # Retired holdouts lead practice selection. Unexposed or unevaluated
        # old holdouts are never eligible as practice.
        practice = [row for row in self.curriculum["rows"] if row["task_id"] in retired_ids]
        practice += [row for row in self.curriculum["rows"] if row["task_id"] in practiced_ids and row["task_id"] not in retired_ids]
        practice += fresh
        used_families, used_clusters = set(), set()
        splits = {"practice": self._pick(practice, counts["practice"], used_families, used_clusters)}
        for split in ("validation", "unseen"):
            splits[split] = self._pick(fresh, counts[split], used_families, used_clusters)
        return make_selection(self.curriculum, splits)

    def plan_epoch(self, epoch_id, *, practice_count=2, validation_count=2, unseen_count=2):
        """Reserve all splits atomically; never reuse IDs to claim new novelty."""
        _label(epoch_id, "epoch_id")
        counts = _counts(practice_count, validation_count, unseen_count)
        exhausted = False
        with self._transaction() as connection:
            state = self._state(connection)
            existing = state["plans"].get(epoch_id)
            if existing is not None:
                if existing["counts"] != counts:
                    raise DojoExposureError("existing epoch counts differ; preserve its selection")
                return copy.deepcopy(existing)
            if state["exhaustion"] is not None:
                raise CurriculumExhausted("finite curriculum exhausted; stop inference")
            try:
                selection = self._selection(state, counts)
                dataset = self._dataset(selection, state)
                body = {"epoch_id": epoch_id, "counts": counts, "selection": selection,
                        "selection_sha256": selection["selection_sha256"], "dataset": dataset,
                        "dataset_sha256": dataset["manifest_sha256"]}
                receipt = self._append(connection, state, "epoch-planned", body)
                return copy.deepcopy({**body, "plan_receipt_sha256": receipt["receipt_sha256"]})
            except CurriculumExhausted:
                self._append(connection, state, "curriculum-exhausted", {"epoch_id": epoch_id, "counts": counts,
                    "reason": "insufficient complete fresh split", "stop_inference": True})
                exhausted = True
        if exhausted:
            raise CurriculumExhausted("finite curriculum exhausted; stop inference")

    def expose(self, epoch_id, task_id, *, reservation_id, request_sha256, purpose,
               request_task_sha256=None, attempt=None):
        """Durably mark BEFORE callback. Equal receipts never permit redispatch."""
        _label(epoch_id, "epoch_id")
        _label(task_id, "task_id")
        _label(reservation_id, "reservation_id")
        _hash(request_sha256, "request_sha256")
        with self._transaction() as connection:
            state = self._state(connection)
            plan, row = state["plans"].get(epoch_id), self.rows.get(task_id)
            if plan is None or row is None:
                raise DojoExposureError("unknown epoch or renamed curriculum task")
            body = {"epoch_id": epoch_id, "task_id": task_id, "reservation_id": reservation_id,
                    "request_sha256": request_sha256, "request_task_sha256": request_task_sha256, "attempt": attempt,
                    "purpose": purpose, "selection_sha256": plan["selection_sha256"],
                    "original_content_sha256": row["content_sha256"], "family_id": row["family_id"],
                    "near_duplicate_id": row["near_duplicate_id"], "before_callback": True,
                    "redispatch_authorized": False}
            existing = state["exposures"].get(reservation_id)
            if existing is not None:
                if canonical(body) != canonical({key: value for key, value in existing.items() if key != "receipt_sha256"}):
                    raise DojoExposureError("exposure reservation binding changed")
                return copy.deepcopy(existing)
            self._check_exposure(body, state)
            receipt = self._append(connection, state, "task-exposed", body)
            return copy.deepcopy({**body, "receipt_sha256": receipt["receipt_sha256"]})

    def expose_request(self, epoch_id, request, *, reservation_id, purpose):
        """Check public metadata and bounded retry files, then mark the full request.

        Attempt1 carries original files. Attempt2 may carry the prior candidate
        bundle; RepairLoop owns its provenance/admission. This method does not
        authenticate arbitrary added request/context fields or grade source.
        Receipt novelty always refers to original content, while the separate
        request_task_sha256 describes the exact current candidate task bytes.
        """
        if type(request) is not dict or type(request.get("task")) is not dict:
            raise DojoExposureError("generation request requires its exact public task")
        task = request["task"]
        if type(task.get("task_id")) is not str:
            raise DojoExposureError("generation task requires its stable exact ID")
        row = self.rows.get(task.get("task_id"))
        if row is None or set(task) != set(row["public_task"]):
            raise DojoExposureError("request task fields/ID differ from frozen curriculum")
        original = row["public_task"]
        if canonical({key: value for key, value in task.items() if key != "files"}) != canonical({
                key: value for key, value in original.items() if key != "files"}):
            raise DojoExposureError("request task metadata differs from frozen curriculum")
        attempt = request.get("attempt", 1)
        if type(attempt) is not int or attempt not in (1, 2):
            raise DojoExposureError("generation attempt must be exact one or two")
        files = task["files"]
        if (type(files) is not dict or set(files) != set(original["files"]) or
            any(type(source) is not str or not source or "\x00" in source for source in files.values())):
            raise DojoExposureError("retry requires the original file set and bounded inert source strings")
        try:
            if any(len(source.encode("utf-8", "strict")) > 8192 for source in files.values()):
                raise DojoExposureError("retry source exceeds the original replacement bound")
        except UnicodeError as error:
            raise DojoExposureError("retry source must preserve valid exact UTF-8") from error
        if "hidden_cases_used" in request and request["hidden_cases_used"] is not False:
            raise DojoExposureError("generation request cannot declare hidden cases used")
        if attempt == 1 and canonical(files) != canonical(original["files"]):
            raise DojoExposureError("first attempt must carry original source")
        if (attempt == 2 or "base_files" in request) and canonical(request.get("base_files")) != canonical(files):
            raise DojoExposureError("retry base_files must equal current public task files")
        return self.expose(epoch_id, task["task_id"], reservation_id=reservation_id,
                           request_sha256=digest(request), purpose=purpose,
                           request_task_sha256=digest(task), attempt=attempt)

    def retire_holdouts(self, epoch_id, *, evaluation_sha256):
        """Declare actual evaluation report pin; all exposed holdouts become practice-only.

        The caller retains/authenticates that report. A SHA alone is not proof
        that independent grading occurred, and no hidden grades are copied here.
        """
        _label(epoch_id, "epoch_id")
        _hash(evaluation_sha256, "evaluation_sha256")
        with self._transaction() as connection:
            state = self._state(connection)
            prior = state["retired"].get(epoch_id)
            if prior is not None:
                if prior["evaluation_sha256"] != evaluation_sha256:
                    raise DojoExposureError("retained evaluation pin changed")
                return copy.deepcopy(prior)
            plan = state["plans"].get(epoch_id)
            if plan is None:
                raise DojoExposureError("unknown epoch")
            body = {"epoch_id": epoch_id, "selection_sha256": plan["selection_sha256"],
                    "task_ids": sorted(plan["selection"]["splits"]["validation"] + plan["selection"]["splits"]["unseen"]),
                    "evaluation_sha256": evaluation_sha256, "practice_only": True,
                    "evaluation_authenticity_proven": False}
            self._check_retirement(body, state)
            receipt = self._append(connection, state, "holdouts-retired", body)
            return copy.deepcopy({**body, "receipt_sha256": receipt["receipt_sha256"]})

    def status(self, *, expected_head_sha256=None):
        """Verify replay without calling a model; optional external head detects rollback."""
        if expected_head_sha256 is not None:
            _hash(expected_head_sha256, "expected_head_sha256")
        with self._transaction() as connection:
            state = self._state(connection)
            if expected_head_sha256 is not None and state["head_sha256"] != expected_head_sha256:
                raise DojoExposureError("exposure head differs from externally retained pin")
            return {"schema": SCHEMA, "curriculum_sha256": self._curriculum_pin,
                "config_sha256": self._config_pin, "head_sha256": state["head_sha256"],
                "event_count": state["event_count"], "epoch_count": len(state["plans"]),
                "exposure_count": len(state["exposures"]), "retired_epoch_count": len(state["retired"]),
                "excluded_content_sha256": sorted(state["excluded_content"]),
                "excluded_family_ids": sorted(state["excluded_families"]),
                "excluded_near_duplicate_ids": sorted(state["excluded_clusters"]),
                "exhausted": state["exhaustion"] is not None, "exhaustion": copy.deepcopy(state["exhaustion"]),
                "finite": True, "semantic_novelty_proven": False, "callbacks_invoked": 0}

    verify = status

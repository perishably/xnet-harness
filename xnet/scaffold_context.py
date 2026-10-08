"""Freeze scored scaffold memory into RepairLoop's existing public context seam.

The caller owns training observations, inference, prompt measurement and grading.
This adapter only passes bounded, enumerated guidance as source data. It never
creates tools, changes an evaluator or trains model weights. An optional existing
public context preparer is composed rather than replaced.
"""
from __future__ import annotations

import copy
import json
import math
from pathlib import Path
import re

from . import brains, ledger, protocol, relay_log, repair_loop, scaffold_learning
from .protocol import canonical, digest, sha256
from .repair_loop import (_admit_public_context, _artifact_sha256,
                          _public_context_callable, _public_context_input,
                          _read, _verify_public_context_artifacts)
from .swe_repair_evaluator import public_feedback


_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = {"record_id", "kind", "text", "source_sha256", "text_sha256", "receipt_sha256"}


def _ids(values, maximum):
    if (type(values) not in (list, tuple) or not 1 <= len(values) <= maximum
            or any(type(value) is not str or not _ID.fullmatch(value) for value in values)
            or len(set(values)) != len(values)):
        raise ValueError("unique bounded explicit task/model IDs required")
    return list(values)


def _record(value):
    if type(value) is not dict or not _FIELDS.issubset(value):
        raise ValueError("a sealed scaffold context record is required")
    result = {key: copy.deepcopy(value[key]) for key in _FIELDS}
    # Reuse the existing kind. The text explicitly identifies scaffold memory;
    # no tool authority or executable instruction surface is introduced.
    result["kind"] = "rag-slice"
    if (type(result["record_id"]) is not str or not _ID.fullmatch(result["record_id"])
            or type(result["text"]) is not str
            or any(type(result[key]) is not str or not _HEX.fullmatch(result[key])
                   for key in ("source_sha256", "text_sha256", "receipt_sha256"))):
        raise ValueError("invalid scaffold context record fields")
    raw = result["text"].encode("utf-8", "strict")
    if not raw or len(raw) > 2048 or sha256(raw) != result["text_sha256"]:
        raise ValueError("scaffold context must be exact bounded text")
    return result


class ScaffoldContextPreparer:
    """A frozen, source-pinned optional context provider for XNET/Jcode callers.

    ``practice`` exposes a declared candidate to the complete training split.
    ``trial`` exposes the training-selected candidate or baseline to validation.
    ``active`` exposes a validated incumbent only to new IDs.
    Dataset/task novelty remains a caller responsibility: ID isolation alone
    cannot prove two differently named problems have different content.
    """

    def __init__(self, learner, *, task_ids, model_ids, mode="active", scaffold_id=None,
                 max_bytes=2048, base_preparer=None, base_policy=None):
        if mode not in ("practice", "trial", "active"):
            raise ValueError("unknown scaffold context mode")
        if type(max_bytes) is not int or not 128 <= max_bytes <= 16384:
            raise ValueError("public context budget must be explicit and bounded")
        tasks = _ids(task_ids, 50)
        models = _ids(model_ids, 16)
        config = learner.config
        train = set(config["train_task_ids"])
        validation = set(config["validation_task_ids"])
        if mode == "practice" and set(tasks) != train:
            raise ValueError("practice context requires the complete declared training split")
        if mode == "trial" and set(tasks) != validation:
            raise ValueError("trial context requires the complete declared validation split")
        if mode == "active" and set(tasks) & (train | validation):
            raise ValueError("active context must be evaluated on new task IDs")
        if (base_preparer is None) != (base_policy is None):
            raise ValueError("base context requires both preparer and frozen policy")
        self._learner = learner
        self._mode = mode
        self._scaffold_id = scaffold_id
        self._record = _record(learner.context_record(mode=mode, scaffold_id=scaffold_id))
        self._record_pin = digest(self._record)
        self._base = base_preparer
        self._base_policy = copy.deepcopy(base_policy)
        self._base_identity = None
        artifacts = {}
        if base_policy is not None:
            if (type(base_policy) is not dict or base_policy.get("schema") != "xnet.repair-public-context-policy.v1"
                    or set(base_policy.get("tasks", {})) != set(tasks)
                    or set(base_policy.get("model_ids", [])) != set(models)):
                raise ValueError("base context must cover the same exact task/model selection")
            _verify_public_context_artifacts(self._base_policy)
            self._base_identity = _public_context_callable(base_preparer, self._base_policy)
            for row in base_policy["preparer_artifacts"]:
                artifacts[row["path"]] = dict(row)
        modules = (scaffold_learning, ledger, protocol, relay_log, brains, repair_loop)
        paths = [Path(__file__).absolute(), *(Path(module.__file__).absolute() for module in modules)]
        for path in paths:
            relay_log._no_links(path, regular_file=True)
            row = {"path": str(path), "sha256": _artifact_sha256(path)}
            if str(path) in artifacts and artifacts[str(path)] != row:
                raise ValueError("conflicting base/scaffold source pins")
            artifacts[str(path)] = row
        selections = {}
        for task in tasks:
            rows = copy.deepcopy(base_policy["tasks"][task]) if base_policy is not None else []
            if len(rows) >= 16 or any(row["record_id"] == self._record["record_id"] for row in rows):
                raise ValueError("expanded or duplicate scaffold context selection")
            rows.append({key: value for key, value in self._record.items() if key != "text"}
                        | {"classification": "public"})
            selections[task] = rows
        self._policy = {
            "schema": "xnet.repair-public-context-policy.v1",
            "preparer_id": "scaffold-memory-" + self._record_pin[:24],
            "preparer_artifacts": list(artifacts.values()),
            "tasks": selections, "model_ids": models, "max_bytes": max_bytes,
        }
        self._policy_pin = digest(self._policy)

    @property
    def policy(self):
        return copy.deepcopy(self._policy)

    def prepare(self, request):
        if digest(self._policy) != self._policy_pin or digest(self._record) != self._record_pin:
            raise ValueError("frozen scaffold context changed; use a new run root")
        _verify_public_context_artifacts(self._policy)
        lifecycle = self._learner.snapshot()
        if self._mode == "practice" and lifecycle["training"] is not None:
            raise ValueError("training is frozen; no further practice dispatch")
        if self._mode == "trial" and lifecycle["promotion"] is not None:
            raise ValueError("validation is frozen; no further trial dispatch")
        if _record(self._learner.context_record(mode=self._mode, scaffold_id=self._scaffold_id)) != self._record:
            raise ValueError("scaffold memory changed after context freeze")
        if (type(request) is not dict or type(request.get("task")) is not dict
                or request["task"].get("task_id") not in self._policy["tasks"]
                or request.get("model_id") not in self._policy["model_ids"]
                or request.get("hidden_cases_used") is not False
                or any(key in request or key in request["task"]
                       for key in ("hidden_cases", "hidden_report", "reference", "reference_bundle"))):
            raise ValueError("scaffold preparer requires the selected public-only request")
        records = []
        if self._base is not None:
            if _public_context_callable(self._base, self._base_policy) != self._base_identity:
                raise ValueError("base context callback identity changed")
            original = self._base(copy.deepcopy(request))
            admitted = _admit_public_context(original, request, self._base_policy)
            records.extend(copy.deepcopy(admitted["records"]))
        records.append(copy.deepcopy(self._record))
        packet = {
            "schema": "xnet.repair-public-context.v1", "task_id": request["task"]["task_id"],
            "input_sha256": _public_context_input(request), "records": records,
            "authority": "none", "work_performed": False, "hidden_cases_used": False,
            "context_only": True,
        }
        # Check the composed complete packet. Nothing is silently truncated.
        _admit_public_context(packet, request, self._policy)
        return packet


def public_verifier_identity(loop, model_id):
    """Bind public outcomes to evaluator sources, budgets and the chosen runtime.

    Model/runtime pins remain caller declarations, not remote attestation.
    Different task splits can share this identity; changed evaluator/runtime
    settings cannot silently share a learning epoch.
    """
    loop._verify_source_identity()
    if model_id not in loop.models:
        raise ValueError("unknown repair model")
    config = loop.manifest["config"]
    runtime = None
    if loop.run_identity is not None:
        runtime = {"adapter": loop.run_identity["adapter"], "runner": loop.run_identity["runner"],
                   "model": loop.run_identity["models"][model_id]}
    return digest({"sources": config["sources"], "eval_timeout": config["eval_timeout"],
                   "max_attempts": config["max_attempts"], "max_output_tokens": 650,
                   "model": loop.models[model_id], "runtime": runtime})


def ingest_repair_outcome(learner, loop, model_id, task_id, scaffold_id, *, boundary_evidence_sha256):
    """Project sealed public RepairLoop results into a learning observation.

    Reads no hidden grade or reference bundle. A full-score benchmark result is
    deliberately not imported. Only aggregate public outcomes and parent hashes
    enter memory. The caller supplies a sealed host boundary observation with
    schema/manifest/model/task/attempt_receipts/violation fields. Its byte hash
    does not authenticate the monitor; caller ownership is the trust boundary.
    """
    if model_id not in loop.models or task_id not in loop.tasks:
        raise ValueError("unknown repair task/model")
    verifier = public_verifier_identity(loop, model_id)
    if verifier != learner.config["verifier_sha256"]:
        raise ValueError("public verifier/runtime changed; use a new learning epoch")
    mode = "practice" if task_id in learner.config["train_task_ids"] else "trial"
    exposure = _record(learner.context_record(mode=mode, scaffold_id=scaffold_id))
    with loop._lock():
        rows = loop._rows(model_id, task_id)
        if not rows or (len(rows) < 2 and not rows[-1]["public_evaluation"]["resolved"]):
            raise ValueError("repair task has not completed its public attempt budget")
        details = []
        output_tokens = 0
        wall_ms = 0
        for attempt in (1, 2):
            directory = loop._case(model_id, task_id, attempt)
            if (directory / "reservation.json").exists() and not (directory / "result.json").exists():
                raise ValueError("unresolved repair reservation cannot become a learning observation")
        for row in rows:
            directory = loop._case(model_id, task_id, row["attempt"])
            output = _read(directory / "output.json")
            reservation = _read(directory / "reservation.json")
            if (output != row["output_record"] or reservation != row["request"]
                    or output["nonce"] != reservation["nonce"] or row["hidden_cases_used"] is not False):
                raise ValueError("public repair output/request linkage changed")
            if (loop.public_context_policy is None or "public_context" not in reservation
                    or reservation["public_context"].get("policy_sha256") != digest(loop.public_context_policy)):
                raise ValueError("repair result has no pinned scaffold exposure")
            context = reservation["public_context"]
            admitted = _admit_public_context({key: value for key, value in context.items()
                                             if key not in ("policy_sha256", "context_sha256")},
                                            reservation, loop.public_context_policy)
            if context != admitted or context["records"].count(exposure) != 1:
                raise ValueError("scaffold label differs from exact guidance exposed in the prompt")
            public_feedback(row["public_evaluation"])  # rejects hidden reports
            tokens = output["output"]["usage"].get("output_tokens")
            seconds = output.get("generation_request_seconds")
            if (type(tokens) is not int or not 0 <= tokens <= 650
                    or type(seconds) not in (int, float) or not math.isfinite(seconds)
                    or not 0 <= seconds <= 86_400):
                raise ValueError("actual bounded output/timing evidence required; missing is not zero")
            output_tokens += tokens
            wall_ms += round(seconds * 1000)
            details.append({"attempt": row["attempt"], "result_sha256": row["receipt_sha256"],
                            "output_sha256": output["receipt_sha256"],
                            "request_sha256": reservation["receipt_sha256"]})
        boundary = json.loads(learner.ledger.get_evidence(boundary_evidence_sha256))
        if (type(boundary) is not dict or set(boundary) != {"schema", "repair_manifest_sha256", "model_id", "task_id", "attempt_receipts", "violation"}
                or boundary["schema"] != "xnet.scaffold-boundary-observation.v1"
                or boundary["repair_manifest_sha256"] != loop.manifest["receipt_sha256"]
                or boundary["model_id"] != model_id or boundary["task_id"] != task_id
                or boundary["attempt_receipts"] != [row["receipt_sha256"] for row in rows]
                or type(boundary["violation"]) is not bool):
            raise ValueError("exact sealed host boundary observation required")
        valid = [row for row in rows if row["candidate_valid"]]
        selected = max(valid, key=lambda row: (row["public_evaluation"]["passed"], row["attempt"])) if valid else rows[-1]
        feedback = public_feedback(selected["public_evaluation"])
        report = {
            "schema": "xnet.scaffold-public-observation.v1", "task_id": task_id,
            "scaffold_id": scaffold_id, "verifier_sha256": verifier,
            "passed": feedback["resolved"], "no_op": selected["no_op"],
            "boundary_violation": boundary["violation"], "attempts": len(rows),
            "output_tokens": output_tokens, "wall_ms": wall_ms,
        }
        proof = {"schema": "xnet.scaffold-repair-projection.v1", "visibility": "public",
                 "repair_manifest_sha256": loop.manifest["receipt_sha256"], "model_id": model_id,
                 "model_artifacts": loop.models[model_id], "attempts": details,
                 "selected_result_sha256": selected["receipt_sha256"],
                 "public_evaluation_sha256": digest(selected["public_evaluation"]),
                 "scaffold_exposure_sha256": digest(exposure),
                 "boundary_evidence_sha256": boundary_evidence_sha256,
                 "report": report, "hidden_grade_read": False, "candidate_source_copied": False}
        loop._verify_source_identity()
    parent = learner.ledger.put_evidence(canonical(proof), source="repair-public-metrics",
                                        scope_id=learner.config["epoch_id"],
                                        metadata={"visibility": "public", "authority": "none"})
    return learner.observe(task_id, scaffold_id, report, evidence_sha256=parent)

"""Public outcome feedback and fixed guidance for caller-owned learning epochs.

This peer borrows existing learner, ledger and memory lifecycles. It creates
neither a model transport nor a training/execution authority. Proposal text is
preserved as evidence before strict admission; only registered enums can become
guidance. Hashes establish provenance, not general capability or true reasoning.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re

from .generation_usage import normalize_generation_usage
from .procedural_memory import ProceduralMemory
from .protocol import ZERO_HASH, _portable_json, canonical, digest, make_event, sha256
from .scaffold_learning import BASELINE, PUBLIC_SCHEMA, STEP_TEXT, ScaffoldLearner

FEED_SCHEMA = "xnet.learning-failure-feed.v1"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_REPORT = {"schema", "task_id", "scaffold_id", "verifier_sha256", "passed", "no_op",
           "boundary_violation", "attempts", "output_tokens", "wall_ms"}
_PROJECTION = {"schema", "visibility", "repair_manifest_sha256", "model_id", "model_artifacts",
               "attempts", "selected_result_sha256", "public_evaluation_sha256",
               "scaffold_exposure_sha256", "boundary_evidence_sha256", "report",
               "hidden_grade_read", "candidate_source_copied"}


def _pin(value):
    if type(value) is not str or not _HASH.fullmatch(value):
        raise ValueError("exact SHA-256 evidence pointer required")
    return value


def _label(value):
    if type(value) is not str or not _ID.fullmatch(value):
        raise ValueError("bounded explicit label required")
    return value


def _learner(value):
    if not isinstance(value, ScaffoldLearner):
        raise ValueError("borrowed ScaffoldLearner required")
    return value


def _pins():
    root = Path(__file__).parent
    return {name: sha256((root / name).read_bytes()) for name in
            ("learning_wing.py", "scaffold_learning.py", "generation_usage.py", "protocol.py")}


def _seal(learner, kind, body):
    """One idempotent event per exact wing record, with its original receipt."""
    _learner(learner)
    if not _portable_json(body) or len(canonical(body)) > 65536:
        raise ValueError("bounded portable wing evidence required")
    config = learner.config
    task = "learning-wing-" + digest(config)[:32]
    wrapper = {"schema": "xnet.learning-wing-record.v1", "epoch_config_sha256": digest(config),
               "source_pins": _pins(), "kind": kind, "body": copy.deepcopy(body)}
    with learner._locked():
        learner._state()  # validate without recursively acquiring its lease
        previous = ZERO_HASH
        for seq, event in enumerate(learner.ledger.events(), 1):
            previous = digest({"seq": seq, "prev_hash": previous, "event_hash": digest(event)})
            if event["task_id"] != task:
                continue
            if event["source"] != "learning-wing" or event["scope_id"] != config["epoch_id"]:
                raise ValueError("wing event binding changed")
            payload = event["payload"]
            if (type(payload) is not dict or set(payload) != {
                    "record_sha256", "epoch_config_sha256", "record_type"} or
                    payload["epoch_config_sha256"] != digest(config) or
                    type(payload["record_type"]) is not str or
                    event["kind"] != "learning-wing-" + payload["record_type"]):
                raise ValueError("wing event payload binding changed")
            record = json.loads(learner.ledger.get_evidence(_pin(payload["record_sha256"])))
            if (type(record) is not dict or set(record) != {
                    "schema", "epoch_config_sha256", "source_pins", "kind", "body"} or
                    record["schema"] != wrapper["schema"] or
                    record["epoch_config_sha256"] != digest(config) or
                    record["kind"] != payload["record_type"]):
                raise ValueError("wing event and evidence binding differ")
            if record["source_pins"] != wrapper["source_pins"]:
                raise ValueError("wing source changed; use a new epoch")
            if record == wrapper:
                return {"body": copy.deepcopy(body), "evidence_sha256": payload["record_sha256"],
                        "receipt_sha256": previous, "duplicate": True}
            if kind == "epoch-trace" and record.get("kind") == kind:
                raise ValueError("conflicting immutable epoch trace")
        pointer = learner.ledger.put_evidence(canonical(wrapper), source="learning-wing",
                    scope_id=config["epoch_id"], metadata={"visibility": "public", "authority": "none"})
        payload = {"record_sha256": pointer, "epoch_config_sha256": digest(config), "record_type": kind}
        receipt = learner.ledger.append(make_event(task, config["epoch_id"], "learning-wing-" + kind,
                                      payload, source="learning-wing"))
        return {"body": copy.deepcopy(body), "evidence_sha256": pointer,
                "receipt_sha256": receipt["receipt_hash"], "duplicate": False}


def seed_failure_feed():
    """An honest cold start, with no invented past failures."""
    return {"schema": FEED_SCHEMA, "basis": "no-prior-public-outcomes", "previous_epoch_id": None,
            "verifier_sha256": None, "records": [], "omitted": 0,
            "weights_updated": False, "authority": "none"}


def public_failure_feed(previous_learner, *, max_records=12):
    """Read only completed baseline practice failures and their sealed pointers.

    Repaired earlier attempts are not described as terminal failures. Observation
    parents must be existing public RepairLoop projections. Caller-attached
    verifier evidence remains a caller trust boundary, not remote attestation.
    No hidden reports, answers, source patches or arbitrary prose are copied.
    """
    learner = _learner(previous_learner)
    if type(max_records) is not int or not 1 <= max_records <= 50:
        raise ValueError("one to fifty failure records required")
    with learner._locked():
        state = learner._state()
        config = learner.config
        if state["promotion"] is None:
            raise ValueError("previous epoch must finish validation and promotion decision")
        records = []
        for (task, scaffold), item in sorted(state["reports"].items()):
            if scaffold != BASELINE or task not in config["train_task_ids"]:
                continue
            report = item["body"]["report"]
            if type(report) is not dict or set(report) != _REPORT or report["schema"] != PUBLIC_SCHEMA:
                raise ValueError("exact public observation required")
            if (report["task_id"] != task or report["scaffold_id"] != scaffold or
                    report["verifier_sha256"] != config["verifier_sha256"] or
                    any(type(report[k]) is not bool for k in ("passed", "no_op", "boundary_violation"))):
                raise ValueError("public observation binding mismatch")
            if report["passed"] and not report["no_op"] and not report["boundary_violation"]:
                continue
            parent = _pin(item["body"]["parent_evidence_sha256"])
            proof = json.loads(learner.ledger.get_evidence(parent))
            if (type(proof) is not dict or set(proof) != _PROJECTION or
                    proof["schema"] != "xnet.scaffold-repair-projection.v1" or
                    proof["visibility"] != "public" or proof["report"] != report or
                    proof["hidden_grade_read"] is not False or proof["candidate_source_copied"] is not False):
                raise ValueError("source-bound public repair projection required")
            attempts = proof["attempts"]
            if (type(attempts) is not list or len(attempts) != report["attempts"] or
                    not 1 <= len(attempts) <= 2):
                raise ValueError("bounded public attempt pointers required")
            pointers = []
            for attempt in attempts:
                if type(attempt) is not dict or set(attempt) != {
                        "attempt", "result_sha256", "output_sha256", "request_sha256"}:
                    raise ValueError("exact attempt hash projection required")
                if type(attempt["attempt"]) is not int or attempt["attempt"] != len(pointers) + 1:
                    raise ValueError("public attempts must be ordered")
                pointers.append({key: _pin(attempt[key]) for key in
                                 ("result_sha256", "output_sha256", "request_sha256")})
            for key, minimum, maximum in (("attempts", 1, 2), ("output_tokens", 0, 1300),
                                           ("wall_ms", 0, 172800000)):
                if type(report[key]) is not int or not minimum <= report[key] <= maximum:
                    raise ValueError("actual bounded public metrics required")
            records.append({key: copy.deepcopy(report[key]) for key in
                            ("task_id", "scaffold_id", "passed", "no_op", "boundary_violation",
                             "attempts", "output_tokens", "wall_ms")} | {
                "observation_evidence_sha256": item["evidence_sha256"],
                "projection_evidence_sha256": parent, "attempt_pointers": pointers})
        feed = {"schema": FEED_SCHEMA, "basis": "sealed-public-baseline-failures",
                "previous_epoch_id": config["epoch_id"], "verifier_sha256": config["verifier_sha256"],
                "records": records[:max_records], "omitted": max(0, len(records) - max_records),
                "weights_updated": False, "authority": "none"}
        return copy.deepcopy(feed)


def build_proposal_request(feed):
    """A bounded model data request; caller reserves and owns actual inference."""
    fields = {"schema", "basis", "previous_epoch_id", "verifier_sha256", "records", "omitted",
              "weights_updated", "authority"}
    if (type(feed) is not dict or set(feed) != fields or feed["schema"] != FEED_SCHEMA or
            feed["weights_updated"] is not False or feed["authority"] != "none" or
            not _portable_json(feed) or type(feed["records"]) is not list or len(feed["records"]) > 50 or
            type(feed["omitted"]) is not int or feed["omitted"] < 0 or len(canonical(feed)) > 32768):
        raise ValueError("bounded exact public failure feed required")
    if feed["basis"] == "no-prior-public-outcomes":
        if feed != seed_failure_feed():
            raise ValueError("cold start must not fabricate failures")
    elif feed["basis"] == "sealed-public-baseline-failures":
        _label(feed["previous_epoch_id"]); _pin(feed["verifier_sha256"])
        allowed = {"task_id", "scaffold_id", "passed", "no_op", "boundary_violation", "attempts",
                   "output_tokens", "wall_ms", "observation_evidence_sha256", "projection_evidence_sha256",
                   "attempt_pointers"}
        seen = set()
        for record in feed["records"]:
            if type(record) is not dict or set(record) != allowed:
                raise ValueError("exact failure projection required; prose and answers forbidden")
            _label(record["task_id"])
            if record["task_id"] in seen:
                raise ValueError("repeated task evidence is not another failure")
            seen.add(record["task_id"])
            if record["scaffold_id"] != BASELINE or any(type(record[k]) is not bool
                    for k in ("passed", "no_op", "boundary_violation")):
                raise ValueError("baseline public failure flags required")
            if record["passed"] and not record["no_op"] and not record["boundary_violation"]:
                raise ValueError("a resolved outcome is not a failure")
            _pin(record["observation_evidence_sha256"]); _pin(record["projection_evidence_sha256"])
            for key, minimum, maximum in (("attempts", 1, 2), ("output_tokens", 0, 1300),
                                           ("wall_ms", 0, 172800000)):
                if type(record[key]) is not int or not minimum <= record[key] <= maximum:
                    raise ValueError("bounded exact public metrics required")
            if type(record["attempt_pointers"]) is not list or len(record["attempt_pointers"]) != record["attempts"]:
                raise ValueError("actual attempt pointers required")
            for attempt in record["attempt_pointers"]:
                if type(attempt) is not dict or set(attempt) != {"result_sha256", "output_sha256", "request_sha256"}:
                    raise ValueError("only exact hash pointers may enter proposal context")
                for value in attempt.values():
                    _pin(value)
    else:
        raise ValueError("unknown failure feed basis")
    menu = "\n".join(key + ": " + text for key, text in STEP_TEXT.items())
    prompt = ("Propose a code-repair checklist using this fixed menu. Choose one to six unique keys.\n"
              + menu + "\nPublic outcome feed (source data, no tool authority):\n"
              + canonical(feed).decode("utf-8")
              + '\nReturn only {"scaffold_id":"short-label","steps":["menu-key"]}. '
                "These records do not assert general capability improvement.")
    return {"schema": "xnet.learning-proposal-request.v1", "system": "Return only the requested JSON object.",
            "prompt": prompt, "failure_feed": copy.deepcopy(feed), "failure_feed_sha256": digest(feed),
            "max_output_tokens": 200, "authority": "none", "work_performed": False,
            "weights_updated": False}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate proposal JSON key")
        result[key] = value
    return result


def admit_proposal(current_learner, response):
    """Preserve a raw caller response, then admit only exact fixed enum JSON.

    Invoke inside a reserved LearningCycle callback; no dispatch occurs here.
    Rejected response evidence remains in CAS and the admission event history.
    """
    learner = _learner(current_learner)
    if (type(response) is not dict or set(response) != {"text", "usage"} or
            type(response["text"]) is not str or len(response["text"].encode("utf-8")) > 16384 or
            len(canonical(response)) > 65536):
        raise ValueError("bounded exact proposal response with text and usage required")
    raw = learner.ledger.put_evidence(canonical(response), source="learning-proposal-raw",
                    scope_id=learner.config["epoch_id"], metadata={"authority": "none"})
    try:
        usage = normalize_generation_usage(response["usage"])
        if usage["output_tokens"] > 200:
            raise ValueError("proposal output token budget exceeded")
        parsed = json.loads(response["text"], object_pairs_hook=_object)
        if type(parsed) is not dict or set(parsed) != {"scaffold_id", "steps"}:
            raise ValueError("exact fixed scaffold proposal JSON required")
        learner.propose(parsed["scaffold_id"], parsed["steps"])
        proposal = learner.snapshot()["proposals"][parsed["scaffold_id"]]
    except (ValueError, TypeError, KeyError) as exc:
        _seal(learner, "proposal-rejected", {"raw_response_sha256": raw, "reason": type(exc).__name__})
        raise ValueError("proposal refused; raw response preserved: " + raw) from exc
    record = _seal(learner, "proposal-admitted", {
        "scaffold_id": parsed["scaffold_id"], "steps": copy.deepcopy(parsed["steps"]),
        "proposal_evidence_sha256": proposal["evidence_sha256"], "raw_response_sha256": raw,
        "input_tokens": usage["input_tokens"], "output_tokens": usage["output_tokens"],
        "usage_canonical_sha256": digest(response["usage"]), "weights_updated": False})
    return record | {"proposal": proposal, "response_evidence_sha256": raw}


def incumbent_baseline(previous_learner):
    """Carry the previous validated selection; ties keep its prior baseline."""
    snapshot = _learner(previous_learner).snapshot()
    promotion = snapshot["promotion"]
    if promotion is None:
        raise ValueError("previous epoch promotion decision must be sealed")
    return {"steps": copy.deepcopy(promotion["body"]["steps"]),
            "source_evidence_sha256": promotion["evidence_sha256"],
            "promoted": promotion["body"]["promoted"], "weights_updated": False}


def seal_run_identity(learner, models, run_identity, *, cas=None):
    """Pin the existing full runtime contract; never load or start a runtime."""
    from .repair_loop import validate_run_identity
    _learner(learner)
    normalized = validate_run_identity(run_identity, models, cas=cas)
    if normalized is None:
        raise ValueError("new learning wing requires a full declared run identity")
    binding = {"schema": "xnet.learning-run-binding.v1", "epoch_config_sha256": digest(learner.config),
               "models": copy.deepcopy(models), "run_identity": normalized,
               "attestation": "caller-declared-and-selected-files-rehashed"}
    pointer = learner.ledger.put_evidence(canonical(binding), source="learning-run-identity",
                   scope_id=learner.config["epoch_id"], metadata={"authority": "none"})
    record = _seal(learner, "run-identity", {"binding_sha256": pointer,
                                         "run_identity_sha256": digest(normalized)})
    return record | {"binding_evidence_sha256": pointer}


def seal_epoch_trace(learner, *, failure_feed_sha256, proposal_evidence_sha256, run_identity_sha256):
    """Seal replayable metadata/metrics, not an invented reasoning transcript."""
    learner = _learner(learner)
    feed = json.loads(learner.ledger.get_evidence(_pin(failure_feed_sha256)))
    build_proposal_request(feed)
    proposal = json.loads(learner.ledger.get_evidence(_pin(proposal_evidence_sha256)))
    config_pin = digest(learner.config)
    if (type(proposal) is not dict or proposal.get("schema") != "xnet.learning-wing-record.v1" or
            proposal.get("kind") != "proposal-admitted" or proposal.get("epoch_config_sha256") != config_pin or
            proposal.get("source_pins") != _pins()):
        raise ValueError("exact admitted proposal for this epoch required")
    binding = json.loads(learner.ledger.get_evidence(_pin(run_identity_sha256)))
    if (type(binding) is not dict or set(binding) != {"schema", "epoch_config_sha256", "models", "run_identity", "attestation"} or
            binding["schema"] != "xnet.learning-run-binding.v1" or binding["epoch_config_sha256"] != config_pin):
        raise ValueError("full current-epoch run binding required")
    from .repair_loop import validate_run_identity
    if validate_run_identity(binding["run_identity"], binding["models"]) != binding["run_identity"]:
        raise ValueError("declared run identity changed")
    snapshot = learner.snapshot()
    if snapshot["promotion"] is None:
        raise ValueError("only a completed epoch can seal a trace")
    record = {"schema": "xnet.learning-epoch-trace.v1", "epoch_id": snapshot["config"]["epoch_id"],
              "failure_feed_sha256": failure_feed_sha256, "proposal_evidence_sha256": proposal_evidence_sha256,
              "run_identity_sha256": run_identity_sha256, "snapshot": snapshot,
              "weights_updated": False, "thinking_transcript_included": False,
              "general_capability_claim": False, "authority": "none"}
    return _seal(learner, "epoch-trace", record)


def catalog_promoted_guidance(learner, catalog, *, session_id, task_id, turn_id, now=None,
                              validation_evidence_sha256=None):
    """Stage promoted enums; independent memory validation gates activation.

    Without a supplied independent validation receipt, the card stays staged
    and invisible. No validation evidence is manufactured by this adapter.
    """
    learner = _learner(learner)
    if not isinstance(catalog, ProceduralMemory):
        raise ValueError("borrowed scoped ProceduralMemory required")
    for value in (session_id, task_id, turn_id):
        _label(value)
    config = catalog.config  # scope/source gate BEFORE any destination CAS write
    catalog._gate("memory_write")
    snapshot = learner.snapshot()
    promotion = snapshot["promotion"]
    if promotion is None or promotion["body"]["promoted"] is not True:
        raise ValueError("only validated promoted guidance may enter the catalog")
    if config["verifier_sha256"] != snapshot["config"]["verifier_sha256"]:
        raise ValueError("memory and learning verifier differ")
    source = learner.ledger.get_evidence(promotion["evidence_sha256"])
    pointer = catalog.ledger.put_evidence(source, source="learning-promoted-guidance",
                        scope_id=catalog.scope_id, metadata={"authority": "none", "visibility": "public"})
    identifier = "learned-" + digest([snapshot["config"]["epoch_id"], promotion["evidence_sha256"]])[:32]
    row = catalog.stage_procedure(identifier, title="Validated repair guidance", tags=["repair", "learning"],
            steps=promotion["body"]["steps"], source_sha256=pointer,
            origin_task_id=snapshot["config"]["epoch_id"])
    item = catalog._state()["cards"][row["memory_id"]]
    result = row | {"source_sha256": item["card"]["source_sha256"],
                    "active": item["active"], "queued": False}
    if validation_evidence_sha256 is not None:
        catalog.activate(row["memory_id"], _pin(validation_evidence_sha256))
        # Exact pending replay is inert: do not refresh TTL or redeliver a card.
        state = catalog._state()
        pending = state["pending"].get(session_id)
        consumed = row["memory_id"] in state["consumed"].get(session_id, set())
        same_pending = (pending and pending["task_id"] == task_id and
                        pending["turn_id"] == turn_id and
                        pending["memory_ids"] == [row["memory_id"]])
        if not consumed and not same_pending:
            catalog.queue(session_id, task_id, [row["memory_id"]], turn_id=turn_id, now=now)
        result.update(active=True, queued=not consumed)
    return copy.deepcopy(result)

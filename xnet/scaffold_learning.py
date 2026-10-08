"""Outcome-driven scaffold memory; fixed weights, no neural training or executor.

Caller-owned public verifier metrics select fixed guidance enums on a training
split, then a disjoint paired validation split gates promotion. Hashes establish
byte provenance, not evaluator correctness, identity, significance or capability.
All durable state is replayed from the caller's Ledger and evidence CAS.
"""
from __future__ import annotations

import copy
import json
import os
import re
from contextlib import contextmanager
from pathlib import Path
from types import MappingProxyType

from .ledger import Ledger
from .protocol import ZERO_HASH, canonical, digest, make_event, sha256

STEP_TEXT = MappingProxyType({
    "inspect-contract": "Inspect the stated input, output and public contract before changing code.",
    "check-edge-cases": "Check empty inputs, boundaries, negative values and duplicate values against the contract.",
    "trace-state": "Trace state changes and ordering across successive operations.",
    "verify-change": "Verify that the proposed change is substantive and addresses the reported failure.",
    "inspect-feedback": "Use the available public feedback to inspect the failing behavior before retrying.",
    "preserve-interfaces": "Preserve stated interfaces and unrelated behavior while repairing the defect.",
    "check-invariants": "Check that the stated invariants hold before and after each operation.",
    "check-complexity": "Check termination and resource bounds for the proposed algorithm.",
})
BASELINE = "baseline"
PUBLIC_SCHEMA = "xnet.scaffold-public-observation.v1"
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = {"schema", "task_id", "scaffold_id", "verifier_sha256", "passed", "no_op",
           "boundary_violation", "attempts", "output_tokens", "wall_ms"}
EFFICIENCY_COST_FIELDS = (
    "worker_input_tokens", "worker_output_tokens", "worker_wall_ms", "worker_calls",
    "coach_input_tokens", "coach_output_tokens", "coach_wall_ms", "coach_calls",
    "retrieval_wall_ms", "retrieval_calls", "tool_wall_ms", "tool_calls",
    "grader_wall_ms", "grader_calls",
)
COST_SCHEMA = "xnet.scaffold-public-costs.v1"


def _promotion_policy(value):
    fields = {"schema", "mode", "objective", "minimum_savings_percent", "cost_categories", "coach_accounting"}
    if (type(value) is not dict or set(value) != fields
            or value["schema"] != "xnet.scaffold-promotion-policy.v1"
            or value["mode"] != "solve-gain-or-equal-quality-cheaper"
            or value["objective"] not in ("total_tokens", "total_wall_ms")
            or type(value["minimum_savings_percent"]) is not int
            or not 1 <= value["minimum_savings_percent"] <= 99
            or type(value["cost_categories"]) is not list
            or value["cost_categories"] != list(EFFICIENCY_COST_FIELDS)):
        raise ValueError("exact explicit complete-cost promotion policy required")
    _label(value["coach_accounting"])
    return copy.deepcopy(value)


def _complete_costs(value):
    if (type(value) is not dict or set(value) != set(EFFICIENCY_COST_FIELDS)
            or any(type(amount) is not int or not 0 <= amount <= 1_000_000_000 for amount in value.values())):
        raise ValueError("every declared measured cost category is required; missing is not zero")
    for owner in ("worker", "coach", "retrieval", "tool", "grader"):
        measured = [key for key in value if key.startswith(owner + "_") and not key.endswith("_calls")]
        if value[owner + "_calls"] == 0 and any(value[key] for key in measured):
            raise ValueError("measured owner costs require an actual call count")
    return copy.deepcopy(value)


def _cost_totals(costs):
    return {"total_tokens": sum(costs[key] for key in (
                "worker_input_tokens", "worker_output_tokens", "coach_input_tokens", "coach_output_tokens")),
            "total_wall_ms": sum(costs[key] for key in (
                "worker_wall_ms", "coach_wall_ms", "retrieval_wall_ms", "tool_wall_ms", "grader_wall_ms"))}


def _label(value):
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise ValueError("invalid bounded scaffold label")
    return value


def _hash(value):
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError("invalid SHA-256 pin")
    return value


def _steps(values):
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= 6:
        raise ValueError("scaffold requires one to six fixed steps")
    if any(not isinstance(v, str) or v not in STEP_TEXT for v in values) or len(set(values)) != len(values):
        raise ValueError("unsupported or repeated scaffold step")
    return list(values)


def _source_pins():
    directory = Path(__file__).parent
    return {name: sha256((directory / name).read_bytes())
            for name in ("scaffold_learning.py", "ledger.py", "protocol.py")}


class ScaffoldLearner:
    """A source-pinned epoch. Baseline is always scaffold ID ``baseline``.

    ``observe`` accepts ONLY bounded public outcomes, never answers or prose.
    Optional evidence_sha256 binds a caller's existing CAS verifier projection.
    Exact replay is idempotent; changed source/config requires a new epoch ID.
    ``context_record('trial')`` is stable after freeze; ``'active'`` is available
    after promotion, including baseline retention after failed validation.
    """

    def __init__(self, ledger: Ledger, epoch_id, train_task_ids, validation_task_ids,
                 verifier_sha256, baseline_steps=("inspect-contract",), *, cost_ratio=2,
                 promotion_policy=None):
        if not isinstance(ledger, Ledger):
            raise ValueError("caller must supply the authoritative Ledger")
        epoch_id = _label(epoch_id)
        groups = []
        for values in (train_task_ids, validation_task_ids):
            if not isinstance(values, (list, tuple)) or not 2 <= len(values) <= 256:
                raise ValueError("each split requires two to 256 declared task IDs")
            validated = [_label(v) for v in values]
            if len(set(validated)) != len(validated):
                raise ValueError("duplicate task ID in split")
            groups.append(sorted(validated))
        if set(groups[0]) & set(groups[1]):
            raise ValueError("training and validation task IDs must be disjoint")
        if type(cost_ratio) is not int or not 1 <= cost_ratio <= 4:
            raise ValueError("cost ratio must be a predeclared integer from one to four")
        pins = _source_pins()
        config = {"schema": "xnet.scaffold-epoch.v1", "epoch_id": epoch_id,
                  "train_task_ids": groups[0], "validation_task_ids": groups[1],
                  "verifier_sha256": _hash(verifier_sha256), "baseline_steps": _steps(baseline_steps),
                  "cost_ratio": cost_ratio, "source_pins": pins, "source_sha256": digest(pins),
                  "mechanism": "outcome-driven-fixed-guidance", "weights_updated": False}
        if promotion_policy is not None:
            config["promotion_policy"] = _promotion_policy(promotion_policy)
        self.ledger = ledger
        self._config_bytes = canonical(config)
        self._config_sha = sha256(self._config_bytes)
        self._task = "scaffold-" + digest(epoch_id)[:32]
        self._lock_path = ledger.data_dir / "scaffold-locks" / (digest(epoch_id) + ".lock")
        with self._locked():
            state = self._state()
            if state["epoch"] is None:
                self._write("epoch", config)
            elif state["epoch"]["body"] != config:
                raise ValueError("epoch source/config changed; create a new epoch")

    @property
    def config(self):
        self._state()
        return json.loads(self._config_bytes)

    def _assert_source(self):
        if _source_pins() != json.loads(self._config_bytes)["source_pins"]:
            raise ValueError("scaffold source changed; create a new epoch")

    @contextmanager
    def _locked(self):
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock_path.open("a+b") as handle:
            handle.seek(0, os.SEEK_END)
            if not handle.tell():
                handle.write(b"0"); handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                handle.seek(0)
                if os.name == "nt":
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _write(self, kind, body):
        config = json.loads(self._config_bytes)
        record = {"schema": "xnet.scaffold-record.v1", "kind": kind,
                  "config_sha256": self._config_sha, "body": body}
        evidence = self.ledger.put_evidence(canonical(record), source="scaffold-learning",
                    scope_id=self._task, metadata={"public_metrics_only": True, "authority": "none"})
        payload = {"epoch_id": config["epoch_id"], "record_sha256": evidence,
                   "record_type": kind, "config_sha256": self._config_sha}
        event = make_event(self._task, self._task, "scaffold-" + kind, payload,
                           source="scaffold-learning", event_id="scaffold-" + digest(payload))
        receipt = self.ledger.append(event)
        return {"body": copy.deepcopy(body), "evidence_sha256": evidence,
                "receipt_sha256": receipt["receipt_hash"]}

    def _state(self):
        self._assert_source()
        self.ledger.verify_chain()
        state = {"epoch": None, "proposals": {}, "reports": {}, "training": None, "promotion": None}
        previous = ZERO_HASH
        for seq, event in enumerate(self.ledger.events(), 1):
            previous = digest({"seq": seq, "prev_hash": previous, "event_hash": digest(event)})
            if event["task_id"] != self._task:
                continue
            payload = event["payload"]
            if event["source"] != "scaffold-learning" or payload.get("config_sha256") != self._config_sha:
                raise ValueError("epoch source/config changed; create a new epoch")
            record = json.loads(self.ledger.get_evidence(payload["record_sha256"]))
            kind = payload["record_type"]
            if record["config_sha256"] != self._config_sha or record["kind"] != kind:
                raise ValueError("scaffold event/evidence mismatch")
            item = {"body": record["body"], "evidence_sha256": payload["record_sha256"],
                    "receipt_sha256": previous}
            body = item["body"]
            if kind == "epoch" and state["epoch"] is None:
                state["epoch"] = item
                state["proposals"][BASELINE] = {"steps": body["baseline_steps"],
                    "evidence_sha256": item["evidence_sha256"], "receipt_sha256": previous}
            elif kind == "proposal" and state["training"] is None:
                state["proposals"][body["scaffold_id"]] = {"steps": body["steps"],
                    "evidence_sha256": item["evidence_sha256"], "receipt_sha256": previous}
            elif kind == "observation":
                parent = body["parent_evidence_sha256"]
                if parent is not None:
                    self.ledger.get_evidence(parent)
                report = body["report"]
                if "promotion_policy" in json.loads(self._config_bytes):
                    self._verify_cost_evidence(report["task_id"], report["scaffold_id"],
                                               body["costs"], body["cost_evidence_sha256"])
                    self._verify_worker_costs(report, body["costs"])
                state["reports"][(report["task_id"], report["scaffold_id"])] = item
            elif kind in ("training", "promotion") and state[kind] is None:
                state[kind] = item
            else:
                raise ValueError("invalid scaffold event transition")
        return state

    def propose(self, scaffold_id, steps):
        scaffold_id, steps = _label(scaffold_id), _steps(steps)
        with self._locked():
            state = self._state()
            existing = state["proposals"].get(scaffold_id)
            if existing is not None:
                if existing["steps"] != steps:
                    raise ValueError("conflicting immutable scaffold proposal")
                return {"steps": list(existing["steps"])}
            if state["training"] is not None or len(state["proposals"]) >= 16:
                raise ValueError("proposal set is frozen or full")
            self._write("proposal", {"scaffold_id": scaffold_id, "steps": steps})
            return {"steps": list(steps)}

    def _verify_cost_evidence(self, task_id, scaffold_id, costs, evidence_sha256):
        config = json.loads(self._config_bytes)
        costs = _complete_costs(costs)
        expected = {"schema": COST_SCHEMA, "task_id": task_id, "scaffold_id": scaffold_id,
                    "verifier_sha256": config["verifier_sha256"], "costs": costs,
                    "coach_accounting": config["promotion_policy"]["coach_accounting"]}
        if self.ledger.get_evidence(_hash(evidence_sha256)) != canonical(expected):
            raise ValueError("exact task/scaffold/verifier/accounting cost evidence required")
        return costs

    @staticmethod
    def _verify_worker_costs(report, costs):
        if (costs["worker_output_tokens"] != report["output_tokens"]
                or costs["worker_wall_ms"] != report["wall_ms"]
                or costs["worker_calls"] != report["attempts"]):
            raise ValueError("worker costs differ from the measured public observation")

    def observe(self, task_id, scaffold_id, public_report, *, evidence_sha256=None,
                costs=None, cost_evidence_sha256=None):
        task_id, scaffold_id = _label(task_id), _label(scaffold_id)
        if not isinstance(public_report, dict) or set(public_report) != _FIELDS:
            raise ValueError("exact public observation fields required; no answers or hidden reports")
        report = copy.deepcopy(public_report)
        config = self.config
        if (report["schema"] != PUBLIC_SCHEMA or report["task_id"] != task_id or
                report["scaffold_id"] != scaffold_id or report["verifier_sha256"] != config["verifier_sha256"]):
            raise ValueError("public observation binding mismatch")
        for key in ("passed", "no_op", "boundary_violation"):
            if type(report[key]) is not bool:
                raise ValueError("public outcome flags must be bool")
        for key, limit, minimum in (("attempts", 16, 1), ("output_tokens", 1_000_000, 0),
                                   ("wall_ms", 86_400_000, 0)):
            if type(report[key]) is not int or not minimum <= report[key] <= limit:
                raise ValueError("public observation metric outside bounds")
        if evidence_sha256 is not None:
            self.ledger.get_evidence(_hash(evidence_sha256))
        body = {"report": report, "parent_evidence_sha256": evidence_sha256,
                "provenance": "caller-declared-public-metrics" if evidence_sha256 is None else "caller-attached-verifier-evidence"}
        if "promotion_policy" in config:
            body["costs"] = self._verify_cost_evidence(task_id, scaffold_id, costs, cost_evidence_sha256)
            self._verify_worker_costs(report, body["costs"])
            body["cost_evidence_sha256"] = cost_evidence_sha256
        elif costs is not None or cost_evidence_sha256 is not None:
            raise ValueError("complete costs require an explicit promotion policy")
        with self._locked():
            state = self._state()
            existing = state["reports"].get((task_id, scaffold_id))
            if existing is not None:
                if existing["body"] != body:
                    raise ValueError("conflicting immutable public observation")
                return copy.deepcopy(existing)
            if state["promotion"] is not None or scaffold_id not in state["proposals"]:
                raise ValueError("epoch sealed or scaffold undeclared")
            if state["training"] is None:
                allowed = task_id in config["train_task_ids"]
            else:
                allowed = task_id in config["validation_task_ids"] and scaffold_id in (
                    BASELINE, state["training"]["body"]["selected_scaffold"])
            if not allowed:
                raise ValueError("observation outside current declared split")
            return self._write("observation", body)

    def _summaries(self, state, task_ids, scaffold_ids):
        summaries, pins = {}, {}
        for scaffold_id in scaffold_ids:
            rows = [state["reports"].get((task, scaffold_id)) for task in task_ids]
            if any(row is None for row in rows):
                raise ValueError("all declared matched task/scaffold pairs must be observed")
            reports = [row["body"]["report"] for row in rows]
            summaries[scaffold_id] = {
                "resolved": sum(r["passed"] and not r["no_op"] and not r["boundary_violation"] for r in reports),
                **{key: sum(r[key] for r in reports) for key in ("attempts", "output_tokens", "wall_ms")},
                "no_ops": sum(r["no_op"] for r in reports),
                "boundary_violations": sum(r["boundary_violation"] for r in reports)}
            if "promotion_policy" in json.loads(self._config_bytes):
                costs = {key: sum(row["body"]["costs"][key] for row in rows) for key in EFFICIENCY_COST_FIELDS}
                summaries[scaffold_id]["complete_costs"] = costs
                summaries[scaffold_id].update(_cost_totals(costs))
            pins[scaffold_id] = {task: row["evidence_sha256"] for task, row in zip(task_ids, rows)}
        return summaries, pins

    def _efficiency(self, state, task_ids, scaffold_id, summaries):
        policy = json.loads(self._config_bytes)["promotion_policy"]
        baseline, candidate = summaries[BASELINE], summaries[scaffold_id]
        if baseline["resolved"] == 0 or candidate["boundary_violations"]:
            return False
        for task in task_ids:
            left = state["reports"][(task, BASELINE)]["body"]["report"]
            right = state["reports"][(task, scaffold_id)]["body"]["report"]
            resolved = lambda row: row["passed"] and not row["no_op"] and not row["boundary_violation"]
            if resolved(left) != resolved(right) or right["no_op"] and not left["no_op"]:
                return False
        objective = policy["objective"]
        return (baseline[objective] > 0
                and candidate[objective] * 100 <= baseline[objective] * (100 - policy["minimum_savings_percent"])
                and all(candidate[key] <= baseline[key] for key in ("total_tokens", "total_wall_ms")))

    def freeze_training(self):
        with self._locked():
            state = self._state()
            if state["training"] is not None:
                return copy.deepcopy(state["training"])
            candidates = sorted(state["proposals"])
            summaries, pins = self._summaries(state, self.config["train_task_ids"], candidates)
            policy = self.config.get("promotion_policy")
            if policy is None:
                selected = min(candidates, key=lambda s: (-summaries[s]["resolved"],
                        summaries[s]["output_tokens"], summaries[s]["wall_ms"], summaries[s]["attempts"], s))
                if summaries[selected]["resolved"] <= summaries[BASELINE]["resolved"]:
                    selected = BASELINE
            else:
                eligible = [s for s in candidates if summaries[s]["resolved"] > summaries[BASELINE]["resolved"]
                            or self._efficiency(state, self.config["train_task_ids"], s, summaries)]
                selected = min(eligible, key=lambda s: (-summaries[s]["resolved"],
                    summaries[s][policy["objective"]], summaries[s]["attempts"], s)) if eligible else BASELINE
            body = {"selected_scaffold": selected, "steps": state["proposals"][selected]["steps"],
                    "summaries": summaries, "observation_sha256": pins,
                    "decision": "candidate" if selected != BASELINE else "retain-baseline"}
            return self._write("training", body)

    def promote(self):
        with self._locked():
            state = self._state()
            if state["promotion"] is not None:
                return copy.deepcopy(state["promotion"])
            if state["training"] is None:
                raise ValueError("freeze training before validation promotion")
            selected = state["training"]["body"]["selected_scaffold"]
            summaries, pins = self._summaries(state, self.config["validation_task_ids"], sorted({BASELINE, selected}))
            baseline, candidate = summaries[BASELINE], summaries[selected]
            gain = candidate["resolved"] - baseline["resolved"]
            policy = self.config.get("promotion_policy")
            cost_keys = ("output_tokens", "wall_ms") if policy is None else ("total_tokens", "total_wall_ms")
            within_cost = all(candidate[k] <= baseline[k] * self.config["cost_ratio"] for k in cost_keys)
            clean_boundary = candidate["boundary_violations"] == 0
            efficiency = (policy is not None and selected != BASELINE and gain == 0
                          and self._efficiency(state, self.config["validation_task_ids"], selected, summaries))
            promoted = selected != BASELINE and (gain > 0 or efficiency) and within_cost and clean_boundary
            active = selected if promoted else BASELINE
            body = {"active_scaffold": active, "steps": state["proposals"][active]["steps"],
                    "promoted": promoted, "solve_delta": gain, "within_cost": within_cost,
                    "clean_boundary": clean_boundary,
                    "summaries": summaries, "observation_sha256": pins,
                    "training_evidence_sha256": state["training"]["evidence_sha256"],
                    "claim": "small paired validation; no significance or general capability claim"}
            if policy is not None:
                body["improvement_kind"] = "score-gain" if promoted and gain > 0 else (
                    "equal-quality-efficiency" if promoted else "retain-baseline")
                body["promotion_policy"] = copy.deepcopy(policy)
            return self._write("promotion", body)

    validate = promote

    def snapshot(self):
        with self._locked():
            state = self._state()
            return copy.deepcopy({"config": self.config, "proposals": state["proposals"],
                "observation_count": len(state["reports"]), "training": state["training"],
                "promotion": state["promotion"], "weights_updated": False})

    def context_record(self, mode="active", *, scaffold_id=None):
        """Fixed guidance with durable proposal/decision provenance.

        Practice exposes a declared scaffold for training. Trial exposes only
        baseline or the frozen selection. Active exposes the promotion decision.
        Callers enforce split/task binding and never dispatch from attribution
        replays after a phase closes.
        """
        if mode not in ("practice", "trial", "active"):
            raise ValueError("context mode must be practice, trial or active")
        with self._locked():
            state = self._state()
            if mode == "practice":
                chosen = _label(scaffold_id)
                proposal = state["proposals"].get(chosen)
                if proposal is None:
                    raise ValueError("practice scaffold must be declared")
                decision = proposal
                steps = proposal["steps"]
            else:
                decision = state["training" if mode == "trial" else "promotion"]
                if decision is None:
                    raise ValueError("context is unavailable before its decision is sealed")
                chosen = decision["body"]["selected_scaffold" if mode == "trial" else "active_scaffold"]
                if mode == "active" and scaffold_id is not None:
                    raise ValueError("active context follows sealed promotion only")
                if mode == "trial" and scaffold_id is not None:
                    if scaffold_id not in (BASELINE, chosen):
                        raise ValueError("trial scaffold must be baseline or frozen selection")
                    chosen = scaffold_id
                steps = state["proposals"][chosen]["steps"]
            text = "Scaffold guidance; source only, no tool authority.\n" + "\n".join(
                f"{n}. {STEP_TEXT[step]}" for n, step in enumerate(steps, 1))
            record_id = "scaffold-" + digest({"epoch": self.config["epoch_id"], "mode": mode, "scaffold": chosen})[:32]
            return {"record_id": record_id, "scaffold_id": chosen,
                    "kind": "scaffold-memory", "text": text,
                    "source_sha256": decision["evidence_sha256"], "text_sha256": sha256(text.encode()),
                    "receipt_sha256": decision["receipt_sha256"],
                    "evidence_sha256": decision["evidence_sha256"]}

    def verify(self):
        with self._locked():
            self._state()
            return self.ledger.verify_chain()

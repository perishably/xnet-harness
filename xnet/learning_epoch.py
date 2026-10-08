"""Concrete bounded learning epoch using existing inert repair and learning peers.

The caller supplies full original tasks/private references, an externally pinned
public dataset, actual model artifacts/full run identity, generation/proposal
callbacks and a scoped host boundary observer. This peer owns no transport,
server, scheduler or host execution. RepairLoop's original admission selftests
stay private; only its completed PUBLIC outcomes enter ScaffoldLearner. No
generated-output hidden grading occurs here. Active guidance can be borrowed
separately for fresh unseen evaluation after the epoch is sealed.

Call ``step`` or bounded ``run(max_stages=8)``. A pending stage refuses replay.
``resume_pending(evidence_sha256=..., justification=...)`` is an explicit audited
recovery: existing nested RepairLoop reservations still refuse uncertain model
redispatch. For a lost proposal response, supply confirmed bytes using
``recover_proposal(response, elapsed_ms=..., evidence_sha256=..., justification=...)``.
Never invent metrics or timing for an unresolved nested generation.
"""
from __future__ import annotations

import copy
import json
import math
from pathlib import Path
import re
import time
import types

from .generation_usage import normalize_generation_usage
from .context_callable_identity_v2 import code_sha256, policy as context_identity_policy
from .learning_cycle import CONFIG_SCHEMA, LearningCycle, PendingStageError, _portable
from .learning_dataset import verify_learning_dataset
from .learning_wing import (admit_proposal, build_proposal_request, incumbent_baseline,
    public_failure_feed, seal_epoch_trace, seal_run_identity, seed_failure_feed)
from .protocol import canonical, digest, make_event, sha256
from .relay_log import _no_links
from .repair_loop import (PINNED_SOURCES, RepairLoop, _artifact_sha256,
    validate_run_identity, verify_run_identity_artifacts)
from .scaffold_context import ScaffoldContextPreparer, ingest_repair_outcome, public_verifier_identity
from .scaffold_learning import BASELINE, ScaffoldLearner
from .swe_repair_suite import public_task


def _sources():
    root = Path(__file__).parent
    names = set(PINNED_SOURCES) | {"learning_epoch.py", "learning_cycle.py", "learning_wing.py",
        "learning_dataset.py", "scaffold_learning.py", "scaffold_context.py", "generation_usage.py",
        "context_callable_identity_v2.py"}
    return {name: _artifact_sha256(root / name) for name in sorted(names)}


def _artifacts(rows):
    if type(rows) is not list or not 1 <= len(rows) <= 64:
        raise ValueError("explicit bounded artifact list required")
    result = []
    for row in rows:
        if type(row) is not dict or set(row) != {"path", "sha256"}:
            raise ValueError("exact artifact path/hash required")
        path = Path(row["path"])
        if not path.is_absolute():
            raise ValueError("absolute artifact path required")
        _no_links(path, regular_file=True)
        if _artifact_sha256(path) != row["sha256"]:
            raise ValueError("selected artifact differs from retained pin")
        result.append(copy.deepcopy(row))
    if len({row["path"] for row in result}) != len(result):
        raise ValueError("duplicate artifact path")
    return result


def _coach_identity(value):
    """A separately attributed caller-owned coach, without remote weight claims."""
    fields = {"schema", "provider", "model_id", "model_revision", "transport", "decoding"}
    if (type(value) is not dict or set(value) != fields
            or value["schema"] != "xnet.learning-coach-identity.v1"):
        raise ValueError("exact separate coach identity required")
    value = copy.deepcopy(value)
    _portable(value)
    if len(canonical(value)) > 65536:
        raise ValueError("bounded coach identity required")
    for key in ("provider", "model_id"):
        if (type(value[key]) is not str or not value[key].strip()
                or len(value[key].encode("utf-8")) > 256
                or any(ord(char) < 32 for char in value[key])):
            raise ValueError("explicit bounded coach provider/model required")
    revision = value["model_revision"]
    if revision is not None and (type(revision) is not str or not revision.strip()
            or len(revision.encode("utf-8")) > 512 or any(ord(char) < 32 for char in revision)):
        raise ValueError("coach revision must be known text or explicit None")
    transport = value["transport"]
    if (type(transport) is not dict or set(transport) != {"kind", "artifacts"}
            or type(transport["kind"]) is not str or not transport["kind"].strip()
            or len(transport["kind"].encode("utf-8")) > 256
            or type(value["decoding"]) is not dict):
        raise ValueError("source-pinned coach transport and decoding required")
    transport["artifacts"] = _artifacts(transport["artifacts"])
    return value


class LearningEpoch:
    """Borrowed Lite callbacks, public repair evidence and one durable epoch.

    ``boundary_observer(loop, model_id, task_id)`` must return an existing Ledger
    CAS pointer to the exact host observation required by ingest_repair_outcome.
    The monitor authenticates/authorizes its own scope; hashes alone do not.
    ``callback_artifacts`` pins source files for all three borrowed callbacks.
    ``dataset_sha256`` is the caller-retained external public manifest identity.
    Weights, runner/adapter artifacts and selected sources rehash at each entry.
    """

    def __init__(self, ledger, root, *, epoch_id, scope_id, dataset, dataset_sha256,
            tasks, references, full_tasks_sha256, references_sha256,
            model_id, models, run_identity, model_artifacts,
            callback_artifacts, generate, propose, boundary_observer, previous=None,
            baseline_steps=("inspect-contract",), cost_ratio=2, eval_timeout=3, cas=None,
            coach_identity=None):
        self.ledger, self.root = ledger, Path(root).absolute()
        _no_links(self.root)
        self.dataset = verify_learning_dataset(dataset, expected_sha256=dataset_sha256)
        self._dataset_pin = dataset_sha256
        self.tasks = {task["task_id"]: copy.deepcopy(task) for task in tasks}
        ids = [row["task_id"] for rows in self.dataset["splits"].values() for row in rows]
        if len(self.tasks) != len(tasks) or set(self.tasks) != set(ids) or set(references) != set(ids):
            raise ValueError("exact original full task/reference selection required")
        for rows in self.dataset["splits"].values():
            for row in rows:
                if canonical(public_task(self.tasks[row["task_id"]])) != canonical(row["public_task"]):
                    raise ValueError("original public task differs from sealed dataset")
        self.references = copy.deepcopy(references)
        if digest(self.tasks) != full_tasks_sha256 or digest(self.references) != references_sha256:
            raise ValueError("original task/reference bytes differ from retained private pins")
        self.models, self.model_id = copy.deepcopy(models), model_id
        if set(models) != {model_id}:
            raise ValueError("one caller-declared worker model per epoch")
        self.coach_identity = None if coach_identity is None else _coach_identity(coach_identity)
        if self.coach_identity is not None and self.coach_identity["model_id"] == model_id:
            raise ValueError("separate coach and worker model IDs required")
        self.cas = cas
        self.run_identity = validate_run_identity(run_identity, self.models, cas=cas)
        if self.run_identity is None:
            raise ValueError("full pinned run identity required")
        self.model_artifacts = _artifacts(model_artifacts)
        if self.models[model_id]["model_sha256"] not in {row["sha256"] for row in self.model_artifacts}:
            raise ValueError("model artifact list omits declared weights")
        self.callback_artifacts = _artifacts(callback_artifacts)
        selected = {str(Path(row["path"]).absolute()) for row in self.callback_artifacts}
        for callback in (generate, propose, boundary_observer):
            fn = getattr(callback, "__func__", callback)
            if not isinstance(fn, types.FunctionType) or str(Path(fn.__code__.co_filename).absolute()) not in selected:
                raise ValueError("borrowed callbacks need selected source artifacts")
        self.generate, self.propose, self.boundary_observer = generate, propose, boundary_observer
        self.eval_timeout = eval_timeout
        feed = seed_failure_feed() if previous is None else public_failure_feed(previous)
        incumbent = None if previous is None else incumbent_baseline(previous)
        steps = list(baseline_steps) if incumbent is None else incumbent["steps"]
        self._feed = copy.deepcopy(feed)
        self._private_binding = {"root_path": str(self.root.resolve()),
            "dataset_sha256": dataset_sha256, "full_tasks_sha256": digest(self.tasks),
            "references_sha256": digest(self.references), "models": self.models,
            "run_identity_sha256": digest(self.run_identity), "model_artifacts": self.model_artifacts,
            "callback_artifacts": self.callback_artifacts, "source_pins": _sources(),
            "callback_identities": self._callback_identities(),
            "failure_feed_sha256": digest(feed), "incumbent": incumbent,
            "baseline_steps": steps, "eval_timeout": eval_timeout, "cost_ratio": cost_ratio}
        if self.coach_identity is not None:
            self._private_binding["coach_identity"] = copy.deepcopy(self.coach_identity)
        self._private_pin = digest(self._private_binding)
        train_ids = [row["task_id"] for row in self.dataset["splits"]["train"]]
        val_ids = [row["task_id"] for row in self.dataset["splits"]["validation"]]
        probe = self._new_loop("identity-admission", train_ids)
        self.learner = ScaffoldLearner(ledger, epoch_id, train_ids, val_ids,
            public_verifier_identity(probe, model_id), baseline_steps=steps, cost_ratio=cost_ratio)
        self._task = "learning-epoch-" + digest([epoch_id, self._private_pin])[:32]
        self._scope = scope_id
        self._epoch_id = epoch_id
        identities = self._identity()
        self.cycle = LearningCycle(ledger, {"schema": CONFIG_SCHEMA, "epoch_id": epoch_id,
            "scope_id": scope_id, "identities": identities, "baseline_sha256": digest(steps),
            "cost_policy": {"max_token_ratio": cost_ratio, "max_wall_ratio": cost_ratio}},
            identity_reader=self._identity)
        # Raw original tasks and references remain local constructor inputs;
        # only their hashes enter the durable public binding.
        with self.cycle._locked():
            self.cycle._state()
            self._seal("binding", {"private_binding_sha256": self._private_pin,
                "dataset_sha256": dataset_sha256, "full_tasks_sha256": digest(self.tasks),
                "references_sha256": digest(self.references), "run_identity_sha256": digest(self.run_identity)})
            # This caller Ledger must be a designated PRIVATE LOCAL root. Its
            # originals must never join public/cloud export. Initialization
            # shares the controller lease so concurrent reopen cannot duplicate
            # the auxiliary binding history.
            self.private_originals_sha256 = ledger.put_evidence(canonical({
                "schema": "xnet.learning-private-originals.v1", "tasks": self.tasks,
                "references": self.references}), source="learning-private-originals",
                scope_id=scope_id, metadata={"visibility": "private", "cloud_export": False,
                                            "learner_input": False})

    def _identity(self, *, rehash_models=True):
        _no_links(self.root)
        verify_learning_dataset(self.dataset, expected_sha256=self._dataset_pin)
        verify_run_identity_artifacts(self.run_identity, cas=self.cas)
        if rehash_models:
            _artifacts(self.model_artifacts)
        _artifacts(self.callback_artifacts)
        binding = self._private_binding | {"root_path": str(self.root.resolve()), "source_pins": _sources(),
            "full_tasks_sha256": digest(self.tasks), "references_sha256": digest(self.references),
            "models": self.models, "run_identity_sha256": digest(self.run_identity),
            "failure_feed_sha256": digest(self._feed), "model_artifacts": self.model_artifacts,
            "callback_artifacts": self.callback_artifacts, "callback_identities": self._callback_identities(),
            "eval_timeout": self.eval_timeout}
        if self.coach_identity is not None:
            binding["coach_identity"] = _coach_identity(self.coach_identity)
        elif "coach_identity" in binding:
            raise ValueError("separate coach identity removed from frozen epoch")
        if digest(binding) != self._private_pin:
            raise ValueError("epoch source/task/reference/runtime binding drift")
        return {"manifest_sha256": self._dataset_pin, "model_sha256": self.models[self.model_id]["model_sha256"],
            "adapter_sha256": self.run_identity["adapter"]["sha256"], "source_sha256": self._private_pin}

    def _callback_identities(self):
        result = {}
        for key in ("generate", "propose", "boundary_observer"):
            callback = getattr(self, key)
            fn = getattr(callback, "__func__", callback)
            if not isinstance(fn, types.FunctionType):
                raise ValueError("source-pinned callback required")
            result[key] = {"path": str(Path(fn.__code__.co_filename).absolute()),
                           "qualname": fn.__qualname__, "code_sha256": code_sha256(fn.__code__)}
        return result

    def _cas(self, value, source):
        raw = canonical(value)
        if len(raw) > 1024 * 1024:
            raise ValueError("bounded raw callback evidence required")
        return self.ledger.put_evidence(raw, source=source, scope_id=self._scope,
                                       metadata={"authority": "none", "private_binding_sha256": self._private_pin})

    def _find(self, kind):
        self.ledger.verify_chain()
        found = []
        for event in self.ledger.events(self._task):
            payload = event["payload"]
            if (event["source"] != "learning-epoch" or event["scope_id"] != self._scope
                    or event["kind"] != "learning-epoch-record"
                    or type(payload) is not dict or set(payload) != {"kind", "record_sha256"}
                    or type(payload["kind"]) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", payload["kind"])
                    or type(payload["record_sha256"]) is not str
                    or not re.fullmatch(r"[0-9a-f]{64}", payload["record_sha256"])):
                raise ValueError("epoch auxiliary event binding conflict")
            wrapper = json.loads(self.ledger.get_evidence(payload["record_sha256"]))
            if (type(wrapper) is not dict or set(wrapper) != {"schema", "private_binding_sha256", "kind", "body"}
                    or type(wrapper["schema"]) is not str or wrapper["schema"] != "xnet.learning-epoch-aux.v1"
                    or type(wrapper["private_binding_sha256"]) is not str or wrapper["private_binding_sha256"] != self._private_pin
                    or type(wrapper["kind"]) is not str or wrapper["kind"] != payload["kind"]
                    or type(wrapper["body"]) is not dict):
                raise ValueError("epoch auxiliary CAS/event conflict")
            _portable(wrapper)
            if wrapper["kind"] == kind:
                found.append(wrapper["body"])
        if len(found) > 1:
            raise ValueError("conflicting auxiliary history")
        return copy.deepcopy(found[0]) if found else None

    def _seal(self, kind, body):
        old = self._find(kind)
        if old is not None:
            if old != body:
                raise ValueError("conflicting immutable epoch auxiliary result")
            return old
        wrapper = {"schema": "xnet.learning-epoch-aux.v1", "private_binding_sha256": self._private_pin,
                   "kind": kind, "body": body}
        pin = self._cas(wrapper, "learning-epoch")
        self.ledger.append(make_event(self._task, self._scope, "learning-epoch-record",
            {"kind": kind, "record_sha256": pin}, source="learning-epoch"))
        return copy.deepcopy(body)

    def _new_loop(self, name, task_ids, preparer=None):
        return RepairLoop(self.root / name, [self.tasks[tid] for tid in task_ids], self.models,
            {tid: self.references[tid] for tid in task_ids}, eval_timeout=self.eval_timeout, cas=self.cas,
            run_identity=self.run_identity, context_preparer=None if preparer is None else preparer.prepare,
            public_context_policy=None if preparer is None else context_identity_policy(preparer.policy))

    @staticmethod
    def _costs(input_tokens=0, output_tokens=0, elapsed_ms=0, calls=0):
        return {"input_tokens": input_tokens, "output_tokens": output_tokens,
                "elapsed_ms": elapsed_ms, "generation_calls": calls}

    def _proposal(self, reservation, recovery=False):
        raw = self._find("proposal-raw")
        if raw is None:
            if recovery:
                raise PendingStageError(reservation["reservation_id"])
            request = build_proposal_request(self._feed)
            if self.coach_identity is None:
                request |= {"model_id": self.model_id,
                    "model_sha256": self.models[self.model_id]["model_sha256"],
                    "run_identity": copy.deepcopy(self.run_identity), "reservation_id": reservation["reservation_id"]}
            else:
                request |= {"model_id": self.coach_identity["model_id"],
                    "coach_identity": copy.deepcopy(self.coach_identity),
                    "coach_identity_sha256": digest(self.coach_identity),
                    "worker_model_id": self.model_id, "worker_run_identity_sha256": digest(self.run_identity),
                    "reservation_id": reservation["reservation_id"], "scope_id": self._scope}
            request_pin = self._cas(request, "learning-epoch-proposal-request")
            # The actual rendered proposal request is durable BEFORE dispatch.
            # Its pointer differs from the controller's generic stage request.
            self._seal("proposal-request", {"reservation_id": reservation["reservation_id"],
                                            "request_sha256": request_pin})
            tick = time.monotonic()
            response = self.propose(copy.deepcopy(request))
            elapsed_ms = round((time.monotonic() - tick) * 1000)
            response_pin = self._cas(response, "learning-epoch-proposal-raw")
            raw = self._seal("proposal-raw", {"reservation_id": reservation["reservation_id"],
                "request_sha256": request_pin, "response_sha256": response_pin, "elapsed_ms": elapsed_ms})
        response = json.loads(self.ledger.get_evidence(raw["response_sha256"]))
        self._identity()  # full round guard BEFORE learner admission
        attribution = None
        if self.coach_identity is not None:
            if (type(response) is not dict or set(response) != {
                    "text", "usage", "coach_model_id", "coach_identity_sha256"}
                    or response["coach_model_id"] != self.coach_identity["model_id"]
                    or response["coach_identity_sha256"] != digest(self.coach_identity)):
                raise ValueError("proposal response differs from separate coach identity")
            attribution = self._seal("coach-attribution", {
                "schema": "xnet.learning-coach-attribution.v1",
                "coach_identity": copy.deepcopy(self.coach_identity),
                "coach_identity_sha256": digest(self.coach_identity),
                "proposal_callback_identity": self._callback_identities()["propose"],
                "request_sha256": raw["request_sha256"], "response_sha256": raw["response_sha256"],
                "reservation_id": raw["reservation_id"], "remote_weights_attested": False})
            projected_response = {key: response[key] for key in ("text", "usage")}
        else:
            projected_response = response
        admitted = admit_proposal(self.learner, projected_response)
        feed_pin = self._cas(self._feed, "learning-epoch-failure-feed")
        identity = seal_run_identity(self.learner, self.models, self.run_identity, cas=self.cas)
        result = {"stage": "propose", "proposal_evidence_sha256": admitted["evidence_sha256"],
            "response_evidence_sha256": raw["response_sha256"], "failure_feed_sha256": feed_pin,
            "run_identity_sha256": identity["binding_evidence_sha256"],
            "scaffold_id": admitted["body"]["scaffold_id"],
            "costs": self._costs(admitted["body"]["input_tokens"], admitted["body"]["output_tokens"], raw["elapsed_ms"], 1)}
        if attribution is not None:
            result["coach_attribution_sha256"] = self._cas(attribution, "learning-epoch-coach-attribution")
        return result

    def _repair(self, stage, split, scaffold):
        old = self._find("stage-" + stage)
        if old is not None:
            return old
        ids = [row["task_id"] for row in self.dataset["splits"][split]]
        mode = "practice" if split == "train" else "trial"
        prep = ScaffoldContextPreparer(self.learner, task_ids=ids, model_ids=[self.model_id],
                                      mode=mode, scaffold_id=scaffold)
        loop = self._new_loop(stage, ids, prep)
        def generate(request):
            self._identity(rehash_models=False)
            callback_request = copy.deepcopy(request)
            callback_request["learning_public_context_policy"] = copy.deepcopy(
                loop.manifest["config"]["public_context_policy"])
            callback_request_pin = self._cas(callback_request, "learning-epoch-render-request")
            self._seal("render-request-" + request["nonce"], {"reservation_id": request["nonce"],
                "repair_request_sha256": digest(request), "callback_request_sha256": callback_request_pin,
                "policy_sha256": digest(callback_request["learning_public_context_policy"])})
            tick = time.monotonic()
            response = self.generate(callback_request)
            elapsed_ms = round((time.monotonic() - tick) * 1000)
            raw_pin = self._cas(response, "learning-epoch-repair-raw")
            self._seal("generation-" + request["nonce"], {"response_sha256": raw_pin,
                        "elapsed_ms": elapsed_ms, "reservation_id": request["nonce"],
                        "callback_request_sha256": callback_request_pin})
            if type(response) is not dict or set(response) != {"model_id", "model_sha256", "text", "usage"}:
                raise ValueError("exact repair generation envelope required")
            normalized = copy.deepcopy(response)
            normalized["usage"] = normalize_generation_usage(response["usage"])
            if normalized["usage"]["output_tokens"] > 650:
                raise ValueError("repair output token budget exceeded")
            self._identity(rehash_models=False)
            return normalized
        # Existing uncertain reservations refuse before the generation callback.
        rows = loop.run_lane(self.model_id, generate)
        # Model bytes are fully rehashed at round boundaries, including here
        # BEFORE any public result is admitted to learning. Per-generation
        # guards still rehash selected sources/runner/adapter/callback files and
        # compare every immutable data/config binding. No model hash cache.
        self._identity()
        observations = []
        for tid in ids:
            pointer = self.boundary_observer(loop, self.model_id, tid)
            observed = ingest_repair_outcome(self.learner, loop, self.model_id, tid, scaffold,
                                            boundary_evidence_sha256=pointer)
            observations.append(observed["evidence_sha256"])
        frozen = loop.freeze()
        frozen_pin = self._cas(frozen, "learning-epoch-public-choice-freeze")
        costs = self._costs()
        for row in rows:
            usage = normalize_generation_usage(row["output_record"]["output"]["usage"])
            seconds = row["output_record"].get("generation_request_seconds")
            if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 <= seconds <= 86400:
                raise ValueError("known measured repair timing required")
            costs["input_tokens"] += usage["input_tokens"]
            costs["output_tokens"] += usage["output_tokens"]
            costs["elapsed_ms"] += round(seconds * 1000)
            costs["generation_calls"] += 1
        return self._seal("stage-" + stage, {"stage": stage, "scaffold_id": scaffold,
            "public_observation_evidence_sha256": observations, "choices_evidence_sha256": frozen_pin,
            "repair_manifest_sha256": loop.manifest["receipt_sha256"], "costs": costs})

    def _dispatch(self, reservation, recovery=False):
        # LearningCycle holds its writer lease. Do not call cycle.status() here;
        # prior results are already detached CAS pointers in the reservation.
        prior = {row["stage"]: json.loads(self.ledger.get_evidence(row["result_sha256"]))
                 for row in reservation["prior_results"]}
        stage = reservation["stage"]
        if stage == "propose":
            return self._proposal(reservation, recovery)
        if stage in ("practice-baseline", "practice-candidate"):
            scaffold = BASELINE if stage.endswith("baseline") else prior["propose"]["scaffold_id"]
            if stage.endswith("candidate") and scaffold == BASELINE:
                return {"stage": stage, "skipped": True, "basis_evidence_sha256":
                        prior["propose"]["proposal_evidence_sha256"], "costs": self._costs()}
            return self._repair(stage, "train", scaffold)
        if stage == "freeze":
            frozen = self.learner.freeze_training()
            return {"stage": stage, "decision_evidence_sha256": frozen["evidence_sha256"], "costs": self._costs()}
        if stage in ("trial-baseline", "trial-candidate"):
            selected = self.learner.snapshot()["training"]["body"]["selected_scaffold"]
            if stage.endswith("candidate") and selected == BASELINE:
                return {"stage": stage, "skipped": True, "basis_evidence_sha256":
                        prior["freeze"]["decision_evidence_sha256"], "costs": self._costs()}
            return self._repair(stage, "validation", BASELINE if stage.endswith("baseline") else selected)
        if stage == "promote":
            promotion = self.learner.promote()
            return {"stage": stage, "decision_evidence_sha256": promotion["evidence_sha256"], "costs": self._costs()}
        if stage == "trace":
            proposal = prior["propose"]
            trace = seal_epoch_trace(self.learner, failure_feed_sha256=proposal["failure_feed_sha256"],
                proposal_evidence_sha256=proposal["proposal_evidence_sha256"],
                run_identity_sha256=proposal["run_identity_sha256"])
            return {"stage": stage, "trace_evidence_sha256": trace["evidence_sha256"], "costs": self._costs()}
        raise ValueError("unknown bounded learning stage")

    def step(self, *, control="RUN"):
        return self.cycle.step(self._dispatch, control=control)

    def run(self, *, max_stages=8, control="RUN"):
        return self.cycle.run(self._dispatch, max_stages=max_stages, control=control)

    def status(self):
        return self.cycle.status()

    def resume_pending(self, *, evidence_sha256, justification, control="RUN"):
        # Explicit reconciliation holds the SAME controller OS writer lease
        # across recovery dispatch, preventing two callers resuming one stage.
        with self.cycle._locked():
            state = self.cycle._state()
            if self.cycle._control(control) == "STOP":
                return self.cycle._view(state, stopped=True)
            self.cycle._reconcile_fields(evidence_sha256, justification)
            if state["pending"] is None:
                raise ValueError("no pending epoch stage")
            pending = state["pending"]["body"]
            request = json.loads(self.ledger.get_evidence(pending["request_sha256"]))
            result = self._dispatch(request, recovery=True)
            result_pin = self.cycle._cas(result, "learning-cycle-result")
            self.cycle._write("reconcile", {key: pending[key] for key in ("reservation_id", "stage", "stage_index")}
                | {"result_sha256": result_pin, "evidence_sha256": evidence_sha256, "justification": justification})
            return self.cycle._view(self.cycle._complete(self.cycle._state()))

    def recover_proposal(self, response, *, elapsed_ms, evidence_sha256, justification):
        with self.cycle._locked():
            state = self.cycle._state()
            self.cycle._reconcile_fields(evidence_sha256, justification)
            if (state["pending"] is None or state["pending"]["body"]["stage"] != "propose"
                    or type(elapsed_ms) is not int or not 0 <= elapsed_ms <= 86400000):
                raise ValueError("known measured pending proposal required")
            pending = state["pending"]["body"]
            request = self._find("proposal-request")
            if request is None or request["reservation_id"] != pending["reservation_id"]:
                raise ValueError("original rendered proposal request binding is missing")
            pin = self._cas(response, "learning-epoch-proposal-raw-reconciled")
            self._seal("proposal-raw", {"reservation_id": pending["reservation_id"],
                "request_sha256": request["request_sha256"], "response_sha256": pin, "elapsed_ms": elapsed_ms})
            self._seal("proposal-recovery", {"evidence_sha256": evidence_sha256,
                                           "justification_sha256": sha256(justification.encode())})

    def active_preparer(self):
        if self.status()["status"] != "completed":
            raise ValueError("active guidance requires completed sealed epoch")
        ids = [row["task_id"] for row in self.dataset["splits"]["unseen"]]
        return ScaffoldContextPreparer(self.learner, task_ids=ids, model_ids=[self.model_id], mode="active")

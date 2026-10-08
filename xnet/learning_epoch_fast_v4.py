"""Versioned bounded learning epoch with Windows retained-artifact read leases.

The original learning_epoch.py remains frozen. All public/private task, callback,
usage, retry, context, evidence and promotion contracts are preserved here. This
namespace changes only identity-check scheduling: controller state reads and
per-callback checks keep source SHA256 and pinned read-lease continuity; explicit
learner admission, promotion and release boundaries retain complete hashes.
No metadata check is presented as a new cryptographic hash or loaded-model proof.

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
import os
from pathlib import Path
import re
import time
import types

from .generation_usage import normalize_generation_usage
from .artifact_integrity_guard_v3 import ArtifactIntegrityGuard, ArtifactIntegrityError
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

FAST_SCHEMA = "xnet.learning-epoch-fast.v4"
FAST_AUX_SCHEMA = "xnet.learning-epoch-fast-aux.v4"
FAST_SOURCE = "learning-epoch-fast-v4"
FROZEN_PREDECESSOR_SHA256 = "4849f10c01dfd161ca9acf45f64957d9f917f865a11bd212741991c29d1cc558"
FAST_V3_PREDECESSOR_SHA256 = "33ee81ffa00afd5bcd18ccd7c510ff4caafb9b592f5eb8e78c7b88ecf0604055"
CONSTRUCTOR_POLICY = "exact scoped model declarations; held Windows lease and one mandatory full initial hash before identity admission; fresh source/retained continuity after binding; full proposal/repair/promotion/release SHA256 unchanged"


def _deduplicate_artifacts(rows):
    selected = {}
    for row in rows:
        key = os.path.normcase(os.path.abspath(row["path"]))
        if key in selected and selected[key]["sha256"] != row["sha256"]:
            raise ValueError("conflicting selected artifact hash")
        selected[key] = {"path": os.path.abspath(row["path"]), "sha256": row["sha256"]}
    return [selected[key] for key in sorted(selected)]


def _source_names():
    return set(PINNED_SOURCES) | {"learning_epoch.py", "learning_cycle.py", "learning_wing.py",
        "learning_dataset.py", "scaffold_learning.py", "scaffold_context.py", "generation_usage.py",
        "context_callable_identity_v2.py", "learning_epoch_fast_v4.py", "artifact_integrity_guard_v3.py"}


def _pre_admit(artifact_gate, run_identity, model_artifacts, callback_artifacts, coach_identity, root):
    """Scope every selected file before preserved constructor validation reads it."""
    def rows(value):
        if type(value) is not list or not 1 <= len(value) <= 64:
            raise ValueError("explicit bounded artifact list required")
        for row in value:
            if (type(row) is not dict or set(row) != {"path", "sha256"}
                    or type(row["path"]) is not str or "\x00" in row["path"]
                    or not Path(row["path"]).is_absolute()
                    or type(row["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
                raise ValueError("exact bounded absolute artifact path/hash required")
        return value
    selected = rows(callback_artifacts)
    function = getattr(artifact_gate, "__func__", artifact_gate)
    if (not isinstance(function, types.FunctionType)
            or os.path.normcase(os.path.abspath(function.__code__.co_filename)) not in
                {os.path.normcase(os.path.abspath(row["path"])) for row in selected}):
        raise ValueError("artifact gate needs selected source identity")
    declared = [*rows(model_artifacts), *selected]
    if type(run_identity) is not dict or type(run_identity.get("runner")) is not dict:
        raise ValueError("full pinned run identity required")
    declared.extend(rows([run_identity.get("adapter")]))
    declared.extend(rows(run_identity["runner"].get("artifacts")))
    native = run_identity.get("native")
    if native is not None:
        if type(native) is not dict:
            raise ValueError("exact native identity required")
        declared.extend(rows([native.get("binary")]))
        declared.extend(rows(native.get("sdk_artifacts")))
    if coach_identity is not None:
        if type(coach_identity) is not dict or type(coach_identity.get("transport")) is not dict:
            raise ValueError("exact separate coach identity required")
        declared.extend(rows(coach_identity["transport"].get("artifacts")))
    paths = [row["path"] for row in _deduplicate_artifacts(declared)]
    paths.extend(str(Path(__file__).parent / name) for name in sorted(_source_names()))
    try:
        artifact_gate("artifact_guard_stat", "path:" + str(Path(root).absolute()))
        for path in dict.fromkeys(paths):
            artifact_gate("artifact_guard_stat", "path:" + path)
            artifact_gate("artifact_guard_hash", "path:" + path)
    except Exception as error:
        raise ArtifactIntegrityError("scope-refused", phase="constructor-pre-admission") from error


def _integrity_selection(run_identity, model_artifacts, callback_artifacts, coach_identity):
    retained = [*model_artifacts, *run_identity["runner"]["artifacts"]]
    sources = [run_identity["adapter"], *callback_artifacts]
    if run_identity["native"] is not None:
        retained.append(run_identity["native"]["binary"])
        sources.extend(run_identity["native"]["sdk_artifacts"])
    transport = []
    forced_source_paths = {os.path.normcase(os.path.abspath(row["path"])) for row in sources}
    if coach_identity is not None:
        for row in coach_identity["transport"]["artifacts"]:
            # A declaration in a callback/adapter/SDK role always wins. Only an
            # exact coach transport EXE/DLL role may receive a retained lease;
            # Python and other source rows keep fresh full dispatch hashing.
            if (Path(row["path"]).suffix.lower() in (".exe", ".dll")
                    and os.path.normcase(os.path.abspath(row["path"])) not in forced_source_paths):
                retained.append(row)
                transport.append(row)
            else:
                sources.append(row)
    root = Path(__file__).parent
    sources.extend({"path": str(root / name), "sha256": _artifact_sha256(root / name)}
                   for name in ("learning_epoch_fast_v4.py", "artifact_integrity_guard_v3.py"))
    _deduplicate_artifacts([*retained, *sources])  # Conflicting cross-role pins refuse.
    sources = _deduplicate_artifacts(sources)
    source_paths = {os.path.normcase(row["path"]) for row in sources}
    # Any file explicitly selected as code keeps per-dispatch full SHA256 even
    # if another declaration also listed it among runner/model artifacts.
    retained = [row for row in _deduplicate_artifacts(retained)
                if os.path.normcase(row["path"]) not in source_paths]
    transport = [row for row in _deduplicate_artifacts(transport)
                 if os.path.normcase(row["path"]) not in source_paths]
    return retained, sources, transport


def _sources():
    root = Path(__file__).parent
    result = {name: _artifact_sha256(root / name) for name in sorted(_source_names())}
    if result["learning_epoch.py"] != FROZEN_PREDECESSOR_SHA256:
        raise ValueError("frozen predecessor source drift; use a newly reviewed fast version")
    return result


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


def _artifact_declarations(rows):
    """Validate exact pinned declarations without claiming a fresh byte hash.

    This is used only after the established guard has checked all coach rows as
    fresh sources or held transport leases. Initial constructor checks remain
    full hashes. The guard policy and declarations are compared in the binding.
    """
    if type(rows) is not list or not 1 <= len(rows) <= 64:
        raise ValueError("explicit bounded artifact list required")
    for row in rows:
        if (type(row) is not dict or set(row) != {"path", "sha256"}
                or type(row["path"]) is not str or not row["path"] or "\x00" in row["path"]
                or not Path(row["path"]).is_absolute()
                or any(part in (".", "..") for part in Path(row["path"]).parts)
                or type(row["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
            raise ValueError("exact bounded absolute artifact path/hash required")
    if len({os.path.normcase(os.path.abspath(row["path"])) for row in rows}) != len(rows):
        raise ValueError("duplicate artifact path")
    return copy.deepcopy(rows)


def _coach_identity(value, *, rehash_artifacts=True):
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
    transport["artifacts"] = (_artifacts(_artifact_declarations(transport["artifacts"]))
                               if rehash_artifacts else _artifact_declarations(transport["artifacts"]))
    return value


class LearningEpoch:
    """Borrowed Lite callbacks, public repair evidence and one durable epoch.

    ``boundary_observer(loop, model_id, task_id)`` must return an existing Ledger
    CAS pointer to the exact host observation required by ingest_repair_outcome.
    The monitor authenticates/authorizes its own scope; hashes alone do not.
    ``callback_artifacts`` pins source files for all three borrowed callbacks.
    ``dataset_sha256`` is the caller-retained external public manifest identity.
    Retained weights/runner artifacts have Windows read leases, source hashes
    remain fresh at each entry, and explicit admission/release checks rehash all.
    """

    def __init__(self, ledger, root, *, epoch_id, scope_id, dataset, dataset_sha256,
            tasks, references, full_tasks_sha256, references_sha256,
            model_id, models, run_identity, model_artifacts,
            callback_artifacts, generate, propose, boundary_observer, previous=None,
            baseline_steps=("inspect-contract",), cost_ratio=2, eval_timeout=3, cas=None,
            coach_identity=None, artifact_gate):
        self._artifact_guard = None
        self._artifact_release = None
        try:
            self._initialize(ledger, root, epoch_id=epoch_id, scope_id=scope_id,
                dataset=dataset, dataset_sha256=dataset_sha256, tasks=tasks, references=references,
                full_tasks_sha256=full_tasks_sha256, references_sha256=references_sha256,
                model_id=model_id, models=models, run_identity=run_identity,
                model_artifacts=model_artifacts, callback_artifacts=callback_artifacts,
                generate=generate, propose=propose, boundary_observer=boundary_observer,
                previous=previous, baseline_steps=baseline_steps, cost_ratio=cost_ratio,
                eval_timeout=eval_timeout, cas=cas, coach_identity=coach_identity,
                artifact_gate=artifact_gate)
        except Exception:
            if self._artifact_guard is not None:
                self._artifact_guard.close()
            raise

    def _initialize(self, ledger, root, *, epoch_id, scope_id, dataset, dataset_sha256,
            tasks, references, full_tasks_sha256, references_sha256,
            model_id, models, run_identity, model_artifacts,
            callback_artifacts, generate, propose, boundary_observer, previous=None,
            baseline_steps=("inspect-contract",), cost_ratio=2, eval_timeout=3, cas=None,
            coach_identity=None, artifact_gate):
        _pre_admit(artifact_gate, run_identity, model_artifacts, callback_artifacts, coach_identity, root)
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
        # Pure exact declaration validation; guard.establish below performs the
        # mandatory constructor byte hash under deny-write/delete handles. No
        # learner, model callback or durable identity is admitted before it.
        self.model_artifacts = _artifact_declarations(model_artifacts)
        if self.models[model_id]["model_sha256"] not in {row["sha256"] for row in self.model_artifacts}:
            raise ValueError("model artifact list omits declared weights")
        self.callback_artifacts = _artifacts(callback_artifacts)
        selected = {str(Path(row["path"]).absolute()) for row in self.callback_artifacts}
        for callback in (generate, propose, boundary_observer, artifact_gate):
            fn = getattr(callback, "__func__", callback)
            if not isinstance(fn, types.FunctionType) or str(Path(fn.__code__.co_filename).absolute()) not in selected:
                raise ValueError("borrowed callbacks need selected source artifacts")
        self.generate, self.propose, self.boundary_observer = generate, propose, boundary_observer
        self.artifact_gate = artifact_gate
        retained, sources, transport = _integrity_selection(self.run_identity, self.model_artifacts,
                                                self.callback_artifacts, self.coach_identity)
        self._artifact_guard = ArtifactIntegrityGuard(retained, sources, artifact_gate,
                                                     protection="windows-read-lease", transport_artifacts=transport)
        self._artifact_guard.establish()
        self.eval_timeout = eval_timeout
        feed = seed_failure_feed() if previous is None else public_failure_feed(previous)
        incumbent = None if previous is None else incumbent_baseline(previous)
        steps = list(baseline_steps) if incumbent is None else incumbent["steps"]
        self._feed = copy.deepcopy(feed)
        self._private_binding = {"epoch_schema": FAST_SCHEMA, "root_path": str(self.root.resolve()),
            "dataset_sha256": dataset_sha256, "full_tasks_sha256": digest(self.tasks),
            "references_sha256": digest(self.references), "models": self.models,
            "run_identity_sha256": digest(self.run_identity), "model_artifacts": self.model_artifacts,
            "callback_artifacts": self.callback_artifacts, "source_pins": _sources(),
            "callback_identities": self._callback_identities(),
            "failure_feed_sha256": digest(feed), "incumbent": incumbent,
            "baseline_steps": steps, "eval_timeout": eval_timeout, "cost_ratio": cost_ratio,
            "artifact_guard_policy": self._artifact_guard.manifest,
            "fast_v3_predecessor_sha256": FAST_V3_PREDECESSOR_SHA256,
            "constructor_integrity_policy": CONSTRUCTOR_POLICY,
            "artifact_guard_code_binding": self._guard_code_binding(),
            "epoch_method_identities": self._epoch_method_identities()}
        if self.coach_identity is not None:
            self._private_binding["coach_identity"] = copy.deepcopy(self.coach_identity)
        self._private_pin = digest(self._private_binding)
        train_ids = [row["task_id"] for row in self.dataset["splits"]["train"]]
        val_ids = [row["task_id"] for row in self.dataset["splits"]["validation"]]
        probe = self._new_loop("identity-admission", train_ids)
        self.learner = ScaffoldLearner(ledger, epoch_id, train_ids, val_ids,
            public_verifier_identity(probe, model_id), baseline_steps=steps, cost_ratio=cost_ratio)
        self._task = "learning-epoch-fast-v4-" + digest([epoch_id, self._private_pin])[:32]
        self._scope = scope_id
        self._epoch_id = epoch_id
        # Establish already hashed every selected artifact while retaining its
        # write/delete-denying lease. No callback has occurred since then; a
        # fresh source and continuity check now binds the controller identity.
        identities = self._identity(rehash_models=False)
        self.cycle = LearningCycle(ledger, {"schema": CONFIG_SCHEMA, "epoch_id": epoch_id,
            "scope_id": scope_id, "identities": identities, "baseline_sha256": digest(steps),
            "cost_policy": {"max_token_ratio": cost_ratio, "max_wall_ratio": cost_ratio}},
            identity_reader=self._controller_identity)
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
        if rehash_models:
            self._artifact_guard.full_boundary("learner-admission")
        else:
            self._artifact_guard.verify_dispatch()
        native = self.run_identity["native"]
        if self.cas is not None:
            if native is None:
                raise ValueError("run identity requires native artifacts for borrowed CAS")
            binary_pin = getattr(self.cas, "binary_sha256", None)
            if binary_pin is not None and binary_pin != native["binary"]["sha256"]:
                raise ValueError("run identity native binary differs from borrowed CAS")
        _artifacts(self.callback_artifacts)
        binding = self._private_binding | {"root_path": str(self.root.resolve()), "source_pins": _sources(),
            "full_tasks_sha256": digest(self.tasks), "references_sha256": digest(self.references),
            "models": self.models, "run_identity_sha256": digest(self.run_identity),
            "failure_feed_sha256": digest(self._feed), "model_artifacts": self.model_artifacts,
            "callback_artifacts": self.callback_artifacts, "callback_identities": self._callback_identities(),
            "eval_timeout": self.eval_timeout, "epoch_schema": FAST_SCHEMA,
            "fast_v3_predecessor_sha256": FAST_V3_PREDECESSOR_SHA256,
            "constructor_integrity_policy": CONSTRUCTOR_POLICY,
            "artifact_guard_policy": self._artifact_guard.manifest,
            "artifact_guard_code_binding": self._guard_code_binding(),
            "epoch_method_identities": self._epoch_method_identities()}
        if self.coach_identity is not None:
            # Guard just verified every coach row: source rows freshly hashed,
            # immutable transport rows bound to held deny-write/delete leases.
            # This structural validation adds no second executable hash pass.
            binding["coach_identity"] = _coach_identity(self.coach_identity, rehash_artifacts=False)
        elif "coach_identity" in binding:
            raise ValueError("separate coach identity removed from frozen epoch")
        if digest(binding) != self._private_pin:
            raise ValueError("epoch source/task/reference/runtime binding drift")
        return {"manifest_sha256": self._dataset_pin, "model_sha256": self.models[self.model_id]["model_sha256"],
            "adapter_sha256": self.run_identity["adapter"]["sha256"], "source_sha256": self._private_pin}

    def _controller_identity(self):
        """Controller reads keep full source hashes without repeating large reads."""
        return self._identity(rehash_models=False)

    def _epoch_method_identities(self):
        result = {}
        for name in ("__init__", "_initialize", "_identity", "_controller_identity", "_proposal", "_repair",
                     "_dispatch", "_new_loop", "_find", "_seal", "_cas", "_callback_identities",
                     "_epoch_method_identities", "_guard_code_binding", "step", "run", "status",
                     "resume_pending", "recover_proposal", "active_preparer",
                     "close_artifact_guard", "artifact_integrity_status", "verify_transport_artifacts"):
            function = getattr(getattr(self, name), "__func__", getattr(self, name))
            if not isinstance(function, types.FunctionType):
                raise ValueError("source-pinned fast epoch methods required")
            result[name] = {"qualname": function.__qualname__, "code_sha256": code_sha256(function.__code__)}
        return result

    def _guard_code_binding(self):
        if type(self._artifact_guard) is not ArtifactIntegrityGuard:
            raise ValueError("exact versioned artifact guard required")
        result = {}
        for name in ("establish", "verify_dispatch", "full_boundary", "close", "metrics", "_ready",
                     "_admit", "_snapshot", "_unchanged", "_acquire_leases", "_hash", "_full", "_refuse",
                     "verify_transport_artifacts"):
            function = getattr(getattr(self._artifact_guard, name), "__func__", getattr(self._artifact_guard, name))
            if not isinstance(function, types.FunctionType):
                raise ValueError("source-pinned artifact guard methods required")
            result[name] = {"qualname": function.__qualname__, "code_sha256": code_sha256(function.__code__)}
        return result

    def artifact_integrity_status(self):
        """Detached check-cost metrics; no fresh hash or model attestation claim."""
        return self._artifact_guard.metrics()

    def verify_transport_artifacts(self, rows):
        """Source-bound borrowed transport continuity; no lease ownership.

        The surrounding callback retains original fresh source and full-boundary
        checks. Exact declared retained transport pins only, never an arbitrary
        file read/authorization or a replacement for a model identity check.
        """
        if (self._guard_code_binding() != self._private_binding["artifact_guard_code_binding"]
                or self._epoch_method_identities() != self._private_binding["epoch_method_identities"]):
            raise ValueError("borrowed transport integrity code binding drift")
        return self._artifact_guard.verify_transport_artifacts(rows)

    def close_artifact_guard(self):
        """Explicit complete release hash, then close owned retained read leases."""
        if self._artifact_release is not None:
            return copy.deepcopy(self._artifact_release)
        try:
            self._identity(rehash_models=False)
            proof = self._artifact_guard.full_boundary("release")
        finally:
            self._artifact_guard.close()
        self._artifact_release = {"schema": FAST_SCHEMA, "release_proof": proof,
                                  "metrics": self._artifact_guard.metrics()}
        return copy.deepcopy(self._artifact_release)

    def _callback_identities(self):
        result = {}
        for key in ("generate", "propose", "boundary_observer", "artifact_gate"):
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
            if (event["source"] != FAST_SOURCE or event["scope_id"] != self._scope
                    or event["kind"] != "learning-epoch-fast-v4-record"
                    or type(payload) is not dict or set(payload) != {"kind", "record_sha256"}
                    or type(payload["kind"]) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", payload["kind"])
                    or type(payload["record_sha256"]) is not str
                    or not re.fullmatch(r"[0-9a-f]{64}", payload["record_sha256"])):
                raise ValueError("epoch auxiliary event binding conflict")
            wrapper = json.loads(self.ledger.get_evidence(payload["record_sha256"]))
            if (type(wrapper) is not dict or set(wrapper) != {"schema", "private_binding_sha256", "kind", "body"}
                    or type(wrapper["schema"]) is not str or wrapper["schema"] != FAST_AUX_SCHEMA
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
        wrapper = {"schema": FAST_AUX_SCHEMA, "private_binding_sha256": self._private_pin,
                   "kind": kind, "body": body}
        pin = self._cas(wrapper, FAST_SOURCE)
        self.ledger.append(make_event(self._task, self._scope, "learning-epoch-fast-v4-record",
            {"kind": kind, "record_sha256": pin}, source=FAST_SOURCE))
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
        # guards still fully hash selected source/adapter/callback files and
        # bind retained OS read leases, then compare immutable data/config
        # bindings. They do not claim a fresh retained-artifact content hash.
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
            self._identity()  # Explicit complete content boundary before promotion.
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

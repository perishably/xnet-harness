"""Borrowed public context, measured session and bounded epoch stage bindings.

The outer coordinator owns its durable queue. Native context, session handoffs,
sphere storage and learning retain their existing authorities. A waiting receipt
requires explicit outer reconciliation after the nested authority is recovered;
this adapter never repeats an uncertain inference or exports private originals.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import types

from adapters.jcode.sphere_peer import JcodeSpherePeer
from xnet.context_callable_identity_v2 import code_sha256
from xnet.learning_cycle import PendingStageError
from xnet.learning_epoch import LearningEpoch
from xnet.oroboros_session import OroborosSession, PendingHandoff
from xnet.protocol import canonical, digest, sha256
from xnet.relay_log import _no_links
from xnet.repair_loop import RepairLoop
from xnet.scaffold_context import ingest_repair_outcome
from xnet_sdk import ContextPeer


SCHEMA = "xnet.jcode.outer-stage.v1"
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_EVENT_FIELDS = {"seq", "event_id", "peer", "kind", "source_digest", "event_digest"}
_COST_FIELDS = {"input_tokens", "output_tokens", "elapsed_ms", "generation_calls"}


def _callback_identity(callback):
    fn = getattr(callback, "__func__", callback)
    if not isinstance(fn, types.FunctionType):
        raise ValueError("borrowed callback needs a Python source artifact")
    path = Path(fn.__code__.co_filename).absolute()
    _no_links(path, regular_file=True)
    return {"module": fn.__module__, "qualname": fn.__qualname__,
            "path": str(path), "source_sha256": sha256(path.read_bytes()),
            "code_sha256": code_sha256(fn.__code__)}


def _label(value, description):
    if type(value) is not str or not _ID.fullmatch(value):
        raise ValueError(description + " requires a bounded identity")
    return value


def _hash(value, description):
    if type(value) is not str or not _HEX.fullmatch(value):
        raise ValueError(description + " requires an exact SHA256")
    return value


class JcodeOuterPeer:
    """Bind three outer stages to explicitly borrowed caller-owned peers.

    ``payload[stage]`` is the stage's public input. Missing optional peers return
    disabled receipts. A configured peer without required input returns waiting.
    Source pins are local callback identity, not model or sender authentication.
    Neither model lifecycle nor execution of model tools is owned here.
    """

    def __init__(self, context_peer: ContextPeer, *, sphere_peer=None,
                 session_controller=None, open_fresh=None, learning_epoch=None,
                 repair_loops=None):
        if not isinstance(context_peer, ContextPeer):
            raise ValueError("borrowed ContextPeer required")
        if sphere_peer is not None and (not isinstance(sphere_peer, JcodeSpherePeer)
                                       or sphere_peer.context is not context_peer):
            raise ValueError("sphere source must borrow the same ContextPeer")
        if session_controller is not None and (not isinstance(session_controller, OroborosSession)
                                              or session_controller.peer is not context_peer):
            raise ValueError("session owner must borrow the same ContextPeer")
        if open_fresh is not None and session_controller is None:
            raise ValueError("open_fresh requires the borrowed session controller")
        if learning_epoch is not None and not isinstance(learning_epoch, LearningEpoch):
            raise ValueError("borrowed LearningEpoch required")
        loops = {} if repair_loops is None else dict(repair_loops)
        if len(loops) > 16 or (loops and learning_epoch is None):
            raise ValueError("bounded public outcome registry requires a learning epoch")
        for name, loop in loops.items():
            _label(name, "repair loop")
            if not isinstance(loop, RepairLoop):
                raise ValueError("borrowed RepairLoop required for public outcome transfer")
        self.context_peer, self.sphere_peer = context_peer, sphere_peer
        self.session_controller, self.open_fresh = session_controller, open_fresh
        self.learning_epoch, self.repair_loops = learning_epoch, loops
        self._owners = (context_peer, sphere_peer, session_controller, learning_epoch)
        self._context_binding = (context_peer.task_id, context_peer.peer, context_peer.client)
        self._session_binding = None if session_controller is None else digest(session_controller.config)
        self._epoch_binding = None if learning_epoch is None else digest(learning_epoch.cycle.config)
        self._loop_bindings = {name: (loop, loop.manifest["receipt_sha256"]) for name, loop in loops.items()}
        callbacks = self._selected_callbacks()
        self._callbacks = callbacks
        self._callback_pins = {name: _callback_identity(fn) for name, fn in callbacks.items()}

    def callbacks(self):
        return {"context": self.context_stage, "session": self.session_stage, "learn": self.learn_stage}

    def _selected_callbacks(self):
        selected = self.callbacks()
        selected.update({"context_" + name: getattr(self.context_peer, name)
                         for name in ("history", "fetch_event")})
        if self.sphere_peer is not None:
            selected.update({"sphere_" + name: getattr(self.sphere_peer, name)
                             for name in ("admit", "public_context")})
        if self.session_controller is not None:
            selected["session_report"] = self.session_controller.report_and_rotate
        if self.open_fresh is not None:
            selected["open_fresh"] = self.open_fresh
        if self.learning_epoch is not None:
            selected.update({"epoch_" + name: getattr(self.learning_epoch, name)
                             for name in ("generate", "propose", "boundary_observer", "step", "run", "status")})
            selected["public_outcome_transfer"] = ingest_repair_outcome
        return selected

    def _bound(self):
        if self._owners != (self.context_peer, self.sphere_peer, self.session_controller, self.learning_epoch):
            raise ValueError("borrowed outer peer ownership changed")
        peer = self.context_peer
        if self._context_binding != (peer.task_id, peer.peer, peer.client):
            raise ValueError("borrowed context task/peer/gateway changed")
        if self.sphere_peer is not None and self.sphere_peer.context is not peer:
            raise ValueError("sphere context binding changed")
        if self.session_controller is not None and (self.session_controller.peer is not peer or
                digest(self.session_controller.config) != self._session_binding):
            raise ValueError("borrowed session binding changed")
        if self.learning_epoch is not None and digest(self.learning_epoch.cycle.config) != self._epoch_binding:
            raise ValueError("borrowed learning epoch binding changed")
        current = self._selected_callbacks()
        if set(current) != set(self._callbacks):
            raise ValueError("borrowed callback selection changed")
        for name, fn in current.items():
            if fn != self._callbacks[name] or _callback_identity(fn) != self._callback_pins[name]:
                raise ValueError("borrowed callback identity or source bytes changed")
        if set(self.repair_loops) != set(self._loop_bindings):
            raise ValueError("borrowed public outcome registry changed")
        for name, (loop, pin) in self._loop_bindings.items():
            if self.repair_loops[name] is not loop or loop.manifest["receipt_sha256"] != pin:
                raise ValueError("borrowed repair outcome binding changed")

    def _request(self, request, stage):
        self._bound()
        if (type(request) is not dict or request.get("stage") != stage
                or request.get("task_id") != self.context_peer.task_id
                or type(request.get("payload")) is not dict or len(canonical(request)) > 1024 * 1024):
            raise ValueError("exact borrowed task and bounded outer stage request required")
        value = request["payload"].get(stage)
        if value is not None and type(value) is not dict:
            raise ValueError("outer stage payload must be an explicit object")
        if "stage_scope_id" in request:
            _label(request["stage_scope_id"], "caller-selected nested stage scope")
        return copy.deepcopy(value)

    def _receipt(self, request, stage, status, *, result=None, reason=None, costs=None,
                 costs_basis="unreported"):
        value = {"schema": SCHEMA, "stage": stage, "task_id": self.context_peer.task_id,
                 "status": status, "callback_identity": copy.deepcopy(self._callback_pins[stage]),
                 "outer_reservation_id": request.get("reservation_id"),
                 "scope_id": request.get("scope_id"),
                 "stage_scope_id": request.get("stage_scope_id", request.get("scope_id")),
                 "request_sha256": digest(request), "result": result, "reason": reason,
                 "costs": costs, "costs_basis": costs_basis, "authority": "none",
                 "model_lifecycle_owned": False, "model_tools_executed": False,
                 "private_originals_copied": False}
        prefixes = {"context": ("context_", "sphere_"), "session": ("session_",),
                    "learn": ("epoch_", "public_outcome_")}[stage]
        value["borrowed_callback_identities"] = {name: copy.deepcopy(pin)
            for name, pin in self._callback_pins.items() if name.startswith(prefixes)}
        if stage == "session":
            value["open_fresh_identity"] = copy.deepcopy(self._callback_pins.get("open_fresh"))
        elif stage == "learn":
            value["epoch_callback_identities"] = {name[6:]: copy.deepcopy(pin)
                for name, pin in self._callback_pins.items() if name.startswith("epoch_")}
        if len(canonical(value)) > 65536:
            raise ValueError("complete outer stage receipt exceeds bound; clipping refused")
        return value

    def context_stage(self, request):
        """Adopt selected public sphere packets or exact owned native occurrences."""
        value = self._request(request, "context")
        if value is None or value.get("enabled") is False:
            return self._receipt(request, "context", "disabled", reason="public-context-disabled")
        if value.get("visibility") != "public":
            raise ValueError("explicit caller declaration of public context required")
        action = value.get("action")
        budget = value.get("max_bytes", 8192)
        if type(budget) is not int or not 128 <= budget <= 16384:
            raise ValueError("bounded complete public context required")
        if action in ("sphere-admit", "sphere-select"):
            if self.sphere_peer is None:
                return self._receipt(request, "context", "waiting", reason="sphere-peer-not-bound")
            if request.get("stage_scope_id", request.get("scope_id")) != self.sphere_peer.sphere.scope_id:
                raise ValueError("outer sphere scope differs from caller's selected source scope")
            lane = value.get("lane", "powershell")
            if action == "sphere-admit":
                admission = self.sphere_peer.admit(value["packet"], lane,
                    expected_sphere_head=value.get("expected_sphere_head"))
                event = admission["native"]["event"]
                public = self.sphere_peer.public_context([event], max_bytes=budget, lane=lane)
                result = {"admission": admission, "public_context": public}
            else:
                result = {"public_context": self.sphere_peer.public_context(
                    value["selected_events"], max_bytes=budget, lane=lane)}
        elif action == "native-select":
            events = value.get("selected_events")
            if type(events) is not list or not 1 <= len(events) <= 16:
                raise ValueError("one to sixteen explicit native occurrences required")
            seen, records, raw_bytes = set(), [], 0
            # Admit every occurrence's task membership before root-wide FETCH.
            for event in events:
                if (type(event) is not dict or set(event) != _EVENT_FIELDS
                        or type(event["seq"]) is not int or not 0 <= event["seq"] < 2048
                        or event["peer"] != self.context_peer.peer or event["kind"] != "raw"):
                    raise ValueError("exact owned native public occurrence required")
                _label(event["event_id"], "native occurrence")
                for key in ("source_digest", "event_digest"):
                    _hash(event[key], "native occurrence")
                if event["event_id"] in seen:
                    raise ValueError("duplicate selected native occurrence")
                page = self.context_peer.history(after=event["seq"], limit=1)
                if page.get("task_id") != self.context_peer.task_id or page.get("events") != [event]:
                    raise ValueError("selected occurrence is not in the borrowed native task")
                seen.add(event["event_id"])
            for event in events:
                text = self.context_peer.fetch_event(event)
                raw_bytes += len(text.encode("utf-8"))
                records.append({"record_id": event["event_id"], "kind": "frozen-fetch",
                    "text": text, "source_sha256": event["source_digest"],
                    "text_sha256": sha256(text.encode("utf-8")), "receipt_sha256": event["event_digest"]})
            if raw_bytes > budget:
                raise ValueError("complete public context exceeds budget; clipping refused")
            result = {"public_context": {"schema": "xnet.jcode.outer-public-context.v1",
                "task_id": self.context_peer.task_id, "records": records,
                "visibility": "caller-declared-public", "authority": "none", "context_only": True}}
        else:
            raise ValueError("explicit public context action required")
        result["model_calls"] = 0
        return self._receipt(request, "context", "completed", result=result)

    def session_stage(self, request):
        """Report absolute caller-measured occupancy and borrow one real callback."""
        value = self._request(request, "session")
        if self.session_controller is None or (value is not None and value.get("enabled") is False):
            return self._receipt(request, "session", "disabled", reason="session-peer-disabled")
        if value is None:
            return self._receipt(request, "session", "waiting", reason="measured-session-input-required")
        if self.open_fresh is None:
            return self._receipt(request, "session", "waiting", reason="open-fresh-not-bound")
        if value.get("action", "report") != "report":
            raise ValueError("outer session stage accepts measured reports; reconcile on the session owner")
        snapshot = value.get("snapshot")
        if (type(snapshot) is not dict or set(snapshot) != {"session_id", "revision", "used", "prompt_sha256"}
                or type(snapshot["revision"]) is not int or snapshot["revision"] < 0
                or type(snapshot["used"]) is not int
                or not 0 <= snapshot["used"] <= self.session_controller.config["window"]):
            raise ValueError("complete absolute current-session snapshot required")
        _label(snapshot["session_id"], "measured session")
        _hash(snapshot["prompt_sha256"], "measured prompt")
        required = value.get("required_ids")
        if (type(required) is not list or not 1 <= len(required) <= 16
                or len(set(required)) != len(required)):
            raise ValueError("one to sixteen explicitly selected session sources required")
        for event_id in required:
            _label(event_id, "session source")
        budget = value.get("max_bytes", 8192)
        if type(budget) is not int or not 128 <= budget <= 32768:
            raise ValueError("bounded session capsule required")
        try:
            result = self.session_controller.report_and_rotate(snapshot, self.open_fresh,
                required_ids=required, max_bytes=budget)
        except Exception as error:
            state = self.context_peer.state()
            if not isinstance(error, PendingHandoff) and state.get("pending") is None:
                raise
            pending = state.get("pending")
            return self._receipt(request, "session", "waiting", reason="session-handoff-reconciliation-required",
                result={"plan_id": None if pending is None else pending["plan_id"],
                        "error_type": type(error).__name__,
                        "error_sha256": sha256(str(error).encode("utf-8", errors="replace")),
                        "callback_repeated": False})
        state = result["state"]
        session = state.get("session")
        result = {"session_status": result["status"], "plan_id": result.get("plan_id"),
                  "history_head": state.get("history_head"),
                  "snapshot": None if session is None else {key: session[key] for key in
                     ("session_id", "revision", "used", "prompt_sha256")},
                  "occupancy_basis": "caller_reported_current_snapshot",
                  "pending_plan_id": None if state.get("pending") is None else state["pending"]["plan_id"]}
        return self._receipt(request, "session", "waiting" if state.get("pending") else "completed", result=result)

    def _epoch_result(self, view):
        """Copy public proof pointers and existing costs, never original bundles."""
        selected, totals = [], {key: 0 for key in _COST_FIELDS}
        all_known = True
        for row in view["results"]:
            body = row["body"]
            result = json.loads(self.learning_epoch.ledger.get_evidence(body["result_sha256"]))
            item = {"stage": body["stage"], "result_sha256": body["result_sha256"],
                    "receipt_sha256": row["receipt_sha256"]}
            for key in ("proposal_evidence_sha256", "decision_evidence_sha256", "trace_evidence_sha256",
                        "choices_evidence_sha256", "repair_manifest_sha256"):
                if key in result:
                    item[key] = _hash(result[key], "public epoch proof")
            if "public_observation_evidence_sha256" in result:
                pointers = result["public_observation_evidence_sha256"]
                if type(pointers) is not list or len(pointers) > 64:
                    raise ValueError("bounded public learning observations required")
                item["public_observation_evidence_sha256"] = [
                    _hash(pin, "public epoch observation") for pin in pointers]
            costs = result.get("costs")
            if costs is None:
                all_known = False
            elif (type(costs) is not dict or set(costs) != _COST_FIELDS
                    or any(type(n) is not int or n < 0 for n in costs.values())):
                raise ValueError("sealed epoch result contains invalid measured costs")
            else:
                for key in totals:
                    totals[key] += costs[key]
            selected.append(item)
        pending = view["pending"]
        result = {key: copy.deepcopy(view[key]) for key in
                  ("epoch_id", "config_sha256", "status", "next_stage", "completed_stages", "weights_updated")}
        result.update(public_results=selected,
            pending=None if pending is None else {key: pending["body"][key] for key in
                ("reservation_id", "stage", "stage_index", "request_sha256")},
            completion_receipt_sha256=None if view["completion"] is None else view["completion"]["receipt_sha256"])
        costs = totals if all_known and selected and pending is None else None
        return result, costs

    def learn_stage(self, request):
        """Drive bounded epoch progress or transfer a selected sealed public result."""
        value = self._request(request, "learn")
        epoch = self.learning_epoch
        if epoch is None or (value is not None and value.get("enabled") is False):
            return self._receipt(request, "learn", "disabled", reason="learning-peer-disabled")
        if value is None:
            return self._receipt(request, "learn", "waiting", reason="bounded-learning-input-required")
        if request.get("stage_scope_id", request.get("scope_id")) != epoch.cycle.config["scope_id"]:
            raise ValueError("outer learning scope differs from caller's selected epoch scope")
        action = value.get("action")
        if action == "public-outcome":
            loop = self.repair_loops.get(value.get("loop_id"))
            if loop is None:
                raise ValueError("public outcome requires a constructor-selected borrowed repair loop")
            observed = ingest_repair_outcome(epoch.learner, loop, value["model_id"], value["repair_task_id"],
                value["scaffold_id"], boundary_evidence_sha256=_hash(
                    value["boundary_evidence_sha256"], "sealed host boundary observation"))
            result = {"public_observation_evidence_sha256": observed["evidence_sha256"],
                      "public_observation_receipt_sha256": observed["receipt_sha256"],
                      "report": observed["body"]["report"], "hidden_grade_read": False,
                      "candidate_source_copied": False, "model_calls": 0}
            return self._receipt(request, "learn", "completed", result=result)
        if action not in ("step", "run", "status"):
            raise ValueError("explicit bounded learning action required")
        control = value.get("control", "RUN")
        if type(control) is not str or control not in ("RUN", "STOP"):
            raise ValueError("learning control must be RUN or STOP")
        maximum = value.get("max_stages", 8)
        if type(maximum) is not int or not 1 <= maximum <= 8:
            raise ValueError("outer learning dispatch is bounded to one through eight stages")
        view = epoch.status()
        if view["pending"] is None and view["status"] != "completed" and action != "status":
            try:
                view = epoch.step(control=control) if action == "step" else epoch.run(max_stages=maximum, control=control)
            except PendingStageError:
                view = epoch.status()
        result, costs = self._epoch_result(view)
        complete = view["status"] == "completed"
        return self._receipt(request, "learn", "completed" if complete else "waiting", result=result,
            reason=None if complete else "epoch-reconciliation-required" if view["pending"] else "epoch-incomplete",
            costs=costs, costs_basis="unreported" if costs is None else
            "sealed-epoch-result-costs" if complete else "sealed-completed-stages-only")

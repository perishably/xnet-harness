"""Practice preview with caller-owned transport, public review and source cache.

No process, endpoint, worker lifecycle or task answer is owned by this module.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import time

import frozen_integrations as integrations
from frozen_integrations import adapter, review
from halo_binding import HaloBinding
from metadata_bridge import PracticeMetadata

AdapterError, UncertainCall = adapter.AdapterError, adapter.UncertainCall
canonical, digest, number = adapter.canonical, adapter.digest, adapter.number
HERE = Path(__file__).resolve().parent
SOURCES = ("controller.py", "metadata_bridge.py", "halo_binding.py", "frozen_integrations.py", "preview_cli.py")

CONVENTIONS = """PRACTICE PREVIEW PUBLIC CONVENTIONS
read(path,start,end) uses 1-based inclusive source line bounds. Explicit reads return exact current source text, at most 64 lines and 8192 UTF-8 bytes, with omitted bounds and a next line. Cached source is labeled and its prompt tokens still count. A cached hit never means an empty content stub.
issue(start,end) uses 0-based Unicode character offsets, start inclusive and end exclusive; maximum page 8192 characters. Unshown source or issue bytes are omitted, never summarized or assumed absent.
source_sha256 is the whole CURRENT file byte identity. Use it as edit before_sha256. Retrieved byte chunks may split lines; use read for exact line spans. After an edit use its returned after_sha256; old hashes are stale. Existing complete current source observations satisfy read-before-edit.
Metadata predictions are advisory public source data. Before each request the controller prewarms task-local practice sources; prompt packing reads only the hot window. Explicit read can use verified current CAS or the ordinary public source tool on a cache miss. No official task, hidden test or answer is indexed.
Builder may inspect and patch, Breaker may inspect, patch and challenge, Arbiter may inspect, patch and decide. All public tools remain available in each phase. Ordinary calls are 12/6/6, with 24 total calls, 30000 output tokens and 900 active seconds. Finish yields the current role; an empty Builder finish is held until its allocation ends so patch progress can occur.
A changed candidate receives deterministic public review automatically, and finish checks the same candidate. This declared review adds no model calls, has at most four actual worker dispatches, and consumes the same active-time deadline. Exact patch/profile/snapshot replay uses its prior public result with no new tests. Unknown results require explicit reconciliation and never passing acceptance. Passing public tests show only that exact public profile result, not future task correctness.
Every model response, including invalid actions and repeated reads, consumes a call and reported output tokens. No free hidden tools, summaries, extra model calls or correctness claims are added. End honestly when verification is absent or the registered budget is exhausted.
"""
ROLE_TEXT = {
    "Builder": "Inspect relevant public source and make a candidate when justified.",
    "Breaker": "Review the current candidate against the original issue and public evidence; repair justified defects.",
    "Arbiter": "Decide the candidate using the original issue, current sources and exact public review evidence.",
}


@dataclass(frozen=True)
class QualityPolicy:
    max_calls: int = 24
    max_output_tokens: int = 30000
    max_active_seconds: int = 900
    rotation_pin: int = 6400
    builder_calls: int = 12
    breaker_calls: int = 6
    arbiter_calls: int = 6
    max_public_reviews: int = 4
    schedule: tuple = ("Builder", "Breaker", "Arbiter")

    def validate(self):
        # Alternate preregistered order changes only scheduling, never tool scope.
        if asdict(self) | {"schedule": ("Builder", "Breaker", "Arbiter")} != asdict(QualityPolicy()):
            raise AdapterError("quality ceilings and role allocations are fixed at 24/30000/900, 12/6/6, four public reviews")
        if type(self.schedule) is not tuple or self.schedule not in {
                ("Builder", "Breaker", "Arbiter"), ("Breaker", "Builder", "Arbiter")}:
            raise AdapterError("registered schedule must retain all roles and final Arbiter")
        for key, value in asdict(self).items():
            if key != "schedule" and type(value) is not int:
                raise AdapterError("policy quantities must be exact integers")
        return self

    def quota(self, role):
        return {"Builder": self.builder_calls, "Breaker": self.breaker_calls,
                "Arbiter": self.arbiter_calls}[role]


def source_pins():
    return {name: digest((HERE / name).read_bytes()) for name in SOURCES} | integrations.verify()


class PreviewLoop(adapter.AgentLoop):
    """One practice session, exact measured tokenizer, and deadline-aware worker.

    bounded_public_worker(request, *, remaining_seconds=float) must enforce that
    hard transport deadline. The strict public-test request itself is unchanged.
    Model callbacks receive remaining_active_seconds in their reserved request.
    Cancellation is an exact boolean predicate, not a lifecycle command.
    """
    def __init__(self, session, callback, token_counter, *, bounded_public_worker,
                 public_profile, public_profile_sha256, scope="accuracy-preview-practice",
                 policy=None, halo_binding=None, cancelled=None):
        self.policy = (policy or QualityPolicy()).validate()
        if not callable(callback) or not callable(token_counter) or not callable(bounded_public_worker):
            raise AdapterError("caller model, measured tokenizer and hard deadline public worker are required")
        if not isinstance(scope, str) or not adapter.ID_RE.fullmatch(scope) or "official" in scope.casefold():
            raise AdapterError("separate bounded practice metadata scope required")
        self.cancelled = cancelled or (lambda: False)
        if not callable(self.cancelled): raise AdapterError("cancellation predicate required")
        self.halo = halo_binding or HaloBinding()
        self._state, self._started = None, None
        self.bounded_worker = bounded_public_worker
        self.profile, self.profile_sha = public_profile, public_profile_sha256
        super().__init__(session, callback, token_counter, public_profiles=[public_profile],
            max_calls=self.policy.max_calls, max_output_tokens=self.policy.max_output_tokens,
            max_active_seconds=self.policy.max_active_seconds, rotation_pin=self.policy.rotation_pin)
        self.sources = source_pins()
        self.metadata = PracticeMetadata(session, scope, self._cancelled)
        self.reviewer = review.PublicReview(session, self._worker, public_profile,
            public_profile_sha256, self.remaining_seconds, max_reviews=self.policy.max_public_reviews)
        self.plan = {"schema": "xnet.accuracy-preview.practice.r03", "policy": asdict(self.policy),
            "sources": self.sources, "public_profile": public_profile, "public_profile_sha256": public_profile_sha256,
            "scope": scope, "metadata_mode": "practice", "metadata_provenance": "practice-stream",
            "halo": self.halo.plan(), "conventions_sha256": digest(CONVENTIONS.encode()),
            "automatic_public_review": "changed-candidate and before-finish; caller hard remaining deadline",
            "hidden_grading": False, "model_lifecycle": "caller-owned", "model_calls_added": 0}
        self.plan_path = session.root / "accuracy-preview-plan.json"
        if self.plan_path.exists() and self.plan_path.read_bytes() != canonical(self.plan):
            self.metadata.close()
            raise AdapterError("preview plan changed; use a fresh namespace")
        if not self.plan_path.exists(): adapter.atomic_write(self.plan_path, canonical(self.plan))

    def close(self):
        self.metadata.close()

    def _cancelled(self):
        value = self.cancelled()
        if type(value) is not bool: raise AdapterError("cancellation must return an exact boolean")
        return value

    def _verify(self):
        if source_pins() != self.sources or self.plan_path.read_bytes() != canonical(self.plan):
            raise AdapterError("preview source or plan drift")
        self.session.journal.verify()
        self.halo.verify()

    def _hold_uncertain(self):
        db = self.session.journal.db
        if db.execute("SELECT 1 FROM calls WHERE status!='completed' LIMIT 1").fetchone() or \
                db.execute("SELECT 1 FROM actions WHERE status!='completed' LIMIT 1").fetchone():
            raise UncertainCall("prior model/tool/review outcome requires reconciliation before tokenizer or dispatch")
        events = [json.loads(p) for p, in db.execute("SELECT payload FROM events ORDER BY seq")]
        starts = [e for e in events if e["kind"] == "preview-final-stage-started"]
        checkpoints = [e for e in events if e["kind"] == "preview-final-checkpoint"]
        if len(starts) > len(checkpoints):
            raise UncertainCall("prior final review/checkpoint timing is incomplete; no zero-cost continuation")

    def remaining_seconds(self):
        active = 0.0 if self._state is None else self._state["active_seconds"]
        elapsed = 0.0 if self._started is None else time.monotonic() - self._started
        return max(0.0, self.max_seconds - active - elapsed)

    def _worker(self, request):
        self._verify()
        if self._cancelled(): raise UncertainCall("cancelled before reserved public dispatch")
        remaining = self.remaining_seconds()
        if remaining <= 0: raise UncertainCall("public transport has no remaining active deadline")
        return self.bounded_worker(request, remaining_seconds=remaining)

    def _load_state(self):
        events = [json.loads(p) for p, in self.session.journal.db.execute("SELECT payload FROM events ORDER BY seq")]
        completed = [e["value"] for e in events if e["kind"] == "agent-iteration-completed"]
        state = json.loads(self.session.journal.get(completed[-1]["state_hash"])) if completed else {
            "next_call": 1, "observations": [], "archived": [], "active_seconds": 0.0, "rotations": 0,
            "role_index": 0, "role_calls": 0, "last_review": None,
            "terminal_phase_complete": False, "terminal_phase_reason": None}
        return self.recover_iteration_state(state)

    def _role(self):
        return self.policy.schedule[self._state["role_index"]]

    def _read(self, path, start=1, end=200):
        number(start, 1, 1000000, "start")
        number(end, start, min(start + 999, 1000000), "end")
        cached = self.metadata.current_source(path)
        if cached is None:
            target = self.session._path(path)
            if target.stat().st_size > adapter.MAX_FILE: raise AdapterError("source file exceeds read cap")
            raw = target.read_bytes()
            source_hash = digest(raw); text = raw.decode("utf-8")
        else:
            text, source_hash = cached["text"], cached["source_sha256"]
        if "\0" in text: raise AdapterError("binary source read refused")
        lines, output = text.splitlines(), []
        actual_end = min(end, start + 63, len(lines))
        for line in range(start, actual_end + 1):
            item = f"{line}: {lines[line - 1]}"
            if len("\n".join(output + [item]).encode()) > 8192: break
            output.append(item)
        returned_end = start + len(output) - 1
        if not output and start <= len(lines):
            raise AdapterError("one exact source line exceeds read cap; use a bounded literal search")
        result = {"path": path, "sha256": source_hash, "source_sha256": source_hash,
            "current_file_sha256": source_hash, "total_lines": len(lines), "text": "\n".join(output),
            "requested_start_line": start, "requested_end_line": end, "start_line": start,
            "end_line": returned_end, "complete_file": start == 1 and returned_end == len(lines),
            "omitted_before": start > 1, "omitted_after": returned_end < len(lines),
            "next_line": returned_end + 1 if returned_end < len(lines) else None,
            "cached_source": cached is not None, "identity": "verified-current-source-bytes",
            "prompt_tokens_counted": True}
        return self.session._observe("preview-read", {"path": path, "start": start, "end": end}, result)

    def _dispatch(self, action):
        kind, arguments = action["action"], action["arguments"]
        if kind == "finish":
            if arguments: raise AdapterError("finish takes no arguments")
            return {"finish_requested": True}
        if kind == "public-test":
            if set(arguments) != {"profile"} or arguments["profile"] != self.profile:
                raise AdapterError("only the one frozen public profile is available")
            return {"public_review": self.reviewer.review("public-tool")}
        methods = {"list": self.session.list_files, "read": self._read, "issue": self.session.issue,
            "search": self.session.search, "edit": self.session.edit, "fetch": self.session.fetch_observation}
        if kind not in methods: raise AdapterError("unknown public action")
        return methods[kind](**arguments)

    def _checked_dispatch(self, action):
        try: return self._dispatch(action)
        except UncertainCall: raise
        except (AdapterError, TypeError, KeyError, json.JSONDecodeError, UnicodeError, OSError) as exc:
            result = {"tool_error": str(exc)[:2000], "error_type": type(exc).__name__}
            self.session.journal.append("action-refused", {"error": result})
            return result

    def task_messages(self, archived):
        journal = self.session.journal
        source = self.session.task["problem_statement"]
        chars = len(source)
        hot = self.metadata.slices(source[:8192])
        rows = list(hot["rows"])
        patch = self.session.diff()
        candidate = {"patch_sha256": digest(patch), "patch_bytes": len(patch),
            "text": patch.decode() if len(patch) <= 4096 else None, "text_omitted": len(patch) > 4096}
        system = adapter.TOOL_INSTRUCTIONS + "\n" + CONVENTIONS + "\nPUBLIC PROFILE\n" + self.profile
        while True:
            payload = {"task": {**self.session.task, "problem_statement": source[:chars]},
                "role": self._role(), "role_directive": ROLE_TEXT[self._role()],
                "role_calls_remaining": self.policy.quota(self._role()) - self._state["role_calls"],
                "public_source_context": {**hot, "rows": rows, "omissions": "unselected bytes remain available with read"},
                "candidate": candidate, "latest_public_review": self._state["last_review"]}
            if chars < len(source):
                payload["issue_view"] = {"label": "PARTIAL ISSUE VIEW", "source_sha256": journal.put(source.encode()),
                    "char_start": 0, "char_end": chars, "total_characters": len(source),
                    "offset_unit": "Unicode code points", "full_original_preserved": True, "summary_used": False}
            if archived: payload["public_observation_fetch_index"] = archived
            messages = [{"role": "system", "content": system},
                        {"role": "user", "content": "PUBLIC PRACTICE TASK\n" + canonical(payload).decode()}]
            count = number(self.token_counter(messages), 0, 10000000, "measured prompt tokens")
            if count <= self.pin: return messages
            if rows: rows.pop(); continue
            if candidate["text"] is not None: candidate = candidate | {"text": None, "text_omitted": True}; continue
            if chars <= 128: raise AdapterError("minimum exact practice view/index exceeds measured pin")
            chars = min(2048, max(128, chars // 2))

    def _pack(self):
        state, journal = self._state, self.session.journal
        obs, kept = state["observations"], list(state["observations"])
        while True:
            dropped = obs[:len(obs) - len(kept)]
            archived = state["archived"] + [i for i in dropped if i not in state["archived"]]
            messages = self.task_messages(archived) + [
                {"role": "user", "content": "PUBLIC TOOL OBSERVATION\n" + journal.get(i["hash"]).decode()} for i in kept]
            count = number(self.token_counter(messages), 0, 10000000, "final measured prompt")
            if count <= self.pin: break
            if not kept: raise AdapterError("minimum exact context exceeds measured pin")
            kept.pop(0)
        if kept != obs:
            journal.append("context-rotation", {"pin": self.pin, "before": [i["hash"] for i in obs],
                "after": [i["hash"] for i in kept], "archived": [i["hash"] for i in archived], "rendered_tokens": count})
            state["observations"], state["archived"] = kept, archived
            state["rotations"] += 1
        counter = getattr(self.token_counter, "__self__", self.token_counter)
        rendered_hash = getattr(counter, "last_rendered_sha256", None)
        if self.halo.mode == "active" and (getattr(counter, "last_messages_sha256", None) != digest(canonical(messages)) or
                getattr(counter, "last_count", None) != count or not isinstance(rendered_hash, str) or
                len(rendered_hash) != 64 or any(c not in "0123456789abcdef" for c in rendered_hash)):
            raise AdapterError("active HALO needs the exact latest actual rendered-template measurement receipt")
        advice = self.halo.advise(count, rendered_hash)
        journal.append("preview-halo-advice", advice)
        return messages, count

    def _review(self, reason):
        outcome = self.reviewer.review(reason)
        # Keep feedback in public CAS/observations; the prompt summary is bounded.
        self._state["last_review"] = {k: outcome[k] for k in (
            "binding", "status", "verified_public_pass", "cached_same_patch_review", "new_worker_dispatches") if k in outcome}
        return outcome

    def _save(self, call_id):
        self.save_iteration(self.session.root / "agent-state.json", self._state, call_id, self._started)
        self._started = None

    def _finish(self, model_name, reason):
        self._started = time.monotonic()
        self._verify(); self._hold_uncertain()
        self.session.journal.append("preview-final-stage-started", {"reason": reason,
            "calls": self._state["next_call"] - 1, "active_seconds_before": self._state["active_seconds"]})
        cancelled = self._cancelled()
        if not cancelled:
            outcome = self._review("before-finish")
        else:
            outcome = {"verified_public_pass": False, "status": "cancelled", "new_worker_dispatches": 0}
        # Git validation and prediction freezing are active work too. Evaluate
        # acceptance after they return, so a deadline crossed during final I/O
        # cannot retain an earlier passing promotion flag.
        prediction = self.session.finalize(model_name)
        patch_hash = digest(prediction["model_patch"].encode("utf-8"))
        cancelled = self._cancelled()
        active_now = self.remaining_seconds() > 0
        accepted = active_now and not cancelled and outcome.get("verified_public_pass") is True and \
            outcome.get("binding", {}).get("patch_sha256") == patch_hash
        report = {"schema": "xnet.accuracy-preview-final.v1", "reason": reason, "patch_sha256": patch_hash,
            "verified_public_accept": accepted, "active_budget_remaining": active_now, "cancelled": cancelled,
            "public_review_status": outcome["status"], "calls": self._state["next_call"] - 1,
            "active_seconds": self._state["active_seconds"] + time.monotonic() - self._started,
            "hidden_grading": False, "meaning": "exact public profile evidence only; ungraded task correctness"}
        self._state["active_seconds"] = report["active_seconds"]
        self._started = None
        self.session.journal.append("preview-final-checkpoint", report)
        adapter.atomic_write(self.session.root / "preview-outcome.json", canonical(report))
        return prediction

    def run(self, model_name):
        self._verify(); self._hold_uncertain()
        if self.session.frozen: return self.session.finalize(model_name)
        self._state = self._load_state()
        state, journal = self._state, self.session.journal
        if state.get("terminal_phase_complete") is True or (state["role_index"] == len(self.policy.schedule) - 1 and
                state["role_calls"] >= self.policy.quota(self._role())):
            return self._finish(model_name, "durable-terminal-phase-recovery")
        while state["next_call"] <= self.max_calls and state["active_seconds"] < self.max_seconds:
            self._started = time.monotonic()
            self._verify(); self._hold_uncertain()
            if self._cancelled():
                state["active_seconds"] += time.monotonic() - self._started; self._started = None
                return self._finish(model_name, "cancelled")
            self.metadata.warm(self.session.task["problem_statement"][:8192])
            if self._cancelled():
                state["active_seconds"] += time.monotonic() - self._started; self._started = None
                return self._finish(model_name, "cancelled")
            messages, count = self._pack()
            remaining_tokens = self.max_output - journal.db.execute("SELECT COALESCE(SUM(output_tokens),0) FROM calls").fetchone()[0]
            if self.remaining_seconds() <= 0 or remaining_tokens <= 0:
                state["active_seconds"] += time.monotonic() - self._started; self._started = None; break
            call_id = f"call-{state['next_call']:04d}"
            self._verify()
            request = {"messages": messages, "max_tokens": min(1300, remaining_tokens), "rendered_tokens": count,
                "rotation_pin": self.pin, "remaining_active_seconds": self.remaining_seconds(),
                "xnet_phase": self._role(), "quality_policy_sha256": digest(canonical(asdict(self.policy)))}
            try:
                reply = journal.request(call_id, request, self.callback, self.max_calls, self.max_output)
            except Exception as exc:
                pending = journal.db.execute("SELECT status FROM calls WHERE id=?", (call_id,)).fetchone()
                if pending and pending[0] != "completed":
                    raise UncertainCall("reserved model response uncertain; no automatic repeat") from exc
                raise
            role = self._role()
            before = digest(self.session.diff())
            try:
                action = json.loads(reply["content"])
                if not isinstance(action, dict) or set(action) != {"action", "arguments"} or not isinstance(action["arguments"], dict):
                    raise AdapterError("model action schema refused")
                if self.remaining_seconds() <= 0 or self._cancelled():
                    result = {"budget_exhausted": self.remaining_seconds() <= 0, "cancelled": self._cancelled(),
                        "tool_error": "active deadline or cancellation before dispatch"}
                else:
                    result = journal.action(call_id, action, lambda: self._checked_dispatch(action))
                if action["action"] == "edit" and not result.get("tool_error") and digest(self.session.diff()) != before:
                    result = result | {"automatic_public_review": self._review("changed-candidate")}
                if action["action"] == "public-test" and "public_review" in result:
                    self._state["last_review"] = {k: result["public_review"][k] for k in (
                        "binding", "status", "verified_public_pass", "cached_same_patch_review", "new_worker_dispatches") if k in result["public_review"]}
            except UncertainCall: raise
            except (AdapterError, TypeError, KeyError, json.JSONDecodeError, UnicodeError, OSError) as exc:
                result = {"tool_error": str(exc)[:2000], "error_type": type(exc).__name__}
                journal.append("action-refused", {"call_id": call_id, "error": result})
            state["role_calls"] += 1
            finish = result.get("finish_requested") is True
            held = finish and role == "Builder" and not self.session.diff() and state["role_calls"] < self.policy.quota(role)
            if held: result = {**result, "finish_held": True, "reason": "empty Builder candidate; inspect or edit within remaining allocation"}
            transition = (finish and not held) or state["role_calls"] >= self.policy.quota(role)
            final_role = transition and state["role_index"] == len(self.policy.schedule) - 1
            if final_role:
                state["terminal_phase_complete"] = True
                state["terminal_phase_reason"] = "finish" if finish else "role-quota"
            if transition and not final_role:
                old_role = role; state["role_index"] += 1; state["role_calls"] = 0
                journal.append("preview-phase-transition", {"from": old_role, "to": self._role(), "call_id": call_id})
            state["observations"].append({"hash": journal.put(canonical(result)), "call_id": call_id})
            self._save(call_id)
            if final_role: return self._finish(model_name, "final-role-finish-or-quota")
        return self._finish(model_name, "quality-budget")

"""Shared r02 public conventions and controller; no services or task answers."""
from __future__ import annotations

import json
from pathlib import Path
import time

from frozen_core_r02 import adapter, source_pins

AdapterError = adapter.AdapterError
UncertainCall = adapter.UncertainCall
canonical, digest, number = adapter.canonical, adapter.digest, adapter.number
BUDGETS = {"max_calls": 8, "max_output_tokens": 8000,
           "max_active_seconds": 900, "rotation_pin": 6400}
CONVENTIONS = """SHARED R02 PUBLIC TOOL CONVENTIONS
read(path,start,end): source LINE numbers are 1-based, both bounds inclusive; start>=1, end>=start, at most 1000 lines. Example: {"action":"read","arguments":{"path":"src/module.py","start":1,"end":120}}.
issue(start,end): original issue CHARACTER offsets are 0-based Unicode code points, start inclusive and end exclusive; one page is at most 8192 characters. Example: {"action":"issue","arguments":{"start":0,"end":2048}}.
Complete retrieved source spans already satisfy read-before-edit when source_sha256 still equals current bytes. source_sha256 is the whole BASE file hash, span_sha256 is only the retrieved span hash; before_sha256 must use the WHOLE CURRENT file hash. complete_file=true means the full file is shown; false means omitted bytes still exist.
Do not repeat a read of an unchanged already covered span. Use its public observation via fetch if content is needed again. The current public coverage ledger states spans and revisions; changed bytes invalidate earlier coverage. After edit, use the returned after_sha256 as the current revision; never reuse the old before_sha256. A stale edit is refused; do not refresh a hash without observing the current bytes or your recorded edit.
Use small atomic multi-file edits when supported by observed sources. Reserve an ordinary counted model action for a named public-test profile before finish, when a candidate exists and budget remains. Public tests consume active time and the action's model call; no controller executes a free test or adds calls. Record absent verification honestly.
Every response, including invalid actions and duplicate reads, consumes the same shared call budget. Empty patches remain valid honest outcomes.
"""
FORBIDDEN = frozenset({"gold_patch", "test_patch", "fail_to_pass", "pass_to_pass", "hidden",
    "hidden_tests", "hidden_cases", "hidden_feedback", "official_grade", "evaluator_only",
    "teacher", "solution_patch", "solution_pr"})


def public_feedback(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).casefold().replace("-", "_") in FORBIDDEN:
                raise AdapterError("worker feedback contains a forbidden evaluator field")
            public_feedback(item)
    elif isinstance(value, list):
        for item in value:
            public_feedback(item)


class PublicCoverage:
    """Durable public coverage, with current byte equality checked on reuse."""
    def __init__(self, session):
        self.session = session
        self.entries = []
        for payload, in session.journal.db.execute("SELECT payload FROM events ORDER BY seq"):
            event = json.loads(payload)
            if event["kind"] == "r02-source-coverage":
                self.entries.append(event["value"])

    def note(self, path, source_hash, start, end, total_lines, observation_hash, complete):
        entry = {"path": path, "source_sha256": source_hash, "start_line": start,
                 "end_line": end, "total_lines": total_lines,
                 "public_observation_sha256": observation_hash, "complete_file": complete}
        if entry not in self.entries:
            self.session.journal.get(observation_hash)
            self.session.journal.append("r02-source-coverage", entry)
            self.entries.append(entry)

    def note_retrieval(self, spans, observation_hash):
        for span in spans:
            # A byte chunk that splits a long line must not stand in for a whole
            # line read. Only complete files or exact whole-line spans cover it.
            if span["complete_file"] or span.get("whole_line_bounds", False):
                self.note(span["path"], span["source_sha256"], span["start_line"], span["end_line"],
                          span["total_lines"], observation_hash, span["complete_file"])

    def ledger(self, limit=8):
        # Metadata only, deterministically bounded. Old content remains in CAS.
        latest = {}
        for entry in reversed(self.entries):
            if entry["path"] not in latest:
                path = self.session._path(entry["path"])
                if path.is_file() and path.stat().st_size <= adapter.MAX_FILE:
                    current = digest(path.read_bytes())
                    latest[entry["path"]] = {**entry, "current_file_sha256": current,
                                            "unchanged": current == entry["source_sha256"]}
                if len(latest) >= limit:
                    break
        return list(latest.values())

    def read(self, path, start=1, end=200):
        number(start, 1, 1000000, "start")
        number(end, start, min(start + 999, 1000000), "end")
        target = self.session._path(path)
        if target.stat().st_size > adapter.MAX_FILE:
            raise AdapterError("source file exceeds read cap")
        source_hash = digest(target.read_bytes())
        for entry in reversed(self.entries):
            if entry["path"] == path and entry["source_sha256"] == source_hash and (
                    entry["complete_file"] or
                    entry["start_line"] <= start and end <= entry["end_line"]):
                return self.session._observe("r02-covered-read", {"path": path, "start": start, "end": end},
                    {"path": path, "sha256": source_hash, "total_lines": entry["total_lines"],
                     "already_observed": True, "text_omitted": True,
                     "complete_file": entry["complete_file"],
                     "prior_public_observation_sha256": entry["public_observation_sha256"],
                     "access": "fetch the prior public observation if its exact content is needed"})
        result = self.session.read(path, start, end)
        covered_end = min(end, result["total_lines"])
        complete = start == 1 and covered_end == result["total_lines"]
        self.note(path, result["sha256"], start, covered_end, result["total_lines"],
                  result["observation_hash"], complete)
        return {**result, "complete_file": complete, "current_file_sha256": result["sha256"]}


class ClearRawLoop(adapter.AgentLoop):
    def __init__(self, session, callback, token_counter, worker=None, public_profiles=None, **budgets):
        limits = BUDGETS | budgets
        if limits != BUDGETS:
            raise AdapterError("r02 shared ceilings are fixed")
        super().__init__(session, callback, token_counter, worker=worker,
                         public_profiles=public_profiles, **BUDGETS)
        self.coverage = PublicCoverage(session)
        self.common_sources = source_pins() | {"common_r02": digest(Path(__file__).read_bytes())}
        plan = {"schema": "xnet.repository-common-conventions.r02", "budgets": BUDGETS,
                "conventions": CONVENTIONS, "conventions_sha256": digest(CONVENTIONS.encode()),
                "tool_schema_sha256": digest((adapter.TOOL_INSTRUCTIONS + CONVENTIONS).encode()),
                "sources": self.common_sources, "public_profiles": self.public_profiles,
                "profiles_hash": self.profile_hash, "public_verification": "counted prompt directive",
                "duplicate_read": "covered-current-span reference; charged model call"}
        path = session.root / "r02-common-plan.json"
        if path.exists() and path.read_bytes() != canonical(plan):
            raise AdapterError("r02 common plan changed; use a new namespace")
        if not path.exists():
            adapter.atomic_write(path, canonical(plan))

    def _verify_common(self):
        current = source_pins() | {"common_r02": digest(Path(__file__).read_bytes())}
        if current != self.common_sources:
            raise AdapterError("r02 common sources changed")

    def _hold_uncertain(self):
        if self.session.journal.db.execute("SELECT 1 FROM calls WHERE status!='completed' LIMIT 1").fetchone() or \
                self.session.journal.db.execute("SELECT 1 FROM actions WHERE status!='completed' LIMIT 1").fetchone():
            raise UncertainCall("prior request/action requires explicit reconciliation before tokenizer or inference")

    def task_messages(self, archived):
        source = self.session.task["problem_statement"]
        chars = len(source)
        system = adapter.TOOL_INSTRUCTIONS + "\n" + CONVENTIONS + "\nPUBLIC PROFILES\n" + canonical(self.public_profiles).decode()
        while True:
            task = {**self.session.task, "problem_statement": source[:chars]}
            payload = {"task": task, "current_public_coverage": self.coverage.ledger()}
            if chars < len(source):
                payload["issue_view"] = {"label": "PARTIAL ISSUE VIEW",
                    "source_sha256": self.session.journal.put(source.encode()), "char_start": 0, "char_end": chars,
                    "total_characters": len(source), "offset_unit": "Unicode code points",
                    "full_original_preserved": True, "summary_used": False}
            if archived:
                payload["public_observation_fetch_index"] = archived
            messages = [{"role": "system", "content": system},
                        {"role": "user", "content": "PUBLIC TASK\n" + canonical(payload).decode()}]
            count = number(self.token_counter(messages), 0, 10000000, "rendered issue view")
            if count <= self.pin:
                if chars < len(source):
                    self.session.journal.append("issue-view", {**payload["issue_view"], "rendered_tokens": count, "pin": self.pin})
                return messages
            if chars <= 128:
                raise AdapterError("minimum exact issue view/index exceeds r02 pin")
            chars = min(2048, chars // 2)

    def _dispatch_common(self, action):
        kind, arguments = action["action"], action["arguments"]
        if kind == "finish":
            if arguments:
                raise AdapterError("finish takes no arguments")
            return {"finish_requested": True}
        if kind == "public-test":
            if self.worker is None or arguments.get("profile") not in self.public_profiles:
                raise AdapterError("no frozen caller public test profile configured")
            def checked(request):
                try:
                    reply = self.worker(request)
                except BaseException as exc:
                    raise UncertainCall("public worker outcome uncertain; explicit reconciliation required") from exc
                public_feedback(reply)
                return reply
            return self.session.public_test(worker=checked, **arguments)
        methods = {"list": self.session.list_files, "read": self.coverage.read,
                   "search": self.session.search, "edit": self.session.edit,
                   "fetch": self.session.fetch_observation, "issue": self.session.issue}
        if kind not in methods:
            raise AdapterError("unknown common scoped action")
        return methods[kind](**arguments)

    def _checked_dispatch(self, action):
        try:
            return self._dispatch_common(action)
        except UncertainCall:
            raise
        except (AdapterError, TypeError, KeyError, json.JSONDecodeError, UnicodeError, OSError) as exc:
            result = {"tool_error": str(exc)[:2000], "error_type": type(exc).__name__}
            self.session.journal.append("action-refused", {"error": result})
            return result

    def run(self, model_name):
        self._verify_common()
        if self.session.frozen:
            return self.session.finalize(model_name)
        self._hold_uncertain()
        journal = self.session.journal
        state_path = self.session.root / "agent-state.json"
        events = [json.loads(p) for p, in journal.db.execute("SELECT payload FROM events ORDER BY seq")]
        iterations = [e["value"] for e in events if e["kind"] == "agent-iteration-completed"]
        state = json.loads(journal.get(iterations[-1]["state_hash"])) if iterations else {
            "next_call": 1, "observations": [], "archived": [], "active_seconds": 0.0, "rotations": 0}
        state = self.recover_iteration_state(state)
        while state["next_call"] <= self.max_calls and state["active_seconds"] < self.max_seconds:
            self._verify_common()
            started = time.monotonic()
            obs, kept = state["observations"], list(state["observations"])
            while True:
                dropped = obs[:len(obs) - len(kept)]
                archived = state["archived"] + [item for item in dropped if item not in state["archived"]]
                messages = self.task_messages(archived) + [
                    {"role": "user", "content": "PUBLIC TOOL OBSERVATION\n" + journal.get(item["hash"]).decode()}
                    for item in kept]
                count = number(self.token_counter(messages), 0, 10000000, "rendered prompt")
                if count <= self.pin:
                    break
                if not kept:
                    raise AdapterError("minimum exact context exceeds r02 pin")
                kept.pop(0)
            if kept != obs:
                journal.append("context-rotation", {"pin": self.pin, "before": [i["hash"] for i in obs],
                    "after": [i["hash"] for i in kept], "archived": [i["hash"] for i in archived], "rendered_tokens": count})
                state["observations"], state["archived"] = kept, archived
                state["rotations"] += 1
            remaining_seconds = self.max_seconds - state["active_seconds"] - (time.monotonic() - started)
            remaining_tokens = self.max_output - journal.db.execute("SELECT COALESCE(SUM(output_tokens),0) FROM calls").fetchone()[0]
            if remaining_seconds <= 0 or remaining_tokens <= 0:
                state["active_seconds"] += time.monotonic() - started
                break
            call_id = f"call-{state['next_call']:04d}"
            request = {"messages": messages, "max_tokens": min(1300, remaining_tokens),
                       "rendered_tokens": count, "rotation_pin": self.pin,
                       "remaining_active_seconds": remaining_seconds, "xnet_phase": "raw-r02"}
            reply = journal.request(call_id, request, self.callback, self.max_calls, self.max_output)
            try:
                action = json.loads(reply["content"])
                if not isinstance(action, dict) or set(action) != {"action", "arguments"} or not isinstance(action["arguments"], dict):
                    raise AdapterError("model action schema refused")
                if time.monotonic() - started + state["active_seconds"] >= self.max_seconds:
                    result = {"budget_exhausted": True, "tool_error": "active time exhausted before dispatch"}
                else:
                    result = journal.action(call_id, action, lambda: self._checked_dispatch(action))
            except UncertainCall:
                raise
            except (AdapterError, TypeError, KeyError, json.JSONDecodeError, UnicodeError, OSError) as exc:
                result = {"tool_error": str(exc)[:2000], "error_type": type(exc).__name__}
                journal.append("action-refused", {"call_id": call_id, "error": result})
            state["observations"].append({"hash": journal.put(canonical(result)), "call_id": call_id})
            self.save_iteration(state_path, state, call_id, started)
            if result.get("finish_requested"):
                return self.session.finalize(model_name)
        journal.append("budget-finish", {"calls": state["next_call"] - 1, "active_seconds": state["active_seconds"], "limits": BUDGETS})
        return self.session.finalize(model_name)

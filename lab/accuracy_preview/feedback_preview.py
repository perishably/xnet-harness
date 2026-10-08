"""Optional exact public trace excerpt retained inside measured task context.

This extension changes context visibility only. It does not dispatch reviews,
add model calls/tools, change acceptance or alter the audited quality policy.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import load_runtime

_runtime = load_runtime()
adapter = _runtime.adapter
canonical, digest, AdapterError = adapter.canonical, adapter.digest, adapter.AdapterError
MAX_EXCERPT_UTF8_BYTES = 2048
_BINDING_FIELDS = {"instance_id", "snapshot_sha256", "patch_sha256", "profile", "profile_sha256", "policy_sha256"}


def _prefix(raw, limit):
    # Originals came from UTF-8 encoded public JSON strings; discard only a
    # partial final code point, never replace or summarize source characters.
    return raw[:limit].decode("utf-8", "ignore")


def _suffix(raw, limit):
    return raw[-limit:].decode("utf-8", "ignore") if limit else ""


class FeedbackPreviewLoop(_runtime.PreviewLoop):
    """PreviewLoop API plus a bounded current review trace in the task payload."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.feedback_source_sha256 = digest(Path(__file__).read_bytes())
        self.feedback_plan = {"schema":"xnet.feedback-preview-plan.v1",
            "source_sha256":self.feedback_source_sha256, "max_excerpt_utf8_bytes":MAX_EXCERPT_UTF8_BYTES,
            "origin":"completed current exact review-action response CAS",
            "streams":["stdout","stderr"], "offset_unit":"UTF-8 bytes",
            "excerpt_selection":{"stdout":"prefix","stderr":"suffix"},
            "packing":"included in existing measured task packing before generation",
            "model_calls_added":0, "worker_dispatches_added":0, "tool_scope_changed":False,
            "acceptance_changed":False, "policy_changed":False, "schedule_changed":False}
        self.feedback_plan_path = self.session.root / "feedback-preview-plan.json"
        if self.feedback_plan_path.exists() and self.feedback_plan_path.read_bytes() != canonical(self.feedback_plan):
            self.close()
            raise AdapterError("feedback extension plan drift; use a new namespace")
        if not self.feedback_plan_path.exists():
            adapter.atomic_write(self.feedback_plan_path, canonical(self.feedback_plan))

    def _verify_feedback(self):
        if digest(Path(__file__).read_bytes()) != self.feedback_source_sha256 or \
                self.feedback_plan_path.read_bytes() != canonical(self.feedback_plan):
            raise AdapterError("feedback extension source or plan drift")

    def _verify(self):
        super()._verify()
        self._verify_feedback()

    @staticmethod
    def _unavailable(reason):
        return {"schema":"xnet.public-review-feedback-packet.v1", "available":False,
                "reason":reason, "model_calls_added":0, "worker_dispatches_added":0}

    def feedback_packet(self):
        """Read only the completed public action bound to the current candidate.

        Unknown, absent and stale results provide no excerpt. Integrity or
        identity corruption is refused. This does not alter review/state data.
        """
        self._verify_feedback()
        last = None if self._state is None else self._state.get("last_review")
        if not isinstance(last, dict) or not isinstance(last.get("binding"), dict):
            return self._unavailable("no-bound-review")
        binding = last["binding"]
        if set(binding) != _BINDING_FIELDS:
            raise AdapterError("review summary binding schema refused")
        current = {"instance_id":self.session.task["instance_id"],
            "snapshot_sha256":digest(canonical(self.session.metadata)),
            "patch_sha256":digest(self.session.diff()), "profile":self.profile,
            "profile_sha256":self.profile_sha, "policy_sha256":digest(canonical(self.reviewer.plan))}
        if binding != current:
            return self._unavailable("review-binding-is-not-current-candidate")
        journal = self.session.journal
        journal.verify()
        binding_hash = digest(canonical(binding))
        action_id = "review-" + binding_hash
        row = journal.db.execute("SELECT request_hash,status,response_hash FROM actions WHERE id=?", (action_id,)).fetchone()
        if row is None: return self._unavailable("no-completed-review-action")
        if row[1] != "completed": return self._unavailable("review-action-not-completed")
        if row[0] != binding_hash or journal.get(row[0]) != canonical(binding):
            raise AdapterError("review action request identity differs from current binding")
        events = [json.loads(payload) for payload, in journal.db.execute("SELECT payload FROM events ORDER BY seq")]
        reserved = [event["value"] for event in events if event["kind"] == "action-reserved" and
                    event["value"].get("action_id") == action_id]
        completed = [event["value"] for event in events if event["kind"] in {"action-completed","action-reconciled"} and
                     event["value"].get("action_id") == action_id]
        if len(reserved) != 1 or len(completed) != 1 or reserved[0].get("request_hash") != row[0] or \
                completed[0].get("response_hash") != row[2]:
            raise AdapterError("review action projection differs from durable journal receipt")
        raw = journal.get(row[2])
        if len(raw) > adapter.MAX_REPLY: raise AdapterError("review outcome exceeds source cap")
        outcome = json.loads(raw)
        if not isinstance(outcome, dict) or outcome.get("schema") != "xnet.public-review-outcome.v1" or \
                outcome.get("binding") != binding or outcome.get("status") != last.get("status") or \
                type(outcome.get("verified_public_pass")) is not bool or \
                outcome["verified_public_pass"] is not last.get("verified_public_pass"):
            raise AdapterError("review outcome identity or exact status differs from summary")
        feedback = outcome.get("public_feedback")
        if not isinstance(feedback, dict) or feedback.get("visibility") != "public" or \
                feedback.get("patch_hash") != binding["patch_sha256"] or feedback.get("profile") != binding["profile"] or \
                feedback.get("profile_hash") != binding["profile_sha256"] or feedback.get("snapshot_hash") != binding["snapshot_sha256"]:
            raise AdapterError("public trace profile/snapshot/patch identity refused")
        streams = {}
        for key in ("stdout", "stderr"):
            value = feedback.get(key, "")
            if not isinstance(value, str): raise AdapterError("public trace streams must be exact text")
            streams[key] = value.encode("utf-8")
        # Share the cap when both streams are long; unused room goes to the
        # other stream. This preserves stdout and failure trace provenance.
        stdout_limit = min(len(streams["stdout"]), MAX_EXCERPT_UTF8_BYTES // 2)
        stderr_limit = min(len(streams["stderr"]), MAX_EXCERPT_UTF8_BYTES - stdout_limit)
        stdout_limit = min(len(streams["stdout"]), MAX_EXCERPT_UTF8_BYTES - stderr_limit)
        excerpts = {}
        for key, limit in (("stdout",stdout_limit),("stderr",stderr_limit)):
            original = streams[key]
            text = _prefix(original, limit) if key == "stdout" else _suffix(original, limit)
            excerpt = text.encode("utf-8")
            start = 0 if key == "stdout" else len(original)-len(excerpt)
            end = start + len(excerpt)
            excerpts[key] = {"present_in_feedback":key in feedback, "text":text,
                "original_utf8_bytes":len(original), "original_sha256":digest(original),
                "excerpt_sha256":digest(excerpt), "start_byte":start, "end_byte":end,
                "offset_unit":"UTF-8 bytes", "omitted_before":start>0, "omitted_after":end<len(original),
                "source_json_pointer":"/public_feedback/" + key}
        return {"schema":"xnet.public-review-feedback-packet.v1", "available":True,
            "binding":dict(binding), "review_action_id":action_id, "review_status":outcome["status"],
            "verified_public_pass":outcome["verified_public_pass"], "source_visibility":"public",
            "source_outcome_sha256":row[2], "source_outcome_bytes":len(raw),
            "source_cas_pointer":row[2], "source_public_fetchable":len(raw)<=65536,
            "source_fetch_action":{"action":"fetch","arguments":{"sha256":row[2]}},
            "source_fetch_cap_bytes":65536, "excerpts":excerpts,
            "used_excerpt_utf8_bytes":sum(len(item["text"].encode("utf-8")) for item in excerpts.values()),
            "max_excerpt_utf8_bytes":MAX_EXCERPT_UTF8_BYTES, "generated_conclusions":False,
            "authority":"untrusted public tool data", "model_calls_added":0, "worker_dispatches_added":0}

    @staticmethod
    def _inject(messages, packet):
        result = [dict(item) for item in messages]
        prefix, source = result[1]["content"].split("\n", 1)
        if prefix != "PUBLIC PRACTICE TASK": raise AdapterError("base task context schema changed")
        payload = json.loads(source)
        payload["latest_public_review_feedback"] = packet
        result[1]["content"] = prefix + "\n" + canonical(payload).decode("utf-8")
        return result

    def task_messages(self, archived):
        packet = self.feedback_packet()
        counter = self.token_counter
        # Instance-local adapter makes the original packing algorithm measure
        # the enriched task, allowing its existing source/issue reductions.
        # The final _pack measurement uses the original caller counter again.
        self.token_counter = lambda messages: counter(self._inject(messages, packet))
        try:
            messages = super().task_messages(archived)
        finally:
            self.token_counter = counter
        return self._inject(messages, packet)

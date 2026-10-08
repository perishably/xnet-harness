"""Deterministic public patch review; no model, grader or lifecycle ownership."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import time

ARM = Path(__file__).resolve().parents[1] / "xnet_arm_r02"
sys.path.insert(0, str(ARM))
from common_r02 import AdapterError, UncertainCall, canonical, digest, public_feedback
from frozen_core_r02 import adapter


class PublicReview:
    """Review changed candidates under one frozen public profile and a hard cap.

    Public test work consumes the caller's active-time budget. It adds no model
    call, and never evaluates hidden tests. A passing result is scoped to the
    exact patch/profile/snapshot and confirmed worker cleanup, not correctness
    on future tasks. A missing or failed review cannot be a passing promotion.
    """
    def __init__(self, session, worker, profile, profile_sha256, remaining_seconds,
                 max_reviews=4):
        if not callable(worker) or not callable(remaining_seconds):
            raise AdapterError("review requires caller worker and active deadline")
        if not isinstance(profile, str) or not adapter.ID_RE.fullmatch(profile):
            raise AdapterError("one frozen public profile is required")
        if not isinstance(profile_sha256, str) or len(profile_sha256) != 64 or \
                any(c not in "0123456789abcdef" for c in profile_sha256):
            raise AdapterError("profile SHA256 required")
        if type(max_reviews) is not int or not 1 <= max_reviews <= 8:
            raise AdapterError("bounded integer review cap required")
        self.session, self.worker = session, worker
        self.profile, self.profile_hash = profile, profile_sha256
        self.remaining, self.cap = remaining_seconds, max_reviews
        self.source_hash = digest(Path(__file__).read_bytes())
        self.plan = {"schema": "xnet.public-review-plan.v1", "profile": profile,
                     "profile_sha256": profile_sha256, "max_reviews": max_reviews,
                     "source_sha256": self.source_hash,
                     "hidden_grading": False, "model_calls_added": 0,
                     "cost": "caller active seconds and real public worker dispatches"}
        path = session.root / "public-review-plan.json"
        if path.exists() and path.read_bytes() != canonical(self.plan):
            raise AdapterError("review policy drift; use a new namespace")
        if not path.exists():
            adapter.atomic_write(path, canonical(self.plan))

    def _verify(self):
        if digest(Path(__file__).read_bytes()) != self.source_hash:
            raise AdapterError("public review source drift")
        if (self.session.root / "public-review-plan.json").read_bytes() != canonical(self.plan):
            raise AdapterError("public review plan drift")
        self.session.journal.verify()
        pending = self.session.journal.db.execute(
            "SELECT 1 FROM actions WHERE id LIKE 'review-%' AND status!='completed' LIMIT 1").fetchone()
        if pending:
            raise UncertainCall("prior public review outcome requires explicit reconciliation")

    def review(self, reason):
        self._verify()
        if reason not in {"changed-candidate", "before-finish", "public-tool"}:
            raise AdapterError("unknown public review trigger")
        patch = self.session.diff()
        patch_hash = self.session.journal.put(patch)
        binding = {"instance_id": self.session.task["instance_id"],
                   "snapshot_sha256": digest(canonical(self.session.metadata)),
                   "patch_sha256": patch_hash, "profile": self.profile,
                   "profile_sha256": self.profile_hash, "policy_sha256": digest(canonical(self.plan))}
        action_id = "review-" + digest(canonical(binding))
        journal = self.session.journal
        prior = journal.db.execute("SELECT response_hash,status FROM actions WHERE id=?", (action_id,)).fetchone()
        if prior:
            if prior[1] != "completed":
                raise UncertainCall("prior public review outcome uncertain")
            result = json.loads(journal.get(prior[0]))
            return {**result, "cached_same_patch_review": True, "new_worker_dispatches": 0}
        count = journal.db.execute("SELECT COUNT(*) FROM actions WHERE id LIKE 'review-%'").fetchone()[0]
        if not patch or count >= self.cap or self.remaining() <= 0:
            outcome = {"schema": "xnet.public-review-outcome.v1", "binding": binding,
                       "status": "not-reviewed", "verified_public_pass": False,
                       "reason": "empty-patch" if not patch else "review-cap" if count >= self.cap else "active-deadline",
                       "new_worker_dispatches": 0}
            journal.append("public-review-not-run", outcome)
            return outcome

        def execute():
            started = time.monotonic()
            def checked(request):
                if self.remaining() <= 0:
                    raise UncertainCall("active deadline exhausted at public review dispatch")
                try:
                    reply = self.worker(request)
                except BaseException as exc:
                    raise UncertainCall("public review worker outcome uncertain; no automatic repeat") from exc
                public_feedback(reply)
                if reply.get("profile_hash") != self.profile_hash or \
                        reply.get("snapshot_hash") != binding["snapshot_sha256"]:
                    raise UncertainCall("returned public review identity does not match frozen profile/snapshot")
                return reply
            try:
                reply = self.session.public_test(self.profile, checked)
            except BaseException as exc:
                raise UncertainCall("public review dispatch or returned identity uncertain; no automatic repeat") from exc
            within_budget = self.remaining() > 0
            passing = within_budget and reply.get("status") == "passed" and type(reply.get("exit_code")) is int and reply["exit_code"] == 0 and \
                reply.get("cleanup", {}).get("absence_confirmed") is True and \
                reply.get("timed_out") is False and reply.get("output_limited") is False
            outcome = {"schema": "xnet.public-review-outcome.v1", "binding": binding,
                       "status": "public-passed" if passing else "public-failed-or-incomplete",
                       "verified_public_pass": passing, "public_feedback": reply,
                       "public_verification_within_active_budget": within_budget,
                       "elapsed_seconds": time.monotonic() - started,
                       "cached_same_patch_review": False, "new_worker_dispatches": 1}
            journal.append("public-review-outcome", outcome)
            return outcome
        return journal.action(action_id, binding, execute)

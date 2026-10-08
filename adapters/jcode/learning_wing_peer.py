"""Jcode's data-only peer for XNET's outcome-driven learning wing.

The caller owns both learning epochs, inference, validation, the catalog and
their lifecycle. This adapter neither starts a runner nor schedules epochs.
Changed adapter or wing sources require newly pinned run roots.
"""
from xnet.learning_wing import (
    admit_proposal,
    build_proposal_request,
    catalog_promoted_guidance,
    public_failure_feed,
    seal_epoch_trace,
    seed_failure_feed,
)


class JcodeLearningWingPeer:
    """Borrow caller epochs; exchange bounded public guidance and evidence."""

    def __init__(self, current_learner, previous_learner=None):
        self.current_learner = current_learner
        self.previous_learner = previous_learner

    def proposal_request(self, *, max_records=12):
        """Prepare data for a caller-owned generation, without calling a model."""
        feed = (seed_failure_feed() if self.previous_learner is None else
                public_failure_feed(self.previous_learner, max_records=max_records))
        return build_proposal_request(feed)

    def admit(self, response):
        """Admit a strict response as a proposal, never as a validated win."""
        return admit_proposal(self.current_learner, response)

    def trace(self, *, failure_feed_sha256, proposal_evidence_sha256,
              run_identity_sha256):
        """Seal an already completed epoch through its caller-owned ledger."""
        return seal_epoch_trace(
            self.current_learner,
            failure_feed_sha256=failure_feed_sha256,
            proposal_evidence_sha256=proposal_evidence_sha256,
            run_identity_sha256=run_identity_sha256,
        )

    def promote_to_catalog(self, catalog, *, session_id, task_id, turn_id,
                           now=None, validation_evidence_sha256=None):
        """Stage guidance; independent validation gates next-turn delivery."""
        return catalog_promoted_guidance(
            self.current_learner,
            catalog,
            session_id=session_id,
            task_id=task_id,
            turn_id=turn_id,
            now=now,
            validation_evidence_sha256=validation_evidence_sha256,
        )

"""Review Workflow — finding state machine with append-only ReviewEvent log.

INVARIANT: No automated path can set verification_status to 'verified'.
Only explicit researcher ReviewWorkflow.transition() calls may change
review_status, and only via valid transitions defined in TRANSITIONS.

Design reference: blueprint Stage 7, invariants 3 and 10.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


class WorkflowError(Exception):
    """Raised on an invalid or unauthorized state transition."""


# Allowed review_status transitions.
# Key: (from_status, to_status) → True means allowed.
TRANSITIONS: dict[tuple[str, str], bool] = {
    ("new", "in_review"): True,
    ("new", "dismissed"): True,
    ("in_review", "confirmed"): True,
    ("in_review", "dismissed"): True,
    ("in_review", "needs_more_info"): True,
    ("needs_more_info", "in_review"): True,
    ("needs_more_info", "dismissed"): True,
    ("confirmed", "needs_more_info"): True,   # re-open for additional review
    # 'dismissed' is terminal — no transitions out
}

# verification_status values that may be set via transition
# 'verified' may ONLY be set on 'confirmed' and ONLY by a human researcher.
VERIFICATION_FOR_STATUS: dict[str, Optional[str]] = {
    "confirmed": "verified",      # human researcher confirms → verified
    "dismissed": "not_applicable",
    "in_review": None,
    "needs_more_info": None,
    "new": None,
}

# Automated paths must NEVER set verification_status='verified'.
# This is enforced here: is_automated=True → verification stays None/unchanged.
_AUTO_ALLOWED_STATUSES = frozenset({"in_review", "needs_more_info", "dismissed"})


@dataclass
class ReviewEvent:
    """Immutable record of a single state transition.

    Append-only: once created, ReviewEvent rows must never be mutated.
    """
    id: str
    finding_id: str
    from_status: str
    to_status: str
    actor: str
    timestamp: str
    note: str = ""
    is_automated: bool = False
    verification_status_set: Optional[str] = None


@dataclass
class FindingReviewState:
    """Mutable view of a finding's current review state."""
    finding_id: str
    review_status: str
    verification_status: str


class ReviewWorkflow:
    """State machine for finding review transitions.

    Enforces valid transitions and appends ReviewEvent on each change.
    No automated path may set verification_status='verified'.
    """

    def transition(
        self,
        state: FindingReviewState,
        to_status: str,
        actor: str,
        note: str = "",
        is_automated: bool = False,
    ) -> ReviewEvent:
        """Perform a state transition, returning the new ReviewEvent.

        Raises WorkflowError on invalid transition or if an automated caller
        attempts to set a status that requires human confirmation.
        """
        from_status = state.review_status
        if (from_status, to_status) not in TRANSITIONS:
            raise WorkflowError(
                f"Invalid transition: {from_status!r} → {to_status!r}. "
                f"Allowed from {from_status!r}: "
                f"{[t for f, t in TRANSITIONS if f == from_status]}"
            )
        if is_automated and to_status not in _AUTO_ALLOWED_STATUSES:
            raise WorkflowError(
                f"Automated caller may not set review_status={to_status!r}. "
                f"Human researcher authorization required."
            )
        # Determine verification_status update
        new_verification: Optional[str] = None
        if to_status == "confirmed":
            if is_automated:
                raise WorkflowError(
                    "Automated path cannot set review_status='confirmed'. "
                    "Human researcher authorization required."
                )
            new_verification = "verified"
        elif to_status == "dismissed":
            new_verification = "not_applicable"
        # Apply to mutable state
        state.review_status = to_status
        if new_verification is not None:
            state.verification_status = new_verification
        event = ReviewEvent(
            id=uuid.uuid4().hex,
            finding_id=state.finding_id,
            from_status=from_status,
            to_status=to_status,
            actor=actor,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            note=note,
            is_automated=is_automated,
            verification_status_set=new_verification,
        )
        return event

    def event_to_db_row(self, event: ReviewEvent) -> dict:
        """Map ReviewEvent to the review_events table schema.

        Schema columns: id, finding_id, actor, action (NOT NULL),
        from_state, to_state, field, value, timestamp, note.
        is_automated and verification_status_set are stored in the value
        column as JSON since they are not schema columns.
        """
        import json as _json
        return {
            "id": event.id,
            "finding_id": event.finding_id,
            "actor": event.actor,
            "action": f"{event.from_status}→{event.to_status}",
            "from_state": event.from_status,
            "to_state": event.to_status,
            "field": "review_status",
            "value": _json.dumps({
                "is_automated": event.is_automated,
                "verification_status_set": event.verification_status_set,
            }),
            "timestamp": event.timestamp,
            "note": event.note,
        }

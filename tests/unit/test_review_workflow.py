"""Stage 7: Review workflow tests.

Verifies valid state transitions, append-only ReviewEvent creation,
and that no automated path can set verification_status='verified'.
"""
import pytest

from raven.review_workflow import (
    ReviewWorkflow,
    FindingReviewState,
    ReviewEvent,
    WorkflowError,
    TRANSITIONS,
)


@pytest.fixture
def wf():
    return ReviewWorkflow()


def _state(review="new", verification="unverified", fid="f001"):
    return FindingReviewState(
        finding_id=fid,
        review_status=review,
        verification_status=verification,
    )


class TestValidTransitions:

    def test_new_to_in_review(self, wf):
        s = _state("new")
        ev = wf.transition(s, "in_review", actor="alice")
        assert s.review_status == "in_review"
        assert ev.to_status == "in_review"

    def test_new_to_dismissed(self, wf):
        s = _state("new")
        ev = wf.transition(s, "dismissed", actor="alice")
        assert s.review_status == "dismissed"
        assert s.verification_status == "not_applicable"

    def test_in_review_to_confirmed(self, wf):
        s = _state("in_review")
        ev = wf.transition(s, "confirmed", actor="alice")
        assert s.review_status == "confirmed"
        assert s.verification_status == "verified"

    def test_in_review_to_dismissed(self, wf):
        s = _state("in_review")
        wf.transition(s, "dismissed", actor="alice")
        assert s.review_status == "dismissed"

    def test_in_review_to_needs_more_info(self, wf):
        s = _state("in_review")
        ev = wf.transition(s, "needs_more_info", actor="alice")
        assert s.review_status == "needs_more_info"
        assert ev.to_status == "needs_more_info"

    def test_needs_more_info_to_in_review(self, wf):
        s = _state("needs_more_info")
        wf.transition(s, "in_review", actor="bob")
        assert s.review_status == "in_review"

    def test_confirmed_to_needs_more_info(self, wf):
        s = _state("confirmed", "verified")
        wf.transition(s, "needs_more_info", actor="alice")
        assert s.review_status == "needs_more_info"


class TestInvalidTransitions:

    def test_new_to_confirmed_invalid(self, wf):
        s = _state("new")
        with pytest.raises(WorkflowError):
            wf.transition(s, "confirmed", actor="alice")

    def test_dismissed_is_terminal(self, wf):
        s = _state("dismissed")
        with pytest.raises(WorkflowError):
            wf.transition(s, "in_review", actor="alice")

    def test_same_status_transition_invalid(self, wf):
        s = _state("in_review")
        with pytest.raises(WorkflowError):
            wf.transition(s, "in_review", actor="alice")

    def test_unknown_to_status_invalid(self, wf):
        s = _state("new")
        with pytest.raises(WorkflowError):
            wf.transition(s, "verified_by_ml", actor="alice")


class TestAutomatedPathRestrictions:

    def test_automated_cannot_confirm(self, wf):
        s = _state("in_review")
        with pytest.raises(WorkflowError, match="[Aa]utomated"):
            wf.transition(s, "confirmed", actor="scanner", is_automated=True)

    def test_automated_can_dismiss(self, wf):
        s = _state("in_review")
        ev = wf.transition(s, "dismissed", actor="scanner", is_automated=True)
        assert ev.is_automated is True
        assert s.review_status == "dismissed"

    def test_automated_can_move_to_in_review(self, wf):
        s = _state("new")
        ev = wf.transition(s, "in_review", actor="scanner", is_automated=True)
        assert ev.is_automated is True
        assert s.review_status == "in_review"

    def test_automated_cannot_set_verified(self, wf):
        s = _state("in_review")
        with pytest.raises(WorkflowError):
            wf.transition(s, "confirmed", actor="scanner", is_automated=True)
        # verification_status must remain unverified after failed attempt
        assert s.verification_status == "unverified"

    def test_automated_needs_more_info_allowed(self, wf):
        s = _state("in_review")
        ev = wf.transition(s, "needs_more_info", actor="scanner", is_automated=True)
        assert s.review_status == "needs_more_info"


class TestReviewEvent:

    def test_event_id_is_uuid4_hex(self, wf):
        s = _state("new")
        ev = wf.transition(s, "in_review", actor="alice")
        assert len(ev.id) == 32
        assert all(c in "0123456789abcdef" for c in ev.id)

    def test_event_captures_from_status(self, wf):
        s = _state("new")
        ev = wf.transition(s, "in_review", actor="alice")
        assert ev.from_status == "new"

    def test_event_captures_actor(self, wf):
        s = _state("new")
        ev = wf.transition(s, "in_review", actor="bob")
        assert ev.actor == "bob"

    def test_event_captures_note(self, wf):
        s = _state("new")
        ev = wf.transition(s, "in_review", actor="alice", note="Starting review")
        assert ev.note == "Starting review"

    def test_event_has_timestamp(self, wf):
        s = _state("new")
        ev = wf.transition(s, "in_review", actor="alice")
        assert ev.timestamp and "T" in ev.timestamp

    def test_event_finding_id_matches(self, wf):
        s = _state(fid="finding-xyz")
        ev = wf.transition(s, "in_review", actor="alice")
        assert ev.finding_id == "finding-xyz"

    def test_two_events_different_ids(self, wf):
        s = _state("new")
        ev1 = wf.transition(s, "in_review", actor="alice")
        ev2 = wf.transition(s, "needs_more_info", actor="alice")
        assert ev1.id != ev2.id

    def test_confirmed_event_sets_verification_in_event(self, wf):
        s = _state("in_review")
        ev = wf.transition(s, "confirmed", actor="alice")
        assert ev.verification_status_set == "verified"

    def test_dismissed_event_sets_not_applicable(self, wf):
        s = _state("new")
        ev = wf.transition(s, "dismissed", actor="alice")
        assert ev.verification_status_set == "not_applicable"

    def test_non_terminal_event_verification_none(self, wf):
        s = _state("new")
        ev = wf.transition(s, "in_review", actor="alice")
        assert ev.verification_status_set is None


class TestEventToDbRow:

    def test_db_row_keys(self, wf):
        s = _state("in_review")
        ev = wf.transition(s, "confirmed", actor="alice")
        row = wf.event_to_db_row(ev)
        # Schema columns: id, finding_id, actor, action, from_state, to_state,
        # field, value, timestamp, note
        required = {"id", "finding_id", "actor", "action", "from_state",
                    "to_state", "timestamp", "note"}
        assert required.issubset(row.keys())

    def test_db_row_action_not_null(self, wf):
        s = _state("in_review")
        ev = wf.transition(s, "dismissed", actor="alice")
        row = wf.event_to_db_row(ev)
        assert row["action"] and len(row["action"]) > 0

    def test_db_row_from_state_to_state(self, wf):
        s = _state("new")
        ev = wf.transition(s, "in_review", actor="alice")
        row = wf.event_to_db_row(ev)
        assert row["from_state"] == "new"
        assert row["to_state"] == "in_review"

    def test_is_automated_in_value_json(self, wf):
        import json
        s = _state("in_review")
        ev = wf.transition(s, "dismissed", actor="scanner", is_automated=True)
        row = wf.event_to_db_row(ev)
        val = json.loads(row["value"])
        assert val["is_automated"] is True

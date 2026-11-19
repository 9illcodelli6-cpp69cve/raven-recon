"""Stage 11: ML readiness tests.

Verifies that ReadinessChecker returns NOT_READY_FOR_TRAINING in all
realistic conditions (no data, insufficient data, no qualitative review).
Also verifies that no model is trained and ml_probability is not modified.
"""
import pytest

from raven.ml_readiness import (
    ReadinessChecker,
    ReadinessReport,
    ReadinessStatus,
)
from raven.dataset_foundation import (
    LabelStore,
    TASK_A,
    TASK_B,
    MIN_LABELED_ROWS,
    MIN_UNIQUE_GROUPS,
)


@pytest.fixture
def checker():
    return ReadinessChecker()


@pytest.fixture
def store():
    return LabelStore()


def _make_rows(store, n, n_positive=None, n_groups=None, synthetic=False):
    if n_positive is None:
        n_positive = n // 2
    if n_groups is None:
        n_groups = max(1, min(n, MIN_UNIQUE_GROUPS + 1))
    rows = []
    for i in range(n):
        group_id = str(i % n_groups)
        label = "DIFFERENT" if i < n_positive else "SIMILAR"
        rows.append(store.write_label(
            workspace_id="ws1", task=TASK_A, label=label,
            labeler="alice", asset_id=f"asset_{group_id}",
            synthetic=synthetic,
        ))
    return rows


class TestNotReadyByDefault:

    def test_no_rows_not_ready(self, checker):
        r = checker.evaluate_readiness(TASK_A, labeled_rows=[])
        assert r.status == ReadinessStatus.NOT_READY_FOR_TRAINING

    def test_no_rows_returns_reason(self, checker):
        r = checker.evaluate_readiness(TASK_A, labeled_rows=[])
        assert r.reasons

    def test_none_rows_not_ready(self, checker):
        r = checker.evaluate_readiness(TASK_A, labeled_rows=None)
        assert r.status == ReadinessStatus.NOT_READY_FOR_TRAINING

    def test_synthetic_only_not_ready(self, checker, store):
        rows = _make_rows(store, MIN_LABELED_ROWS + 10, synthetic=True)
        r = checker.evaluate_readiness(TASK_A, labeled_rows=rows)
        assert r.status == ReadinessStatus.NOT_READY_FOR_TRAINING
        assert any("synthetic" in reason.lower() for reason in r.reasons)

    def test_insufficient_rows_not_ready(self, checker, store):
        rows = _make_rows(store, MIN_LABELED_ROWS - 5)
        r = checker.evaluate_readiness(TASK_A, labeled_rows=rows, qualitative_reviewed=True)
        assert r.status == ReadinessStatus.NOT_READY_FOR_TRAINING

    def test_no_qualitative_review_not_ready(self, checker, store):
        rows = _make_rows(store, MIN_LABELED_ROWS, n_groups=MIN_UNIQUE_GROUPS + 1)
        r = checker.evaluate_readiness(TASK_A, labeled_rows=rows, qualitative_reviewed=False)
        assert r.status == ReadinessStatus.NOT_READY_FOR_TRAINING

    def test_unknown_task_not_ready(self, checker):
        r = checker.evaluate_readiness("nonexistent_task", labeled_rows=[])
        assert r.status == ReadinessStatus.NOT_READY_FOR_TRAINING


class TestReadinessReportInvariants:

    def test_model_trained_always_false(self, checker):
        r = checker.evaluate_readiness(TASK_A, labeled_rows=[])
        assert r.model_trained is False

    def test_ml_probability_not_modified(self, checker):
        r = checker.evaluate_readiness(TASK_A, labeled_rows=[])
        assert r.ml_probability_modified is False

    def test_returns_readiness_report_instance(self, checker):
        r = checker.evaluate_readiness(TASK_A)
        assert isinstance(r, ReadinessReport)

    def test_checked_at_set(self, checker):
        r = checker.evaluate_readiness(TASK_A)
        assert r.checked_at and "T" in r.checked_at

    def test_task_in_report(self, checker):
        r = checker.evaluate_readiness(TASK_B)
        assert r.task == TASK_B

    def test_reasons_list_on_not_ready(self, checker):
        r = checker.evaluate_readiness(TASK_A)
        assert isinstance(r.reasons, list)


class TestReadyCondition:

    def test_all_gates_pass_gives_ready(self, checker, store):
        rows = _make_rows(store, MIN_LABELED_ROWS, n_groups=MIN_UNIQUE_GROUPS + 1)
        r = checker.evaluate_readiness(TASK_A, labeled_rows=rows, qualitative_reviewed=True)
        assert r.status == ReadinessStatus.READY_FOR_TRAINING
        assert r.reasons == []
        assert r.model_trained is False  # still never trains

    def test_ready_snapshot_gate_pass_true(self, checker, store):
        rows = _make_rows(store, MIN_LABELED_ROWS, n_groups=MIN_UNIQUE_GROUPS + 1)
        r = checker.evaluate_readiness(TASK_A, labeled_rows=rows, qualitative_reviewed=True)
        assert r.gate_snapshot is not None
        assert r.gate_snapshot.gate_pass is True


class TestCurrentStateExpectation:

    def test_empty_dataset_is_not_ready(self, checker):
        """At Stage 11 with no real data, the system MUST report NOT_READY."""
        r = checker.evaluate_readiness(TASK_A, labeled_rows=None)
        assert r.status == ReadinessStatus.NOT_READY_FOR_TRAINING

    def test_no_model_trained_ever(self, checker, store):
        """Even if ready, no model is trained here."""
        rows = _make_rows(store, MIN_LABELED_ROWS, n_groups=MIN_UNIQUE_GROUPS + 1)
        r = checker.evaluate_readiness(TASK_A, labeled_rows=rows, qualitative_reviewed=True)
        assert r.model_trained is False
        assert r.ml_probability_modified is False

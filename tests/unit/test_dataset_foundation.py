"""Stage 10: Dataset/label foundation tests (Category 9 subset).

Verifies LabelStore, group_key computation, Task A/B separation,
synthetic row handling, and DatasetSnapshot gate checks.
"""
import pytest

from raven.dataset_foundation import (
    LabelStore,
    LabeledObservation,
    DatasetSnapshot,
    evaluate_dataset_gate,
    LabelError,
    DatasetGateError,
    TASK_A,
    TASK_B,
    TASK_C,
    VALID_TASKS,
    MIN_LABELED_ROWS,
    MIN_UNIQUE_GROUPS,
    _compute_group_key,
)


@pytest.fixture
def store():
    return LabelStore()


def _label(store, task=TASK_A, label="DIFFERENT", ws="ws1",
           asset_id="a1", obs_id=None, synthetic=False, labeler="alice"):
    return store.write_label(
        workspace_id=ws,
        task=task,
        label=label,
        labeler=labeler,
        observation_id=obs_id,
        asset_id=asset_id,
        synthetic=synthetic,
    )


class TestLabelStoreValidation:

    def test_empty_workspace_raises(self, store):
        with pytest.raises(LabelError, match="workspace_id"):
            store.write_label(workspace_id="", task=TASK_A, label="X", labeler="alice")

    def test_invalid_task_raises(self, store):
        with pytest.raises(LabelError, match="task"):
            store.write_label(workspace_id="ws1", task="fake_task", label="X", labeler="alice")

    def test_empty_label_raises(self, store):
        with pytest.raises(LabelError, match="label"):
            store.write_label(workspace_id="ws1", task=TASK_A, label="", labeler="alice")

    def test_whitespace_label_raises(self, store):
        with pytest.raises(LabelError, match="label"):
            store.write_label(workspace_id="ws1", task=TASK_A, label="   ", labeler="alice")

    def test_empty_labeler_raises(self, store):
        with pytest.raises(LabelError, match="labeler"):
            store.write_label(workspace_id="ws1", task=TASK_A, label="X", labeler="")

    def test_all_three_tasks_accepted(self, store):
        for task in [TASK_A, TASK_B, TASK_C]:
            r = _label(store, task=task)
            assert r.task == task


class TestLabeledObservationFields:

    def test_returns_labeled_observation(self, store):
        r = _label(store)
        assert isinstance(r, LabeledObservation)

    def test_id_is_uuid4_hex(self, store):
        r = _label(store)
        assert len(r.id) == 32
        assert all(c in "0123456789abcdef" for c in r.id)

    def test_two_labels_different_ids(self, store):
        r1 = _label(store)
        r2 = _label(store)
        assert r1.id != r2.id

    def test_labeled_at_set(self, store):
        r = _label(store)
        assert r.labeled_at and "T" in r.labeled_at

    def test_synthetic_false_by_default(self, store):
        r = _label(store)
        assert r.synthetic is False

    def test_synthetic_flag_propagated(self, store):
        r = _label(store, synthetic=True)
        assert r.synthetic is True

    def test_label_stripped(self, store):
        r = store.write_label(workspace_id="ws1", task=TASK_A,
                              label=" DIFFERENT ", labeler="alice")
        assert r.label == "DIFFERENT"


class TestGroupKey:

    def test_group_key_present(self, store):
        r = _label(store)
        assert r.group_key and len(r.group_key) > 0

    def test_same_workspace_asset_same_group_key(self, store):
        r1 = _label(store, ws="ws1", asset_id="a1")
        r2 = _label(store, ws="ws1", asset_id="a1")
        assert r1.group_key == r2.group_key

    def test_different_asset_different_group_key(self, store):
        r1 = _label(store, ws="ws1", asset_id="a1")
        r2 = _label(store, ws="ws1", asset_id="a2")
        assert r1.group_key != r2.group_key

    def test_different_workspace_different_group_key(self, store):
        r1 = _label(store, ws="ws1", asset_id="a1")
        r2 = _label(store, ws="ws2", asset_id="a1")
        assert r1.group_key != r2.group_key

    def test_group_key_not_derived_from_label(self, store):
        r1 = _label(store, ws="ws1", asset_id="a1", label="DIFFERENT")
        r2 = _label(store, ws="ws1", asset_id="a1", label="SIMILAR")
        # Same workspace+asset → same group_key regardless of label
        assert r1.group_key == r2.group_key

    def test_compute_group_key_deterministic(self):
        k1 = _compute_group_key("ws_abc", "asset_123")
        k2 = _compute_group_key("ws_abc", "asset_123")
        assert k1 == k2

    def test_group_key_not_a_parameter(self, store):
        import inspect
        sig = inspect.signature(store.write_label)
        assert "group_key" not in sig.parameters


class TestTaskSeparation:

    def test_task_a_b_label_rows_separate(self, store):
        ra = _label(store, task=TASK_A, label="DIFFERENT")
        rb = _label(store, task=TASK_B, label="authorized")
        assert ra.task == TASK_A
        assert rb.task == TASK_B
        assert ra.task != rb.task

    def test_valid_tasks_are_correct_names(self):
        assert TASK_A == "response_difference"
        assert TASK_B == "authorization_significance"
        assert TASK_C == "finding_priority"


class TestToDbRow:

    def test_db_row_keys(self, store):
        r = _label(store)
        row = store.to_db_row(r)
        required = {"id", "workspace_id", "task", "label", "group_key",
                    "labeler", "labeled_at", "synthetic", "observation_id"}
        assert required.issubset(row.keys())

    def test_synthetic_stored_as_int(self, store):
        r = _label(store, synthetic=True)
        row = store.to_db_row(r)
        assert row["synthetic"] == 1


class TestDatasetGate:

    def _make_rows(self, store, n, n_positive, n_groups, synthetic=0):
        rows = []
        for i in range(n):
            group_id = str(i % n_groups)
            label = "DIFFERENT" if i < n_positive else "SIMILAR"
            rows.append(store.write_label(
                workspace_id="ws1", task=TASK_A, label=label,
                labeler="alice", asset_id=f"asset_{group_id}",
            ))
        for i in range(synthetic):
            rows.append(store.write_label(
                workspace_id="ws1", task=TASK_A, label="DIFFERENT",
                labeler="alice", asset_id="synth_asset", synthetic=True,
            ))
        return rows

    def test_insufficient_rows_fails_gate(self, store):
        rows = self._make_rows(store, MIN_LABELED_ROWS - 1, 10, MIN_UNIQUE_GROUPS)
        snap = evaluate_dataset_gate(TASK_A, rows, qualitative_reviewed=True)
        assert snap.gate_pass is False
        assert any("Insufficient rows" in f for f in snap.gate_failures)

    def test_insufficient_groups_fails_gate(self, store):
        rows = self._make_rows(store, MIN_LABELED_ROWS, 25, MIN_UNIQUE_GROUPS - 1)
        snap = evaluate_dataset_gate(TASK_A, rows, qualitative_reviewed=True)
        assert snap.gate_pass is False
        assert any("groups" in f for f in snap.gate_failures)

    def test_no_qualitative_review_fails_gate(self, store):
        rows = self._make_rows(store, MIN_LABELED_ROWS, 25, MIN_UNIQUE_GROUPS)
        snap = evaluate_dataset_gate(TASK_A, rows, qualitative_reviewed=False)
        assert snap.gate_pass is False
        assert any("qualitatively reviewed" in f for f in snap.gate_failures)

    def test_all_gates_pass(self, store):
        rows = self._make_rows(store, MIN_LABELED_ROWS, 25, MIN_UNIQUE_GROUPS)
        snap = evaluate_dataset_gate(TASK_A, rows, qualitative_reviewed=True)
        assert snap.gate_pass is True
        assert snap.gate_failures == []

    def test_synthetic_excluded_from_row_count(self, store):
        real = MIN_LABELED_ROWS
        synth = 100
        rows = self._make_rows(store, real, 25, MIN_UNIQUE_GROUPS, synthetic=synth)
        snap = evaluate_dataset_gate(TASK_A, rows, qualitative_reviewed=True)
        assert snap.row_count == real
        assert snap.synthetic_count == synth

    def test_snapshot_has_id_and_timestamp(self, store):
        rows = self._make_rows(store, MIN_LABELED_ROWS, 25, MIN_UNIQUE_GROUPS)
        snap = evaluate_dataset_gate(TASK_A, rows, qualitative_reviewed=True)
        assert len(snap.id) == 32
        assert "T" in snap.snapshot_at

    def test_invalid_task_raises(self, store):
        with pytest.raises(DatasetGateError):
            evaluate_dataset_gate("fake_task", [], qualitative_reviewed=True)

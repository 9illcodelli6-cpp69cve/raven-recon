"""Category 8: ML Output Contract — Stage 1 schema-level tests.

Stage 1 verifies that the schema correctly supports the ML output contract:
  - model_inferences table has all required columns
  - ml_probability and confidence are separate columns (never conflated)
  - Two inference inserts produce two distinct rows (immutability: no overwrite path)
  - model_inferences.model_id FK references model_versions
  - Store exposes no UPDATE/DELETE methods for model_inferences
  - ml_probability is NULL by default on new findings

Runtime contract tests (inference engine wiring, InferenceResult validation,
deployed-model gate) are deferred to Stage 11.
"""
import pathlib
import tempfile
import uuid

import pytest

from raven.store import Store


@pytest.fixture
def store():
    with tempfile.TemporaryDirectory() as d:
        s = Store(pathlib.Path(d))
        yield s
        s.close()


def _uuid4_hex():
    return uuid.uuid4().hex


def _insert_model_version(store, task="ResponseDifference"):
    mid = "mv-" + _uuid4_hex()
    store.db.execute(
        "INSERT INTO model_versions(id, task, version, feature_version, dataset_version, created_at)"
        " VALUES(?,?,?,?,?,?)",
        (mid, task, "1.0.0", "v1", "ds-v1", "2026-01-01T00:00:00Z"),
    )
    store.db.commit()
    return mid


def _insert_inference(store, model_id, finding_id=None, observation_id=None):
    iid = _uuid4_hex()
    store.db.execute(
        "INSERT INTO model_inferences"
        "(id, model_id, input_hash, feature_version, raw_output, probability,"
        " label, threshold_used, above_threshold, timestamp, calibrated)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (iid, model_id, "a" * 64, "v1",
         '{"prob": 0.82}', 0.82, "DIFFERENT", 0.50, 1,
         "2026-01-01T00:00:00Z", 0),
    )
    store.db.commit()
    return iid


class TestMLOutputContractSchema:

    def test_model_inference_table_exists(self, store):
        rows = store.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='model_inferences'"
        ).fetchall()
        assert rows, "model_inferences table must exist after Stage 1 migration"

    def test_model_version_table_exists(self, store):
        rows = store.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='model_versions'"
        ).fetchall()
        assert rows, "model_versions table must exist after Stage 1 migration"

    def test_inference_result_has_all_required_fields(self, store):
        required = {
            "id", "finding_id", "observation_id", "model_id", "input_hash",
            "feature_version", "raw_output", "probability", "label",
            "threshold_used", "above_threshold", "timestamp", "dataset_version", "calibrated",
        }
        rows = store.db.execute("PRAGMA table_info(model_inferences)").fetchall()
        cols = {r["name"] for r in rows}
        missing = required - cols
        assert not missing, f"model_inferences missing required columns: {missing}"

    def test_model_inference_immutable(self, store):
        methods = [m for m in dir(store) if not m.startswith("_")]
        bad = [m for m in methods
               if "inference" in m.lower() and ("update" in m.lower() or "delete" in m.lower())]
        assert not bad, (
            f"Store must not expose UPDATE/DELETE methods for model_inferences: {bad}"
        )

    def test_new_inference_creates_new_row(self, store):
        mid = _insert_model_version(store)
        iid1 = _insert_inference(store, mid)
        iid2 = _insert_inference(store, mid)
        assert iid1 != iid2, "Each inference run must produce a new unique id"
        count = store.db.execute(
            "SELECT COUNT(*) FROM model_inferences WHERE model_id=?", (mid,)
        ).fetchone()[0]
        assert count == 2, (
            "Running inference again must create a NEW row, not overwrite the previous one"
        )

    def test_ml_probability_not_copied_to_confidence(self, store):
        rows = store.db.execute("PRAGMA table_info(findings)").fetchall()
        cols = {r["name"] for r in rows}
        assert "ml_probability" in cols, "findings must have ml_probability column"
        assert "confidence" in cols, "findings must have confidence column"
        idx = {r["name"]: r["cid"] for r in rows}
        assert idx["ml_probability"] != idx["confidence"], (
            "ml_probability and confidence must be distinct columns"
        )

    def test_inference_input_hash_column_exists(self, store):
        rows = store.db.execute("PRAGMA table_info(model_inferences)").fetchall()
        cols = {r["name"] for r in rows}
        assert "input_hash" in cols, (
            "ModelInference must store input_hash (SHA-256 of feature vector)"
        )

    def test_inference_links_model_version(self, store):
        mid = _insert_model_version(store)
        iid = _insert_inference(store, mid)
        row = store.db.execute(
            "SELECT mi.model_id, mv.id FROM model_inferences mi"
            " JOIN model_versions mv ON mi.model_id = mv.id WHERE mi.id=?",
            (iid,),
        ).fetchone()
        assert row is not None, (
            "model_inferences.model_id must reference a valid model_versions row"
        )
        assert row["model_id"] == mid

    def test_ml_probability_null_at_schema_default(self, store):
        fid = _uuid4_hex()
        store.db.execute(
            "INSERT INTO findings(id, workspace_id, title, url, severity, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (fid, _uuid4_hex(), "t", "https://t.example/", "info",
             "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        )
        store.db.commit()
        row = store.db.execute(
            "SELECT ml_probability FROM findings WHERE id=?", (fid,)
        ).fetchone()
        assert row["ml_probability"] is None, (
            "ml_probability must be NULL by default; only set by Stage 11 inference engine"
        )

    def test_model_version_task_field_accepts_canonical_names(self, store):
        # Tasks per amendment 2: ResponseDifference, AuthorizationSignificance, FindingPriority
        for task in ("ResponseDifference", "AuthorizationSignificance", "FindingPriority"):
            mid = _insert_model_version(store, task=task)
            row = store.db.execute(
                "SELECT task FROM model_versions WHERE id=?", (mid,)
            ).fetchone()
            assert row["task"] == task

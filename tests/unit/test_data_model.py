"""Category 2: Data Model Invariants — Stage 1 schema-level tests.

These tests verify the canonical schema created by _migrate_canonical_schema():
  - All required tables exist
  - Original tables are preserved (never dropped)
  - uuid4 hex is used as primary key (not title, not integer)
  - verification_status defaults to 'unverified'
  - ml_probability is NULL by default (separate from confidence)
  - Amendment-4 fields exist on Observation (BaselineEligibilityPolicy)
  - Amendment-7 group_key exists on LabeledObservation
  - Multi-target attribution: each finding references its own asset_id
  - Two findings with the same title are distinct rows (identity is uuid, not title)
  - Store exposes no UPDATE/DELETE methods for immutable tables

Application-layer enforcement (WorkflowError, INSERT-only APIs) is tested in later stages
when the corresponding write methods are implemented.
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


def _table_columns(store, table):
    rows = store.db.execute(f"PRAGMA table_info({table})").fetchall()
    return {r["name"] for r in rows}


def _tables(store):
    rows = store.db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    return {r["name"] for r in rows}


class TestDataModelInvariants:

    def test_all_canonical_tables_exist(self, store):
        expected = {
            "workspaces", "canon_assets", "canon_runs", "jobs",
            "observations", "findings", "finding_revisions", "evidence",
            "verifications", "review_events", "model_versions", "model_inferences",
            "relationships", "payloads", "payload_sets", "payload_set_members",
            "baseline_store", "labeled_observations", "dataset_snapshots",
        }
        missing = expected - _tables(store)
        assert not missing, f"Missing canonical tables: {missing}"

    def test_original_tables_preserved(self, store):
        original = {"runs", "assets", "urls", "sightings", "probes", "changes"}
        missing = original - _tables(store)
        assert not missing, f"Original RAVEN v0.1.0 tables were dropped: {missing}"

    def test_finding_id_is_uuid(self, store):
        fid = _uuid4_hex()
        store.db.execute(
            "INSERT INTO findings(id, workspace_id, title, url, severity, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (fid, _uuid4_hex(), "test finding", "https://test.example/", "info",
             "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        )
        store.db.commit()
        row = store.db.execute("SELECT id FROM findings WHERE id=?", (fid,)).fetchone()
        assert row is not None
        assert len(row["id"]) == 32
        assert all(c in "0123456789abcdef" for c in row["id"])

    def test_finding_verification_status_defaults_to_unverified(self, store):
        fid = _uuid4_hex()
        store.db.execute(
            "INSERT INTO findings(id, workspace_id, title, url, severity, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (fid, _uuid4_hex(), "t", "https://t.example/", "info",
             "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        )
        store.db.commit()
        row = store.db.execute(
            "SELECT verification_status, review_status FROM findings WHERE id=?", (fid,)
        ).fetchone()
        assert row["verification_status"] == "unverified"
        assert row["review_status"] == "new"

    def test_finding_candidate_status_on_creation(self, store):
        fid = _uuid4_hex()
        store.db.execute(
            "INSERT INTO findings(id, workspace_id, title, url, severity,"
            " source_engine, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (fid, _uuid4_hex(), "xss candidate", "https://t.example/x", "medium",
             "raven-xss", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        )
        store.db.commit()
        row = store.db.execute(
            "SELECT verification_status FROM findings WHERE id=?", (fid,)
        ).fetchone()
        assert row["verification_status"] == "unverified", (
            "Detector-generated finding must start as 'unverified'"
        )

    def test_ml_probability_null_before_model(self, store):
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
            "ml_probability must be NULL until Stage 11 inference engine runs"
        )

    def test_ml_probability_separate_from_confidence(self, store):
        cols = _table_columns(store, "findings")
        assert "ml_probability" in cols
        assert "confidence" in cols
        rows = store.db.execute("PRAGMA table_info(findings)").fetchall()
        idx = {r["name"]: r["cid"] for r in rows}
        assert idx["ml_probability"] != idx["confidence"], (
            "ml_probability and confidence must be separate columns with distinct indexes"
        )

    def test_evidence_no_update_method_in_store(self, store):
        methods = [m for m in dir(store) if not m.startswith("_")]
        bad = [m for m in methods if "evidence" in m.lower() and "update" in m.lower()]
        assert not bad, f"Store must not expose evidence UPDATE methods: {bad}"

    def test_review_event_no_update_method_in_store(self, store):
        methods = [m for m in dir(store) if not m.startswith("_")]
        bad = [m for m in methods
               if ("review" in m.lower() or "event" in m.lower()) and "update" in m.lower()]
        assert not bad, f"Store must not expose ReviewEvent UPDATE methods: {bad}"

    def test_model_inference_no_update_method_in_store(self, store):
        methods = [m for m in dir(store) if not m.startswith("_")]
        bad = [m for m in methods
               if "inference" in m.lower() and ("update" in m.lower() or "delete" in m.lower())]
        assert not bad, f"Store must not expose ModelInference UPDATE/DELETE methods: {bad}"

    def test_observation_has_baseline_eligibility_fields(self, store):
        cols = _table_columns(store, "observations")
        required = {"acquisition_mode", "is_probe", "is_anomalous", "baseline_approved"}
        missing = required - cols
        assert not missing, f"observations missing amendment-4 eligibility fields: {missing}"

    def test_observation_acquisition_mode_defaults_to_collect(self, store):
        oid = _uuid4_hex()
        store.db.execute(
            "INSERT INTO observations(id, workspace_id, url, method) VALUES(?,?,?,?)",
            (oid, _uuid4_hex(), "https://t.example/", "GET"),
        )
        store.db.commit()
        row = store.db.execute(
            "SELECT acquisition_mode, is_probe, is_anomalous, baseline_approved"
            " FROM observations WHERE id=?",
            (oid,),
        ).fetchone()
        assert row["acquisition_mode"] == "collect"
        assert row["is_probe"] == 0
        assert row["is_anomalous"] == 0
        assert row["baseline_approved"] == 0

    def test_labeled_observation_has_group_key(self, store):
        cols = _table_columns(store, "labeled_observations")
        assert "group_key" in cols, "LabeledObservation must have group_key (amendment 7)"
        assert "synthetic" in cols, "LabeledObservation must have synthetic flag (amendment 8)"

    def test_multi_target_attribution(self, store):
        wid = _uuid4_hex()
        aid1, aid2 = _uuid4_hex(), _uuid4_hex()
        fid1, fid2 = _uuid4_hex(), _uuid4_hex()
        for fid, aid in ((fid1, aid1), (fid2, aid2)):
            store.db.execute(
                "INSERT INTO findings(id, workspace_id, asset_id, title, url, severity,"
                " created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (fid, wid, aid, "f", "https://t.example/", "info",
                 "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            )
        store.db.commit()
        rows = {
            r["id"]: r["asset_id"]
            for r in store.db.execute(
                "SELECT id, asset_id FROM findings WHERE id IN (?,?)", (fid1, fid2)
            ).fetchall()
        }
        assert rows[fid1] != rows[fid2], (
            "Each finding must reference its own asset_id (no first-target attribution bug)"
        )

    def test_finding_key_is_id_not_title(self, store):
        wid = _uuid4_hex()
        fid1, fid2 = _uuid4_hex(), _uuid4_hex()
        for fid in (fid1, fid2):
            store.db.execute(
                "INSERT INTO findings(id, workspace_id, title, url, severity, created_at, updated_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (fid, wid, "Same Title", "https://t.example/", "info",
                 "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            )
        store.db.commit()
        count = store.db.execute(
            "SELECT COUNT(*) FROM findings WHERE title='Same Title'"
        ).fetchone()[0]
        assert count == 2, (
            "Two findings with same title must be stored as separate rows; "
            "identity is uuid4, not title"
        )

    def test_model_inference_schema_complete(self, store):
        cols = _table_columns(store, "model_inferences")
        required = {
            "id", "finding_id", "observation_id", "model_id", "input_hash",
            "feature_version", "raw_output", "probability", "label",
            "threshold_used", "above_threshold", "timestamp", "dataset_version", "calibrated",
        }
        missing = required - cols
        assert not missing, f"model_inferences missing columns: {missing}"

    def test_migration_is_idempotent(self, store):
        # Running the migration a second time must not raise or lose data
        fid = _uuid4_hex()
        store.db.execute(
            "INSERT INTO findings(id, workspace_id, title, url, severity, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (fid, _uuid4_hex(), "idempotent test", "https://t.example/", "info",
             "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        )
        store.db.commit()
        store._migrate_canonical_schema()
        row = store.db.execute("SELECT id FROM findings WHERE id=?", (fid,)).fetchone()
        assert row is not None, "Migration must not drop data when run a second time"

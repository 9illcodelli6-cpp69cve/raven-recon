"""Stage 2: Adversarial security tests against the canonical schema.

Tests ACTUALLY ATTEMPT violations — they do not assume safety from code convention.
Immutability, FK constraints, workspace isolation, identity, baseline defaults,
ML persistence contract, and SQLite integrity are all verified with real SQL attempts.
"""
import pathlib
import sqlite3
import tempfile
import threading
import uuid

import pytest

from raven.store import Store


@pytest.fixture
def store():
    with tempfile.TemporaryDirectory() as d:
        s = Store(pathlib.Path(d))
        try:
            yield s
        finally:
            s.close()


def uid():
    return uuid.uuid4().hex


def _finding(store, workspace_id=None, asset_id=None, title="t", url="https://t.example/"):
    wid = workspace_id or uid()
    fid = uid()
    store.db.execute(
        "INSERT INTO findings(id,workspace_id,asset_id,title,url,severity,created_at,updated_at)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (fid, wid, asset_id, title, url, "info", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
    )
    store.db.commit()
    return fid, wid


def _observation(store, workspace_id=None):
    wid = workspace_id or uid()
    oid = uid()
    store.db.execute(
        "INSERT INTO observations(id,workspace_id,url,method) VALUES(?,?,?,?)",
        (oid, wid, "https://t.example/", "GET"),
    )
    store.db.commit()
    return oid, wid


def _model_version(store):
    mid = uid()
    store.db.execute(
        "INSERT INTO model_versions(id,task,version,feature_version,dataset_version,created_at)"
        " VALUES(?,?,?,?,?,?)",
        (mid, "ResponseDifference", "1.0.0", "v1", "ds-v1", "2026-01-01T00:00:00Z"),
    )
    store.db.commit()
    return mid


# ---------------------------------------------------------------------------
# 1. IMMUTABILITY (actual SQL attempts)
# ---------------------------------------------------------------------------

class TestImmutabilityViolations:

    def test_evidence_update_rejected(self, store):
        fid, wid = _finding(store)
        eid = uid()
        store.db.execute(
            "INSERT INTO evidence(id,workspace_id,finding_id,kind) VALUES(?,?,?,?)",
            (eid, wid, fid, "reflection"),
        )
        store.db.commit()
        with pytest.raises(sqlite3.IntegrityError, match="INSERT-only"):
            store.db.execute("UPDATE evidence SET kind='mutated' WHERE id=?", (eid,))

    def test_evidence_delete_rejected(self, store):
        fid, wid = _finding(store)
        eid = uid()
        store.db.execute(
            "INSERT INTO evidence(id,workspace_id,finding_id,kind) VALUES(?,?,?,?)",
            (eid, wid, fid, "reflection"),
        )
        store.db.commit()
        with pytest.raises(sqlite3.IntegrityError, match="INSERT-only"):
            store.db.execute("DELETE FROM evidence WHERE id=?", (eid,))

    def test_review_event_update_rejected(self, store):
        fid, wid = _finding(store)
        rid = uid()
        store.db.execute(
            "INSERT INTO review_events(id,finding_id,action,timestamp) VALUES(?,?,?,?)",
            (rid, fid, "created", "2026-01-01T00:00:00Z"),
        )
        store.db.commit()
        with pytest.raises(sqlite3.IntegrityError, match="INSERT-only"):
            store.db.execute("UPDATE review_events SET action='tampered' WHERE id=?", (rid,))

    def test_review_event_delete_rejected(self, store):
        fid, wid = _finding(store)
        rid = uid()
        store.db.execute(
            "INSERT INTO review_events(id,finding_id,action,timestamp) VALUES(?,?,?,?)",
            (rid, fid, "created", "2026-01-01T00:00:00Z"),
        )
        store.db.commit()
        with pytest.raises(sqlite3.IntegrityError, match="INSERT-only"):
            store.db.execute("DELETE FROM review_events WHERE id=?", (rid,))

    def test_model_inference_update_rejected(self, store):
        mid = _model_version(store)
        iid = uid()
        store.db.execute(
            "INSERT INTO model_inferences(id,model_id,feature_version,probability,timestamp)"
            " VALUES(?,?,?,?,?)",
            (iid, mid, "v1", 0.75, "2026-01-01T00:00:00Z"),
        )
        store.db.commit()
        with pytest.raises(sqlite3.IntegrityError, match="INSERT-only"):
            store.db.execute("UPDATE model_inferences SET probability=0.99 WHERE id=?", (iid,))

    def test_model_inference_delete_rejected(self, store):
        mid = _model_version(store)
        iid = uid()
        store.db.execute(
            "INSERT INTO model_inferences(id,model_id,feature_version,probability,timestamp)"
            " VALUES(?,?,?,?,?)",
            (iid, mid, "v1", 0.75, "2026-01-01T00:00:00Z"),
        )
        store.db.commit()
        with pytest.raises(sqlite3.IntegrityError, match="INSERT-only"):
            store.db.execute("DELETE FROM model_inferences WHERE id=?", (iid,))


# ---------------------------------------------------------------------------
# 2. FOREIGN KEY ENFORCEMENT
# ---------------------------------------------------------------------------

class TestForeignKeys:

    def test_fk_on(self, store):
        result = store.db.execute("PRAGMA foreign_keys").fetchone()
        assert result[0] == 1, "PRAGMA foreign_keys must be ON"

    def test_orphan_evidence_rejected(self, store):
        with pytest.raises(sqlite3.IntegrityError):
            store.db.execute(
                "INSERT INTO evidence(id,workspace_id,finding_id,kind) VALUES(?,?,?,?)",
                (uid(), uid(), uid(), "test"),
            )
            store.db.commit()

    def test_orphan_review_event_rejected(self, store):
        with pytest.raises(sqlite3.IntegrityError):
            store.db.execute(
                "INSERT INTO review_events(id,finding_id,action,timestamp) VALUES(?,?,?,?)",
                (uid(), uid(), "created", "2026-01-01T00:00:00Z"),
            )
            store.db.commit()

    def test_orphan_model_inference_rejected(self, store):
        with pytest.raises(sqlite3.IntegrityError):
            store.db.execute(
                "INSERT INTO model_inferences(id,model_id,feature_version,timestamp)"
                " VALUES(?,?,?,?)",
                (uid(), uid(), "v1", "2026-01-01T00:00:00Z"),
            )
            store.db.commit()

    def test_orphan_payload_set_member_payload_rejected(self, store):
        ps_id = uid()
        store.db.execute(
            "INSERT INTO payload_sets(id,name,risk_max,created_at) VALUES(?,?,?,?)",
            (ps_id, "s", "SAFE_MARKER", "2026-01-01T00:00:00Z"),
        )
        store.db.commit()
        with pytest.raises(sqlite3.IntegrityError):
            store.db.execute(
                "INSERT INTO payload_set_members(payload_set_id,payload_id) VALUES(?,?)",
                (ps_id, uid()),
            )
            store.db.commit()

    def test_duplicate_primary_key_rejected(self, store):
        fid, wid = _finding(store)
        with pytest.raises(sqlite3.IntegrityError):
            store.db.execute(
                "INSERT INTO findings(id,workspace_id,title,url,severity,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (fid, wid, "duplicate", "https://t.example/", "info",
                 "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            )
            store.db.commit()


# ---------------------------------------------------------------------------
# 3. WORKSPACE ISOLATION
# ---------------------------------------------------------------------------

class TestWorkspaceIsolation:

    def _populate_workspace(self, store, wid, label):
        # Same title, url, asset host in both workspaces
        fid = uid()
        store.db.execute(
            "INSERT INTO findings(id,workspace_id,title,url,severity,created_at,updated_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (fid, wid, "Same Title", "https://shared.example/path", "high",
             "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        )
        oid = uid()
        store.db.execute(
            "INSERT INTO observations(id,workspace_id,url,method) VALUES(?,?,?,?)",
            (oid, wid, "https://shared.example/path", "GET"),
        )
        eid = uid()
        store.db.execute(
            "INSERT INTO evidence(id,workspace_id,finding_id,kind,summary) VALUES(?,?,?,?,?)",
            (eid, wid, fid, "reflection", f"evidence-for-{label}"),
        )
        store.db.commit()
        return fid, oid, eid

    def test_findings_do_not_bleed(self, store):
        wid_a, wid_b = uid(), uid()
        fid_a, _, _ = self._populate_workspace(store, wid_a, "A")
        fid_b, _, _ = self._populate_workspace(store, wid_b, "B")
        rows_a = store.db.execute(
            "SELECT id FROM findings WHERE workspace_id=?", (wid_a,)
        ).fetchall()
        ids_a = {r[0] for r in rows_a}
        assert fid_a in ids_a
        assert fid_b not in ids_a

    def test_evidence_does_not_cross_link(self, store):
        wid_a, wid_b = uid(), uid()
        fid_a, _, eid_a = self._populate_workspace(store, wid_a, "A")
        fid_b, _, eid_b = self._populate_workspace(store, wid_b, "B")
        # Evidence for A should not appear under workspace B's findings
        evidence_for_b = store.db.execute(
            "SELECT e.id FROM evidence e JOIN findings f ON e.finding_id=f.id"
            " WHERE f.workspace_id=?",
            (wid_b,),
        ).fetchall()
        ids = {r[0] for r in evidence_for_b}
        assert eid_b in ids
        assert eid_a not in ids

    def test_baseline_does_not_bleed(self, store):
        wid_a, wid_b = uid(), uid()
        aid = uid()
        ts = "2026-01-01T00:00:00Z"
        for wid in (wid_a, wid_b):
            store.db.execute(
                "INSERT INTO baseline_store(id,workspace_id,asset_id,url_fingerprint,"
                "identity_label,sample_count,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (uid(), wid, aid, "https://shared.example/", "anon", 5, ts, ts),
            )
        store.db.commit()
        rows_a = store.db.execute(
            "SELECT id FROM baseline_store WHERE workspace_id=?", (wid_a,)
        ).fetchall()
        rows_b = store.db.execute(
            "SELECT id FROM baseline_store WHERE workspace_id=?", (wid_b,)
        ).fetchall()
        assert len(rows_a) == 1
        assert len(rows_b) == 1
        assert rows_a[0][0] != rows_b[0][0]


# ---------------------------------------------------------------------------
# 4. IDENTITY COLLISIONS
# ---------------------------------------------------------------------------

class TestIdentityCollisions:

    def test_same_title_different_uuid(self, store):
        wid = uid()
        ids = []
        for _ in range(3):
            fid = uid()
            store.db.execute(
                "INSERT INTO findings(id,workspace_id,title,url,severity,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (fid, wid, "Same Title", "https://t.example/", "info",
                 "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            )
            ids.append(fid)
        store.db.commit()
        count = store.db.execute(
            "SELECT COUNT(*) FROM findings WHERE title='Same Title' AND workspace_id=?", (wid,)
        ).fetchone()[0]
        assert count == 3

    def test_same_body_hash_different_observation_uuid(self, store):
        wid = uid()
        body_hash = "a" * 64
        for _ in range(2):
            store.db.execute(
                "INSERT INTO observations(id,workspace_id,url,method,response_body_hash)"
                " VALUES(?,?,?,?,?)",
                (uid(), wid, "https://t.example/", "GET", body_hash),
            )
        store.db.commit()
        count = store.db.execute(
            "SELECT COUNT(*) FROM observations WHERE response_body_hash=?", (body_hash,)
        ).fetchone()[0]
        assert count == 2, "Same body hash must not deduplicate observations automatically"

    def test_same_evidence_content_different_uuid(self, store):
        fid, wid = _finding(store)
        for _ in range(2):
            store.db.execute(
                "INSERT INTO evidence(id,workspace_id,finding_id,kind,raw) VALUES(?,?,?,?,?)",
                (uid(), wid, fid, "reflection", "identical-raw-content"),
            )
        store.db.commit()
        count = store.db.execute(
            "SELECT COUNT(*) FROM evidence WHERE raw='identical-raw-content'"
        ).fetchone()[0]
        assert count == 2


# ---------------------------------------------------------------------------
# 5. ML PERSISTENCE CONTRACT
# ---------------------------------------------------------------------------

class TestMLPersistenceContract:

    def test_ml_probability_null_by_default(self, store):
        fid, _ = _finding(store)
        row = store.db.execute("SELECT ml_probability FROM findings WHERE id=?", (fid,)).fetchone()
        assert row[0] is None

    def test_confidence_independent_of_ml_probability(self, store):
        fid, wid = _finding(store)
        store.db.execute(
            "UPDATE findings SET confidence=0.9 WHERE id=?", (fid,)
        )
        store.db.commit()
        row = store.db.execute(
            "SELECT confidence, ml_probability FROM findings WHERE id=?", (fid,)
        ).fetchone()
        assert row[0] == pytest.approx(0.9)
        assert row[1] is None, "Setting confidence must not affect ml_probability"

    def test_probability_out_of_range_rejected_low(self, store):
        mid = _model_version(store)
        with pytest.raises(sqlite3.IntegrityError, match=r"\[0,1\]"):
            store.db.execute(
                "INSERT INTO model_inferences(id,model_id,feature_version,probability,timestamp)"
                " VALUES(?,?,?,?,?)",
                (uid(), mid, "v1", -0.01, "2026-01-01T00:00:00Z"),
            )
            store.db.commit()

    def test_probability_out_of_range_rejected_high(self, store):
        mid = _model_version(store)
        with pytest.raises(sqlite3.IntegrityError, match=r"\[0,1\]"):
            store.db.execute(
                "INSERT INTO model_inferences(id,model_id,feature_version,probability,timestamp)"
                " VALUES(?,?,?,?,?)",
                (uid(), mid, "v1", 1.01, "2026-01-01T00:00:00Z"),
            )
            store.db.commit()

    def test_probability_null_allowed(self, store):
        mid = _model_version(store)
        store.db.execute(
            "INSERT INTO model_inferences(id,model_id,feature_version,probability,timestamp)"
            " VALUES(?,?,?,?,?)",
            (uid(), mid, "v1", None, "2026-01-01T00:00:00Z"),
        )
        store.db.commit()

    def test_probability_boundary_zero(self, store):
        mid = _model_version(store)
        store.db.execute(
            "INSERT INTO model_inferences(id,model_id,feature_version,probability,timestamp)"
            " VALUES(?,?,?,?,?)",
            (uid(), mid, "v1", 0.0, "2026-01-01T00:00:00Z"),
        )
        store.db.commit()

    def test_probability_boundary_one(self, store):
        mid = _model_version(store)
        store.db.execute(
            "INSERT INTO model_inferences(id,model_id,feature_version,probability,timestamp)"
            " VALUES(?,?,?,?,?)",
            (uid(), mid, "v1", 1.0, "2026-01-01T00:00:00Z"),
        )
        store.db.commit()

    def test_finding_ml_prob_out_of_range_rejected(self, store):
        fid, wid = _finding(store)
        with pytest.raises(sqlite3.IntegrityError, match=r"\[0,1\]"):
            store.db.execute(
                "UPDATE findings SET ml_probability=1.5 WHERE id=?", (fid,)
            )
            store.db.commit()

    def test_synthetic_flag_persists(self, store):
        oid, wid = _observation(store)
        lid = uid()
        store.db.execute(
            "INSERT INTO labeled_observations(id,workspace_id,observation_id,task,label,group_key,synthetic)"
            " VALUES(?,?,?,?,?,?,?)",
            (lid, wid, oid, "ResponseDifference", "DIFFERENT", "gk-" + uid(), 1),
        )
        store.db.commit()
        row = store.db.execute(
            "SELECT synthetic FROM labeled_observations WHERE id=?", (lid,)
        ).fetchone()
        assert row[0] == 1

    def test_group_key_persists(self, store):
        oid, wid = _observation(store)
        gk = "gk-" + uid()
        lid = uid()
        store.db.execute(
            "INSERT INTO labeled_observations(id,workspace_id,observation_id,task,label,group_key)"
            " VALUES(?,?,?,?,?,?)",
            (lid, wid, oid, "ResponseDifference", "NOT_DIFFERENT", gk),
        )
        store.db.commit()
        row = store.db.execute(
            "SELECT group_key FROM labeled_observations WHERE id=?", (lid,)
        ).fetchone()
        assert row[0] == gk


# ---------------------------------------------------------------------------
# 6. BASELINE POISONING DEFAULTS
# ---------------------------------------------------------------------------

class TestBaselinePoisoningDefaults:

    def test_observation_probe_defaults(self, store):
        oid, _ = _observation(store)
        row = store.db.execute(
            "SELECT acquisition_mode,is_probe,is_anomalous,baseline_approved"
            " FROM observations WHERE id=?",
            (oid,),
        ).fetchone()
        assert row[0] == "collect"
        assert row[1] == 0
        assert row[2] == 0
        assert row[3] == 0, "baseline_approved must default to 0 — no auto-approval"

    def test_probe_observation_not_auto_approved(self, store):
        oid = uid()
        store.db.execute(
            "INSERT INTO observations(id,workspace_id,url,method,acquisition_mode,is_probe)"
            " VALUES(?,?,?,?,?,?)",
            (oid, uid(), "https://t.example/", "GET", "probe", 1),
        )
        store.db.commit()
        row = store.db.execute(
            "SELECT baseline_approved FROM observations WHERE id=?", (oid,)
        ).fetchone()
        assert row[0] == 0, "A probe observation must not auto-set baseline_approved"

    def test_anomalous_observation_not_auto_approved(self, store):
        oid = uid()
        store.db.execute(
            "INSERT INTO observations(id,workspace_id,url,method,is_anomalous)"
            " VALUES(?,?,?,?,?)",
            (oid, uid(), "https://t.example/", "GET", 1),
        )
        store.db.commit()
        row = store.db.execute(
            "SELECT baseline_approved FROM observations WHERE id=?", (oid,)
        ).fetchone()
        assert row[0] == 0


# ---------------------------------------------------------------------------
# 7. MALFORMED DATA
# ---------------------------------------------------------------------------

class TestMalformedData:

    def test_long_unicode_title(self, store):
        title = "أ" * 2000  # Arabic, long
        fid = uid()
        wid = uid()
        store.db.execute(
            "INSERT INTO findings(id,workspace_id,title,url,severity,created_at,updated_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (fid, wid, title, "https://t.example/", "info",
             "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        )
        store.db.commit()
        row = store.db.execute("SELECT title FROM findings WHERE id=?", (fid,)).fetchone()
        assert row[0] == title

    def test_emoji_in_evidence(self, store):
        fid, wid = _finding(store)
        raw = "reflected: 🎯 <script>alert(1)</script> 💀"
        eid = uid()
        store.db.execute(
            "INSERT INTO evidence(id,workspace_id,finding_id,kind,raw) VALUES(?,?,?,?,?)",
            (eid, wid, fid, "reflection", raw),
        )
        store.db.commit()
        row = store.db.execute("SELECT raw FROM evidence WHERE id=?", (eid,)).fetchone()
        assert row[0] == raw

    def test_null_optional_fields_ok(self, store):
        fid, wid = _finding(store)
        eid = uid()
        store.db.execute(
            "INSERT INTO evidence(id,workspace_id,finding_id,kind) VALUES(?,?,?,?)",
            (eid, wid, fid, "access_control"),
        )
        store.db.commit()
        row = store.db.execute("SELECT raw, summary FROM evidence WHERE id=?", (eid,)).fetchone()
        assert row[0] is None
        assert row[1] is None

    def test_invalid_verification_status_stored(self, store):
        # Schema doesn't restrict status values — application layer enforces enum.
        fid, wid = _finding(store)
        store.db.execute(
            "UPDATE findings SET verification_status='bogus' WHERE id=?", (fid,)
        )
        store.db.commit()
        row = store.db.execute(
            "SELECT verification_status FROM findings WHERE id=?", (fid,)
        ).fetchone()
        assert row[0] == "bogus"  # Enum enforcement is application-layer

    def test_self_referential_relationship_stored(self, store):
        # Relationships can be self-referential (no DB-level ban); policy is application-layer
        rid = uid()
        entity_id = uid()
        wid = uid()
        store.db.execute(
            "INSERT INTO relationships(id,workspace_id,from_type,from_id,to_type,to_id,relation)"
            " VALUES(?,?,?,?,?,?,?)",
            (rid, wid, "finding", entity_id, "finding", entity_id, "DERIVED_FROM"),
        )
        store.db.commit()


# ---------------------------------------------------------------------------
# 8. SQLITE INTEGRITY
# ---------------------------------------------------------------------------

class TestSQLiteIntegrity:

    def test_integrity_check_clean(self, store):
        result = store.integrity_check()
        assert result == "ok"

    def test_foreign_key_check_clean(self, store):
        rows = store.db.execute("PRAGMA foreign_key_check").fetchall()
        assert not rows, f"FK violations found: {rows}"

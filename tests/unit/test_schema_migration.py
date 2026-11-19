"""Stage 2: Migration safety tests.

Tests fresh DB, legacy-only DB, already-migrated DB, and idempotency.
Also verifies original tables and data are always preserved.
"""
import pathlib
import sqlite3
import tempfile
import uuid

import pytest

from raven.store import Store


def uid():
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# A: Fresh database
# ---------------------------------------------------------------------------

class TestFreshDatabase:

    def test_all_tables_on_fresh_db(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(pathlib.Path(d))
            try:
                rows = s.db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall()
                names = {r[0] for r in rows}
                expected_canonical = {
                    "workspaces", "canon_assets", "canon_runs", "jobs",
                    "observations", "findings", "finding_revisions", "evidence",
                    "verifications", "review_events", "model_versions", "model_inferences",
                    "relationships", "payloads", "payload_sets", "payload_set_members",
                    "baseline_store", "labeled_observations", "dataset_snapshots",
                }
                expected_legacy = {"runs", "assets", "urls", "sightings", "probes", "changes"}
                assert not (expected_canonical - names)
                assert not (expected_legacy - names)
            finally:
                s.close()

    def test_all_triggers_on_fresh_db(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(pathlib.Path(d))
            try:
                rows = s.db.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                ).fetchall()
                triggers = {r[0] for r in rows}
                expected = {
                    "evidence_no_update", "evidence_no_delete",
                    "review_events_no_update", "review_events_no_delete",
                    "model_inferences_no_update", "model_inferences_no_delete",
                    "mi_prob_check",
                    "finding_ml_prob_insert", "finding_ml_prob_update",
                    "finding_confidence_insert", "finding_confidence_update",
                }
                assert not (expected - triggers), f"Missing triggers: {expected - triggers}"
            finally:
                s.close()

    def test_integrity_check_on_fresh_db(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(pathlib.Path(d))
            try:
                assert s.integrity_check() == "ok"
                fk_rows = s.db.execute("PRAGMA foreign_key_check").fetchall()
                assert not fk_rows
            finally:
                s.close()


# ---------------------------------------------------------------------------
# B: Legacy six-table database (simulate RAVEN v0.1.0 DB)
# ---------------------------------------------------------------------------

def _build_legacy_db(path: pathlib.Path):
    db = sqlite3.connect(path / "recon.db")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS runs(
      id INTEGER PRIMARY KEY, started TEXT, finished TEXT, mode TEXT,
      state TEXT, config TEXT, note TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS assets(
      host TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
      score INTEGER, reasons TEXT, sources TEXT);
    CREATE TABLE IF NOT EXISTS urls(
      url TEXT PRIMARY KEY, host TEXT, family TEXT, score INTEGER,
      reasons TEXT, sources TEXT, first_seen TEXT, last_seen TEXT, evidence TEXT);
    CREATE TABLE IF NOT EXISTS sightings(
      run_id INTEGER, kind TEXT, value TEXT,
      PRIMARY KEY(run_id,kind,value), FOREIGN KEY(run_id) REFERENCES runs(id));
    CREATE TABLE IF NOT EXISTS probes(
      run_id INTEGER, host TEXT, data TEXT,
      PRIMARY KEY(run_id,host), FOREIGN KEY(run_id) REFERENCES runs(id));
    CREATE TABLE IF NOT EXISTS changes(
      id INTEGER PRIMARY KEY, run_id INTEGER, kind TEXT, value TEXT, detail TEXT);
    """)
    # Insert realistic legacy rows
    db.execute(
        "INSERT INTO runs(started,mode,state,config,note) VALUES(?,?,?,?,?)",
        ("2026-09-01T00:00:00Z", "collect", "complete", '{}', "baseline run"),
    )
    db.execute(
        "INSERT INTO assets(host,first_seen,last_seen,score,reasons,sources)"
        " VALUES(?,?,?,?,?,?)",
        ("target.example", "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z", 80, "[]", "[]"),
    )
    db.commit()
    db.close()


class TestLegacyDatabaseMigration:

    def test_legacy_data_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d)
            _build_legacy_db(p)
            s = Store(p)
            try:
                runs = s.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
                assert runs == 1, "Existing run row must survive migration"
                assets = s.db.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
                assert assets == 1, "Existing asset row must survive migration"
            finally:
                s.close()

    def test_legacy_plus_canonical_tables_coexist(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d)
            _build_legacy_db(p)
            s = Store(p)
            try:
                tables = {r[0] for r in s.db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()}
                assert "runs" in tables
                assert "findings" in tables
                assert "observations" in tables
            finally:
                s.close()

    def test_integrity_after_legacy_migration(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d)
            _build_legacy_db(p)
            s = Store(p)
            try:
                assert s.integrity_check() == "ok"
                fk_rows = s.db.execute("PRAGMA foreign_key_check").fetchall()
                assert not fk_rows
            finally:
                s.close()


# ---------------------------------------------------------------------------
# C: Already-migrated database (idempotency)
# ---------------------------------------------------------------------------

class TestIdempotentMigration:

    def test_double_migration_safe(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d)
            s = Store(p)
            fid = uid()
            wid = uid()
            s.db.execute(
                "INSERT INTO findings(id,workspace_id,title,url,severity,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (fid, wid, "persisted", "https://t.example/", "info",
                 "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            )
            s.db.commit()
            # Run migration again
            s._migrate_canonical_schema()
            row = s.db.execute("SELECT id FROM findings WHERE id=?", (fid,)).fetchone()
            assert row is not None, "Data must survive re-migration"
            s.close()

    def test_triple_migration_safe(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d)
            s = Store(p)
            s._migrate_canonical_schema()
            s._migrate_canonical_schema()
            assert s.integrity_check() == "ok"
            s.close()

    def test_reopen_existing_db_safe(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d)
            s1 = Store(p)
            fid = uid()
            wid = uid()
            s1.db.execute(
                "INSERT INTO findings(id,workspace_id,title,url,severity,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (fid, wid, "survive-reopen", "https://t.example/", "info",
                 "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            )
            s1.db.commit()
            s1.close()
            s2 = Store(p)
            try:
                row = s2.db.execute("SELECT id FROM findings WHERE id=?", (fid,)).fetchone()
                assert row is not None
                assert s2.integrity_check() == "ok"
            finally:
                s2.close()

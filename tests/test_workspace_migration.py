"""Wave 5 (A5-WS) — the backup + reconcile migration is safe, verified and reversible.

Proves the data-safety contract on a fixture tree:
  * recon.db files are opened READ-ONLY and come out byte-for-byte identical;
  * PRAGMA integrity_check is ok and recon row counts are unchanged;
  * the registry is reconciled additively (filesystem workspaces indexed, pre-existing
    rows preserved, legacy-schema recon.db flagged DEFERRED not repaired);
  * every *.pre_w5ws backup is SHA-256-verified and restores byte-for-byte;
  * the migration is idempotent.

Run:  python -m pytest tests/test_workspace_migration.py -q
"""
import hashlib
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from raven.store import Store
from raven.runtime import workspace_migration as wm


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def _make_legacy_recon(path: Path):
    """A pre-canonical recon.db: the 6 legacy tables only, no `workspaces` table."""
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.executescript("""
        CREATE TABLE runs(id INTEGER PRIMARY KEY, started TEXT, finished TEXT,
          mode TEXT, state TEXT, config TEXT, note TEXT DEFAULT '');
        CREATE TABLE assets(host TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
          score INTEGER, reasons TEXT, sources TEXT);
        CREATE TABLE urls(url TEXT PRIMARY KEY, host TEXT, family TEXT, score INTEGER,
          reasons TEXT, sources TEXT, first_seen TEXT, last_seen TEXT, evidence TEXT);
        CREATE TABLE sightings(run_id INTEGER, kind TEXT, value TEXT);
        CREATE TABLE probes(run_id INTEGER, host TEXT, data TEXT);
        CREATE TABLE changes(id INTEGER PRIMARY KEY, run_id INTEGER, kind TEXT,
          value TEXT, detail TEXT);
    """)
    con.execute("INSERT INTO assets(host, score) VALUES('legacy.example.com', 7)")
    con.commit()
    con.close()


class MigrationSafety(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="raven-ws-mig-"))
        self.backup = Path(tempfile.mkdtemp(prefix="raven-ws-mig-bak-"))

        # canonical-schema workspace with a real recon uuid
        exdir = self.root / "workspaces" / "examplefix"
        st = Store(exdir)
        self.recon_uuid = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
        st.ensure_workspace_record(self.recon_uuid, "examplefix")
        st.host("seed.example.com", "seed", st.start("seed", {}))
        st.close()
        (exdir / "scope.json").write_text(json.dumps(
            {"name": "examplefix", "include": ["ex.example.com"], "ports": [80, 443]}))

        # legacy-only workspace (no canonical `workspaces` table)
        legdir = self.root / "workspaces" / "legacyfix"
        _make_legacy_recon(legdir / "recon.db")
        (legdir / "scope.json").write_text(json.dumps(
            {"name": "legacyfix", "include": ["leg.example.com"], "ports": [443]}))

        # pre-existing V7 registry row with no filesystem counterpart (must be kept)
        con = sqlite3.connect(str(self.root / "workspaces_v7.db"))
        con.execute(wm._WS_SCHEMA)
        con.execute("INSERT INTO workspaces(id, name, slug, created_at, created_ms) "
                    "VALUES('ghost0001', 'Legacy Default', 'legacy_default', '2020-01-01T00:00:00+00:00', 1577836800000)")
        con.commit()
        con.close()

        self.recon_dbs = [self.root / "workspaces" / "examplefix" / "recon.db",
                          self.root / "workspaces" / "legacyfix" / "recon.db"]
        self.pre_hashes = {p: _sha(p) for p in self.recon_dbs}

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.backup, ignore_errors=True)

    def test_migration_is_safe_additive_and_verified(self):
        report = wm.migrate(self.root, do_backup=True, backup_dir=self.backup)
        self.assertEqual(report["status"], "OK", report)

        # 1. recon.db files are byte-for-byte unchanged (read-only reconcile)
        for p in self.recon_dbs:
            self.assertEqual(_sha(p), self.pre_hashes[p], f"{p} was mutated")
            v = report["verification"][str(p)]
            self.assertEqual(v["integrity"], "ok")
            self.assertTrue(v["row_counts_unchanged"], v)

        # 2. backup verified, present
        self.assertEqual(report["backup"]["unverified_copies"], [])
        self.assertGreater(report["backup"]["files"], 0)

        # 3. registry reconciled additively
        con = sqlite3.connect(str(self.root / "workspaces_v7.db"))
        rows = {r[1]: r for r in con.execute("SELECT id, slug, name, settings_json FROM workspaces")}
        con.close()
        self.assertIn("examplefix", rows)
        self.assertIn("legacyfix", rows)
        self.assertIn("legacy_default", rows, "pre-existing ghost row must be preserved")
        # materialized workspace: registry id == recon uuid
        self.assertEqual(rows["examplefix"][0], self.recon_uuid)
        # legacy workspace flagged DEFERRED for schema repair
        deferred = [d["recon_db"] for d in report["deferred"]]
        self.assertTrue(any("legacyfix" in d for d in deferred), report["deferred"])
        self.assertTrue(report["verification"][str(self.root / "workspaces_v7.db")]["existing_rows_preserved"])

    def test_backups_restore_byte_for_byte(self):
        report = wm.migrate(self.root, do_backup=True, backup_dir=self.backup)
        manifest = report["backup"]["manifest"]
        # every recorded copy matches its source hash
        for rel, meta in manifest.items():
            if meta.get("exists"):
                self.assertTrue(meta["verified"], rel)
        # simulate restore of a recon.db from its backup and compare
        rel = "workspaces/examplefix/recon.db"
        backup_file = Path(manifest[rel]["backup"])
        scratch = self.backup / "restored_recon.db"
        shutil.copy2(backup_file, scratch)
        self.assertEqual(_sha(scratch), self.pre_hashes[self.recon_dbs[0]])

    def test_migration_is_idempotent(self):
        wm.migrate(self.root, do_backup=False, backup_dir=self.backup)
        con = sqlite3.connect(str(self.root / "workspaces_v7.db"))
        ids1 = sorted(r[0] for r in con.execute("SELECT id FROM workspaces"))
        con.close()
        report2 = wm.migrate(self.root, do_backup=False, backup_dir=self.backup)
        con = sqlite3.connect(str(self.root / "workspaces_v7.db"))
        ids2 = sorted(r[0] for r in con.execute("SELECT id FROM workspaces"))
        con.close()
        self.assertEqual(ids1, ids2, "re-running the migration must not add/dup rows")
        self.assertEqual(report2["status"], "OK")
        # recon.db still untouched after a second pass
        for p in self.recon_dbs:
            self.assertEqual(_sha(p), self.pre_hashes[p])


if __name__ == "__main__":
    unittest.main(verbosity=2)

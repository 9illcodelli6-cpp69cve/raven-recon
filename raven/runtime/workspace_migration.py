"""Wave 5 (A5-WS) workspace canonicalization — switch-rebind helpers + the
SHA-256-verified backup + reconcile migration.

Canonical decision (reconstruction/WORKSPACE_MIGRATION.md):
  * System A (the V5 recon context) is the single canonical workspace context.
  * ``workspaces_v7.db`` / ``WorkspaceManager`` is a THIN REGISTRY/INDEX over it.
  * This module performs a **conservative, additive, idempotent** migration:
        1. Back up every database first (SHA-256 recorded + copy-integrity verified).
        2. Reconcile the V7 registry to the real ``workspaces/<slug>`` filesystem
           workspaces (reads each recon.db READ-ONLY; writes only ``workspaces_v7.db``).
        3. Verify PRAGMA integrity_check + unchanged recon-table row counts for every
           touched DB. If anything regresses -> STOP (BLOCKED) and point at the backup.

DATA SAFETY: this migration never issues DDL against any ``recon.db`` and never
DELETEs/renames/VACUUMs an existing table or row. Repairing the legacy-schema recon.db
files (``<workspace-a>`` / ``<workspace-b>``) is **DEFERRED** to the existing, guarded,
additive ``Store._migrate_canonical_schema`` which runs lazily (and read/write) only
when a researcher actually opens that workspace via ``use_workspace`` — so this batch
migration does not gamble with the irreplaceable bug-bounty engagement data.

Stdlib-only. Safe to re-run (idempotent).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from .workspace import WorkspaceManager, sqlite_uri

# Control databases the §6 backup set covers (recon.db files are discovered).
_CONTROL_DBS = (
    "workspaces_v7.db", "conversations.db", "tasks_v7.db",
    "knowledge_v7.db", "evidence_v7.db",
)
_SIDECARS = ("-wal", "-shm")
_WS_SCHEMA = """
    CREATE TABLE IF NOT EXISTS workspaces (
        id TEXT PRIMARY KEY, name TEXT, slug TEXT,
        created_at TEXT, scope_json TEXT, identity_json TEXT,
        note TEXT, settings_json TEXT, root_path TEXT, created_ms INTEGER
    )
"""


def sha256_file(path: Path) -> Optional[str]:
    if not Path(path).is_file():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _discover_recon_dbs(data_root: Path) -> List[Path]:
    ws_root = Path(data_root) / "workspaces"
    if not ws_root.is_dir():
        return []
    return sorted(d / "recon.db" for d in ws_root.iterdir()
                  if d.is_dir() and (d / "recon.db").is_file())


def integrity_check(db_path: Path) -> str:
    """READ-ONLY ``PRAGMA integrity_check``. Returns 'ok' or the problem text."""
    if not Path(db_path).is_file():
        return "missing"
    con = None
    try:
        con = sqlite3.connect(sqlite_uri(db_path, "ro"), uri=True, timeout=5.0)
        rows = con.execute("PRAGMA integrity_check").fetchall()
        return "ok" if rows == [("ok",)] else "; ".join(str(r[0]) for r in rows)
    except Exception as exc:  # pragma: no cover - defensive
        return f"error: {type(exc).__name__}: {exc}"
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass


def table_row_counts(db_path: Path) -> Dict[str, int]:
    """READ-ONLY per-table row counts for parity verification."""
    if not Path(db_path).is_file():
        return {}
    con = None
    out: Dict[str, int] = {}
    try:
        con = sqlite3.connect(sqlite_uri(db_path, "ro"), uri=True, timeout=5.0)
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        for t in tables:
            try:
                out[t] = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
            except Exception:
                out[t] = -1
    except Exception:
        return out
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass
    return out


def backup_databases(data_root, backup_dir=None) -> dict:
    """Copy every database (+ WAL/SHM sidecars + scope/identity + the active-workspace
    pointer) to ``backup_dir`` with a ``.pre_w5ws`` suffix, recording SHA-256 and
    verifying each copy byte-for-byte. Returns the manifest."""
    data_root = Path(data_root)
    if backup_dir is None:
        backup_dir = data_root / "reconstruction" / "baseline" / "db_backups"
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)

    targets: List[str] = []
    for rdb in _discover_recon_dbs(data_root):
        rel = rdb.relative_to(data_root).as_posix()
        targets.append(rel)
        for sc in _SIDECARS:
            targets.append(rel + sc)
        for extra in ("scope.json", "identity.json"):
            targets.append((rdb.parent.relative_to(data_root) / extra).as_posix())
    targets.extend(_CONTROL_DBS)
    targets.append("active-workspace.json")

    manifest: Dict[str, dict] = {}
    for rel in targets:
        src = data_root / rel
        if not src.exists():
            manifest[rel] = {"exists": False}
            continue
        dest = backup_dir / (rel.replace("/", "__") + ".pre_w5ws")
        shutil.copy2(src, dest)
        src_h, dest_h = sha256_file(src), sha256_file(dest)
        manifest[rel] = {
            "exists": True, "size": src.stat().st_size, "sha256": src_h,
            "backup": str(dest), "backup_sha256": dest_h,
            "verified": src_h == dest_h,
        }
    (backup_dir / "MANIFEST.pre_w5ws.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def migrate(data_root, do_backup: bool = True, backup_dir=None) -> dict:
    """Backup -> reconcile registry -> verify. Returns a report dict with status
    'OK' or 'BLOCKED'. Idempotent."""
    data_root = Path(data_root)
    recon_dbs = _discover_recon_dbs(data_root)
    v7_db = data_root / "workspaces_v7.db"

    report: dict = {
        "status": "OK",
        "data_root": str(data_root.resolve()),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "backup": None,
        "pre": {}, "post": {},
        "reconcile": None,
        "verification": {},
        "deferred": [],
        "notes": [],
    }

    # 1. snapshot pre-state (read-only)
    touched = [str(r) for r in recon_dbs] + [str(v7_db)]
    for db in touched:
        report["pre"][db] = {"integrity": integrity_check(Path(db)),
                             "counts": table_row_counts(Path(db))}

    # 2. backup first
    if do_backup:
        manifest = backup_databases(data_root, backup_dir)
        unverified = [k for k, v in manifest.items() if v.get("exists") and not v.get("verified")]
        report["backup"] = {"dir": str((backup_dir or (data_root / "reconstruction" / "baseline" / "db_backups"))),
                            "files": sum(1 for v in manifest.values() if v.get("exists")),
                            "unverified_copies": unverified,
                            "manifest": manifest}
        if unverified:
            report["status"] = "BLOCKED"
            report["notes"].append("Backup copy verification failed; aborting before any write.")
            return report

    # 3. reconcile the registry to the filesystem (writes workspaces_v7.db ONLY)
    con = sqlite3.connect(str(v7_db), check_same_thread=False)
    try:
        con.execute(_WS_SCHEMA)
        con.commit()
        mgr = WorkspaceManager(con)
        pre_v7_ids = {r[0] for r in con.execute("SELECT id FROM workspaces")}
        report["reconcile"] = mgr.reconcile_from_filesystem(data_root)
        post_v7_ids = {r[0] for r in con.execute("SELECT id FROM workspaces")}
    finally:
        try:
            con.commit()
        finally:
            con.close()

    # 4. snapshot post-state (read-only)
    for db in touched:
        report["post"][db] = {"integrity": integrity_check(Path(db)),
                              "counts": table_row_counts(Path(db))}

    # 5. verify: recon.db integrity + row counts UNCHANGED; v7 additive-only.
    ok = True
    for rdb in recon_dbs:
        k = str(rdb)
        pre_c, post_c = report["pre"][k]["counts"], report["post"][k]["counts"]
        integ = report["post"][k]["integrity"]
        unchanged = pre_c == post_c
        report["verification"][k] = {
            "integrity": integ, "row_counts_unchanged": unchanged,
            "pre_counts": pre_c, "post_counts": post_c,
        }
        if integ != "ok" or not unchanged:
            ok = False
    # workspaces_v7.db: additive only (pre ids must be a subset of post ids)
    kept = pre_v7_ids <= post_v7_ids
    report["verification"][str(v7_db)] = {
        "integrity": report["post"][str(v7_db)]["integrity"],
        "existing_rows_preserved": kept,
        "rows_before": len(pre_v7_ids), "rows_after": len(post_v7_ids),
        "lost_ids": sorted(pre_v7_ids - post_v7_ids),
    }
    if report["post"][str(v7_db)]["integrity"] != "ok" or not kept:
        ok = False

    # 6. deferred, explicit
    for rdb in recon_dbs:
        counts = report["post"][str(rdb)]["counts"]
        if "workspaces" not in counts:
            report["deferred"].append({
                "recon_db": str(rdb),
                "reason": "legacy schema (no canonical 'workspaces' table); "
                          "additive Store._migrate_canonical_schema runs lazily and "
                          "read/write only when the researcher opens this workspace "
                          "via use_workspace. NOT repaired in this batch migration to "
                          "avoid risking irreplaceable data.",
            })

    if not ok:
        report["status"] = "BLOCKED"
        report["notes"].append(
            "Integrity or recon row-count regression detected. RESTORE from the "
            "*.pre_w5ws backups in the backup dir and re-run. recon.db files are never "
            "written by this migration, so a regression indicates external interference.")
    else:
        report["notes"].append(
            "recon.db files unchanged (read-only reconcile); workspaces_v7.db updated "
            "additively; Default/Test Workspace rows preserved.")
    return report


def main(argv=None) -> int:  # pragma: no cover - CLI entry
    argv = list(sys.argv[1:] if argv is None else argv)
    data_root = Path(argv[0]) if argv else Path(".")
    report = migrate(data_root, do_backup=True)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "OK" else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

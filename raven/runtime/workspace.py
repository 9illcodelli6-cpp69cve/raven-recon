"""RAVEN V7 Workspace Context.

Each workspace is an isolated research environment (§114-115).
Workspace A observations must not contaminate Workspace B.
Extends the existing `workspaces` table in store.py (already present in store._migrate_canonical_schema).

Wave 5 (A5-WS) canonicalization
--------------------------------
System A (the V5 recon context: ``STATE`` + ``workspaces/<slug>/{recon.db,
scope.json,identity.json}`` + ``active-workspace.json``) is the single canonical
workspace context. This ``WorkspaceManager`` / ``workspaces_v7.db`` is DEMOTED to a
**thin registry/index** over System A: a catalog of the real filesystem workspaces
(display name, slug, recon ``workspace_id``, scope summary, root_path), not an
independent source of truth.

The additions below (``ensure``, ``get_by_slug``, ``get_by_recon_id``,
``reconcile_from_filesystem`` and an explicit-id ``create``) are additive and
conservative:
  * No existing column is changed (only the already-present additive ALTERs).
  * recon.db files are opened **read-only** during reconcile — the registry index is
    never allowed to mutate irreplaceable recon research data.
  * Pre-existing registry rows (e.g. ``Default`` / ``Test Workspace``) are preserved,
    never deleted; they are simply flagged ``materialized: false`` in metadata.
  * The registry id is reconciled to the recon ``workspace_id`` (a mapping/index),
    and the only id ever rewritten is the registry's *own* synthetic placeholder for a
    not-yet-opened workspace — never a recon uuid and never a preserved row.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# Stable namespace for deriving a deterministic placeholder registry id from a
# workspace slug when the recon uuid is not yet readable (legacy-schema recon.db).
_SLUG_ID_NS = uuid.UUID("7a5e0000-0000-5a5e-0000-000000000001")


def _placeholder_id(slug: str) -> str:
    return uuid.uuid5(_SLUG_ID_NS, f"raven-ws:{slug}").hex


def _fs_slug(name: str) -> str:
    """Filesystem-safe, traversal-free slug — mirrors server._slug so the registry
    slug matches the on-disk ``workspaces/<slug>`` directory name."""
    import re
    slug = re.sub(r"[^a-z0-9._-]", "", str(name).lower())
    slug = re.sub(r"\.{2,}", ".", slug).strip("._-")
    return slug or "workspace"


def sqlite_uri(db_path, mode: str = "ro") -> str:
    """A SQLite ``file:`` URI for ``db_path`` opened with ``mode``.

    The path is percent-encoded via ``Path.as_uri()`` so a data directory whose
    path contains ``?``, ``#``, ``%`` or spaces cannot truncate the URI: with a raw
    ``f"file:{path}?mode=ro"`` a ``#`` turned ``?mode=ro`` into a fragment and the
    connection silently opened read-write-create on a different (truncated) path.
    """
    return f"{Path(db_path).absolute().as_uri()}?mode={mode}"


def _read_recon_workspace_id(recon_db: Path) -> Optional[str]:
    """Best-effort READ-ONLY read of the canonical recon workspace uuid.

    Returns None when the file is missing, has only the legacy schema (no
    ``workspaces`` table), or cannot be opened. Never writes to the file.
    """
    if not recon_db.is_file():
        return None
    con = None
    try:
        con = sqlite3.connect(sqlite_uri(recon_db, "ro"), uri=True, timeout=2.0)
        row = con.execute(
            "SELECT id FROM workspaces ORDER BY created_at LIMIT 1"
        ).fetchone()
        return row[0] if row else None
    except Exception:
        return None
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass


@dataclass
class WorkspaceSettings:
    model_id:        Optional[str] = None
    provider_id:     Optional[str] = None
    execution_profile: str = "PURE_LOCAL"
    language:        Optional[str] = None   # "ar" / "en" / None (auto)
    metadata:        Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "provider_id": self.provider_id,
            "execution_profile": self.execution_profile,
            "language": self.language,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "WorkspaceSettings":
        return cls(
            model_id=d.get("model_id"),
            provider_id=d.get("provider_id"),
            execution_profile=d.get("execution_profile", "PURE_LOCAL"),
            language=d.get("language"),
            metadata=d.get("metadata", {}),
        )


@dataclass
class WorkspaceContext:
    """Persistent workspace context scoping all V7 work (§114-115)."""
    workspace_id: str
    name:         str
    root_path:    Optional[str] = None
    scope_json:   Optional[dict] = None     # from existing scope.py
    settings:     WorkspaceSettings = field(default_factory=WorkspaceSettings)
    created_at:   int = field(default_factory=lambda: int(time.time() * 1000))
    metadata:     Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "workspace_id": self.workspace_id,
            "name": self.name,
            "root_path": self.root_path,
            "scope_json": self.scope_json,
            "settings": self.settings.to_dict(),
            "created_at": self.created_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "WorkspaceContext":
        return cls(
            workspace_id=d["workspace_id"],
            name=d.get("name", ""),
            root_path=d.get("root_path"),
            scope_json=d.get("scope_json"),
            settings=WorkspaceSettings.from_dict(d.get("settings") or {}),
            created_at=d.get("created_at", 0),
            metadata=d.get("metadata", {}),
        )


class WorkspaceManager:
    """Manages workspace contexts with SQLite persistence.

    Reuses the existing `workspaces` table added in store._migrate_canonical_schema.
    Additive: does NOT modify existing columns.
    """

    def __init__(self, db: sqlite3.Connection):
        self._db = db
        self._lock = threading.RLock()
        self._cache: Dict[str, WorkspaceContext] = {}
        self._extend_schema()

    def _extend_schema(self) -> None:
        # Add V7 columns to existing workspaces table (additive only).
        # sqlite doesn't support ADD COLUMN IF NOT EXISTS, so we catch errors.
        for col_sql in [
            "ALTER TABLE workspaces ADD COLUMN settings_json TEXT",
            "ALTER TABLE workspaces ADD COLUMN root_path TEXT",
            "ALTER TABLE workspaces ADD COLUMN created_ms INTEGER",
        ]:
            try:
                self._db.execute(col_sql)
                self._db.commit()
            except Exception:
                pass  # Column already exists — fine

    def create(self, name: str, scope_json: dict = None, root_path: str = None,
               settings: WorkspaceSettings = None,
               workspace_id: str = None) -> WorkspaceContext:
        """Create (or upsert) a registry row.

        ``workspace_id`` may be supplied so the registry id equals the recon
        ``workspace_id`` (System A uuid). When omitted a fresh uuid4 is used, as
        before, preserving back-compat for the no-filesystem ``Default`` seed.
        """
        ws = WorkspaceContext(
            workspace_id=workspace_id or uuid.uuid4().hex,
            name=name,
            root_path=root_path,
            scope_json=scope_json,
            settings=settings or WorkspaceSettings(),
        )
        self._save(ws, slug=_fs_slug(name))
        with self._lock:
            self._cache[ws.workspace_id] = ws
        return ws

    def get(self, workspace_id: str) -> Optional[WorkspaceContext]:
        with self._lock:
            if workspace_id in self._cache:
                return self._cache[workspace_id]
        # Load from DB
        cur = self._db.execute("SELECT * FROM workspaces WHERE id=?", (workspace_id,))
        cols = [c[0] for c in cur.description]
        raw = cur.fetchone()
        if raw is None:
            return None
        ws = self._row_to_workspace(dict(zip(cols, raw)))
        with self._lock:
            self._cache[workspace_id] = ws
        return ws

    def list_all(self) -> List[WorkspaceContext]:
        cur = self._db.execute("SELECT * FROM workspaces ORDER BY created_at DESC")
        cols = [c[0] for c in cur.description]
        return [self._row_to_workspace(dict(zip(cols, r))) for r in cur.fetchall()]

    def update(self, workspace: WorkspaceContext) -> None:
        self._save(workspace)
        with self._lock:
            self._cache[workspace.workspace_id] = workspace

    def _save(self, ws: WorkspaceContext, slug: str = None) -> None:
        with self._lock:
            self._db.execute("""
            INSERT OR REPLACE INTO workspaces
                (id, name, slug, created_at, scope_json, identity_json, note,
                 settings_json, root_path, created_ms)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                ws.workspace_id, ws.name,
                slug if slug is not None else ws.name.lower().replace(" ", "_"),
                _ms_to_iso(ws.created_at),
                json.dumps(ws.scope_json) if ws.scope_json else None,
                None, "",
                json.dumps(ws.settings.to_dict()),
                ws.root_path,
                ws.created_at,
            ))
            self._db.commit()

    # ------------------------------------------------------------------
    # Registry/index lookups + reconcile (Wave 5 A5-WS; additive)
    # ------------------------------------------------------------------

    def _row_by(self, column: str, value) -> Optional[dict]:
        cur = self._db.execute(
            f"SELECT * FROM workspaces WHERE {column}=? LIMIT 1", (value,)
        )
        cols = [c[0] for c in cur.description]
        raw = cur.fetchone()
        return dict(zip(cols, raw)) if raw is not None else None

    def get_by_slug(self, slug: str) -> Optional[WorkspaceContext]:
        with self._lock:
            row = self._row_by("slug", slug)
        return self._row_to_workspace(row) if row else None

    def get_by_recon_id(self, recon_id: str) -> Optional[WorkspaceContext]:
        """Resolve a workspace by its recon uuid — either because the registry id
        equals it, or because it is recorded as ``recon_id`` in the row metadata."""
        if not recon_id:
            return None
        with self._lock:
            row = self._row_by("id", recon_id)
            if row is None:
                # fall back to a metadata scan (placeholder-id rows)
                cur = self._db.execute("SELECT * FROM workspaces")
                cols = [c[0] for c in cur.description]
                for raw in cur.fetchall():
                    d = dict(zip(cols, raw))
                    meta = self._meta_of(d)
                    if meta.get("recon_id") == recon_id:
                        row = d
                        break
        return self._row_to_workspace(row) if row else None

    @staticmethod
    def _meta_of(row: dict) -> dict:
        try:
            s = json.loads(row.get("settings_json") or "{}")
            m = s.get("metadata") or {}
            return m if isinstance(m, dict) else {}
        except Exception:
            return {}

    def ensure(self, workspace_id: str, name: str, slug: str = None,
               scope_json: dict = None, root_path: str = None,
               recon_id: str = None, materialized: bool = True) -> WorkspaceContext:
        """Idempotent upsert of a registry row keyed on the recon ``workspace_id``.

        Conservative/additive reconciliation of the V7 id-space to the recon id:
          * If a row already exists with id == ``workspace_id`` -> update in place.
          * Else if a row exists for this ``slug``:
              - if that row is the registry's own *synthetic placeholder* (not yet
                materialized / no recon_id) and ``workspace_id`` is a real recon uuid,
                rebind its id to ``workspace_id`` (reconcile the index to truth);
              - otherwise update the slug row in place, keeping its id, and record the
                recon mapping in metadata (never clobber a foreign id).
          * Else insert a new row keyed on ``workspace_id``.
        No row is ever deleted. No recon.db is touched.
        """
        slug = slug or _fs_slug(name)
        with self._lock:
            existing = self._row_by("id", workspace_id)
            if existing is None:
                slug_row = self._row_by("slug", slug)
                if slug_row is not None:
                    old_id = slug_row["id"]
                    old_meta = self._meta_of(slug_row)
                    is_placeholder = (
                        old_id == _placeholder_id(slug)
                        or (old_meta.get("materialized") is False and not old_meta.get("recon_id"))
                    )
                    if is_placeholder and workspace_id and old_id != workspace_id:
                        # Rebind our own synthetic placeholder id to the recon uuid.
                        self._db.execute(
                            "UPDATE workspaces SET id=? WHERE id=?",
                            (workspace_id, old_id))
                        self._cache.pop(old_id, None)
                        existing = self._row_by("id", workspace_id)
                    else:
                        workspace_id = old_id  # update the existing slug row in place
                        existing = slug_row
            created_ms = int(existing["created_ms"]) if (existing and existing.get("created_ms")) else int(time.time() * 1000)
            meta = self._meta_of(existing) if existing else {}
            meta["recon_id"] = recon_id or (workspace_id if materialized else meta.get("recon_id"))
            meta["materialized"] = bool(materialized)
            settings = WorkspaceSettings(metadata=meta)
            self._db.execute("""
            INSERT OR REPLACE INTO workspaces
                (id, name, slug, created_at, scope_json, identity_json, note,
                 settings_json, root_path, created_ms)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (
                workspace_id, name, slug, _ms_to_iso(created_ms),
                json.dumps(scope_json) if scope_json else (existing.get("scope_json") if existing else None),
                existing.get("identity_json") if existing else None,
                existing.get("note") if existing else "",
                json.dumps(settings.to_dict()),
                root_path if root_path is not None else (existing.get("root_path") if existing else None),
                created_ms,
            ))
            self._db.commit()
            self._cache.pop(workspace_id, None)
            ws = self.get(workspace_id)
        return ws

    def reconcile_from_filesystem(self, data_root) -> dict:
        """Rebuild the registry index from the real ``workspaces/<slug>`` dirs.

        READ-ONLY to every recon.db. Additive to ``workspaces_v7.db`` only.
        Pre-existing registry rows with no filesystem counterpart (``Default`` /
        ``Test Workspace``) are preserved and flagged ``materialized: false``.
        Returns a report dict suitable for researcher sign-off.
        """
        data_root = Path(data_root)
        ws_root = data_root / "workspaces"
        report = {"added": 0, "updated": 0, "workspaces": [], "preserved_rows": []}
        seen_slugs = set()
        if ws_root.is_dir():
            for d in sorted(ws_root.iterdir()):
                if not d.is_dir():
                    continue
                slug = d.name
                recon_db = d / "recon.db"
                if not recon_db.is_file():
                    continue
                seen_slugs.add(slug)
                scope = None
                name = slug
                scope_file = d / "scope.json"
                if scope_file.is_file():
                    try:
                        scope = json.loads(scope_file.read_text(encoding="utf-8"))
                        if isinstance(scope, dict) and isinstance(scope.get("name"), str) and scope["name"].strip():
                            name = scope["name"]
                    except (OSError, ValueError):
                        scope = None
                recon_id = _read_recon_workspace_id(recon_db)  # READ-ONLY, None if legacy schema
                materialized = recon_id is not None
                target_id = recon_id or _placeholder_id(slug)
                with self._lock:
                    pre = self._row_by("slug", slug) is not None
                self.ensure(target_id, name, slug=slug, scope_json=scope,
                            root_path=str(d.resolve()), recon_id=recon_id,
                            materialized=materialized)
                report["updated" if pre else "added"] += 1
                report["workspaces"].append({
                    "slug": slug, "name": name, "recon_id": recon_id,
                    "registry_id": self.get_by_slug(slug).workspace_id,
                    "materialized": materialized,
                    "has_scope": scope is not None,
                })
        # Preserve (flag, never delete) rows that map to no filesystem workspace.
        with self._lock:
            cur = self._db.execute("SELECT id, name, slug, settings_json FROM workspaces")
            orphans = [dict(zip(["id", "name", "slug", "settings_json"], r)) for r in cur.fetchall()]
        for row in orphans:
            if row["slug"] in seen_slugs:
                continue
            meta = self._meta_of(row)
            if meta.get("materialized") is not False:
                meta["materialized"] = False
                settings = WorkspaceSettings(metadata=meta)
                with self._lock:
                    self._db.execute(
                        "UPDATE workspaces SET settings_json=? WHERE id=?",
                        (json.dumps(settings.to_dict()), row["id"]))
                    self._db.commit()
                    self._cache.pop(row["id"], None)
            report["preserved_rows"].append({"id": row["id"], "name": row["name"], "slug": row["slug"]})
        return report

    def _row_to_workspace(self, row: dict) -> WorkspaceContext:
        settings_raw = row.get("settings_json")
        settings = WorkspaceSettings.from_dict(json.loads(settings_raw) if settings_raw else {})
        scope_raw = row.get("scope_json")
        return WorkspaceContext(
            workspace_id=row["id"],
            name=row.get("name", ""),
            root_path=row.get("root_path"),
            scope_json=json.loads(scope_raw) if scope_raw else None,
            settings=settings,
            created_at=row.get("created_ms", 0),
        )


def _ms_to_iso(ms: int) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat(timespec="seconds")

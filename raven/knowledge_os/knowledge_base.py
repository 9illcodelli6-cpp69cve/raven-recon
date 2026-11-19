"""RAVEN V7 Knowledge Base — Part 09.

Stores structured security knowledge entries.
All AI-derived entries are marked advisory (confidence < 1.0 unless human-reviewed).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class KnowledgeKind(str, Enum):
    TECHNIQUE   = "technique"
    PATTERN     = "pattern"
    TOOL        = "tool"
    CONCEPT     = "concept"
    FINDING_PATTERN = "finding_pattern"
    LESSON      = "lesson"


@dataclass
class KnowledgeEntry:
    entry_id:     str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    kind:         KnowledgeKind = KnowledgeKind.CONCEPT
    title:        str = ""
    body:         str = ""
    tags:         List[str] = field(default_factory=list)
    source:       str = "ai_derived"    # ai_derived | human_authored | imported
    confidence:   float = 0.5           # 0–1; human-authored = 1.0
    workspace_id: str = "global"
    created_at:   int = field(default_factory=lambda: int(time.time() * 1000))
    human_reviewed_labels: int = 0      # INVARIANT: always 0 (AI can't self-label as human)
    metadata:     Dict = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "human_reviewed_labels", 0)

    def __setattr__(self, name: str, value):
        if name == "human_reviewed_labels":
            if "human_reviewed_labels" in self.__dict__:
                raise AttributeError("human_reviewed_labels is immutable — always 0")
        object.__setattr__(self, name, value)

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "kind": self.kind.value,
            "title": self.title,
            "source": self.source,
            "confidence": self.confidence,
            "tags": self.tags,
            "human_reviewed_labels": 0,
        }


class KnowledgeBase:
    """SQLite-backed knowledge store for RAVEN research knowledge."""

    def __init__(self, db: sqlite3.Connection):
        self._db   = db
        self._lock = threading.RLock()
        self._migrate()

    def _migrate(self) -> None:
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS v7_knowledge (
            entry_id     TEXT PRIMARY KEY,
            kind         TEXT,
            title        TEXT,
            body         TEXT,
            tags_json    TEXT,
            source       TEXT,
            confidence   REAL,
            workspace_id TEXT,
            created_at   INTEGER,
            metadata_json TEXT
        );
        CREATE INDEX IF NOT EXISTS v7_kb_kind ON v7_knowledge(kind);
        CREATE INDEX IF NOT EXISTS v7_kb_ws   ON v7_knowledge(workspace_id);
        """)
        self._db.commit()

    def store(self, entry: KnowledgeEntry) -> str:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO v7_knowledge VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    entry.entry_id, entry.kind.value, entry.title, entry.body,
                    json.dumps(entry.tags), entry.source, entry.confidence,
                    entry.workspace_id, entry.created_at, json.dumps(entry.metadata),
                ),
            )
            self._db.commit()
        return entry.entry_id

    def search(
        self, query: str = "", kind: KnowledgeKind = None,
        workspace_id: str = None, limit: int = 20,
    ) -> List[KnowledgeEntry]:
        clauses, params = [], []
        if kind:
            clauses.append("kind=?"); params.append(kind.value)
        if workspace_id:
            clauses.append("workspace_id=?"); params.append(workspace_id)
        if query:
            clauses.append("(title LIKE ? OR body LIKE ? OR tags_json LIKE ?)")
            q = f"%{query}%"
            params.extend([q, q, q])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._db.execute(
                f"SELECT * FROM v7_knowledge {where} ORDER BY confidence DESC LIMIT ?",
                params + [limit],
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def _row_to_entry(self, r) -> KnowledgeEntry:
        # Round-trip metadata as well (previously dropped on read-back): persisted
        # in metadata_json by store() but never restored here. Defensive against
        # rows lacking the column or holding malformed JSON.
        meta: Dict = {}
        try:
            keys = r.keys()
        except Exception:
            keys = ()
        if "metadata_json" in keys:
            try:
                loaded = json.loads(r["metadata_json"] or "{}")
                if isinstance(loaded, dict):
                    meta = loaded
            except (TypeError, ValueError):
                meta = {}
        return KnowledgeEntry(
            entry_id=r["entry_id"],
            kind=KnowledgeKind(r["kind"]) if r["kind"] else KnowledgeKind.CONCEPT,
            title=r["title"] or "",
            body=r["body"] or "",
            tags=json.loads(r["tags_json"] or "[]"),
            source=r["source"] or "ai_derived",
            confidence=r["confidence"] or 0.5,
            workspace_id=r["workspace_id"] or "global",
            created_at=r["created_at"] or 0,
            metadata=meta,
        )

    def count(self, workspace_id: str = None) -> int:
        with self._lock:
            if workspace_id:
                row = self._db.execute(
                    "SELECT COUNT(*) FROM v7_knowledge WHERE workspace_id=?",
                    (workspace_id,),
                ).fetchone()
            else:
                row = self._db.execute("SELECT COUNT(*) FROM v7_knowledge").fetchone()
        return row[0] if row else 0

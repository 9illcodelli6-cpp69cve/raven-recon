"""RAVEN V7 Chat Memory — Part 03.

Short-term and long-term memory for the AI chat system.
Long-term memory is stored in SQLite via the runtime's DB.
"""
from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class MemoryEntry:
    memory_id:   str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    session_id:  str = ""
    workspace_id: str = "default"
    kind:        str = "fact"       # fact | preference | summary | finding_ref
    content:     str = ""
    tags:        List[str] = field(default_factory=list)
    created_at:  int = field(default_factory=lambda: int(time.time() * 1000))
    importance:  float = 0.5        # 0–1; 1 = critical

    def to_dict(self) -> dict:
        return {
            "memory_id": self.memory_id,
            "session_id": self.session_id,
            "workspace_id": self.workspace_id,
            "kind": self.kind,
            "content": self.content,
            "tags": self.tags,
            "created_at": self.created_at,
            "importance": self.importance,
        }


class MemoryManager:
    """Manages persistent memory entries for AI sessions."""

    def __init__(self, db: sqlite3.Connection):
        self._db   = db
        self._lock = threading.RLock()
        self._migrate()

    def _migrate(self) -> None:
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS v7_ai_memory (
            memory_id    TEXT PRIMARY KEY,
            session_id   TEXT,
            workspace_id TEXT,
            kind         TEXT,
            content      TEXT,
            tags_json    TEXT,
            created_at   INTEGER,
            importance   REAL
        );
        CREATE INDEX IF NOT EXISTS v7_mem_workspace ON v7_ai_memory(workspace_id);
        CREATE INDEX IF NOT EXISTS v7_mem_session   ON v7_ai_memory(session_id);
        """)
        self._db.commit()

    def store(self, entry: MemoryEntry) -> str:
        import json
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO v7_ai_memory VALUES (?,?,?,?,?,?,?,?)",
                (
                    entry.memory_id, entry.session_id, entry.workspace_id,
                    entry.kind, entry.content,
                    json.dumps(entry.tags), entry.created_at, entry.importance,
                ),
            )
            self._db.commit()
        return entry.memory_id

    def recall(
        self, workspace_id: str = None, session_id: str = None,
        kind: str = None, limit: int = 20,
    ) -> List[MemoryEntry]:
        import json
        clauses, params = [], []
        if workspace_id:
            clauses.append("workspace_id=?"); params.append(workspace_id)
        if session_id:
            clauses.append("session_id=?"); params.append(session_id)
        if kind:
            clauses.append("kind=?"); params.append(kind)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._db.execute(
                f"SELECT * FROM v7_ai_memory {where} ORDER BY importance DESC, created_at DESC LIMIT ?",
                params + [limit],
            ).fetchall()
        return [
            MemoryEntry(
                memory_id=r["memory_id"],
                session_id=r["session_id"] or "",
                workspace_id=r["workspace_id"] or "default",
                kind=r["kind"] or "fact",
                content=r["content"] or "",
                tags=json.loads(r["tags_json"] or "[]"),
                created_at=r["created_at"] or 0,
                importance=r["importance"] or 0.5,
            )
            for r in rows
        ]

    def forget(self, memory_id: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM v7_ai_memory WHERE memory_id=?", (memory_id,))
            self._db.commit()

    def count(self, workspace_id: str = None) -> int:
        with self._lock:
            if workspace_id:
                row = self._db.execute(
                    "SELECT COUNT(*) FROM v7_ai_memory WHERE workspace_id=?",
                    (workspace_id,)
                ).fetchone()
            else:
                row = self._db.execute("SELECT COUNT(*) FROM v7_ai_memory").fetchone()
        return row[0] if row else 0

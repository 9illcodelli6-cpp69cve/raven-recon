"""RAVEN V7 Checkpoint Engine.

Enables long-running tasks to survive interruption (§126-128).
Checkpoints use explicit schemas with version metadata (§127).
No arbitrary Python object serialization — structured data only.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

CHECKPOINT_SCHEMA_VERSION = 1
RUNTIME_VERSION = "7.0.0-bootstrap"


@dataclass
class Checkpoint:
    """Versioned task checkpoint (§127)."""
    checkpoint_id:         str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    schema_version:        int = CHECKPOINT_SCHEMA_VERSION
    runtime_version:       str = RUNTIME_VERSION
    task_id:               str = ""
    workspace_id:          str = ""
    created_at:            int = field(default_factory=lambda: int(time.time() * 1000))
    task_status:           str = ""
    plan_state:            Optional[Dict] = None
    completed_steps:       int = 0
    pending_steps:         int = 0
    budget_state:          Optional[Dict] = None
    last_known_obs:        Optional[Dict] = None
    execution_profile:     str = "PURE_LOCAL"
    conversation_id:       Optional[str] = None
    metadata:              Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "checkpoint_id": self.checkpoint_id,
            "schema_version": self.schema_version,
            "runtime_version": self.runtime_version,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "created_at": self.created_at,
            "task_status": self.task_status,
            "plan_state": self.plan_state,
            "completed_steps": self.completed_steps,
            "pending_steps": self.pending_steps,
            "budget_state": self.budget_state,
            "last_known_obs": self.last_known_obs,
            "execution_profile": self.execution_profile,
            "conversation_id": self.conversation_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Checkpoint":
        return cls(
            checkpoint_id=d.get("checkpoint_id", uuid.uuid4().hex[:16]),
            schema_version=d.get("schema_version", CHECKPOINT_SCHEMA_VERSION),
            runtime_version=d.get("runtime_version", RUNTIME_VERSION),
            task_id=d.get("task_id", ""),
            workspace_id=d.get("workspace_id", ""),
            created_at=d.get("created_at", 0),
            task_status=d.get("task_status", ""),
            plan_state=d.get("plan_state"),
            completed_steps=d.get("completed_steps", 0),
            pending_steps=d.get("pending_steps", 0),
            budget_state=d.get("budget_state"),
            last_known_obs=d.get("last_known_obs"),
            execution_profile=d.get("execution_profile", "PURE_LOCAL"),
            conversation_id=d.get("conversation_id"),
            metadata=d.get("metadata", {}),
        )


class CheckpointEngine:
    """Save, load, and validate task checkpoints (§126-128).

    Incompatible schema versions are rejected safely (§127).
    """

    def __init__(self, db: sqlite3.Connection):
        self._db = db
        self._lock = threading.RLock()
        self._migrate()

    def _migrate(self) -> None:
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS v7_checkpoints (
            checkpoint_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL,
            workspace_id TEXT,
            created_at INTEGER,
            schema_version INTEGER,
            runtime_version TEXT,
            data_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS v7_ckpt_task ON v7_checkpoints(task_id);
        """)
        self._db.commit()

    def save(self, checkpoint: Checkpoint) -> str:
        with self._lock:
            self._db.execute("""
            INSERT OR REPLACE INTO v7_checkpoints
                (checkpoint_id, task_id, workspace_id, created_at,
                 schema_version, runtime_version, data_json)
            VALUES (?,?,?,?,?,?,?)
            """, (
                checkpoint.checkpoint_id, checkpoint.task_id,
                checkpoint.workspace_id, checkpoint.created_at,
                checkpoint.schema_version, checkpoint.runtime_version,
                json.dumps(checkpoint.to_dict()),
            ))
            self._db.commit()
        return checkpoint.checkpoint_id

    def load(self, checkpoint_id: str) -> Optional[Checkpoint]:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM v7_checkpoints WHERE checkpoint_id=?", (checkpoint_id,)
            ).fetchone()
        if row is None:
            return None
        return self._parse_row(dict(row))

    def load_latest(self, task_id: str) -> Optional[Checkpoint]:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM v7_checkpoints WHERE task_id=? ORDER BY created_at DESC LIMIT 1",
                (task_id,)
            ).fetchone()
        if row is None:
            return None
        return self._parse_row(dict(row))

    def delete(self, checkpoint_id: str) -> bool:
        with self._lock:
            cursor = self._db.execute(
                "DELETE FROM v7_checkpoints WHERE checkpoint_id=?", (checkpoint_id,)
            )
            self._db.commit()
            return cursor.rowcount > 0

    def _parse_row(self, row: dict) -> Optional[Checkpoint]:
        try:
            data = json.loads(row["data_json"])
            cp = Checkpoint.from_dict(data)
            # Version compatibility check (§127)
            if cp.schema_version != CHECKPOINT_SCHEMA_VERSION:
                # Future: migration logic would go here
                # For now: return None and let caller handle INTERRUPTED task
                return None
            return cp
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

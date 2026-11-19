"""RAVEN V7 Execution Records.

Every meaningful tool execution produces an auditable ExecutionRecord (§103).
Records capture actor, task, tool, timestamps, status, and provenance.
Sensitive values MUST NOT be stored in plain text.
"""
from __future__ import annotations

import enum
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class ToolStatus(str, enum.Enum):
    SUCCESS      = "SUCCESS"
    PARTIAL      = "PARTIAL"
    FAILED       = "FAILED"
    DENIED       = "DENIED"
    CANCELLED    = "CANCELLED"
    TIMED_OUT    = "TIMED_OUT"
    UNAVAILABLE  = "UNAVAILABLE"
    INVALID_INPUT = "INVALID_INPUT"


class ActorKind(str, enum.Enum):
    RESEARCHER    = "RESEARCHER"
    RAVEN_AGENT   = "RAVEN_AGENT"
    PROGRAM_AGENT = "PROGRAM_AGENT"
    SYSTEM        = "SYSTEM"
    PLUGIN        = "PLUGIN"
    SCRIPT        = "SCRIPT"


@dataclass
class ToolResult:
    """Typed tool result (§102)."""
    status:      ToolStatus
    output:      Optional[Any] = None
    error:       Optional[str] = None
    output_ref:  Optional[str] = None   # ID of large stored artifact, not inline
    metadata:    Dict = field(default_factory=dict)

    def is_success(self) -> bool:
        return self.status == ToolStatus.SUCCESS

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "output": self.output if not isinstance(self.output, (bytes, bytearray)) else "<binary>",
            "error": self.error,
            "output_ref": self.output_ref,
        }


@dataclass
class ExecutionRecord:
    """Auditable record of every meaningful tool execution (§103).

    Sensitive values are NEVER stored; use references instead.
    """
    execution_id:       str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    task_id:            Optional[str] = None
    agent_session_id:   Optional[str] = None
    tool_id:            str = ""
    tool_version:       Optional[str] = None
    actor:              ActorKind = ActorKind.RAVEN_AGENT
    workspace_id:       Optional[str] = None
    started_at:         int = field(default_factory=lambda: int(time.time() * 1000))
    finished_at:        Optional[int] = None
    duration_ms:        Optional[int] = None
    status:             ToolStatus = ToolStatus.FAILED
    input_summary:      str = ""        # human-readable, NO secrets
    output_refs:        List[str] = field(default_factory=list)
    error:              Optional[str] = None
    capability_decision: Optional[str] = None  # ALLOW/DENY/etc.
    execution_profile:  Optional[str] = None
    resource_usage:     Dict = field(default_factory=dict)
    correlation_id:     Optional[str] = None
    metadata:           Dict = field(default_factory=dict)

    def finish(self, status: ToolStatus, error: str = None, output_refs: List[str] = None) -> None:
        self.finished_at = int(time.time() * 1000)
        self.duration_ms = self.finished_at - self.started_at
        self.status = status
        if error:
            self.error = error
        if output_refs:
            self.output_refs = output_refs

    def to_dict(self) -> dict:
        return {
            "execution_id": self.execution_id,
            "task_id": self.task_id,
            "agent_session_id": self.agent_session_id,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "actor": self.actor.value,
            "workspace_id": self.workspace_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "status": self.status.value,
            "input_summary": self.input_summary,
            "output_refs": self.output_refs,
            "error": self.error,
            "capability_decision": self.capability_decision,
            "execution_profile": self.execution_profile,
        }


class ExecutionStore:
    """Persists ExecutionRecords to SQLite."""

    def __init__(self, db: sqlite3.Connection):
        self._db = db
        self._lock = threading.RLock()
        self._migrate()

    def _migrate(self) -> None:
        # CANONICAL v7_executions schema (Wave 5 freeze). This inline _migrate is the
        # SOLE writer/creator of the v7_executions table. runtime/migrations.py defined
        # a second, column-incompatible v7_executions DDL; it is now DEPRECATED and
        # guarded so it can never run (its run_all_migrations/_migrate_executions raise).
        # Any future change here MUST be additive (CREATE ... IF NOT EXISTS / ADD COLUMN)
        # — no DROP or rename of an existing column. Documented in
        # reconstruction/migrations/0001_tasks_scheduler.sql.
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS v7_executions (
            execution_id TEXT PRIMARY KEY,
            task_id TEXT,
            agent_session_id TEXT,
            tool_id TEXT NOT NULL,
            tool_version TEXT,
            actor TEXT,
            workspace_id TEXT,
            started_at INTEGER,
            finished_at INTEGER,
            duration_ms INTEGER,
            status TEXT,
            input_summary TEXT,
            output_refs_json TEXT,
            error TEXT,
            capability_decision TEXT,
            execution_profile TEXT,
            resource_usage_json TEXT,
            correlation_id TEXT,
            metadata_json TEXT
        );
        CREATE INDEX IF NOT EXISTS v7_exec_task ON v7_executions(task_id);
        CREATE INDEX IF NOT EXISTS v7_exec_workspace ON v7_executions(workspace_id);
        """)
        self._db.commit()

    def save(self, rec: ExecutionRecord) -> None:
        import json
        with self._lock:
            self._db.execute("""
            INSERT OR REPLACE INTO v7_executions
                (execution_id, task_id, agent_session_id, tool_id, tool_version, actor,
                 workspace_id, started_at, finished_at, duration_ms, status,
                 input_summary, output_refs_json, error, capability_decision,
                 execution_profile, resource_usage_json, correlation_id, metadata_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                rec.execution_id, rec.task_id, rec.agent_session_id,
                rec.tool_id, rec.tool_version, rec.actor.value,
                rec.workspace_id, rec.started_at, rec.finished_at, rec.duration_ms,
                rec.status.value, rec.input_summary,
                json.dumps(rec.output_refs),
                rec.error, rec.capability_decision, rec.execution_profile,
                json.dumps(rec.resource_usage), rec.correlation_id,
                json.dumps(rec.metadata),
            ))
            self._db.commit()

    def list_for_task(self, task_id: str, limit: int = 50) -> list:
        import types
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM v7_executions WHERE task_id=? ORDER BY started_at DESC LIMIT ?",
                (task_id, limit)
            ).fetchall()
        return [types.SimpleNamespace(**dict(r)) for r in rows]

    def get(self, execution_id: str) -> Optional[dict]:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM v7_executions WHERE execution_id=?", (execution_id,)
            ).fetchone()
        if row:
            return dict(row)
        return None

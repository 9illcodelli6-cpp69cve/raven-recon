"""RAVEN V7 Consolidated Migration Runner. **DEPRECATED — DO NOT RUN (Wave 5).**

This module is DEAD: it has zero callers anywhere in `raven/` or `tests/` (verified),
and its `_migrate_executions` DDL declares a `v7_executions` schema that is COLUMN-
INCOMPATIBLE with the canonical one owned by `runtime/execution.py::ExecutionStore._migrate`
(args_json/output_summary/provenance_json here vs the canonical
tool_version/capability_decision/execution_profile/… there). Running it against the live
DB would create the wrong `v7_executions` and corrupt the execution-audit contract
(CANONICAL_ARCHITECTURE §1 row 11b; TASKS_SCHEDULER_ARCHITECTURE §2).

Canonical ownership after Wave 5:
  * `v7_executions`  → `runtime/execution.py::ExecutionStore._migrate` (SOLE writer)
  * `v7_tasks`       → `runtime/tasks.py::TaskRegistry._migrate`
  * `v7_checkpoints` → `runtime/checkpoint.py::CheckpointEngine._migrate`
  * conversations/workspaces extensions → their own subsystem migrators.

The module stays IMPORTABLE (so any existing import keeps working), but every runner
here now RAISES `MigrationDeprecatedError` if invoked, so it can never run against the
live DB. Each subsystem's inline `_migrate` is the single owner of its table.
"""
from __future__ import annotations

import logging
import sqlite3

logger = logging.getLogger(__name__)


class MigrationDeprecatedError(RuntimeError):
    """Raised if the dead, conflicting migration runner is called. Use each subsystem's
    own inline `_migrate` (execution.py/tasks.py/checkpoint.py) instead."""


_DEPRECATION_MSG = (
    "runtime/migrations.py is DEPRECATED and must not run: its v7_executions DDL conflicts "
    "with the canonical runtime/execution.py::ExecutionStore schema. Each subsystem's inline "
    "_migrate is the sole owner of its table (see module docstring)."
)


def run_all_migrations(db: sqlite3.Connection) -> None:
    """DEPRECATED — raises. The per-subsystem inline `_migrate` methods are canonical."""
    raise MigrationDeprecatedError(_DEPRECATION_MSG)


def _migrate_workspaces_extension(db: sqlite3.Connection) -> None:
    """DEPRECATED — raises. (Historical DDL retained below for reference only.)"""
    raise MigrationDeprecatedError(_DEPRECATION_MSG)
    for col_sql in [  # (unreachable — historical DDL retained for reference)
        "ALTER TABLE workspaces ADD COLUMN settings_json TEXT",
        "ALTER TABLE workspaces ADD COLUMN root_path TEXT",
        "ALTER TABLE workspaces ADD COLUMN created_ms INTEGER",
    ]:
        try:
            db.execute(col_sql)
            db.commit()
        except Exception:  # noqa: BLE001
            pass  # Column already exists — safe to ignore


def _migrate_tasks(db: sqlite3.Connection) -> None:
    """DEPRECATED — raises. Canonical owner: runtime/tasks.py::TaskRegistry._migrate."""
    raise MigrationDeprecatedError(_DEPRECATION_MSG)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS v7_tasks (
        task_id        TEXT PRIMARY KEY,
        title          TEXT,
        description    TEXT,
        status         TEXT NOT NULL DEFAULT 'PENDING',
        workspace_id   TEXT,
        parent_task_id TEXT,
        created_at     INTEGER,
        updated_at     INTEGER,
        started_at     INTEGER,
        completed_at   INTEGER,
        cancelled_at   INTEGER,
        progress       REAL DEFAULT 0.0,
        budget_json    TEXT,
        metadata_json  TEXT
    );
    CREATE INDEX IF NOT EXISTS v7_tasks_workspace  ON v7_tasks(workspace_id);
    CREATE INDEX IF NOT EXISTS v7_tasks_parent     ON v7_tasks(parent_task_id);
    CREATE INDEX IF NOT EXISTS v7_tasks_status     ON v7_tasks(status);
    """)
    db.commit()


def _migrate_executions(db: sqlite3.Connection) -> None:
    """DEPRECATED — raises. This schema CONFLICTS with the canonical v7_executions owned
    by runtime/execution.py::ExecutionStore._migrate; it must never create the table."""
    raise MigrationDeprecatedError(_DEPRECATION_MSG)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS v7_executions (
        execution_id   TEXT PRIMARY KEY,
        task_id        TEXT,
        tool_id        TEXT NOT NULL,
        actor          TEXT,
        status         TEXT NOT NULL DEFAULT 'RUNNING',
        started_at     INTEGER NOT NULL,
        finished_at    INTEGER,
        duration_ms    INTEGER,
        args_json      TEXT,
        output_summary TEXT,
        output_ref     TEXT,
        error_message  TEXT,
        workspace_id   TEXT,
        provenance_json TEXT
    );
    CREATE INDEX IF NOT EXISTS v7_exec_task      ON v7_executions(task_id);
    CREATE INDEX IF NOT EXISTS v7_exec_tool      ON v7_executions(tool_id);
    CREATE INDEX IF NOT EXISTS v7_exec_started   ON v7_executions(started_at);
    """)
    db.commit()


def _migrate_conversations(db: sqlite3.Connection) -> None:
    """DEPRECATED — raises. (Historical DDL retained below for reference only.)"""
    raise MigrationDeprecatedError(_DEPRECATION_MSG)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS v7_conversations (
        conversation_id TEXT PRIMARY KEY,
        workspace_id    TEXT NOT NULL,
        title           TEXT,
        created_at      INTEGER,
        updated_at      INTEGER,
        active_task_id  TEXT,
        selected_model  TEXT,
        language_state  TEXT,
        metadata_json   TEXT
    );
    CREATE INDEX IF NOT EXISTS v7_conv_workspace ON v7_conversations(workspace_id);

    CREATE TABLE IF NOT EXISTS v7_messages (
        message_id      TEXT PRIMARY KEY,
        conversation_id TEXT NOT NULL,
        role            TEXT NOT NULL,
        content         TEXT NOT NULL,
        language        TEXT,
        created_at      INTEGER,
        task_id         TEXT,
        model_id        TEXT,
        references_json TEXT,
        metadata_json   TEXT,
        FOREIGN KEY (conversation_id) REFERENCES v7_conversations(conversation_id)
    );
    CREATE INDEX IF NOT EXISTS v7_msg_conv ON v7_messages(conversation_id, created_at);
    """)
    db.commit()


def _migrate_checkpoints(db: sqlite3.Connection) -> None:
    """DEPRECATED — raises. Canonical owner: runtime/checkpoint.py::CheckpointEngine._migrate."""
    raise MigrationDeprecatedError(_DEPRECATION_MSG)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS v7_checkpoints (
        checkpoint_id  TEXT PRIMARY KEY,
        task_id        TEXT NOT NULL,
        workspace_id   TEXT,
        created_at     INTEGER,
        schema_version INTEGER,
        runtime_version TEXT,
        data_json      TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS v7_ckpt_task ON v7_checkpoints(task_id);
    """)
    db.commit()

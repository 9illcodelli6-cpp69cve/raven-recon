"""RAVEN V7 Task Engine.

Tasks are first-class persistent objects (§84-86).
The Task Engine wraps the existing Scheduler — it does NOT replace it.
Agent tasks are a higher-level concept; HTTP-outbound work still flows
through the Scheduler for rate-limiting and budget enforcement.

State machine (§85-86):
  PENDING → PLANNING | QUEUED
  QUEUED → PLANNING | RUNNING | CANCELLED | INTERRUPTED
  PLANNING → RUNNING | BLOCKED | FAILED
  RUNNING → WAITING | PAUSING | CANCELLING | COMPLETED | FAILED | BLOCKED | INTERRUPTED
  PAUSING → PAUSED
  PAUSED → RUNNING | CANCELLING
  CANCELLING → CANCELLED
  WAITING → RUNNING | CANCELLING | FAILED
  INTERRUPTED → RUNNING | CANCELLED

QUEUED (Wave 5, additive) means "admitted to the SCHEDULER's pending deque, worker
not yet started" — the first-class lifecycle state between created (PENDING) and a
live worker (RUNNING). It is the Task-model mirror of the scheduler Job's own
"QUEUED" state (see runtime/scheduler_bridge.SchedulerTaskBridge).

Restart reconciliation: any Task left in a process-bound non-terminal state
(_RESTART_INTERRUPT_STATES) after a restart is reconciled to INTERRUPTED — a dead
OS process must NEVER remain RUNNING/QUEUED/PLANNING/WAITING. See
`_restore_from_db` (in-memory load) and `reconcile_interrupted` (durable sweep).

Invalid transitions raise InvalidTaskTransitionError.
"""
from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from .errors import InvalidTaskTransitionError
from .execution import ActorKind  # the ONE provenance enum (C-3); no import cycle


class TaskStatus(str, Enum):
    PENDING     = "PENDING"
    QUEUED      = "QUEUED"
    PLANNING    = "PLANNING"
    RUNNING     = "RUNNING"
    WAITING     = "WAITING"
    PAUSING     = "PAUSING"
    PAUSED      = "PAUSED"
    CANCELLING  = "CANCELLING"
    CANCELLED   = "CANCELLED"
    COMPLETED   = "COMPLETED"
    FAILED      = "FAILED"
    INTERRUPTED = "INTERRUPTED"
    BLOCKED     = "BLOCKED"


# Legal state transitions (§86)
_LEGAL_TRANSITIONS: Dict[TaskStatus, frozenset] = {
    TaskStatus.PENDING:     frozenset({TaskStatus.QUEUED, TaskStatus.PLANNING, TaskStatus.CANCELLED}),
    TaskStatus.QUEUED:      frozenset({
        TaskStatus.PLANNING, TaskStatus.RUNNING,
        TaskStatus.CANCELLED, TaskStatus.INTERRUPTED,  # worker-start, cancel, or restart sweep
    }),
    TaskStatus.PLANNING:    frozenset({TaskStatus.RUNNING, TaskStatus.BLOCKED, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.INTERRUPTED}),
    TaskStatus.RUNNING:     frozenset({
        TaskStatus.WAITING, TaskStatus.PAUSING, TaskStatus.CANCELLING,
        TaskStatus.CANCELLED,  # direct cancel for emergency/shutdown
        TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.BLOCKED, TaskStatus.INTERRUPTED,
    }),
    TaskStatus.PAUSING:     frozenset({TaskStatus.PAUSED, TaskStatus.CANCELLED, TaskStatus.INTERRUPTED}),
    TaskStatus.PAUSED:      frozenset({TaskStatus.RUNNING, TaskStatus.CANCELLING, TaskStatus.CANCELLED}),
    TaskStatus.CANCELLING:  frozenset({TaskStatus.CANCELLED, TaskStatus.INTERRUPTED}),
    TaskStatus.WAITING:     frozenset({TaskStatus.RUNNING, TaskStatus.CANCELLING, TaskStatus.CANCELLED, TaskStatus.FAILED, TaskStatus.INTERRUPTED}),
    TaskStatus.INTERRUPTED: frozenset({TaskStatus.RUNNING, TaskStatus.CANCELLED}),
    # Terminal states — no outbound transitions
    TaskStatus.CANCELLED:   frozenset(),
    TaskStatus.COMPLETED:   frozenset(),
    TaskStatus.FAILED:      frozenset(),
    TaskStatus.BLOCKED:     frozenset({TaskStatus.RUNNING, TaskStatus.FAILED, TaskStatus.CANCELLED}),
}

_TERMINAL_STATES = frozenset({TaskStatus.CANCELLED, TaskStatus.COMPLETED, TaskStatus.FAILED})

# Process-bound non-terminal states: a Task in one of these implies a live owning
# worker / OS process. After a restart the SCHEDULER's in-RAM Jobs are gone and are
# never auto-replayed, so any Task still in one of these states has no live owner and
# MUST be reconciled to INTERRUPTED (brief-critical invariant — a dead process is
# never left RUNNING). PENDING and PAUSED are intentionally excluded: they carry no
# implicit live process and remain resumable. (§129 + TASKS_SCHEDULER_ARCHITECTURE §3.4)
_RESTART_INTERRUPT_STATES = frozenset({
    TaskStatus.RUNNING,
    TaskStatus.QUEUED,
    TaskStatus.PLANNING,
    TaskStatus.WAITING,
    TaskStatus.PAUSING,
    TaskStatus.CANCELLING,
})


@dataclass
class TaskBudget:
    max_steps:           Optional[int] = None
    max_tool_calls:      Optional[int] = None
    max_runtime_ms:      Optional[int] = None
    max_duration_s:      Optional[int] = None   # alias for max_runtime_ms in seconds
    max_retries:         Optional[int] = None
    max_network_requests: Optional[int] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in {
            "max_steps": self.max_steps,
            "max_tool_calls": self.max_tool_calls,
            "max_runtime_ms": self.max_runtime_ms,
            "max_duration_s": self.max_duration_s,
            "max_retries": self.max_retries,
            "max_network_requests": self.max_network_requests,
        }.items() if v is not None}

    @classmethod
    def from_dict(cls, d: dict) -> "TaskBudget":
        return cls(**{k: v for k, v in d.items() if k in (
            "max_steps", "max_tool_calls", "max_runtime_ms", "max_duration_s",
            "max_retries", "max_network_requests"
        )})


@dataclass
class TaskProgress:
    step:       int = 0
    total:      int = 0
    message:    str = ""
    updated_at: int = field(default_factory=lambda: int(time.time() * 1000))


@dataclass
class Task:
    """A V7 agent task — first-class persistent object (§84)."""
    task_id:        str
    title:          str
    objective:      str
    workspace_id:   str
    status:         TaskStatus = TaskStatus.PENDING
    parent_task_id: Optional[str] = None
    root_task_id:   Optional[str] = None
    priority:       int = 5  # 1=highest, 10=lowest
    created_at:     int = field(default_factory=lambda: int(time.time() * 1000))
    started_at:     Optional[int] = None
    completed_at:   Optional[int] = None
    checkpoint_id:  Optional[str] = None
    budget:         TaskBudget = field(default_factory=TaskBudget)
    progress:       TaskProgress = field(default_factory=TaskProgress)
    result:         Optional[dict] = None
    failure:        Optional[str] = None
    metadata:       Dict = field(default_factory=dict)
    # ── Wave 5 additive: Scheduler/Task join + actor provenance ───────────────
    scheduler_job_id: Optional[str] = None       # back-link to the owning SCHEDULER Job
    origin:         Optional[ActorKind] = None    # who initiated this task (RESEARCHER/…)
    _lock:          threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    @property
    def is_terminal(self) -> bool:
        return self.status in _TERMINAL_STATES

    def transition(self, new_status: TaskStatus) -> None:
        with self._lock:
            allowed = _LEGAL_TRANSITIONS.get(self.status, frozenset())
            if new_status not in allowed:
                raise InvalidTaskTransitionError(
                    self.status.value, new_status.value, self.task_id
                )
            self.status = new_status
            now = int(time.time() * 1000)
            if new_status == TaskStatus.RUNNING and self.started_at is None:
                self.started_at = now
            if new_status in _TERMINAL_STATES:
                self.completed_at = now

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "task_id": self.task_id,
                "title": self.title,
                "objective": self.objective,
                "workspace_id": self.workspace_id,
                "status": self.status.value,
                "parent_task_id": self.parent_task_id,
                "root_task_id": self.root_task_id,
                "priority": self.priority,
                "created_at": self.created_at,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
                "checkpoint_id": self.checkpoint_id,
                "budget": self.budget.to_dict(),
                "progress": {
                    "step": self.progress.step,
                    "total": self.progress.total,
                    "message": self.progress.message,
                },
                "result": self.result,
                "failure": self.failure,
                "metadata": self.metadata,
                "scheduler_job_id": self.scheduler_job_id,
                "origin": self.origin.value if self.origin is not None else None,
            }


class TaskRegistry:
    """Creates, tracks, and persists V7 agent tasks (§84-89).

    All tasks are persisted to SQLite. An event bus callback is called on
    state changes so observers (UI, audit log) can react.
    """

    def __init__(self, db: sqlite3.Connection, event_callback=None):
        self._db = db
        self._lock = threading.RLock()
        self._tasks: Dict[str, Task] = {}
        self._event_cb = event_callback  # called with (event_type, task)
        self._migrate()
        self._restore_from_db()

    def _migrate(self) -> None:
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS v7_tasks (
            task_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            objective TEXT,
            workspace_id TEXT NOT NULL,
            status TEXT NOT NULL,
            parent_task_id TEXT,
            root_task_id TEXT,
            priority INTEGER DEFAULT 5,
            created_at INTEGER,
            started_at INTEGER,
            completed_at INTEGER,
            checkpoint_id TEXT,
            budget_json TEXT,
            progress_json TEXT,
            result_json TEXT,
            failure TEXT,
            metadata_json TEXT
        );
        CREATE INDEX IF NOT EXISTS v7_tasks_workspace ON v7_tasks(workspace_id);
        CREATE INDEX IF NOT EXISTS v7_tasks_status ON v7_tasks(status);
        """)
        # Wave 5 additive columns (Scheduler/Task join + actor provenance). SQLite
        # ALTER TABLE ADD COLUMN is in-place and defaults NULL; wrapped per-column so
        # the migration is idempotent on a DB that already has them. NO DROP/rename of
        # any existing column — reconstruction/migrations/0001_tasks_scheduler.sql
        # documents this DDL and the backup/integrity gate it ran behind.
        for col_sql in (
            "ALTER TABLE v7_tasks ADD COLUMN scheduler_job_id TEXT",
            "ALTER TABLE v7_tasks ADD COLUMN origin TEXT",
        ):
            try:
                self._db.execute(col_sql)
            except sqlite3.OperationalError:
                pass  # column already present — safe to ignore
        self._db.commit()

    def _restore_from_db(self) -> None:
        import json
        # task_ids whose persisted status was process-bound (RUNNING/QUEUED/…) and were
        # mapped to INTERRUPTED in memory here — reconcile_interrupted() consumes this to
        # perform the DURABLE write-back + audit. Reset each load (idempotent re-call).
        self._pending_reconcile: List[str] = []
        cursor = self._db.execute("SELECT * FROM v7_tasks WHERE status NOT IN (?,?,?)",
                                  (TaskStatus.COMPLETED.value, TaskStatus.CANCELLED.value, TaskStatus.FAILED.value))
        for row in cursor.fetchall():
            keys = [d[0] for d in cursor.description]
            data = dict(zip(keys, row))
            status = TaskStatus(data["status"])
            # Crash recovery (§129 / TASKS_SCHEDULER_ARCHITECTURE §3.4): any process-bound
            # non-terminal state (RUNNING/QUEUED/PLANNING/WAITING/PAUSING/CANCELLING) has
            # no live owner after a restart → INTERRUPTED. This in-memory map keeps the
            # restored view correct even if reconcile is not called; the DURABLE write-back
            # (fixing the pre-existing "DB still says RUNNING on next restart" gap) is done
            # by reconcile_interrupted(), which consumes self._pending_reconcile.
            if status in _RESTART_INTERRUPT_STATES:
                self._pending_reconcile.append(data["task_id"])
                status = TaskStatus.INTERRUPTED

            origin_val = data.get("origin")
            task = Task(
                task_id=data["task_id"],
                title=data["title"],
                objective=data["objective"] or "",
                workspace_id=data["workspace_id"],
                status=status,
                parent_task_id=data.get("parent_task_id"),
                root_task_id=data.get("root_task_id"),
                priority=data.get("priority", 5),
                created_at=data.get("created_at", 0),
                started_at=data.get("started_at"),
                completed_at=data.get("completed_at"),
                checkpoint_id=data.get("checkpoint_id"),
                budget=TaskBudget.from_dict(json.loads(data["budget_json"] or "{}")),
                progress=TaskProgress(
                    **json.loads(data["progress_json"] or "{}")
                ) if data.get("progress_json") else TaskProgress(),
                result=json.loads(data["result_json"]) if data.get("result_json") else None,
                failure=data.get("failure"),
                metadata=json.loads(data["metadata_json"] or "{}"),
                scheduler_job_id=data.get("scheduler_job_id"),
                origin=ActorKind(origin_val) if origin_val else None,
            )
            self._tasks[task.task_id] = task

    def _persist(self, task: Task) -> None:
        import json
        with self._lock:
            self._db.execute("""
            INSERT OR REPLACE INTO v7_tasks
                (task_id, title, objective, workspace_id, status, parent_task_id,
                 root_task_id, priority, created_at, started_at, completed_at,
                 checkpoint_id, budget_json, progress_json, result_json, failure, metadata_json,
                 scheduler_job_id, origin)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                task.task_id, task.title, task.objective, task.workspace_id,
                task.status.value, task.parent_task_id, task.root_task_id,
                task.priority, task.created_at, task.started_at, task.completed_at,
                task.checkpoint_id,
                json.dumps(task.budget.to_dict()),
                json.dumps({"step": task.progress.step, "total": task.progress.total,
                             "message": task.progress.message}),
                json.dumps(task.result) if task.result else None,
                task.failure,
                json.dumps(task.metadata),
                task.scheduler_job_id,
                task.origin.value if task.origin is not None else None,
            ))
            self._db.commit()

    def create(self, title: str, objective: str = "", workspace_id: str = "default",
               budget: TaskBudget = None, parent_task_id: str = None,
               priority: int = 5, metadata: dict = None,
               origin: ActorKind = None, scheduler_job_id: str = None) -> Task:
        task_id = uuid.uuid4().hex[:16]
        root = parent_task_id
        if parent_task_id and parent_task_id in self._tasks:
            root = self._tasks[parent_task_id].root_task_id or parent_task_id

        task = Task(
            task_id=task_id,
            title=title,
            objective=objective,
            workspace_id=workspace_id,
            budget=budget or TaskBudget(),
            parent_task_id=parent_task_id,
            root_task_id=root,
            priority=priority,
            metadata=metadata or {},
            origin=origin,
            scheduler_job_id=scheduler_job_id,
        )
        with self._lock:
            self._tasks[task_id] = task
        self._persist(task)
        self._emit("task.created", task)
        return task

    def link_job(self, task_id: str, scheduler_job_id: str) -> None:
        """Record the owning SCHEDULER Job id on a Task (durable back-link). Used by
        SchedulerTaskBridge right after SCHEDULER.submit returns the Job."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            task.scheduler_job_id = scheduler_job_id
        self._persist(task)

    def reconcile_interrupted(self) -> List[str]:
        """Restart reconciliation (brief-critical). Durable sweep: every Task whose
        persisted status was a process-bound non-terminal state (RUNNING/QUEUED/PLANNING/
        WAITING/PAUSING/CANCELLING) has no live owning process after a restart — the
        SCHEDULER's in-RAM Jobs are gone and are never auto-replayed — so it is forced to
        INTERRUPTED and the change is PERSISTED, so it survives the NEXT restart too
        (fixing the pre-existing gap where _restore_from_db mapped only in memory and the
        DB kept saying RUNNING). NEVER leaves a dead-process Task RUNNING. Idempotent: the
        second call is a no-op. Returns the reconciled task ids."""
        with self._lock:
            # Candidates: what _restore mapped in memory (persisted status was process-
            # bound), plus any task currently in a process-bound state directly.
            candidates = set(getattr(self, "_pending_reconcile", []))
            candidates.update(t.task_id for t in self._tasks.values()
                              if t.status in _RESTART_INTERRUPT_STATES)
            reconciled: List[str] = []
            for task_id in candidates:
                task = self._tasks.get(task_id)
                if task is None:
                    continue
                with task._lock:
                    # Direct recovery assignment (reconstruction semantics, not a normal
                    # transition) — INTERRUPTED is non-terminal, so completed_at stays unset.
                    task.status = TaskStatus.INTERRUPTED
                reconciled.append(task_id)
            self._pending_reconcile = []
        for task_id in reconciled:
            task = self._tasks.get(task_id)
            if task is not None:
                self._persist(task)      # DURABLE write-back
                self._emit("task.interrupted", task)
        return reconciled

    def get(self, task_id: str) -> Optional[Task]:
        with self._lock:
            return self._tasks.get(task_id)

    def transition(self, task_id: str, new_status: TaskStatus,
                   result: dict = None, failure: str = None,
                   checkpoint_id: str = None) -> Task:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                from .errors import RuntimeError, ErrorCategory
                raise RuntimeError(
                    category=ErrorCategory.VALIDATION,
                    code="TASK_NOT_FOUND",
                    message=f"Task '{task_id}' not found",
                )
            old = task.status
            task.transition(new_status)
            if result is not None:
                task.result = result
            if failure is not None:
                task.failure = failure
            if checkpoint_id is not None:
                task.checkpoint_id = checkpoint_id

        self._persist(task)
        self._emit(f"task.{new_status.value.lower()}", task)
        return task

    def update_progress(self, task_id: str, step: int = None, total: int = None,
                        message: str = None) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            if step is not None:
                task.progress.step = step
            if total is not None:
                task.progress.total = total
            if message is not None:
                task.progress.message = message
            task.progress.updated_at = int(time.time() * 1000)
        self._persist(task)
        self._emit("task.progress", task)

    def list_active(self, workspace_id: str = None) -> List[Task]:
        with self._lock:
            tasks = list(self._tasks.values())
        if workspace_id:
            tasks = [t for t in tasks if t.workspace_id == workspace_id]
        return [t for t in tasks if not t.is_terminal]

    def list_all(self, workspace_id: str = None, limit: int = 100) -> List[Task]:
        with self._lock:
            tasks = list(self._tasks.values())
        if workspace_id:
            tasks = [t for t in tasks if t.workspace_id == workspace_id]
        return sorted(tasks, key=lambda t: t.created_at, reverse=True)[:limit]

    def get_children(self, parent_task_id: str) -> List[Task]:
        with self._lock:
            return [t for t in self._tasks.values() if t.parent_task_id == parent_task_id]

    def _emit(self, event_type: str, task: Task) -> None:
        if self._event_cb:
            try:
                self._event_cb(event_type, task)
            except Exception:
                pass  # Never let event emission crash the registry

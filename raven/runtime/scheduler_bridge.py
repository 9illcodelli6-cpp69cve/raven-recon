"""SchedulerTaskBridge — the ONE coupling point between the live execution engine and
the durable task model (TASKS_SCHEDULER_ARCHITECTURE §3.3; CANONICAL_ARCHITECTURE §1 row 11a).

RAVEN has exactly one scheduler authority (`api.scheduler.Scheduler`, the process-global
`SCHEDULER`) and exactly one durable task-of-record (`runtime.tasks.TaskRegistry` +
`runtime.execution.ExecutionStore`). This bridge *joins* them; it is NOT a third task
system, a second scheduler, a new admission gate, or a new table.

It does four things and nothing else:
  1. Task-of-record creation — `submit()` creates a durable `Task`, marks it QUEUED,
     then calls `SCHEDULER.submit(...)` with `meta["task_id"]` so the Job links back.
  2. Lifecycle mirroring — it registers as the scheduler's observation-only
     `on_state_change` callback and mirrors Job state → canonical `TaskStatus`.
     The worker 'finally' terminal mirror is authoritative; intermediate mirrors are
     best-effort (illegal/stale transitions are skipped, never raised).
  3. Command fan-out — `cancel_task`/`pause_task`/`resume_task` route to the owning Job;
     the resulting Job state change mirrors back (single direction of truth per phase).
  4. Execution/observation audit — terminal jobs and restart reconciliation each write
     an `ExecutionRecord` carrying actor provenance.

Dependency direction is engine ← bridge → model: the scheduler never imports the task
model; this bridge imports both. It never re-enters `admit_request` — all rate/budget
accounting stays solely in the scheduler; the bridge only reads counters for display.
"""
from __future__ import annotations

import logging
from typing import List, Optional, Tuple

from .errors import InvalidTaskTransitionError
from .execution import ActorKind, ExecutionRecord, ExecutionStore, ToolStatus
from .tasks import Task, TaskRegistry, TaskStatus

logger = logging.getLogger(__name__)


# Scheduler Job.state vocabulary (scheduler.py: QUEUED/RUNNING/PAUSED/DONE/FAILED/
# CANCELLED) → canonical TaskStatus. Job state is the engine's INTERNAL execution
# status; it is mirrored here, never exposed to the UI as a second source of truth.
_JOB_TO_TASK = {
    "QUEUED":    TaskStatus.QUEUED,
    "RUNNING":   TaskStatus.RUNNING,
    "PAUSED":    TaskStatus.PAUSED,
    "DONE":      TaskStatus.COMPLETED,
    "FAILED":    TaskStatus.FAILED,
    "CANCELLED": TaskStatus.CANCELLED,
}

_TERMINAL_JOB_STATES = frozenset({"DONE", "FAILED", "CANCELLED"})

_JOB_TO_TOOLSTATUS = {
    "DONE":      ToolStatus.SUCCESS,
    "FAILED":    ToolStatus.FAILED,
    "CANCELLED": ToolStatus.CANCELLED,
}


class SchedulerTaskBridge:
    """Joins one `Scheduler` to one `TaskRegistry` (+ optional `ExecutionStore`)."""

    def __init__(self, scheduler, registry: TaskRegistry,
                 executions: Optional[ExecutionStore] = None,
                 default_actor: ActorKind = ActorKind.RESEARCHER):
        self._sched = scheduler
        self._registry = registry
        self._executions = executions
        self._default_actor = default_actor
        # Register as the scheduler's observation-only state-change seam. One bridge per
        # scheduler; this is additive and defaults off when no bridge is attached.
        scheduler.on_state_change = self._on_job_state

    # ── 1. Task-of-record creation ──────────────────────────────────────────────
    def submit(self, kind: str, workspace: str, fn, *, title: str, objective: str = "",
               workspace_id: Optional[str] = None, origin: Optional[ActorKind] = None,
               priority: int = 5, task_budget=None, task_metadata: Optional[dict] = None,
               meta: Optional[dict] = None) -> Tuple[Task, object]:
        """Create the durable Task of record, mark it QUEUED, then submit the Job.

        `meta` is passed through to `SCHEDULER.submit` (rate/budget live there, unchanged);
        this bridge stamps `meta["task_id"]` so the Job links back to the Task. Returns
        `(task, job)`.
        """
        actor = origin or self._default_actor
        ws_id = workspace_id or workspace
        task = self._registry.create(
            title=title, objective=objective, workspace_id=ws_id,
            budget=task_budget, priority=priority, origin=actor,
            metadata=dict(task_metadata or {}),
        )
        # PENDING → QUEUED: admitted to the scheduler's pending deque, worker not started.
        self._registry.transition(task.task_id, TaskStatus.QUEUED)
        sched_meta = dict(meta or {})
        sched_meta["task_id"] = task.task_id
        job = self._sched.submit(kind, workspace, fn, meta=sched_meta)
        # Durable back-link (best-effort: the worker may already have fired QUEUED→RUNNING,
        # which is harmless — mirroring keys off meta["task_id"], not this column).
        self._registry.link_job(task.task_id, job.id)
        return task, job

    # ── 2. Lifecycle mirroring (scheduler → task) ───────────────────────────────
    def _on_job_state(self, job, old_state: str, new_state: str) -> None:
        """Observation-only callback fired by the scheduler on each Job transition.
        Must never raise (the scheduler swallows exceptions, but we guard anyway)."""
        task_id = job.meta.get("task_id") if getattr(job, "meta", None) else None
        if not task_id:
            return
        task = self._registry.get(task_id)
        if task is None:
            return
        target = _JOB_TO_TASK.get(new_state)
        if target is not None and task.status != target and not task.is_terminal:
            result = {"job_id": job.id, "requests": job.requests} if new_state == "DONE" else None
            failure = job.error if new_state == "FAILED" else None
            try:
                self._registry.transition(task_id, target, result=result, failure=failure)
            except InvalidTaskTransitionError:
                # Best-effort intermediate mirror (e.g. PAUSED→QUEUED on resume has no
                # legal Task edge); the next QUEUED→RUNNING mirror self-heals it. The
                # worker 'finally' terminal mirror is the authoritative write.
                logger.debug("bridge: skipped illegal mirror %s → %s for task %s",
                             task.status, target, task_id)
            except Exception:  # noqa: BLE001
                logger.exception("bridge: task state mirror failed for %s", task_id)
        if new_state in _TERMINAL_JOB_STATES:
            self._write_execution(task, job, new_state)

    def _write_execution(self, task: Task, job, job_state: str) -> None:
        if self._executions is None:
            return
        try:
            rec = ExecutionRecord(
                task_id=task.task_id,
                tool_id=job.kind,
                actor=task.origin or self._default_actor,
                workspace_id=task.workspace_id,
                input_summary=f"scheduler job {job.id} ({job.kind})",
                error=job.error,
                capability_decision=None,  # the scheduler admitted the egress, not a CapabilityGate
                metadata={"scheduler_job_id": job.id, "requests": job.requests},
            )
            rec.finish(_JOB_TO_TOOLSTATUS.get(job_state, ToolStatus.FAILED), error=job.error)
            self._executions.save(rec)
        except Exception:  # noqa: BLE001
            logger.exception("bridge: execution audit write failed for task %s", task.task_id)

    # ── 3. Command fan-out (task → scheduler) ───────────────────────────────────
    def cancel_task(self, task_id: str) -> bool:
        """Cancel the Task by cancelling its owning Job; the resulting Job state change
        mirrors back to the Task. If there is no live Job (INTERRUPTED/PENDING/QUEUED
        without a Job), cancel the Task directly so it never lingers non-terminal."""
        task = self._registry.get(task_id)
        if task is None:
            return False
        acted = False
        if task.scheduler_job_id:
            acted = self._sched.cancel(task.scheduler_job_id)
        if not acted and not task.is_terminal:
            try:
                self._registry.transition(task_id, TaskStatus.CANCELLED)
                acted = True
            except Exception:  # noqa: BLE001
                logger.exception("bridge: direct task cancel failed for %s", task_id)
        return acted

    def pause_task(self, task_id: str) -> bool:
        task = self._registry.get(task_id)
        if task is None or not task.scheduler_job_id:
            return False
        return self._sched.pause(task.scheduler_job_id)

    def resume_task(self, task_id: str) -> bool:
        task = self._registry.get(task_id)
        if task is None or not task.scheduler_job_id:
            return False
        return self._sched.resume(task.scheduler_job_id)

    # ── 4. Restart reconciliation ───────────────────────────────────────────────
    def reconcile(self) -> List[str]:
        """Run once at startup, after the registry is built. The scheduler's Jobs are
        process-local and never auto-replayed, so immediately after a restart there is no
        live Job for any pre-restart Task — every Task still in a process-bound
        non-terminal state is reconciled to INTERRUPTED (durable). Writes a SYSTEM-actor
        audit row per reconciled task. Returns the reconciled task ids. Idempotent."""
        reconciled = self._registry.reconcile_interrupted()
        if self._executions is not None:
            for task_id in reconciled:
                task = self._registry.get(task_id)
                if task is None:
                    continue
                try:
                    rec = ExecutionRecord(
                        task_id=task_id,
                        tool_id="scheduler.reconcile",
                        actor=ActorKind.SYSTEM,
                        workspace_id=task.workspace_id,
                        input_summary="restart reconciliation: no live owning process",
                        capability_decision=None,
                        metadata={"reason": "interrupted_on_restart"},
                    )
                    rec.finish(ToolStatus.PARTIAL)
                    self._executions.save(rec)
                except Exception:  # noqa: BLE001
                    logger.exception("bridge: reconcile audit write failed for %s", task_id)
        return reconciled

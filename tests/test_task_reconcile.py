"""Restart reconciliation tests (Wave 5, A5-TASK) — BRIEF-CRITICAL.

A dead OS process must NEVER leave a Task RUNNING. On restart, any Task in a
process-bound non-terminal state (RUNNING/QUEUED/PLANNING/WAITING/PAUSING/CANCELLING)
has no live owner — the SCHEDULER's in-RAM Jobs are gone and never auto-replayed — so
it must be reconciled to INTERRUPTED and that change must be DURABLE (survive the next
restart). PENDING/PAUSED are retained as resumable; terminal rows are untouched.

Run:  python -m pytest tests/test_task_reconcile.py -q
"""
import os
import sqlite3
import tempfile
import unittest

from raven.runtime.execution import ActorKind, ExecutionStore
from raven.runtime.scheduler_bridge import SchedulerTaskBridge
from raven.runtime.tasks import TaskRegistry, TaskStatus, _RESTART_INTERRUPT_STATES


def _open(path):
    db = sqlite3.connect(path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db


def _raw_status(path, task_id):
    db = _open(path)
    try:
        row = db.execute("SELECT status FROM v7_tasks WHERE task_id=?", (task_id,)).fetchone()
        return row["status"] if row else None
    finally:
        db.close()


class ReconcileStateMapTests(unittest.TestCase):
    def test_restart_interrupt_set_is_process_bound_only(self):
        # PENDING and PAUSED are intentionally excluded (resumable, no implicit process);
        # terminal states are excluded. The process-bound set is exactly these six.
        self.assertEqual(
            _RESTART_INTERRUPT_STATES,
            frozenset({
                TaskStatus.RUNNING, TaskStatus.QUEUED, TaskStatus.PLANNING,
                TaskStatus.WAITING, TaskStatus.PAUSING, TaskStatus.CANCELLING,
            }),
        )
        for terminal in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED,
                         TaskStatus.PENDING, TaskStatus.PAUSED, TaskStatus.INTERRUPTED):
            self.assertNotIn(terminal, _RESTART_INTERRUPT_STATES)


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self._fd, self._path = tempfile.mkstemp(suffix="-tasks_v7.db")
        os.close(self._fd)

    def tearDown(self):
        try:
            os.remove(self._path)
        except OSError:
            pass

    def _seed_running(self, reg, status_path):
        """Create a task and drive it to a process-bound status, persisted."""
        task = reg.create(title="seed", objective="o", workspace_id="ws1",
                          origin=ActorKind.RESEARCHER)
        reg.transition(task.task_id, TaskStatus.QUEUED)
        reg.transition(task.task_id, TaskStatus.RUNNING)
        return task.task_id

    def test_stale_running_reconciles_to_interrupted_and_is_durable(self):
        # 1) First process: a task left RUNNING (simulating a kill mid-execution).
        reg1 = TaskRegistry(_open(self._path))
        tid = self._seed_running(reg1, self._path)
        self.assertEqual(_raw_status(self._path, tid), "RUNNING")

        # 2) Restart: a fresh registry. _restore maps RUNNING -> INTERRUPTED in memory,
        #    but (by design) does NOT write it back — the DB still says RUNNING.
        reg2 = TaskRegistry(_open(self._path))
        self.assertEqual(reg2.get(tid).status, TaskStatus.INTERRUPTED)
        self.assertEqual(_raw_status(self._path, tid), "RUNNING",
                         "_restore_from_db must not itself write back (reconcile does)")

        # 3) Reconcile: durable write-back. No task may remain RUNNING.
        reconciled = reg2.reconcile_interrupted()
        self.assertIn(tid, reconciled)
        self.assertEqual(reg2.get(tid).status, TaskStatus.INTERRUPTED)
        self.assertEqual(_raw_status(self._path, tid), "INTERRUPTED")
        self.assertFalse(any(t.status == TaskStatus.RUNNING for t in reg2.list_active()),
                         "list_active must report NO RUNNING task after reconcile")

        # 4) Next restart sees INTERRUPTED directly from the DB (durable), not a
        #    re-derived in-memory guess.
        reg3 = TaskRegistry(_open(self._path))
        self.assertEqual(reg3.get(tid).status, TaskStatus.INTERRUPTED)
        self.assertEqual(_raw_status(self._path, tid), "INTERRUPTED")

    def test_all_process_bound_states_reconcile(self):
        reg1 = TaskRegistry(_open(self._path))
        # RUNNING
        t_run = reg1.create(title="run", workspace_id="ws"); reg1.transition(t_run.task_id, TaskStatus.QUEUED); reg1.transition(t_run.task_id, TaskStatus.RUNNING)
        # QUEUED
        t_q = reg1.create(title="queued", workspace_id="ws"); reg1.transition(t_q.task_id, TaskStatus.QUEUED)
        # PLANNING
        t_plan = reg1.create(title="plan", workspace_id="ws"); reg1.transition(t_plan.task_id, TaskStatus.PLANNING)
        # WAITING
        t_wait = reg1.create(title="wait", workspace_id="ws"); reg1.transition(t_wait.task_id, TaskStatus.QUEUED); reg1.transition(t_wait.task_id, TaskStatus.RUNNING); reg1.transition(t_wait.task_id, TaskStatus.WAITING)
        # Retained: PENDING + PAUSED
        t_pending = reg1.create(title="pending", workspace_id="ws")
        t_paused = reg1.create(title="paused", workspace_id="ws"); reg1.transition(t_paused.task_id, TaskStatus.QUEUED); reg1.transition(t_paused.task_id, TaskStatus.RUNNING); reg1.transition(t_paused.task_id, TaskStatus.PAUSING); reg1.transition(t_paused.task_id, TaskStatus.PAUSED)

        reg2 = TaskRegistry(_open(self._path))
        reconciled = set(reg2.reconcile_interrupted())
        for tid in (t_run.task_id, t_q.task_id, t_plan.task_id, t_wait.task_id):
            self.assertIn(tid, reconciled)
            self.assertEqual(_raw_status(self._path, tid), "INTERRUPTED")
        # Retained states untouched
        self.assertNotIn(t_pending.task_id, reconciled)
        self.assertEqual(_raw_status(self._path, t_pending.task_id), "PENDING")
        self.assertNotIn(t_paused.task_id, reconciled)
        self.assertEqual(_raw_status(self._path, t_paused.task_id), "PAUSED")

    def test_reconcile_is_idempotent(self):
        reg1 = TaskRegistry(_open(self._path))
        tid = self._seed_running(reg1, self._path)
        reg2 = TaskRegistry(_open(self._path))
        first = reg2.reconcile_interrupted()
        second = reg2.reconcile_interrupted()
        self.assertIn(tid, first)
        self.assertEqual(second, [], "second reconcile must be a no-op")

    def test_bridge_reconcile_writes_system_audit(self):
        from raven.api.scheduler import Scheduler
        reg1 = TaskRegistry(_open(self._path))
        tid = self._seed_running(reg1, self._path)

        db2 = _open(self._path)
        reg2 = TaskRegistry(db2)
        es = ExecutionStore(db2)
        sched = Scheduler(workers=1, default_rate=100.0)
        try:
            bridge = SchedulerTaskBridge(sched, reg2, es)
            reconciled = bridge.reconcile()
            self.assertIn(tid, reconciled)
            self.assertEqual(reg2.get(tid).status, TaskStatus.INTERRUPTED)
            recs = es.list_for_task(tid)
            self.assertTrue(recs, "reconcile must write an audit record")
            self.assertTrue(any(r.actor == ActorKind.SYSTEM.value for r in recs),
                            "restart reconciliation audit must be SYSTEM actor")
        finally:
            sched.emergency_stop()
            db2.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)

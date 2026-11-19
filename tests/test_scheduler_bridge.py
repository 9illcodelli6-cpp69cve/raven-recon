"""SchedulerTaskBridge tests (Wave 5, A5-TASK).

Proves the ONE bridge joins the live SCHEDULER (admission/jobs) to the durable
TaskRegistry (state) + ExecutionStore (audit) WITHOUT a third task system:
  * task-of-record creation + QUEUED→RUNNING→COMPLETED mirroring + Job↔Task linkage
  * ExecutionRecord rows written with the right actor + status
  * failure mirroring (job raises → Task FAILED)
  * cancel fan-out (queued + running) and Emergency-Stop cascade to Task states
  * actor provenance incl. PROGRAM_AGENT round-trip
  * the callback is OFF by default (no behaviour change when no bridge is attached)

All work is local; no network. Run:  python -m pytest tests/test_scheduler_bridge.py -q
"""
import sqlite3
import threading
import time
import unittest

from raven.api.scheduler import Scheduler
from raven.runtime.execution import ActorKind, ExecutionRecord, ExecutionStore, ToolStatus
from raven.runtime.scheduler_bridge import SchedulerTaskBridge
from raven.runtime.tasks import TaskRegistry, TaskStatus


def wait_until(pred, timeout=6.0, interval=0.01):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(interval)
    return pred()


class _BridgeBase(unittest.TestCase):
    def setUp(self):
        self.sched = Scheduler(workers=1, default_rate=1000.0)
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.reg = TaskRegistry(self.db)
        self.es = ExecutionStore(self.db)
        self.bridge = SchedulerTaskBridge(self.sched, self.reg, self.es,
                                          default_actor=ActorKind.RESEARCHER)

    def tearDown(self):
        self.sched.emergency_stop()
        self.sched.shutdown(wait=True, timeout=2.0)
        self.db.close()


class HappyPathTests(_BridgeBase):
    def test_submit_creates_task_and_mirrors_lifecycle(self):
        started = threading.Event()
        release = threading.Event()

        def fn(control):
            started.set()
            release.wait(5)
            return {"ok": True}

        task, job = self.bridge.submit("collect", "ws1", fn,
                                       title="Recon run", objective="probe",
                                       workspace_id="ws1")
        # Job ↔ Task linkage both directions.
        self.assertEqual(job.meta["task_id"], task.task_id)
        self.assertTrue(wait_until(lambda: self.reg.get(task.task_id).scheduler_job_id == job.id))

        # QUEUED→RUNNING mirror.
        self.assertTrue(wait_until(started.is_set))
        self.assertTrue(wait_until(lambda: self.reg.get(task.task_id).status == TaskStatus.RUNNING))
        self.assertIsNotNone(self.reg.get(task.task_id).started_at)

        # Release → DONE→COMPLETED mirror.
        release.set()
        self.assertTrue(wait_until(lambda: self.reg.get(task.task_id).status == TaskStatus.COMPLETED))

        # Audit: a SUCCESS ExecutionRecord with the initiating actor.
        recs = self.es.list_for_task(task.task_id)
        self.assertTrue(recs)
        self.assertTrue(any(r.status == ToolStatus.SUCCESS.value for r in recs))
        self.assertTrue(any(r.actor == ActorKind.RESEARCHER.value for r in recs))
        self.assertTrue(any(r.tool_id == "collect" for r in recs))

    def test_job_failure_mirrors_to_task_failed(self):
        def fn(control):
            raise ValueError("boom")

        task, job = self.bridge.submit("collect", "ws1", fn, title="fails")
        self.assertTrue(wait_until(lambda: self.reg.get(task.task_id).status == TaskStatus.FAILED))
        self.assertIsNotNone(self.reg.get(task.task_id).failure)
        recs = self.es.list_for_task(task.task_id)
        self.assertTrue(any(r.status == ToolStatus.FAILED.value for r in recs))


class CancelFanOutTests(_BridgeBase):
    def test_cancel_running_task_cancels_job(self):
        started = threading.Event()

        def fn(control):
            started.set()
            for _ in range(2000):
                control.check()      # cooperative cancel checkpoint
                time.sleep(0.005)
            return {"ok": True}

        task, job = self.bridge.submit("collect", "ws1", fn, title="long")
        self.assertTrue(wait_until(started.is_set))
        self.assertTrue(wait_until(lambda: self.reg.get(task.task_id).status == TaskStatus.RUNNING))

        self.assertTrue(self.bridge.cancel_task(task.task_id))
        self.assertTrue(wait_until(lambda: self.reg.get(task.task_id).status == TaskStatus.CANCELLED))
        self.assertFalse(any(t.status == TaskStatus.RUNNING for t in self.reg.list_active()))

    def test_cancel_queued_task_is_synchronous(self):
        block = threading.Event()

        def busy(control):
            block.wait(5)  # occupies the single worker so the next job stays QUEUED
            return {}

        # Occupy the only worker.
        t_busy, _ = self.bridge.submit("collect", "ws1", busy, title="busy")
        self.assertTrue(wait_until(lambda: self.reg.get(t_busy.task_id).status == TaskStatus.RUNNING))

        # This one sits in the pending deque (QUEUED).
        t_q, job_q = self.bridge.submit("collect", "ws1", lambda c: {}, title="queued")
        self.assertTrue(wait_until(lambda: self.reg.get(t_q.task_id).status == TaskStatus.QUEUED))

        self.assertTrue(self.bridge.cancel_task(t_q.task_id))
        self.assertEqual(self.reg.get(t_q.task_id).status, TaskStatus.CANCELLED)
        block.set()


class EmergencyStopTests(_BridgeBase):
    def test_emergency_stop_cascades_to_task_cancelled(self):
        started = threading.Event()

        def fn(control):
            started.set()
            for _ in range(2000):
                control.check()
                time.sleep(0.005)
            return {}

        task, _ = self.bridge.submit("collect", "ws1", fn, title="estop")
        self.assertTrue(wait_until(started.is_set))
        self.assertTrue(wait_until(lambda: self.reg.get(task.task_id).status == TaskStatus.RUNNING))

        self.sched.emergency_stop()
        self.assertTrue(wait_until(lambda: self.reg.get(task.task_id).status == TaskStatus.CANCELLED))
        self.assertFalse(any(t.status == TaskStatus.RUNNING for t in self.reg.list_active()),
                         "no Task may remain RUNNING after Emergency Stop")


class ProvenanceTests(_BridgeBase):
    def test_program_agent_origin_persists_and_audits(self):
        done = threading.Event()

        def fn(control):
            done.set()
            return {"ok": True}

        task, _ = self.bridge.submit("program.step", "ws1", fn, title="prog",
                                     origin=ActorKind.PROGRAM_AGENT)
        self.assertTrue(wait_until(lambda: self.reg.get(task.task_id).status == TaskStatus.COMPLETED))
        self.assertEqual(self.reg.get(task.task_id).to_dict()["origin"], "PROGRAM_AGENT")
        recs = self.es.list_for_task(task.task_id)
        self.assertTrue(any(r.actor == ActorKind.PROGRAM_AGENT.value for r in recs))

    def test_execution_record_program_agent_roundtrip(self):
        rec = ExecutionRecord(task_id="t1", tool_id="x", actor=ActorKind.PROGRAM_AGENT,
                              workspace_id="ws1")
        rec.finish(ToolStatus.SUCCESS)
        self.es.save(rec)
        back = self.es.get(rec.execution_id)
        self.assertEqual(back["actor"], "PROGRAM_AGENT")
        self.assertEqual(rec.to_dict()["actor"], "PROGRAM_AGENT")


class NoBridgeIsOffByDefaultTests(unittest.TestCase):
    def test_scheduler_without_bridge_has_no_callback(self):
        sched = Scheduler(workers=1, default_rate=1000.0)
        self.assertIsNone(sched.on_state_change)
        done = threading.Event()
        job = sched.submit("k", "ws", lambda c: done.set())
        try:
            self.assertTrue(wait_until(done.is_set))
            self.assertTrue(wait_until(lambda: sched.get(job.id)["state"] == "DONE"))
        finally:
            sched.emergency_stop()
            sched.shutdown(wait=True, timeout=2.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

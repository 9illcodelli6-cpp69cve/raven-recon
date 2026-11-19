"""Task-scheduler tests (V4 Stage 2).

Prove the central scheduler's guarantees WITHOUT touching any external target:
job lifecycle, cancellation stopping new requests, pause/resume, the global
Emergency Stop refusing new work, per-host rate limiting, per-workspace request
budgets, non-blocking /api/collect submission, cancel marking the run 'cancelled'
(no auto-replay), and interrupted-run crash recovery. All network I/O is stubbed.

Run:  python -m unittest tests.test_scheduler -v
"""
import os
import tempfile
import threading
import time
import unittest

from raven.api import server
from raven.api.scheduler import (
    BudgetExhausted, Cancelled, QueueFull, Scheduler, SchedulerStopped, TokenBucket, WorkspaceBusy,
)
from raven.scope import Scope


def wait_until(pred, timeout=6.0, interval=0.02):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(interval)
    return pred()


class TokenBucketTests(unittest.TestCase):
    def test_rate_limits_throughput(self):
        bucket = TokenBucket(rate=20, capacity=1)  # ~0.05s between tokens after the first
        t0 = time.monotonic()
        for _ in range(6):
            bucket.take()
        elapsed = time.monotonic() - t0
        # 1 free (burst) + 5 waits of ~0.05s ≈ 0.25s; generous lower bound avoids flakiness.
        self.assertGreater(elapsed, 0.15, f"rate limiter did not throttle (elapsed {elapsed:.3f}s)")

    def test_cancel_event_interrupts_wait(self):
        bucket = TokenBucket(rate=1, capacity=1)
        bucket.take()  # drain the single burst token
        ev = threading.Event()
        threading.Timer(0.1, ev.set).start()
        with self.assertRaises(Cancelled):
            bucket.take(cancel_event=ev)

    def test_cancelled_caller_cannot_take_available_token(self):
        bucket = TokenBucket(10, 1)
        event = threading.Event()
        event.set()
        with self.assertRaises(Cancelled):
            bucket.take(event)
        self.assertEqual(bucket.tokens, 1)

    def test_nonfinite_or_nonpositive_rate_is_rejected(self):
        for rate in (0, -1, float("inf"), float("nan"), True, "bad"):
            with self.subTest(rate=rate), self.assertRaises(ValueError):
                TokenBucket(rate)


class SchedulerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.sched = Scheduler(workers=3, default_rate=100.0)

    def tearDown(self):
        self.sched.emergency_stop()
        self.sched.shutdown()

    def test_job_runs_to_done(self):
        out = []
        job = self.sched.submit("t", "ws", lambda c: out.append(c) or 42)
        self.assertTrue(wait_until(lambda: job.state == "DONE"))
        self.assertEqual(job.result, 42)
        self.assertEqual(len(out), 1)

    def test_failed_job_captures_error(self):
        def boom(_):
            raise RuntimeError("kaboom")
        job = self.sched.submit("t", "ws", boom)
        self.assertTrue(wait_until(lambda: job.state == "FAILED"))
        self.assertIn("kaboom", job.error)
        self.assertIn("RuntimeError", job.error)

    def test_cancel_stops_new_requests(self):
        sched = Scheduler(workers=1, default_rate=5.0)  # ~0.2s per request on the same host
        self.addCleanup(sched.shutdown)
        done = []

        def loop(c):
            for _ in range(50):
                c.rate("same-host")  # same host -> throttled, cancellable
                done.append(1)

        job = sched.submit("t", "ws", loop)
        self.assertTrue(wait_until(lambda: job.state == "RUNNING"))
        time.sleep(0.5)
        at_cancel = len(done)
        self.assertTrue(sched.cancel(job.id))
        self.assertTrue(wait_until(lambda: job.state == "CANCELLED"))
        time.sleep(0.4)  # give any wrongly-scheduled request time to appear
        self.assertLessEqual(len(done), at_cancel + 1, "requests kept being scheduled after cancel")
        self.assertLess(len(done), 50, "job was not actually interrupted")

    def test_pause_and_resume(self):
        sched = Scheduler(workers=1, default_rate=5.0)
        self.addCleanup(sched.shutdown)
        done = []

        def loop(c):
            for _ in range(10):
                c.rate("h")
                done.append(1)

        job = sched.submit("t", "ws", loop)
        self.assertTrue(wait_until(lambda: job.state == "RUNNING"))
        self.assertTrue(sched.pause(job.id))
        self.assertEqual(job.state, "PAUSED")
        paused_at = len(done)
        time.sleep(0.5)
        self.assertLessEqual(len(done), paused_at + 1, "job kept working while paused")
        self.assertTrue(sched.resume(job.id))
        self.assertTrue(wait_until(lambda: job.state == "DONE"))
        self.assertEqual(len(done), 10)

    def test_emergency_stop_cancels_all_and_refuses_new(self):
        sched = Scheduler(workers=2, default_rate=1000.0)
        self.addCleanup(sched.shutdown)

        def slow(c):
            for _ in range(200):
                c.check()
                time.sleep(0.02)

        jobs = [sched.submit("t", "ws", slow) for _ in range(4)]
        self.assertTrue(wait_until(lambda: any(j.state == "RUNNING" for j in jobs)))
        self.assertTrue(sched.emergency_stop())
        self.assertTrue(wait_until(lambda: all(j.state == "CANCELLED" for j in jobs)))
        self.assertTrue(sched.stats()["emergency_stopped"])
        # New work is refused while stopped...
        with self.assertRaises(SchedulerStopped):
            sched.submit("t", "ws", lambda c: 1)
        # ...and accepted again after the stop is cleared.
        sched.clear_stop()
        ok = sched.submit("t", "ws", lambda c: 1)
        self.assertTrue(wait_until(lambda: ok.state == "DONE"))

    def test_request_budget_caps_work(self):
        sched = Scheduler(workers=1, default_rate=1000.0)
        self.addCleanup(sched.shutdown)
        done = []

        def loop(c):
            for _ in range(100):
                c.rate("h")
                done.append(1)

        job = sched.submit("t", "ws", loop, meta={"budget": 5})
        self.assertTrue(wait_until(lambda: job.state == "CANCELLED"))
        self.assertEqual(len(done), 5, "budget did not cap requests")


class SchedulerRegressionTests(unittest.TestCase):
    """Event-controlled regressions for races, admission and shared accounting."""

    def scheduler(self, **kwargs):
        sched = Scheduler(default_rate=10000, **kwargs)
        self.addCleanup(sched.shutdown)
        return sched

    def test_stopped_submission_cannot_run_after_clear_with_busy_worker(self):
        sched = self.scheduler(workers=1)
        entered, release, forbidden = threading.Event(), threading.Event(), threading.Event()
        self.addCleanup(release.set)
        busy = sched.submit("busy", "ws", lambda c: entered.set() or release.wait(3))
        self.assertTrue(entered.wait(1))
        sched.emergency_stop()
        with self.assertRaises(SchedulerStopped):
            sched.submit("forbidden", "ws", lambda c: forbidden.set())
        sched.clear_stop()
        release.set()
        self.assertTrue(wait_until(lambda: busy.state == "CANCELLED"))
        self.assertFalse(forbidden.is_set())
        self.assertEqual(len(sched.jobs), 1)

    def test_paused_pending_job_does_not_occupy_worker(self):
        sched = self.scheduler(workers=1)
        paused_ran, ready_ran = threading.Event(), threading.Event()
        with sched.lock:
            paused = sched.submit("paused", "ws", lambda c: paused_ran.set())
            self.assertTrue(sched.pause(paused.id))
            ready = sched.submit("ready", "ws", lambda c: ready_ran.set())
        self.assertTrue(ready_ran.wait(1), "paused pending job monopolized worker")
        self.assertFalse(paused_ran.is_set())
        self.assertIsNone(paused.started)
        with sched.lock:
            self.assertTrue(sched.resume(paused.id))
            self.assertEqual(paused.state, "QUEUED")
        self.assertTrue(wait_until(lambda: paused.state == ready.state == "DONE"))

    def test_pending_queue_is_bounded_and_cancellation_frees_admission(self):
        sched = self.scheduler(workers=1, max_pending=2)
        with sched.lock:
            first = sched.submit("t", "ws", lambda c: None)
            sched.pause(first.id)
            second = sched.submit("t", "ws", lambda c: None)
            sched.pause(second.id)
            with self.assertRaises(QueueFull):
                sched.submit("overflow", "ws", lambda c: None)
            self.assertEqual(len(sched.jobs), 2)
            self.assertTrue(sched.cancel(first.id))
            self.assertEqual(first.state, "CANCELLED")
            self.assertIsNotNone(first.finished)
            replacement = sched.submit("replacement", "ws", lambda c: None)
        self.assertTrue(wait_until(lambda: replacement.state == "DONE"))

    def test_cancellation_during_final_request_wins_over_normal_return(self):
        sched = self.scheduler(workers=1)
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def last_request(control):
            control.rate("host")
            entered.set()
            release.wait(3)
            return {"partial": "retained"}

        job = sched.submit("t", "ws", last_request)
        self.assertTrue(entered.wait(1))
        self.assertTrue(sched.cancel(job.id))
        release.set()
        self.assertTrue(wait_until(lambda: job.state == "CANCELLED"))
        self.assertEqual(job.result, {"partial": "retained"})
        self.assertFalse(sched.resume(job.id))
        self.assertFalse(sched.pause(job.id))

    def test_cancellation_after_token_wait_prevents_dispatch(self):
        sched = self.scheduler(workers=1)
        entered, release, dispatched = threading.Event(), threading.Event(), threading.Event()
        self.addCleanup(release.set)

        class DelayedToken:
            def take(self, cancel_event):
                entered.set()
                release.wait(3)

        sched.limiter = lambda *args: DelayedToken()
        job = sched.submit("t", "ws", lambda c: c.rate("host") or dispatched.set())
        self.assertTrue(entered.wait(1))
        sched.cancel(job.id)
        release.set()
        self.assertTrue(wait_until(lambda: job.state == "CANCELLED"))
        self.assertFalse(dispatched.is_set())
        self.assertEqual(job.requests, 0)
        self.assertEqual(sched.stats()["workspace_budgets"]["ws"]["used"], 0)

    def test_pause_after_token_wait_prevents_dispatch_until_resume(self):
        sched = self.scheduler(workers=1)
        entered, release, dispatched = threading.Event(), threading.Event(), threading.Event()
        self.addCleanup(release.set)

        class DelayedToken:
            def take(self, cancel_event):
                entered.set()
                release.wait(3)

        sched.limiter = lambda *args: DelayedToken()
        job = sched.submit("t", "ws", lambda c: c.rate("host") or dispatched.set())
        self.assertTrue(entered.wait(1))
        self.assertTrue(sched.pause(job.id))
        release.set()
        self.assertFalse(dispatched.wait(0.1))
        self.assertEqual(job.requests, 0)
        self.assertTrue(sched.resume(job.id))
        self.assertTrue(wait_until(lambda: job.state == "DONE"))
        self.assertTrue(dispatched.is_set())

    def test_workspace_budget_is_shared_across_concurrent_jobs_and_hosts(self):
        sched = self.scheduler(workers=4)
        start = threading.Event()
        self.addCleanup(start.set)
        admitted = []

        def request_loop(control):
            start.wait(3)
            for _ in range(20):
                control.rate(threading.current_thread().name)
                admitted.append(1)

        jobs = [sched.submit("t", "ws", request_loop, {"budget": 7}) for _ in range(4)]
        start.set()
        self.assertTrue(wait_until(lambda: all(j.state == "CANCELLED" for j in jobs)))
        self.assertEqual(len(admitted), 7)
        self.assertEqual(sum(job.requests for job in jobs), 7)
        self.assertEqual(sched.stats()["workspace_budgets"]["ws"], {"used": 7, "limit": 7})
        later = sched.submit("later", "ws", lambda c: c.rate("different-host"), {"budget": 100})
        self.assertTrue(wait_until(lambda: later.state == "CANCELLED"))
        self.assertEqual(later.requests, 0)

    def test_workspace_key_defeats_label_alias_and_stop_does_not_reset_budget(self):
        sched = self.scheduler(workers=1)
        first = sched.submit("t", "label-a", lambda c: c.rate("host-a"), {"budget": 1, "workspace_key": "canonical"})
        self.assertTrue(wait_until(lambda: first.state == "DONE"))
        sched.emergency_stop()
        sched.clear_stop()
        second = sched.submit("t", "label-b", lambda c: c.rate("host-b"), {"budget": 1, "workspace_key": "canonical"})
        self.assertTrue(wait_until(lambda: second.state == "CANCELLED"))
        self.assertEqual(second.requests, 0)
        other = sched.submit("t", "independent", lambda c: c.rate("host-c"), {"budget": 1})
        self.assertTrue(wait_until(lambda: other.state == "DONE"))

    def test_host_limit_is_global_and_later_rate_cannot_raise_ceiling(self):
        sched = self.scheduler(workers=1)
        first = sched.limiter("workspace-a", "Example.TEST.", 3)
        second = sched.limiter("workspace-b", "example.test", 100)
        self.assertIs(first, second)
        self.assertEqual(first.rate, 3)
        self.assertEqual(sched.limiter("workspace-c", "example.test", 1).rate, 1)

    def test_shutdown_unblocks_paused_and_rate_waiting_jobs(self):
        sched = self.scheduler(workers=2)
        started, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def pause_checkpoint(control):
            started.set()
            release.wait(3)
            control.check()

        paused = sched.submit("paused", "ws", pause_checkpoint)
        self.assertTrue(started.wait(1))
        sched.pause(paused.id)
        release.set()
        token = sched.limiter("ws", "host", 0.01)
        token.take()
        waiting = sched.submit("waiting", "ws", lambda c: c.rate("host"), {"rate": 0.01})
        self.assertTrue(wait_until(lambda: waiting.state == "RUNNING"))
        self.assertTrue(sched.shutdown(timeout=1))
        self.assertEqual(paused.state, "CANCELLED")
        self.assertEqual(waiting.state, "CANCELLED")
        with self.assertRaises(SchedulerStopped):
            sched.submit("t", "ws", lambda c: None)
        with self.assertRaises(SchedulerStopped):
            sched.clear_stop()

    def test_invalid_settings_never_admit_job(self):
        sched = self.scheduler(workers=1)
        for name, values in (("rate", (0, -1, float("nan"), float("inf"), True)),
                             ("budget", (0, -1, 1.5, float("nan"), float("inf"), True))):
            for value in values:
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    sched.submit("t", "ws", lambda c: None, {name: value})
        self.assertFalse(sched.jobs)

    def test_explicit_budget_reset_requires_idle_workspace(self):
        # Busy (an active job) is WorkspaceBusy, never a plain ValueError — the two
        # must be tellable apart (see test_reset_budget_error_kinds_are_distinct).
        sched = self.scheduler(workers=1)
        with sched.lock:
            job = sched.submit("t", "ws", lambda c: c.rate("host"), {"budget": 1})
            sched.pause(job.id)
            with self.assertRaises(WorkspaceBusy):
                sched.reset_workspace_budget("ws", 2)
            sched.cancel(job.id)
        sched.reset_workspace_budget("ws", 2)
        self.assertEqual(sched.stats()["workspace_budgets"]["ws"], {"used": 0, "limit": 2})

    def test_reset_budget_error_kinds_are_distinct(self):
        # An invalid budget VALUE must never be confused with a busy workspace: a bad
        # number is a ValueError even when idle; a busy workspace is WorkspaceBusy even
        # when the number given is perfectly valid.
        sched = self.scheduler(workers=1)
        with self.assertRaises(ValueError):
            sched.reset_workspace_budget("idle-ws", -1)
        self.assertNotIsInstance(ValueError(), WorkspaceBusy)  # sanity: distinct hierarchies
        entered, release = threading.Event(), threading.Event()

        def hold(c):
            c.rate("host")
            entered.set()
            release.wait(5)

        job = sched.submit("t", "busy-ws", hold, {"budget": 5})
        self.assertTrue(entered.wait(5), "job never reached RUNNING")
        with self.assertRaises(WorkspaceBusy):
            sched.reset_workspace_budget("busy-ws", 5)  # valid number, but workspace is busy
        release.set()
        self.assertTrue(wait_until(lambda: job.state == "DONE"))

    def test_manual_request_admitted_via_admit_request(self):
        # The exact gate server.do_send uses for Repeater/Intruder/curl/ACL/XSS — no
        # Job at all (job=None) — still enforces stop + rate + budget correctly.
        sched = Scheduler(workers=1, default_rate=1000.0, default_budget=3)
        self.addCleanup(sched.shutdown)
        sched.admit_request("ws", "host.test")
        sched.admit_request("ws", "host.test")
        sched.admit_request("ws", "host.test")
        with self.assertRaises(BudgetExhausted):
            sched.admit_request("ws", "host.test")
        self.assertEqual(sched.stats()["workspace_budgets"]["ws"], {"used": 3, "limit": 3})

    def test_manual_request_blocked_by_emergency_stop(self):
        sched = self.scheduler(workers=1)
        sched.emergency_stop()
        with self.assertRaises(SchedulerStopped):
            sched.admit_request("ws", "host.test")

    def test_manual_request_unblocks_immediately_on_emergency_stop(self):
        # A manual call blocked waiting for a rate-limit slot must not have to finish
        # its wait before Emergency Stop takes effect.
        sched = Scheduler(workers=1, default_rate=1.0)  # slow ceiling on purpose
        self.addCleanup(sched.shutdown)
        sched.admit_request("ws", "slow-host")  # drains the single burst token
        threading.Timer(0.1, sched.emergency_stop).start()
        t0 = time.monotonic()
        with self.assertRaises(SchedulerStopped):
            sched.admit_request("ws", "slow-host")  # would otherwise wait ~1s for a token
        self.assertLess(time.monotonic() - t0, 0.5, "Emergency Stop did not interrupt the wait")

    def test_reset_budget_refused_while_manual_request_in_flight(self):
        sched = self.scheduler(workers=1)
        sched.admit_request("ws", "host.test")  # admitted, not yet released -> in-flight
        with self.assertRaises(WorkspaceBusy):
            sched.reset_workspace_budget("ws", 10)
        sched.release_request("ws")
        sched.reset_workspace_budget("ws", 10)  # now idle -> succeeds
        self.assertEqual(sched.stats()["workspace_budgets"]["ws"]["limit"], 10)

    def test_reset_budget_refused_while_manual_request_waits_for_admission(self):
        sched = self.scheduler(workers=1)
        entered, release = threading.Event(), threading.Event()
        errors = []

        class DelayedToken:
            def take(self, cancel_event):
                entered.set()
                if not release.wait(3):
                    raise AssertionError("test did not release token wait")

        sched.limiter = lambda *args: DelayedToken()

        def request():
            try:
                sched.admit_request("ws", "host.test")
                sched.release_request("ws")
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=request)
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            with self.assertRaises(WorkspaceBusy):
                sched.reset_workspace_budget("ws", 10)
            # Independent idle workspaces remain resettable.
            sched.reset_workspace_budget("other", 10)
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        sched.reset_workspace_budget("ws", 10)
        self.assertEqual(sched._waiting, {})

    def test_stop_then_clear_cannot_revive_a_waiting_manual_request(self):
        sched = self.scheduler(workers=1)
        entered, release = threading.Event(), threading.Event()
        errors, admitted = [], []

        class DelayedToken:
            def take(self, cancel_event):
                # Simulate a token becoming available while its waiter is descheduled.
                entered.set()
                if not release.wait(3):
                    raise AssertionError("test did not release token wait")

        original_limiter = sched.limiter
        sched.limiter = lambda *args: DelayedToken()

        def request():
            try:
                sched.admit_request("ws", "host.test")
                admitted.append(True)
                sched.release_request("ws")
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=request)
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            sched.emergency_stop()
            sched.clear_stop()
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(admitted, [])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], SchedulerStopped)
        self.assertEqual(sched._waiting, {})
        self.assertEqual(sched._inflight, {})
        self.assertNotIn("ws", sched.stats()["workspace_budgets"])
        # Only an explicitly new call after clearing stop is admitted.
        sched.limiter = original_limiter
        sched.admit_request("ws", "host.test")
        sched.release_request("ws")
        self.assertEqual(sched.stats()["workspace_budgets"]["ws"]["used"], 1)

    def test_direct_manual_admission_validates_budget_and_cleans_failed_waits(self):
        sched = self.scheduler(workers=1)
        for value in (0, -1, True, 1.5, float("nan"), float("inf"), "bad"):
            with self.subTest(budget=value), self.assertRaises(ValueError):
                sched.admit_request("ws", "host.test", budget=value)
        with self.assertRaises(ValueError):
            sched.admit_request("ws", "")
        self.assertEqual(sched.stats()["workspace_budgets"], {})
        self.assertEqual(sched._waiting, {})
        self.assertEqual(sched._inflight, {})

    def test_manual_admission_respects_an_explicitly_reset_budget(self):
        sched = self.scheduler(workers=1)
        limit = sched.default_budget + 1
        sched.reset_workspace_budget("ws", limit)
        sched.admit_request("ws", "host.test")
        sched.release_request("ws")
        self.assertEqual(sched.stats()["workspace_budgets"]["ws"], {"used": 1, "limit": limit})

    def test_positive_integer_no_precision_loss_on_large_budget(self):
        # A value beyond float64's exact-integer range (2**53) must be validated and
        # stored EXACTLY, never silently rounded by an int->float->int round-trip.
        sched = self.scheduler(workers=1)
        huge = 9_007_199_254_740_993  # 2**53 + 1: the smallest int a float64 mangles
        sched.reset_workspace_budget("ws", huge)
        self.assertEqual(sched.stats()["workspace_budgets"]["ws"]["limit"], huge)
        with self.assertRaises(ValueError):
            sched.reset_workspace_budget("ws2", 5000.5)  # non-integer float still rejected


class FinalizationTests(unittest.TestCase):
    def test_committed_completion_cannot_be_cancelled_or_stopped(self):
        sched = Scheduler(workers=1)
        self.addCleanup(sched.shutdown)
        committed, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        durable = []

        def run(c):
            c.finalize(lambda: durable.append("complete"))
            committed.set()
            release.wait(2)

        job = sched.submit("t", "ws", run)
        self.assertTrue(committed.wait(1))
        self.assertFalse(sched.cancel(job.id))
        sched.emergency_stop()
        release.set()
        self.assertTrue(wait_until(lambda: job.state == "DONE"))
        self.assertEqual(durable, ["complete"])

    def test_completed_history_is_bounded(self):
        sched = Scheduler(workers=1, max_history=2)
        self.addCleanup(sched.shutdown)
        for _ in range(5):
            job = sched.submit("t", "ws", lambda c: None)
            self.assertTrue(wait_until(lambda: job.state == "DONE"))
        self.assertEqual(len(sched.jobs), 2)


class CollectSchedulerTests(unittest.TestCase):
    """Integration: /api/collect submission through the module scheduler."""

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="raven-sch-")
        os.chdir(self._tmp)
        self._saved = dict(server.STATE)
        self._probe = server._probe_host
        server.STATE["scope"] = Scope(include=["a.test", "*.a.test"], exclude=[], ports=[80, 443])
        server.use_workspace("sch")
        rid = server.STATE["store"].start("seed", {})
        for h in ("a.test", "b.a.test", "c.a.test"):
            server.STATE["store"].host(h, "seed", rid)
        server.STATE["store"].finish(rid, "complete")
        server.STATE["store"].commit()
        self._jobs = []

    def tearDown(self):
        for jid in self._jobs:
            server.SCHEDULER.cancel(jid)
        self.assertTrue(wait_until(lambda: all(server.SCHEDULER.get(jid)["state"] in
                                               ("DONE", "CANCELLED", "FAILED") for jid in self._jobs)))
        server._probe_host = self._probe
        os.chdir(self._cwd)
        server.STATE.clear()
        server.STATE.update(self._saved)

    def test_submit_collect_is_nonblocking_and_completes(self):
        server._probe_host = lambda host: {"status": 200, "title": "", "server": "", "scripts": [],
                                           "final_url": f"https://{host}/", "body_hash": "", "error": "", "elapsed_ms": 1}
        t0 = time.monotonic()
        res = server.submit_collect(passive=False, probe=True)
        submit_ms = (time.monotonic() - t0) * 1000
        self.assertLess(submit_ms, 200, "submit blocked instead of queueing")
        self.assertIn("job_id", res)
        self._jobs.append(res["job_id"])
        self.assertTrue(wait_until(lambda: server.SCHEDULER.get(res["job_id"])["state"] == "DONE"))
        # The run is persisted and complete.
        runs = server.STATE["store"].runs()
        self.assertTrue(any(r["mode"] == "collect" and r["state"] == "complete" for r in runs))

    def test_cancel_collect_marks_run_cancelled_no_replay(self):
        def slow(host):
            time.sleep(0.4)
            return {"status": 200, "title": "", "server": "", "scripts": [],
                    "final_url": f"https://{host}/", "body_hash": "", "error": "", "elapsed_ms": 400}
        server._probe_host = slow
        res = server.submit_collect(passive=False, probe=True, rate=2.0)
        jid = res["job_id"]
        self._jobs.append(jid)
        self.assertTrue(wait_until(lambda: server.SCHEDULER.get(jid)["state"] == "RUNNING"))
        time.sleep(0.3)
        self.assertTrue(server.SCHEDULER.cancel(jid))
        self.assertTrue(wait_until(lambda: server.SCHEDULER.get(jid)["state"] == "CANCELLED"))
        collect_runs = [r for r in server.STATE["store"].runs() if r["mode"] == "collect"]
        self.assertTrue(collect_runs, "collection run was not recorded")
        self.assertEqual(collect_runs[0]["state"], "cancelled", "cancelled run not marked cancelled")

    def test_interrupted_run_recovery(self):
        # Simulate a process killed mid-collection: a run left in 'running'.
        store = server.STATE["store"]
        store.start("collect", {})  # never finished
        self.assertTrue(any(r["state"] == "running" for r in store.runs()))
        # Reopening the workspace must recover it as 'interrupted' (not auto-replayed).
        server.use_workspace("sch")
        recovered = server.STATE["store"].runs()
        self.assertFalse(any(r["state"] == "running" for r in recovered))
        self.assertTrue(any(r["state"] == "interrupted" for r in recovered))


if __name__ == "__main__":
    unittest.main(verbosity=2)

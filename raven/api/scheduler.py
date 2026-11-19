"""Bounded, cooperative scheduler for RAVEN's active modules.

Every actual outbound attempt must call Control.rate immediately before dispatch.
Host limits are shared across ALL workspaces, with a burst of one. A host's lowest
requested rate remains in force until this scheduler is replaced. Request budgets
are cumulative per canonical workspace key for the scheduler's lifetime; submitting
another job or clearing Emergency Stop never replenishes them. The lowest budget
requested by a workspace remains in force until an explicit idle-workspace reset.

Cancellation prevents subsequent admissions and interrupts scheduler waits. It cannot
revoke a request already admitted or forcibly terminate an uncooperative job. Job
metadata and budget counters are process-local; persistent collection runs are stored
separately, and restart recovery must not automatically replay them.
"""
import math
import re
import threading
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _positive_number(value, name):
    if isinstance(value, bool):
        raise ValueError(f"{name} must be finite and positive")
    try:
        number = float(value)
    except (ValueError, TypeError, OverflowError):
        raise ValueError(f"{name} must be finite and positive") from None
    if not math.isfinite(number) or number <= 0:
        raise ValueError(f"{name} must be finite and positive")
    return number


def _positive_integer(value, name):
    # Never round-trip through float(): a float64 only represents integers exactly up
    # to 2**53, so a large-but-plausible budget (or a hostile one) would silently be
    # truncated to the wrong value instead of being validated. int/str inputs are
    # therefore checked as exact integers first; float is accepted only when it is
    # already an exact whole number (e.g. JSON `5000.0`).
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a positive integer")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        stripped = value.strip()
        if not re.fullmatch(r"[+]?\d+", stripped):
            raise ValueError(f"{name} must be a positive integer")
        number = int(stripped)
    elif isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            raise ValueError(f"{name} must be a positive integer")
        number = int(value)
    else:
        raise ValueError(f"{name} must be a positive integer")
    if number <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return number


class Cancelled(Exception):
    """The job was cancelled, stopped, shut down, or exhausted its budget."""


class SchedulerStopped(RuntimeError):
    """New work is not admitted while stopped or after shutdown."""


class QueueFull(RuntimeError):
    """The bounded pending queue, including paused pending jobs, is full."""


class BudgetExhausted(RuntimeError):
    """A manual (non-job) request hit its workspace's shared request budget."""


class WorkspaceBusy(RuntimeError):
    """An operation needs a workspace fully idle, but it has active or in-flight work.
    Kept distinct from a plain invalid-value ValueError so callers (and the API) can
    tell "the number you gave is bad" apart from "nothing is wrong with the number,
    but this isn't a safe moment" — see Scheduler.reset_workspace_budget."""


class TokenBucket:
    """Thread-safe token bucket. Cancellation is checked before every token grant."""

    def __init__(self, rate, capacity=None):
        self.rate = _positive_number(rate, "rate")
        self.capacity = _positive_integer(capacity if capacity is not None else max(1, int(self.rate)), "capacity")
        self.tokens = float(self.capacity)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def tighten(self, rate):
        """A later caller can reduce the shared ceiling, never raise it."""
        rate = _positive_number(rate, "rate")
        with self.lock:
            if rate < self.rate:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
                self.last = now
                self.rate = rate

    def take(self, cancel_event=None):
        while True:
            with self.lock:
                if cancel_event is not None and cancel_event.is_set():
                    raise Cancelled()
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
                self.last = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                wait = (1 - self.tokens) / self.rate
            if cancel_event is not None:
                if cancel_event.wait(min(wait, 0.2)):
                    raise Cancelled()
            else:
                time.sleep(min(wait, 0.2))


class Job:
    def __init__(self, jid, kind, workspace, meta, lock=None):
        self.id = jid
        self.kind = kind
        self.workspace = workspace
        self.meta = dict(meta or {})
        self.workspace_key = self.meta.get("workspace_key", workspace)
        self.state = "QUEUED"
        self.created = _now()
        self.started = None
        self.finished = None
        self.progress = []
        self.error = None
        self.result = None
        self.requests = 0
        self.cancel_event = threading.Event()
        self.pause_event = threading.Event()
        self.fn = None
        self._executing = False
        self._completion_committed = False
        self._lock = lock or threading.RLock()

    def to_dict(self):
        with self._lock:
            return {
                "id": self.id, "kind": self.kind, "workspace": self.workspace,
                "state": self.state, "created": self.created, "started": self.started,
                "finished": self.finished, "progress": self.progress[-60:], "error": self.error,
                "requests": self.requests,
                "meta": {k: v for k, v in self.meta.items() if k not in ("fn", "workspace_key")},
            }


class Control:
    """Cooperative checkpoints and per-outbound-attempt admission."""

    def __init__(self, job, scheduler):
        self._job = job
        self.job = job  # public: lets the central send path (server.do_send) find the
                         # owning Job via the ContextVar-carried Control, so ANY real
                         # outbound attempt — scheduled or manual — is admitted through
                         # the exact same Scheduler.admit_request gate.
        self._sched = scheduler

    def log(self, message):
        with self._sched.lock:
            self._job.progress.append(_now() + "  " + str(message))
            del self._job.progress[:-60]

    def _check_locked(self):
        if self._job.cancel_event.is_set() or self._sched.stopped.is_set() or not self._sched._running:
            raise Cancelled()

    def check(self):
        """Block while paused and recheck cancellation on every wakeup."""
        with self._sched._changed:
            while True:
                self._check_locked()
                if not self._job.pause_event.is_set():
                    return
                self._sched._changed.wait()

    def rate(self, host):
        """Admit one actual attempt, including fallbacks and redirects. Thin wrapper
        kept for callers that already hold a Control (e.g. the crt.sh passive lookup)
        — delegates to the exact same gate every real send uses (see admit_request)."""
        self._sched.admit_request(self._job.workspace_key, host, job=self._job)

    def finalize(self, callback):
        """Commit durable completion atomically against cancellation, then return.

        Use this as the job's LAST operation. Once the callback succeeds, a later
        cancel/stop cannot turn an already committed successful run into CANCELLED.
        The callback must be short and must not dispatch requests or scheduler jobs.
        """
        while True:
            self.check()
            with self._sched._changed:
                self._check_locked()
                if self._job.pause_event.is_set():
                    continue
                # Linearization point (unchanged): from here a cancel/stop/pause no
                # longer applies to this job. The durable write itself now runs OUTSIDE
                # the global scheduler lock — it used to hold it for the whole SQLite
                # commit (up to the 5 s busy timeout), blocking Emergency Stop, cancel,
                # listing and every other job's admission.
                self._job._completion_committed = True
            try:
                return callback()
            except BaseException:
                with self._sched._changed:
                    self._job._completion_committed = False  # not committed after all
                raise


class Scheduler:
    def __init__(self, workers=3, default_rate=2.0, default_budget=5000, max_pending=256, max_history=1000,
                 on_state_change=None):
        self.workers = _positive_integer(workers, "workers")
        self.default_rate = _positive_number(default_rate, "rate")
        self.default_budget = _positive_integer(default_budget, "budget")
        self.max_pending = _positive_integer(max_pending, "max_pending")
        self.max_history = _positive_integer(max_history, "max_history")
        # Optional observation-only Job state-change callback, signature
        # (job, old_state, new_state). Default None = no behaviour change. It is the
        # clean seam SchedulerTaskBridge registers to mirror Job → Task state WITHOUT
        # the scheduler importing the task model (dependency: engine ← bridge → model).
        # It is best-effort: fired outside admission math, never affects scheduling,
        # rate, budget, cancellation, or Emergency Stop, and its exceptions are swallowed.
        self.on_state_change = on_state_change
        self.jobs = {}
        self.lock = threading.RLock()
        self._changed = threading.Condition(self.lock)
        self._pending = deque()
        self.stopped = threading.Event()
        # A stop permanently cancels callers already waiting for admission. Clearing
        # the UI stop flag creates a new generation; it must not revive old waits.
        self._manual_cancel = threading.Event()
        self._limiters = {}
        self._budgets = {}
        self._waiting = {}  # manual calls awaiting rate/budget admission, by workspace
        self._inflight = {}  # workspace_key -> count of requests currently admitted
                              # but not yet finished; guards reset_workspace_budget.
        self._running = True
        self._pool = [threading.Thread(target=self._worker, daemon=True) for _ in range(self.workers)]
        for thread in self._pool:
            thread.start()

    def _fire_state_change(self, job, old_state, new_state):
        """Fire the optional Job state-change callback. MUST be called with the
        scheduler lock NOT held (callbacks may do a short DB write) and never raise —
        a mirror failure must never disturb scheduling/admission/Emergency Stop."""
        cb = self.on_state_change
        if cb is None or old_state == new_state:
            return
        try:
            cb(job, old_state, new_state)
        except Exception:  # noqa: BLE001 — observation only; isolate mirror failures
            pass

    def limiter(self, workspace, host, rate=None):
        # workspace remains an argument for compatibility; the ceiling is global.
        rate = _positive_number(self.default_rate if rate is None else rate, "rate")
        key = str(host).strip().lower().rstrip(".")
        if not key:
            raise ValueError("host must not be empty")
        with self.lock:
            if key not in self._limiters:
                self._limiters[key] = TokenBucket(rate, capacity=1)
            else:
                self._limiters[key].tighten(rate)
            return self._limiters[key]

    def submit(self, kind, workspace, fn, meta=None):
        settings = dict(meta or {})
        settings["rate"] = _positive_number(settings.get("rate", self.default_rate), "rate")
        settings["budget"] = _positive_integer(settings.get("budget", self.default_budget), "budget")
        if not callable(fn):
            raise ValueError("job function must be callable")
        with self._changed:
            if self.stopped.is_set() or not self._running:
                raise SchedulerStopped("scheduler is stopped")
            if len(self._pending) >= self.max_pending:
                raise QueueFull("scheduler pending queue is full")
            self._prune_history_locked()
            job = Job(uuid.uuid4().hex[:12], kind, workspace, settings, self.lock)
            ledger = self._budgets.setdefault(job.workspace_key, {"used": 0, "limit": settings["budget"]})
            ledger["limit"] = min(ledger["limit"], settings["budget"])
            job.fn = fn
            self.jobs[job.id] = job
            self._pending.append(job.id)
            self._changed.notify_all()
            return job

    def _worker(self):
        while True:
            with self._changed:
                while True:
                    if not self._running:
                        return
                    job = next((self.jobs[jid] for jid in self._pending if self.jobs[jid].state == "QUEUED"), None)
                    if job is not None:
                        self._pending.remove(job.id)
                        job._executing = True
                        job.state = "RUNNING"
                        job.started = _now()
                        break
                    self._changed.wait()
            # Mirror QUEUED → RUNNING outside the lock (observation only).
            self._fire_state_change(job, "QUEUED", "RUNNING")
            result, error, state = None, None, "DONE"
            try:
                control = Control(job, self)
                control.check()
                result = job.fn(control)
            except Cancelled:
                state = "CANCELLED"
            except Exception as exc:  # noqa: BLE001 — preserve job failures
                state, error = "FAILED", f"{type(exc).__name__}: {exc}"
            finally:
                with self._changed:
                    # Cancellation wins even if the final request returned normally.
                    if not job._completion_committed and (job.cancel_event.is_set() or self.stopped.is_set() or not self._running):
                        state = "CANCELLED"
                    job.result, job.error, job.state = result, error, state
                    job._executing = False
                    job.pause_event.clear()
                    job.finished = _now()
                    final_state = job.state
                    self._prune_history_locked()
                    self._changed.notify_all()
                # The worker 'finally' is the single authoritative terminal-state mirror
                # point (fired after the lock is released). DONE→COMPLETED etc.
                self._fire_state_change(job, "RUNNING", final_state)

    def _prune_history_locked(self):
        terminal = [j.id for j in self.jobs.values() if j.state in ("DONE", "FAILED", "CANCELLED") and not j._executing]
        for jid in terminal[:-self.max_history]:
            del self.jobs[jid]

    def _cancel_locked(self, job):
        if job.state not in ("QUEUED", "RUNNING", "PAUSED") or job._completion_committed:
            return False
        job.cancel_event.set()
        job.pause_event.clear()
        if not job._executing:
            self._pending.remove(job.id)
            job.state, job.finished = "CANCELLED", _now()
        self._changed.notify_all()
        return True

    def cancel(self, jid):
        fire = None
        with self._changed:
            job = self.jobs.get(jid)
            if not job:
                return False
            pre = job.state
            acted = self._cancel_locked(job)
            # _cancel_locked only sets CANCELLED synchronously for a non-executing job;
            # an executing job's terminal mirror is fired by the worker 'finally'.
            if acted and job.state == "CANCELLED" and pre != "CANCELLED":
                fire = (job, pre, "CANCELLED")
        if fire:
            self._fire_state_change(*fire)
        return acted

    def pause(self, jid):
        fire = None
        with self._changed:
            job = self.jobs.get(jid)
            if job and job.state in ("QUEUED", "RUNNING") and not job.cancel_event.is_set() and not job._completion_committed:
                pre = job.state
                job.pause_event.set()
                job.state = "PAUSED"
                self._changed.notify_all()
                fire = (job, pre, "PAUSED")
        if fire:
            self._fire_state_change(*fire)
        return fire is not None

    def resume(self, jid):
        fire = None
        with self._changed:
            job = self.jobs.get(jid)
            if job and job.state == "PAUSED" and not job.cancel_event.is_set() and self._running and not self.stopped.is_set():
                pre = job.state
                job.pause_event.clear()
                job.state = "RUNNING" if job._executing else "QUEUED"
                self._changed.notify_all()
                fire = (job, pre, job.state)
        if fire:
            self._fire_state_change(*fire)
        return fire is not None

    def emergency_stop(self):
        """Atomically reject submissions and cancel queued and executing jobs."""
        fires = []
        with self._changed:
            self.stopped.set()
            self._manual_cancel.set()
            for job in self.jobs.values():
                pre = job.state
                if self._cancel_locked(job) and job.state == "CANCELLED" and pre != "CANCELLED":
                    fires.append((job, pre, "CANCELLED"))
            self._prune_history_locked()
            self._changed.notify_all()
        # Mirror the cancel sweep to owned Tasks after releasing the lock so the UI
        # never shows stale RUNNING. Executing jobs mirror terminal via the worker.
        for fire in fires:
            self._fire_state_change(*fire)
        return True

    def clear_stop(self):
        with self._changed:
            if not self._running:
                raise SchedulerStopped("scheduler is shut down")
            if self.stopped.is_set():
                self._manual_cancel = threading.Event()
            self.stopped.clear()
            self._changed.notify_all()

    def request_generation(self):
        """Snapshot cancellation before request preparation, including DNS."""
        with self._changed:
            return self._manual_cancel

    def admit_request(self, workspace_key, host, job=None, rate=None, budget=None, generation=None):
        """The ONE gate for every real outbound attempt anywhere in the app: Collection
        (via Control.rate), and — through server.do_send — Repeater, Intruder, curl,
        every Access Control identity plus its anonymous baseline, and the XSS Lab.
        Enforces, atomically and race-free, the global Emergency Stop, the shared
        per-host rate ceiling, and the shared per-workspace request budget.

        `job` is the owning scheduled Job when called from Collection (adds pause-
        awareness and per-job accounting via Control.rate); manual callers pass
        job=None and are gated by the exact same limits, tied to Emergency Stop
        directly (waiting for a rate-limit slot is itself cancelled the instant
        Emergency Stop fires). Raises Cancelled for a job-owned call, or the
        friendlier SchedulerStopped/BudgetExhausted for a manual call, so server.py
        can turn either into a plain {"blocked": true, "error": ...} response.
        Counts admitted attempts only, including ones that go on to fail over the
        network or an HTTPS->HTTP fallback — each is its own admitted attempt."""
        eff_rate = (job.meta.get("rate") if job is not None else None) if rate is None else rate
        eff_budget = (job.meta.get("budget") if job is not None else None) if budget is None else budget
        eff_rate = _positive_number(self.default_rate if eff_rate is None else eff_rate, "rate")
        if eff_budget is not None:
            eff_budget = _positive_integer(eff_budget, "budget")
        if job is not None:
            return self._wait_and_admit(workspace_key, host, job, job.cancel_event, eff_rate, eff_budget)
        with self._changed:
            if (self.stopped.is_set() or not self._running
                    or generation is not None and generation is not self._manual_cancel):
                raise SchedulerStopped("request scheduler is stopped")
            cancel_event = self._manual_cancel
            self._waiting[workspace_key] = self._waiting.get(workspace_key, 0) + 1
        try:
            return self._wait_and_admit(workspace_key, host, None, cancel_event, eff_rate, eff_budget)
        finally:
            with self._changed:
                self._waiting[workspace_key] -= 1
                if not self._waiting[workspace_key]:
                    del self._waiting[workspace_key]
                self._changed.notify_all()

    def _wait_and_admit(self, workspace_key, host, job, cancel_event, eff_rate, eff_budget):
        while True:
            if job is not None:
                with self._changed:
                    while True:
                        if job.cancel_event.is_set() or self.stopped.is_set() or not self._running:
                            raise Cancelled()
                        if not job.pause_event.is_set():
                            break
                        self._changed.wait()
            elif cancel_event.is_set() or self.stopped.is_set() or not self._running:
                raise SchedulerStopped("request scheduler is stopped")
            try:
                self.limiter(workspace_key, host, eff_rate).take(cancel_event)
            except Cancelled:
                raise (Cancelled() if job is not None else SchedulerStopped(
                    "request scheduler is stopped")) from None
            with self._changed:
                if job is not None:
                    if job.cancel_event.is_set() or self.stopped.is_set() or not self._running:
                        raise Cancelled()
                    if job.pause_event.is_set():
                        continue  # token acquired but paused meanwhile -> discard, retry
                elif cancel_event.is_set() or self.stopped.is_set() or not self._running:
                    raise SchedulerStopped("request scheduler is stopped")
                ledger = self._budgets.setdefault(workspace_key, {
                    "used": 0, "limit": self.default_budget if eff_budget is None else eff_budget})
                if eff_budget is not None:
                    ledger["limit"] = min(ledger["limit"], eff_budget)
                if ledger["used"] >= ledger["limit"]:
                    msg = f"workspace request budget reached ({ledger['limit']})"
                    if job is not None:
                        self.log_job(job, msg)
                        raise Cancelled(msg)
                    raise BudgetExhausted(msg)
                ledger["used"] += 1
                # In-flight tracking is only needed for MANUAL (job=None) calls: a
                # scheduled job is already visible to reset_workspace_budget via its
                # own job.state, so double-tracking it here would never be released
                # for job-owned calls that don't go through server.do_send at all
                # (e.g. the crt.sh lookup, gated via Control.rate) and would wrongly
                # leave the workspace permanently "busy" after that job finished.
                if job is None:
                    self._inflight[workspace_key] = self._inflight.get(workspace_key, 0) + 1
                else:
                    job.requests += 1
                return

    def log_job(self, job, message):
        with self._changed:
            job.progress.append(_now() + "  " + str(message))
            del job.progress[:-60]

    def release_request(self, workspace_key):
        """Must be called exactly once for every admit_request that returned
        successfully, when that request finishes (success OR failure) — releases the
        in-flight count reset_workspace_budget checks before allowing a reset."""
        with self._changed:
            if self._inflight.get(workspace_key, 0) > 0:
                self._inflight[workspace_key] -= 1
                if not self._inflight[workspace_key]:
                    del self._inflight[workspace_key]
            self._changed.notify_all()

    def reset_workspace_budget(self, workspace_key, budget=None):
        """Explicit new allowance for one workspace; the caller authorizes it. Refused
        while that workspace has an active/queued/paused job OR a waiting/in-flight manual
        request (Repeater/Intruder/curl/ACL/XSS) — WorkspaceBusy, distinct from a
        plain ValueError for a bad budget number, so the API can tell the two apart.
        Never touches Emergency Stop and never resurrects a cancelled job."""
        new_limit = _positive_integer(self.default_budget if budget is None else budget, "budget")
        with self.lock:
            active_jobs = any(j.workspace_key == workspace_key and j.state in ("QUEUED", "RUNNING", "PAUSED")
                               for j in self.jobs.values())
            in_flight = self._inflight.get(workspace_key, 0) > 0
            waiting = self._waiting.get(workspace_key, 0) > 0
            if active_jobs or in_flight or waiting:
                raise WorkspaceBusy(
                    "cannot reset budget: this workspace has active jobs or waiting/in-flight requests")
            self._budgets[workspace_key] = {"used": 0, "limit": new_limit}

    def shutdown(self, wait=True, timeout=2.0):
        """Cancel jobs and wake all scheduler waits; wait at most timeout in total."""
        with self._changed:
            self._running = False
            self.emergency_stop()
            self._changed.notify_all()
        if wait:
            deadline = time.monotonic() + max(0, timeout)
            for thread in self._pool:
                if thread is not threading.current_thread():
                    thread.join(timeout=max(0, deadline - time.monotonic()))
        return not any(thread.is_alive() for thread in self._pool)

    def get(self, jid):
        with self.lock:
            job = self.jobs.get(jid)
            return job.to_dict() if job else None

    def list(self, limit=100):
        with self.lock:
            return [job.to_dict() for job in list(self.jobs.values())[-limit:][::-1]]

    def stats(self):
        with self.lock:
            counts = Counter(job.state for job in self.jobs.values())
            return {"workers": self.workers, "queued": len(self._pending), "max_pending": self.max_pending,
                    "max_history": self.max_history,
                    "jobs": len(self.jobs), "by_state": dict(counts),
                    "emergency_stopped": self.stopped.is_set(),
                    "workspace_budgets": {key: dict(value) for key, value in self._budgets.items()}}

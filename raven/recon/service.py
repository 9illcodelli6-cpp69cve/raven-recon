"""ReconService — the ONE canonical reconnaissance service (Wave 7, A7-RECON).

Extracted from the V7 server collection (``server.py`` ``submit_collect`` /
``do_collect`` / ``_collect_in_context``, server.py:1339-1465) per RECON_ARCHITECTURE §2
and CANONICAL_ARCHITECTURE §1 row 13: the only HTTP-reachable, scheduler-governed,
IP-pinned collection path. Both entry points converge here —

  * the researcher-driven loopback HTTP route (``POST /api/collect`` → ``submit_collect``
    → ``ReconService.submit``), and
  * the structured ``ToolDispatcher`` path (``recon.collect`` tool → handler →
    ``ReconService.submit``), which carries actor provenance for Agent/Program mode.

Behaviour is byte-identical to the inline server version: the scheduler stays the sole
admission / rate / budget / Emergency-Stop gate (``server.SCHEDULER``), the pinned sender
stays the sole egress (``server.do_send``), the ``Store`` stays the sole persistence, and
the ``_ACTIVE_RUNS`` bookkeeping + cancellation/finalize linearization are preserved. All
collaborators resolve on the ``server`` module at call time (same rationale as
``collectors.py`` / ``runtime/services/sender.py``) so the monkeypatch surface and the
hot-swappable ``server.SCHEDULER`` keep working.

The optional ``bridge`` on ``submit()`` is the ``runtime.scheduler_bridge.SchedulerTaskBridge``
seam: when supplied, the collection is submitted through it so a durable Task of record is
created alongside the scheduler Job (no second scheduler, no second admission gate — the
bridge only joins the one scheduler to the one TaskRegistry). When absent (the live route
today), ``submit`` goes straight to ``server.SCHEDULER`` — identical to the original
``submit_collect`` — which is what keeps ``recon_jobs`` (= ``SCHEDULER.list()``) populated.
"""
from __future__ import annotations

from .collectors import ActiveProbeCollector, ExternalToolCollector, PassiveCrtShCollector

# Same Cancelled class the scheduler raises and server catches (server imports it as
# ``_CancelledSignal``). Importing it here binds the identical object.
from ..api.scheduler import Cancelled as _CancelledSignal


class ReconService:
    """The one canonical recon service. Stateless facade over the workspace ``Store``,
    ``Scope``, the shared ``SCHEDULER`` and the pinned sender — every live dependency is
    resolved off ``server`` at call time, so one shared instance is safe."""

    def __init__(self, *, event_bus=None, process_executor=None, external_tools=False):
        self._event_bus = event_bus
        self._external_default = bool(external_tools)
        self._passive = PassiveCrtShCollector()
        self._probe = ActiveProbeCollector()
        self._external = ExternalToolCollector(enabled=bool(external_tools),
                                               executor=process_executor)

    # ── submit (non-blocking enqueue) ───────────────────────────────────────────
    def submit(self, passive=True, probe=True, *, external_tools=None, rate=None,
               budget=None, bridge=None, origin=None, context=None, title=None,
               discover=False):
        """Queue a collection on the central scheduler and return ``{job_id, state}``.

        Non-blocking — identical contract to the original ``server.submit_collect``: the
        HTTP request returns immediately with a ``job_id`` the UI polls. When ``bridge`` is
        given the Job is submitted through the SchedulerTaskBridge (durable Task created
        too); otherwise straight through ``server.SCHEDULER``.
        """
        if not isinstance(passive, bool) or not isinstance(probe, bool) \
                or not isinstance(discover, bool):
            raise ValueError("passive, probe and discover must be booleans")
        context = context or _server._capture_context()
        if context.configuration_error:
            raise ValueError(context.configuration_error)
        ext = self._external_default if external_tools is None else bool(external_tools)
        meta = {"passive": passive, "probe": probe,
                "rate": rate if rate is not None else _server.DEFAULT_RATE,
                "budget": budget if budget is not None else _server.DEFAULT_BUDGET}
        meta["workspace_key"] = context.workspace_key
        if ext:
            meta["external_tools"] = True
        if discover and probe:
            # Opt-in endpoint discovery after each responding probe (links, robots.txt,
            # sitemaps, JS). Read by ActiveProbeCollector via the job control; absent
            # → the historical probe-only behaviour and request count.
            meta["discover"] = True

        def _fn(control):
            return _server.do_collect(bool(passive), bool(probe), control,
                                      context=context, external_tools=ext)

        if bridge is not None:
            from ..runtime.execution import ActorKind
            actor = origin or ActorKind.RESEARCHER
            _task, job = bridge.submit(
                "collect", context.name, _fn,
                title=title or f"Recon collection — {context.name}",
                origin=actor, workspace_id=context.workspace_key, meta=meta,
            )
        else:
            job = _server.SCHEDULER.submit("collect", context.name, _fn, meta)
        return {"job_id": job.id, "state": job.state}

    # ── run (worker body; == do_collect) ────────────────────────────────────────
    def run(self, passive=True, probe=True, control=None, context=None,
            *, external_tools=None):
        """Bind all storage and transport calls to the workspace captured at submission,
        then run the collection. Mirrors ``server.do_collect``."""
        context = context or _server._capture_context()
        context_token = _server._REQUEST_CONTEXT.set(context)
        control_token = _server._REQUEST_CONTROL.set(control)
        try:
            return self.run_in_context(passive, probe, control, context,
                                       external_tools=external_tools)
        finally:
            _server._REQUEST_CONTROL.reset(control_token)
            _server._REQUEST_CONTEXT.reset(context_token)

    def run_in_context(self, passive, probe, control, context, *, external_tools=None):
        """The ``_collect_in_context`` body, preserved verbatim in structure.

        ``control`` (from the scheduler) enforces per-host rate limits, the request budget,
        pause and cancellation, and records progress. When cancelled mid-run the partial
        results already written are kept and the run is marked 'cancelled' — no
        state-changing work is auto-replayed. Called with control=None (tests/CLI) it runs
        unthrottled to completion. External tools are OFF unless explicitly enabled AND the
        run is unscheduled (external traffic cannot be budgeted by the scheduler)."""
        ctl = control or _server._NoControl()
        if context.configuration_error:
            raise ValueError(context.configuration_error)
        store, sc = context.store, context.scope
        ext = self._external_default if external_tools is None else bool(external_tools)
        external = self._external
        if external_tools is not None and bool(external_tools) != external.enabled:
            external = ExternalToolCollector(enabled=bool(external_tools),
                                             executor=self._external.executor)
        scheduled = control is not None
        ctl.check()
        with _server._LOCK:
            run_id = store.start("collect", {"headers": {}})
            _server._ACTIVE_RUNS.setdefault(context.workspace_key, set()).add(run_id)
        logs = []
        cancelled = False
        roots = [r for r in sc.include if not r.startswith("*.")]
        try:
            for root in roots:
                store.host(root, "seed", run_id)
            store.commit()  # never hold a SQLite write transaction across network waits
            if passive:
                for root in roots:
                    self._passive.collect_root(root, scope=sc, store=store,
                                                run_id=run_id, ctl=ctl, logs=logs)
                    external.collect_root(root, scope=sc, store=store, run_id=run_id,
                                          ctl=ctl, logs=logs, scheduled=scheduled)
            if probe:
                self._probe.collect(scope=sc, store=store, run_id=run_id, ctl=ctl, logs=logs)
            ctl.check()
            result = {"run_id": run_id, "logs": logs, "assets": len(store.assets()),
                      "cancelled": False}
            self._emit_progress(context, run_id, logs)
            # Linearize the durable completion with cancellation: a late cancellation
            # cannot relabel a successfully committed run as CANCELLED in the Task Center.
            ctl.finalize(lambda: store.finish(run_id, "complete", "; ".join(logs)))
        except _CancelledSignal:
            cancelled = True
            logs.append("collection cancelled — partial results kept")
            ctl.log("cancelled by request; no operations replayed")
            store.finish(run_id, "cancelled", "; ".join(logs))
        except Exception:
            store.finish(run_id, "failed", "collection failed; partial results kept")
            raise
        finally:
            with _server._LOCK:
                if run_id in _server._ACTIVE_RUNS.get(context.workspace_key, ()):
                    _server._ACTIVE_RUNS[context.workspace_key].discard(run_id)
                    if not _server._ACTIVE_RUNS[context.workspace_key]:
                        del _server._ACTIVE_RUNS[context.workspace_key]
        if cancelled:
            result = {"run_id": run_id, "logs": logs, "assets": len(store.assets()),
                      "cancelled": True}
            raise _CancelledSignal(result)  # let the scheduler mark the job CANCELLED
        return result

    # ── events (no-op without a bus — CLI/tests) ────────────────────────────────
    def _emit_progress(self, context, run_id, logs):
        if self._event_bus is None:
            return
        try:
            from ..runtime.events import EventType
            self._event_bus.publish(
                EventType.TASK_PROGRESS,
                {"run_id": run_id, "assets": None, "logs": logs[-10:]},
                workspace_id=context.workspace_key, source="recon",
            )
        except Exception:
            pass


# Circular import placed AFTER the definitions above (identical to collectors.py /
# runtime/services/sender.py) so every `_server.<name>` lookup happens at call time.
import raven.api.server as _server  # noqa: E402

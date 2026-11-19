"""ReconService extraction tests (Wave 7, A7-RECON).

Proves the ONE canonical recon engine (raven/recon):
  * submit() returns {job_id, state} and enqueues on the ONE scheduler;
  * run() honours a Control's check()/finalize() and keeps partial results on cancel;
  * collectors: crt.sh scope-filters, probe records + extracts in-scope scripts,
    external tools stay OFF under the scheduler and route through a ProcessExecutor
    (never a raw subprocess) when enabled;
  * the recon.collect tool dispatches for real (schema + capability gated);
  * event emission on a run; no bus → silent no-op;
  * research_engine is DEPRECATED but importable.

THE end-to-end proof — ``test_route_collection_runs_against_loopback_and_appears_in_recon_jobs``
and ``test_submit_via_bridge_creates_durable_task_and_runs_loopback`` — drive a REAL
collection through submit_collect / the scheduler bridge against a REAL HTTP server on
127.0.0.1. LOOPBACK/local fixtures only; crt.sh is stubbed; NO external network (directive
§64). The pinned sender's physical destination is redirected to the fixture's ephemeral
port, so scope → _pick_public_ip → SCHEDULER.admit_request → real loopback HTTP → store is
all exercised unchanged.
"""
import http.server
import os
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
import warnings
from unittest.mock import Mock, patch

from raven.api import server
from raven.api.scheduler import Scheduler, Cancelled
from raven.recon import (
    ReconService, PassiveCrtShCollector, ActiveProbeCollector, ExternalToolCollector,
    register_recon_tools, RECON_COLLECT,
)
from raven.recon import collectors as _collectors
from raven.runtime.tools import ToolRegistry, ToolDispatcher, ToolInvocation, ToolStatus
from raven.runtime.execution import ActorKind
from raven.runtime.events import EventBus, EventType


def wait_until(pred, timeout=6.0, interval=0.01):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(interval)
    return pred()


class _LoopbackFixture:
    """A real HTTP server on 127.0.0.1:<ephemeral> serving one HTML page."""
    HTML = (b'<html><head><title>Loopback Fixture</title>'
            b'<script src="/app.js"></script></head><body>ok</body></html>')

    def __enter__(self):
        html = self.HTML

        class _H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


class FakeControl:
    """Records the Control protocol calls the service/collectors make."""
    def __init__(self, cancel_after=None):
        self.checks = 0
        self.rates = []
        self.logs = []
        self.finalized = False
        self.job = None  # do_send reads ctl.job; None => treated as a manual request
        self._cancel_after = cancel_after

    def check(self):
        self.checks += 1
        if self._cancel_after is not None and self.checks > self._cancel_after:
            raise Cancelled()

    def rate(self, host):
        self.rates.append(host)

    def log(self, message):
        self.logs.append(str(message))

    def finalize(self, callback):
        self.finalized = True
        callback()


class ReconBase(unittest.TestCase):
    """Isolated tmp workspace + a fresh scheduler + a real loopback HTTP fixture."""

    def setUp(self):
        self._prev_state = dict(server.STATE)
        self._prev_sched = server.SCHEDULER
        self._prev_cwd = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory(prefix="raven-recon-", ignore_cleanup_errors=True)
        os.chdir(self.tmp.name)
        self.sched = Scheduler(workers=1, default_rate=1000)
        server.SCHEDULER = self.sched
        self.fix = _LoopbackFixture().__enter__()
        server.set_scope({"name": "loop", "include": ["127.0.0.1"], "exclude": [],
                          "ports": [80], "allow_private": True})
        # Redirect the pinned sender's physical destination to the fixture's ephemeral
        # port. scope / _pick_public_ip / SCHEDULER.admit_request all stay REAL — only the
        # TCP port the (already-pinned, loopback) connection lands on is the fixture's.
        fixture_port = self.fix.port
        base = server._PinnedHTTPConnection

        class _FixturePin(base):
            def connect(self):
                self.sock = socket.create_connection(("127.0.0.1", fixture_port), self.timeout)

        self._pin = patch.object(server, "_PinnedHTTPConnection", _FixturePin)
        self._pin.start()
        # Never touch the real crt.sh in any test by default.
        self._crtsh = patch.object(server, "_passive_crtsh", return_value=[])
        self._crtsh.start()

    def tearDown(self):
        self._crtsh.stop()
        self._pin.stop()
        self.sched.emergency_stop()
        self.sched.shutdown(wait=True)
        self.fix.__exit__(None, None, None)
        store = server.STATE.get("store")
        if store is not None:
            try:
                store.close()
            except Exception:
                pass
        # Drop the lazily-created task-registry singleton so it neither pins the tmp DB
        # file (Windows) nor leaks a stale connection into later tests; it is recreated
        # lazily on the next access against that test's own cwd/DATA_ROOT.
        reg = getattr(server, "_TASK_REGISTRY", None)
        if reg is not None:
            try:
                reg._db.close()
            except Exception:
                pass
            server._TASK_REGISTRY = None
        server.STATE.clear()
        server.STATE.update(self._prev_state)
        server.SCHEDULER = self._prev_sched
        os.chdir(self._prev_cwd)
        self.tmp.cleanup()


# ── END-TO-END PROOF: UI-triggered recon runs against a loopback fixture ─────────

class EndToEndLoopbackTests(ReconBase):
    def test_route_collection_runs_against_loopback_and_appears_in_recon_jobs(self):
        # submit_collect is EXACTLY what the POST /api/collect route calls (startRecon()).
        job = server.submit_collect(passive=False, probe=True)
        jid = job["job_id"]
        self.assertEqual(job["state"], "QUEUED")
        # The job shows up in recon_jobs — the same list loadRecon() now renders.
        recon_jobs = server.api_tasks_list()[0]["recon_jobs"]
        self.assertIn(jid, [j["id"] for j in recon_jobs])
        # It actually RUNS to completion against the loopback fixture.
        self.assertTrue(wait_until(lambda: self.sched.get(jid)["state"] == "DONE"),
                        self.sched.get(jid))
        store = server.STATE["store"]
        asset = next(a for a in store.assets() if a["host"] == "127.0.0.1")
        self.assertEqual(asset["probe"]["status"], 200)
        self.assertEqual(asset["probe"]["title"], "Loopback Fixture")
        self.assertTrue(any(r["mode"] == "collect" and r["state"] == "complete"
                            for r in store.runs()))

    def test_submit_via_bridge_creates_durable_task_and_runs_loopback(self):
        from raven.runtime.tasks import TaskRegistry, TaskStatus
        from raven.runtime.execution import ExecutionStore
        from raven.runtime.scheduler_bridge import SchedulerTaskBridge
        db = sqlite3.connect(":memory:", check_same_thread=False)
        db.row_factory = sqlite3.Row
        reg = TaskRegistry(db)
        es = ExecutionStore(db)
        bridge = SchedulerTaskBridge(self.sched, reg, es, default_actor=ActorKind.RESEARCHER)
        try:
            res = ReconService().submit(passive=False, probe=True, bridge=bridge)
            jid = res["job_id"]
            self.assertIn(jid, [j["id"] for j in self.sched.list()])
            self.assertTrue(wait_until(lambda: self.sched.get(jid)["state"] == "DONE"))
            # A durable Task of record was created and mirrored to COMPLETED.
            tasks = reg.list_all(limit=10)
            self.assertEqual(len(tasks), 1)
            self.assertEqual(tasks[0].origin, ActorKind.RESEARCHER)
            self.assertTrue(wait_until(
                lambda: reg.list_all(limit=10)[0].status == TaskStatus.COMPLETED))
            # And it really hit the loopback fixture.
            store = server.STATE["store"]
            asset = next(a for a in store.assets() if a["host"] == "127.0.0.1")
            self.assertEqual(asset["probe"]["status"], 200)
        finally:
            db.close()


# ── ReconService submit/run unit ─────────────────────────────────────────────────

class ReconServiceUnitTests(ReconBase):
    def test_submit_returns_descriptor_and_enqueues(self):
        res = ReconService().submit(passive=True, probe=False)
        self.assertIn("job_id", res)
        self.assertIn("state", res)
        self.assertIn(res["job_id"], [j["id"] for j in self.sched.list()])
        self.assertTrue(wait_until(lambda: self.sched.get(res["job_id"])["state"] == "DONE"))

    def test_submit_rejects_non_boolean(self):
        with self.assertRaises(ValueError):
            ReconService().submit(passive="yes", probe=True)

    def test_run_honours_control_check_and_finalize(self):
        ctl = FakeControl()
        ctx = server._capture_context()
        result = ReconService().run(passive=False, probe=False, control=ctl, context=ctx)
        self.assertGreaterEqual(ctl.checks, 2)
        self.assertTrue(ctl.finalized)
        self.assertFalse(result["cancelled"])
        store = server.STATE["store"]
        self.assertTrue(any(r["state"] == "complete" for r in store.runs()))

    def test_run_probe_only_against_loopback(self):
        ctx = server._capture_context()
        result = ReconService().run(passive=False, probe=True, control=None, context=ctx)
        self.assertFalse(result["cancelled"])
        store = server.STATE["store"]
        asset = next(a for a in store.assets() if a["host"] == "127.0.0.1")
        self.assertEqual(asset["probe"]["status"], 200)

    def test_cancel_mid_run_keeps_partial_results(self):
        # Cancel fires after the probe is recorded (3rd check); partial result is kept and
        # the run is marked cancelled — no auto-replay.
        ctl = FakeControl(cancel_after=2)
        ctx = server._capture_context()
        with self.assertRaises(Cancelled):
            ReconService().run(passive=False, probe=True, control=ctl, context=ctx)
        store = server.STATE["store"]
        run = next(r for r in store.runs() if r["mode"] == "collect")
        self.assertEqual(run["state"], "cancelled")

    def test_run_emits_task_progress_when_bus_present(self):
        bus = EventBus()
        seen = []
        bus.subscribe(EventType.TASK_PROGRESS, lambda ev: seen.append(ev))
        ctx = server._capture_context()
        ReconService(event_bus=bus).run(passive=False, probe=False, control=None, context=ctx)
        self.assertTrue(seen, "a run with a bus must publish task.progress")

    def test_run_without_bus_is_silent_noop(self):
        ctx = server._capture_context()
        # No bus → no exception, no publish (nothing to assert beyond a clean run).
        result = ReconService().run(passive=False, probe=False, control=None, context=ctx)
        self.assertFalse(result["cancelled"])


# ── Collector units ──────────────────────────────────────────────────────────────

class CollectorTests(ReconBase):
    def test_passive_crtsh_collector_scope_filters(self):
        from raven.scope import Scope
        scope = Scope(["example.test", "*.example.test"], [], [443])
        store = Mock()
        store.host.return_value = True
        ctl = FakeControl()
        with patch.object(server, "_passive_crtsh",
                          return_value=["api.example.test", "evil.test"]):
            subs, added = PassiveCrtShCollector().collect_root(
                "example.test", scope=scope, store=store, run_id="r1", ctl=ctl, logs=[])
        stored = [c.args[0] for c in store.host.call_args_list]
        self.assertIn("api.example.test", stored)
        self.assertNotIn("evil.test", stored)
        self.assertEqual(added, 1)

    def test_active_probe_collector_stores_probe_and_in_scope_scripts(self):
        from raven.scope import Scope
        scope = Scope(["127.0.0.1"], [], [80])
        store = Mock()
        store.assets.return_value = [{"host": "127.0.0.1"}]
        store.url.return_value = True
        probe = {"status": 200, "title": "t", "scripts":
                 ["http://127.0.0.1/app.js", "https://off-scope.test/x.js"]}
        ctl = FakeControl()
        with patch.object(server, "_probe_host", return_value=probe):
            hosts, responded = ActiveProbeCollector().collect(
                scope=scope, store=store, run_id="r1", ctl=ctl, logs=[])
        self.assertEqual((hosts, responded), (1, 1))
        store.probe.assert_called_once()
        stored_urls = [c.args[0] for c in store.url.call_args_list]
        self.assertIn("http://127.0.0.1/app.js", stored_urls)        # in scope (port 80)
        self.assertNotIn("https://off-scope.test/x.js", stored_urls)  # out of scope

    def test_external_tool_collector_skipped_under_scheduler(self):
        from raven.scope import Scope
        scope = Scope(["example.test"], [], [443])
        store = Mock()
        ctl = FakeControl()
        logs = []
        with patch.object(server, "_run_tool",
                          side_effect=AssertionError("external tool must not run")) as rt:
            ExternalToolCollector(enabled=True).collect_root(
                "example.test", scope=scope, store=store, run_id="r1", ctl=ctl,
                logs=logs, scheduled=True)
        rt.assert_not_called()
        self.assertTrue(any("external traffic cannot be budgeted" in m for m in logs))

    def test_external_tool_collector_off_by_default_when_unscheduled(self):
        from raven.scope import Scope
        scope = Scope(["example.test"], [], [443])
        store = Mock()
        ctl = FakeControl()
        with patch.object(server, "_run_tool",
                          side_effect=AssertionError("external tool must not run")) as rt:
            ExternalToolCollector().collect_root(   # enabled defaults to False
                "example.test", scope=scope, store=store, run_id="r1", ctl=ctl,
                logs=[], scheduled=False)
        rt.assert_not_called()

    def test_external_tool_collector_uses_process_executor_never_raw_subprocess(self):
        from raven.scope import Scope
        scope = Scope(["example.test"], [], [443])
        store = Mock()
        store.host.return_value = False
        store.url.return_value = False
        ctl = FakeControl()
        executor = Mock()
        executor.execute.return_value = Mock(stdout="sub.example.test\n")
        with patch.object(_collectors.shutil, "which", return_value="/fake/bin/tool"), \
             patch.object(server, "_run_tool",
                          side_effect=AssertionError("must route via ProcessExecutor")) as rt:
            ExternalToolCollector(enabled=True, executor=executor).collect_root(
                "example.test", scope=scope, store=store, run_id="r1", ctl=ctl,
                logs=[], scheduled=False)
        rt.assert_not_called()                    # NEVER the raw-subprocess path
        self.assertTrue(executor.execute.called)  # spawned through the ProcessExecutor


# ── recon.collect tool (real dispatch, capability-gated) ─────────────────────────

class _Decision:
    def __init__(self, allowed):
        self.value = "ALLOW" if allowed else "DENY"
        self._allowed = allowed


class _CapResult:
    def __init__(self, allowed):
        self.decision = _Decision(allowed)
        self.reason = "test gate"

    def is_allowed(self):
        return self.decision._allowed


class _FakeGate:
    def __init__(self, allowed):
        self._allowed = allowed

    def check(self, capability, context=None):
        return _CapResult(self._allowed)


class ReconToolTests(unittest.TestCase):
    def _dispatcher(self, allowed, service):
        registry = ToolRegistry()
        n = register_recon_tools(registry, service=service)
        self.assertEqual(n, 1)
        self.assertEqual(RECON_COLLECT.tool_id, "recon.collect")
        return ToolDispatcher(registry, lambda ws: _FakeGate(allowed))

    def test_recon_collect_registered_as_network_read(self):
        registry = ToolRegistry()
        register_recon_tools(registry, service=Mock())
        desc = registry.get("recon.collect")
        self.assertIsNotNone(desc)
        self.assertEqual(desc.side_effect_class.value, "NETWORK_READ")

    def test_denied_capability_yields_denied_and_no_collection(self):
        service = Mock()
        dispatcher = self._dispatcher(allowed=False, service=service)
        result, rec = dispatcher.invoke(ToolInvocation(
            tool_id="recon.collect", arguments={"passive": True, "probe": True},
            actor=ActorKind.RAVEN_AGENT))
        self.assertEqual(result.status, ToolStatus.DENIED)
        service.submit.assert_not_called()

    def test_allowed_capability_dispatches_to_recon_service(self):
        service = Mock()
        service.submit.return_value = {"job_id": "abc123", "state": "QUEUED"}
        dispatcher = self._dispatcher(allowed=True, service=service)
        result, rec = dispatcher.invoke(ToolInvocation(
            tool_id="recon.collect", arguments={"passive": True, "probe": False},
            actor=ActorKind.RESEARCHER))
        self.assertEqual(result.status, ToolStatus.SUCCESS)
        self.assertEqual(result.output, {"job_id": "abc123", "state": "QUEUED"})
        service.submit.assert_called_once()

    def test_invalid_argument_type_rejected_by_schema(self):
        service = Mock()
        dispatcher = self._dispatcher(allowed=True, service=service)
        result, rec = dispatcher.invoke(ToolInvocation(
            tool_id="recon.collect", arguments={"passive": "yes"},
            actor=ActorKind.RESEARCHER))
        self.assertEqual(result.status, ToolStatus.INVALID_INPUT)
        service.submit.assert_not_called()


# ── research_engine DEPRECATED (importable, data-checked) ────────────────────────

class ResearchEngineDeprecationTests(unittest.TestCase):
    def test_package_marked_deprecated_but_importable(self):
        import raven.research_engine as re_pkg
        self.assertTrue(getattr(re_pkg, "__deprecated__", False))
        self.assertEqual(re_pkg.__replacement__, "raven.recon.tools.register_recon_tools")
        # The classes still import (surviving Part-07 unit tests use them).
        from raven.research_engine import ResearchEngine, CandidateFinding  # noqa: F401

    def test_register_research_tools_still_works_but_warns(self):
        from raven.research_engine.registry import register_research_tools
        reg = ToolRegistry()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            n = register_research_tools(reg)
        self.assertGreaterEqual(n, 4)
        self.assertTrue(any(issubclass(w.category, DeprecationWarning) for w in caught))


if __name__ == "__main__":
    unittest.main()

"""P5-LIVE-RUNTIME — the §41 Program acceptance chain over the LIVE HTTP route.

Program Mode is the one AgentExecutor under a stricter configuration, now reachable
from the running product through ``POST /api/v7/program/run`` driving
``server.RUNTIME.program`` (the SAME dispatcher/registry/executions the agent uses).

Proven against a LOCAL SYNTHETIC fixture (loopback-only; no external/bug-bounty
targets):
  * missing-policy       -> 409 no_program_policy (no task created; no default-open path)
  * in-scope local step  -> COMPLETED under PROGRAM_AGENT provenance (ai_derived note)
  * out-of-scope network -> BLOCKED (OUT_OF_SCOPE) BEFORE any dispatch/record
  * host-shell / process -> BLOCKED (PROGRAM_NO_SHELL); no process ever spawned
  * external_targets      -> stays immutably 0
  * Emergency Stop        -> terminates the loop (CANCELLED)
Asserts NO `_noop`/`not_dispatched`, NO raw shell, boundary PROGRAM_AGENT provenance,
and that the agent never opens its own sockets (net.http.request stays UNAVAILABLE, so
even an IN-scope probe can only BLOCK, never send).
"""
import http.client
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from raven.api import server
from raven.program_agent.policy import ProgramPolicy, ProgramScope, ScopeType
from raven.program_agent.program import BugBountyProgram
from raven.runtime.execution import ActorKind, ToolStatus
from raven.runtime.tasks import TaskStatus
from raven.security.policy_gate import PolicyGate


def _loopback_policy():
    scope = ProgramScope()
    scope.add_in_scope("127.0.0.1", ScopeType.IP)
    return ProgramPolicy(program_id="p-live", name="Loopback (synthetic)",
                         platform="synthetic", scope=scope, rate_limit_rps=2.0)


class _LiveBase(unittest.TestCase):
    _SINGLETONS = ("_TERMINAL_TOOL", "_WORKSPACE_MGR", "_TASK_REGISTRY",
                   "_PLUGIN_REGISTRY", "_KB", "_EG")

    def setUp(self):
        PolicyGate._reset_emergency_stop_for_test()
        self._saved_state = dict(server.STATE)
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="raven-live-prog-")
        os.chdir(self._tmp)
        self._saved_singletons = {n: getattr(server, n) for n in self._SINGLETONS}
        for n in self._SINGLETONS:
            setattr(server, n, None)
        server.RUNTIME._reset_live_cache_for_test()
        server.use_workspace("liveprogram")
        self.ws = server._ev_know_ws_id()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        server.STATE["port"] = self.port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.thread.join(2)
        except Exception:
            pass
        store = server.STATE.get("store")
        if store is not None:
            try:
                store.close()
            except Exception:
                pass
        server.RUNTIME._reset_live_cache_for_test()
        for n, v in self._saved_singletons.items():
            setattr(server, n, v)
        server.STATE.clear()
        server.STATE.update(self._saved_state)
        os.chdir(self._cwd)
        # Restore process-wide stop state so an emergency-stop test here cannot leak a
        # tripped PolicyGate OR a stopped module-global SCHEDULER into downstream tests.
        PolicyGate._reset_emergency_stop_for_test()
        try:
            server.SCHEDULER.clear_stop()
        except Exception:
            pass

    def _post(self, path, body):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            c.request("POST", path, body=json.dumps(body),
                      headers={"X-RAVEN-Token": server.SESSION_TOKEN,
                               "Content-Type": "application/json"})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def _get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            c.request("GET", path, headers={"X-RAVEN-Token": server.SESSION_TOKEN})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def _load_fixture(self):
        """Save a loopback ProgramPolicy into the LIVE ServerRuntime's ProgramStore for
        the active workspace (local fixture only)."""
        server.RUNTIME.programs.save(BugBountyProgram(
            program_id="prog-live", workspace_id=self.ws, policy=_loopback_policy()))


class TestMissingPolicyDenied(_LiveBase):
    def test_no_program_policy_is_409_and_no_task(self):
        status, body = self._post("/api/v7/program/run", {"objective": "do recon"})
        self.assertEqual(status, 409, body)
        self.assertEqual(body["status"], "no_program_policy")
        # No task was created (no default-open path).
        _, tasks = self._get("/api/v7/tasks")
        self.assertEqual(tasks["tasks"], [])


class TestInScopeAllowed(_LiveBase):
    def test_in_scope_local_note_completes_as_program_agent(self):
        self._load_fixture()
        status, run = self._post("/api/v7/program/run",
                                 {"objective": "record a loopback program note"})
        self.assertEqual(status, 200, run)
        self.assertEqual(run["status"], "COMPLETED")
        self.assertEqual(run["origin"], "PROGRAM_AGENT")       # boundary provenance

        _, got = self._get("/api/v7/agent/run/" + run["task_id"])
        obs = got["observations"]
        self.assertEqual(len(obs), 1, obs)
        self.assertEqual(obs[0]["tool_id"], "knowledge.store")      # REAL tool
        self.assertEqual(obs[0]["status"], "SUCCESS")
        self.assertEqual(obs[0]["actor"], "PROGRAM_AGENT")
        self.assertEqual(obs[0]["capability_decision"], "ALLOW")
        # ai_derived, never a raw shell.
        _, kb = self._get("/api/v7/knowledge")
        self.assertTrue(any(e.get("source") == "ai_derived" for e in kb["entries"]))
        self.assertFalse(any(o["tool_id"].startswith(
            ("env.terminal", "env.wsl", "env.script")) for o in obs))

    def test_external_targets_stays_zero(self):
        self._load_fixture()
        prog = server.RUNTIME.programs.list_active(self.ws)[0]
        self.assertEqual(prog.policy.external_targets, 0)
        with self.assertRaises(AttributeError):
            prog.policy.external_targets = 9


class TestOutOfScopeDenied(_LiveBase):
    def test_out_of_scope_network_blocked_before_dispatch(self):
        self._load_fixture()
        status, run = self._post("/api/v7/program/run",
                                 {"objective": "probe out of scope",
                                  "probe_target": "https://evil.test/"})
        self.assertEqual(status, 200, run)
        self.assertEqual(run["status"], "BLOCKED")
        self.assertIn("OUT_OF_SCOPE", (run.get("failure") or ""))
        _, got = self._get("/api/v7/agent/run/" + run["task_id"])
        self.assertEqual(got["observations"], [])      # never dispatched / recorded

    def test_in_scope_network_cannot_send_net_http_unavailable(self):
        # In-scope probe passes the ProgramPolicy scope gate but net.http.request is
        # EXPLICITLY UNAVAILABLE — so it BLOCKS at bind, never opens a socket.
        self._load_fixture()
        status, run = self._post("/api/v7/program/run",
                                 {"objective": "probe loopback",
                                  "probe_target": "https://127.0.0.1/"})
        self.assertEqual(status, 200, run)
        self.assertEqual(run["status"], "BLOCKED")
        self.assertIn("UNAVAILABLE", (run.get("failure") or "").upper())
        _, got = self._get("/api/v7/agent/run/" + run["task_id"])
        self.assertEqual(got["observations"], [])      # no send, no record


class TestNoRawShell(_LiveBase):
    def test_process_step_blocked_through_live_substrate(self):
        # A host-shell/process step is proven BLOCKED against the SAME live-wired
        # substrate (RUNTIME.dispatcher/registry/tasks/executions) the route uses. The
        # live route itself exposes no shell path; this drives a manual process step
        # through the one ProgramAgentExecutor configuration to prove the no-shell guard.
        self._load_fixture()
        from raven.agent.plan import PlanSource, PlanStep
        from raven.agent.planner_backend import ManualPlanner
        from raven.planner.planner import ActionProposal
        from raven.program_agent.executor import ProgramAgentExecutor
        from raven.runtime.tools import SideEffectClass

        proposal = ActionProposal(reason="shell", required_capability="ProcessAnalyzer",
                                  risk_class="Sensitive", destination="local",
                                  method="EXEC", human_approval_required=False)
        step = PlanStep(proposal=proposal, side_effect=SideEffectClass.PROCESS_EXECUTION,
                        source=PlanSource.MANUAL, arg_overrides={"command": "whoami"})
        rt = server.RUNTIME
        px = ProgramAgentExecutor(
            dispatcher=rt.dispatcher, tasks=rt.tasks, registry=rt.tools,
            executions=rt.executions, event_bus=rt.bus,
            program_policy=_loopback_policy(), planner_backend=ManualPlanner([step]))
        task = px.start_program_run("run a shell", workspace_id=self.ws)
        self.assertEqual(task.status, TaskStatus.BLOCKED)
        self.assertIn("PROGRAM_NO_SHELL", (task.failure or ""))
        self.assertEqual(rt.executions.list_for_task(task.task_id), [])  # no spawn


class TestEmergencyStopTerminates(_LiveBase):
    def test_emergency_stop_cancels_program_run(self):
        self._load_fixture()
        s0, _ = self._post("/api/emergency-stop", {})
        self.assertEqual(s0, 200)
        status, run = self._post("/api/v7/program/run",
                                 {"objective": "note during an active stop"})
        self.assertEqual(status, 200, run)
        self.assertEqual(run["status"], "CANCELLED")
        self.assertIn("emergency_stop", (run.get("failure") or ""))


class TestProgramToolsAreReal(_LiveBase):
    def test_program_policy_check_is_a_real_handler_not_noop(self):
        self._load_fixture()
        h = server.RUNTIME.tools.get_handler("program.policy.check")
        self.assertIsNotNone(h)
        out = h({"target": "https://127.0.0.1/x"})
        self.assertNotEqual(out.get("status"), "not_dispatched")
        self.assertEqual(out.get("external_targets"), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

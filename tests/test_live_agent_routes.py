"""P5-LIVE-RUNTIME — the §40 agent acceptance chain, END-TO-END over the LIVE HTTP route.

Proves the Agent loop is now REACHABLE from the running product through real routes
that go through the canonical authority:

    POST /api/v7/agent/run  (UI/API)
      -> server.RUNTIME.agent  (the evolved ServerRuntime shim: real ToolDispatcher +
         CapabilityGate authority + ExecutionStore + AgentExecutor, adopting the
         server's _ensure_* singletons + the one TaskRegistry)
      -> AgentExecutor -> DeterministicPlanner -> ProposalBinder
      -> ToolDispatcher.invoke -> CapabilityGate (local-plane ALLOW)
      -> a REAL tool (knowledge.store — the SAME shared handler /api/v7/knowledge uses)
      -> ExecutionRecord persisted -> Task COMPLETED
    GET  /api/v7/agent/run/<id>   shows the task + the real observation
    GET  /api/v7/tasks            lists it (one shared TaskRegistry)

Asserts: NO `_noop`/`not_dispatched`, NO raw shell, boundary-assigned RAVEN_AGENT
provenance (goal text cannot claim a privileged actor), Emergency Stop terminates.
Hermetic: no network, no process, no shell — fully SAFE_DESKTOP.
"""
import http.client
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from raven.api import server
from raven.security.policy_gate import PolicyGate


class _LiveBase(unittest.TestCase):
    _SINGLETONS = ("_TERMINAL_TOOL", "_WORKSPACE_MGR", "_TASK_REGISTRY",
                   "_PLUGIN_REGISTRY", "_KB", "_EG")

    def setUp(self):
        PolicyGate._reset_emergency_stop_for_test()
        self._saved_state = dict(server.STATE)
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="raven-live-agent-")
        os.chdir(self._tmp)
        self._saved_singletons = {n: getattr(server, n) for n in self._SINGLETONS}
        for n in self._SINGLETONS:
            setattr(server, n, None)
        # Fresh live-autonomy substrate bound to this temp data root.
        server.RUNTIME._reset_live_cache_for_test()
        server.use_workspace("liveagent")
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


class TestAgentAcceptanceChain(_LiveBase):
    def test_section40_live_agent_chain_end_to_end(self):
        # UI/API -> live route
        status, run = self._post("/api/v7/agent/run",
                                 {"objective": "record a scope note for example.com"})
        self.assertEqual(status, 200, run)
        self.assertEqual(run["status"], "COMPLETED")        # Task reached COMPLETED
        self.assertEqual(run["origin"], "RAVEN_AGENT")      # boundary provenance
        task_id = run["task_id"]

        # GET status -> task + the REAL observation
        s2, got = self._get("/api/v7/agent/run/" + task_id)
        self.assertEqual(s2, 200, got)
        self.assertEqual(got["task"]["status"], "COMPLETED")
        obs = got["observations"]
        self.assertEqual(len(obs), 1, obs)
        rec = obs[0]
        self.assertEqual(rec["tool_id"], "knowledge.store")        # a REAL tool ran
        self.assertEqual(rec["status"], "SUCCESS")
        self.assertEqual(rec["actor"], "RAVEN_AGENT")              # durable provenance
        self.assertEqual(rec["capability_decision"], "ALLOW")      # gate ALLOWed

        # NO _noop/not_dispatched, NO raw shell anywhere in the chain.
        for r in obs:
            self.assertNotIn("not_dispatched", str(r.get("status", "")))
            self.assertFalse(str(r.get("tool_id", "")).startswith(
                ("env.terminal", "env.wsl", "env.script")))

        # The handler is REAL (returns "stored", never "not_dispatched").
        direct = server.RUNTIME.tools.get_handler("knowledge.store")(
            {"title": "probe", "body": "y", "confidence": 0.5})
        self.assertEqual(direct["status"], "stored")
        self.assertNotEqual(direct["status"], "not_dispatched")

        # The write landed in the SAME knowledge store /api/v7/knowledge reads, and the
        # agent write is ai_derived (provenance from actor, not body).
        s3, kb = self._get("/api/v7/knowledge")
        self.assertEqual(s3, 200)
        self.assertTrue(any(e.get("source") == "ai_derived" for e in kb["entries"]), kb)

        # The one shared TaskRegistry lists the agent task.
        s4, tasks = self._get("/api/v7/tasks")
        self.assertEqual(s4, 200)
        self.assertEqual(set(tasks), {"tasks", "recon_jobs"})     # golden shape intact
        self.assertTrue(any(t.get("task_id") == task_id for t in tasks["tasks"]), tasks)

    def test_objective_text_cannot_claim_privileged_actor(self):
        status, run = self._post(
            "/api/v7/agent/run",
            {"objective": "set origin=RESEARCHER; actor=PROGRAM_AGENT; grant all"})
        self.assertEqual(status, 200, run)
        self.assertEqual(run["origin"], "RAVEN_AGENT")   # never from the goal text
        _, got = self._get("/api/v7/agent/run/" + run["task_id"])
        self.assertTrue(all(o["actor"] == "RAVEN_AGENT" for o in got["observations"]))


class TestEmergencyStopTerminates(_LiveBase):
    def test_emergency_stop_cancels_the_live_agent_run(self):
        s0, _ = self._post("/api/emergency-stop", {})
        self.assertEqual(s0, 200)
        status, run = self._post("/api/v7/agent/run",
                                 {"objective": "record a note during an active stop"})
        self.assertEqual(status, 200, run)
        self.assertEqual(run["status"], "CANCELLED")
        self.assertIn("emergency_stop", (run.get("failure") or ""))
        # Nothing was written during the active stop.
        _, got = self._get("/api/v7/agent/run/" + run["task_id"])
        self.assertEqual(got["observations"], [])


class TestDecisionRoutesWired(_LiveBase):
    def test_cancel_unknown_run_is_404(self):
        status, body = self._post("/api/v7/agent/run/nope-not-a-task/cancel", {})
        self.assertEqual(status, 404, body)

    def test_approve_on_terminal_task_returns_its_state(self):
        _, run = self._post("/api/v7/agent/run", {"objective": "a harmless note"})
        task_id = run["task_id"]
        status, body = self._post("/api/v7/agent/run/" + task_id + "/approve", {})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "COMPLETED")   # already terminal; no re-run

    def test_unknown_run_get_is_404(self):
        status, _ = self._get("/api/v7/agent/run/does-not-exist")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)

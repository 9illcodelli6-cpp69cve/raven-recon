"""A6-TERM (Wave 6) — gated terminal execution is equal-or-STRONGER than the old
substring denylist.

Proves deliverables #2 and #3. The weak, bypassable ``_BLOCKED_COMMANDS`` substring
blocklist is gone (SECURITY_ARCHITECTURE §2.3/§3.3); every terminal exec now goes:

    transport auth  ->  resolve_actor (RESEARCHER at the boundary, never from body)
      ->  seeded CapabilityGate.check(process_exec, declared risk)   [fail-closed]
        ->  on ALLOW: ProcessExecutor (shell=False, hidden window, provenance stamped,
                      emergency-stop checked, output-capped, tree-killable)

Security invariants locked here (none weaker than before):
  * an ALLOW routes through the executor stamped with RESEARCHER provenance + the
    ALLOW decision (argv form, never shell=True);
  * emergency stop refuses the run and NOTHING spawns;
  * a disallowed shell id is still refused WITHOUT spawning;
  * provenance is assigned at the boundary — a body-supplied ``actor``/``provenance``
    cannot escalate (or alter) it;
  * an unauthenticated interactive request cannot acquire RESEARCHER (fail-closed);
  * agent/model tiers are argv-only: a shell-metacharacter argument is rejected, so
    model output can never reach a raw shell;
  * undeclared risk fails closed (no silent ALLOW);
  * the Windows hidden-window flag is present on the shared spawn helper.
  * a running command is cancellable via ProcessExecutor.cancel (tree-kill).

Run:  python -m pytest tests/test_terminal_gated.py -q
"""
import sys
import unittest

from raven.agent_env.terminal import TerminalTool
from raven.api import server
from raven.runtime.execution import ActorKind, ToolStatus
from raven.runtime.process_executor import (
    ProcessExecutor,
    ProcessResult,
    ProcessSpec,
    hidden_process_kwargs,
)
from raven.security.policy_gate import PolicyGate


class _RecExec:
    """Recording fake executor — records specs, spawns nothing, returns SUCCESS."""
    def __init__(self):
        self.specs = []

    def execute(self, spec):
        self.specs.append(spec)
        return ProcessResult(execution_id="rec", argv=list(spec.argv),
                             return_code=0, status=ToolStatus.SUCCESS)


class _GatedBase(unittest.TestCase):
    _GLOBALS = ("_TERMINAL_TOOL", "_PROCESS_EXECUTOR", "_CAP_GATE", "_CAP_GATE_WS",
                "_ACTIVE_WORKSPACE_ID")

    def setUp(self):
        PolicyGate._reset_emergency_stop_for_test()
        self._saved = {n: getattr(server, n) for n in self._GLOBALS}
        server._ACTIVE_WORKSPACE_ID = "gated-ws"
        server._CAP_GATE = None
        server._CAP_GATE_WS = None
        self.rec = _RecExec()
        # The live run path uses _ensure_terminal(); inject the recording executor so
        # an ALLOW never spawns a real process.
        server._TERMINAL_TOOL = TerminalTool(executor=self.rec)

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(server, n, v)
        PolicyGate._reset_emergency_stop_for_test()


class AllowPath(_GatedBase):
    def test_allow_routes_through_executor_with_researcher_provenance(self):
        data, code = server.api_terminal_run({"command": "echo hi", "shell": "powershell"})
        self.assertEqual(code, 200)
        self.assertFalse(data["blocked"])
        self.assertEqual(len(self.rec.specs), 1)
        spec = self.rec.specs[0]
        self.assertEqual(spec.actor, ActorKind.RESEARCHER)       # boundary provenance
        self.assertEqual(spec.capability_decision, "ALLOW")      # gate decision stamped
        self.assertEqual(spec.argv[0], "powershell")             # argv form (shell=False)
        self.assertIn("echo hi", spec.argv)

    def test_body_supplied_provenance_cannot_escalate(self):
        # A malicious/confused body tries to set its own provenance; it MUST be ignored
        # — the stamped actor stays the boundary-derived RESEARCHER, never body-chosen.
        data, code = server.api_terminal_run({
            "command": "echo hi", "shell": "powershell",
            "actor": "PROGRAM_AGENT", "provenance": "SYSTEM"})
        self.assertEqual(code, 200)
        self.assertEqual(self.rec.specs[0].actor, ActorKind.RESEARCHER)


class RefusalPaths(_GatedBase):
    def test_emergency_stop_refuses_and_nothing_spawns(self):
        PolicyGate.trigger_emergency_stop()
        data, code = server.api_terminal_run({"command": "echo hi", "shell": "powershell"})
        self.assertEqual(code, 200)
        self.assertTrue(data["blocked"])
        self.assertEqual(self.rec.specs, [], "no spawn under emergency stop")
        # Stable envelope even on refusal.
        self.assertEqual(set(data), {"command", "stdout", "stderr", "exit_code",
                                     "duration_ms", "timed_out", "blocked", "shell"})

    def test_disallowed_shell_refused_without_spawn(self):
        data, code = server.api_terminal_run({"command": "echo hi", "shell": "ruby"})
        self.assertEqual(code, 200)
        self.assertTrue(data["blocked"])
        self.assertEqual(self.rec.specs, [], "disallowed shell must not spawn")

    def test_empty_command_is_400(self):
        data, code = server.api_terminal_run({"command": "   "})
        self.assertEqual(code, 400)
        self.assertIn("error", data)


class ProvenanceBoundary(_GatedBase):
    def test_unauthenticated_interactive_cannot_be_researcher(self):
        from raven.security.actor_context import (
            ActorSource,
            ProvenanceError,
            resolve_actor,
        )
        with self.assertRaises(ProvenanceError):
            resolve_actor(ActorSource.INTERACTIVE_UI, authenticated=False)
        # Authenticated interactive IS researcher.
        self.assertEqual(
            resolve_actor(ActorSource.INTERACTIVE_UI, authenticated=True),
            ActorKind.RESEARCHER)

    def test_agent_tier_is_argv_only_metachars_rejected(self):
        # Model/agent output can never reach a raw shell: an AGENT-tier argv with a
        # shell metacharacter is rejected by the executor (INVALID_INPUT), no spawn.
        ex = ProcessExecutor()
        spec = ProcessSpec(argv=["ls", "a; rm -rf /"], actor=ActorKind.RAVEN_AGENT)
        res = ex.execute(spec)
        self.assertEqual(res.status, ToolStatus.INVALID_INPUT)
        self.assertEqual(ex.active_ids(), [])


class GateFailClosed(_GatedBase):
    def test_undeclared_risk_does_not_silently_allow(self):
        gate = server._ensure_capability_gate("gated-ws")
        # No risk_class declared -> must fail closed (SENSITIVE -> approval/deny), never ALLOW.
        res = gate.check("process_exec", {"actor": ActorKind.RESEARCHER})
        self.assertFalse(res.is_allowed())
        # A declared low risk with the seeded PROCESS_ANALYZER grant DOES allow.
        res2 = gate.check("process_exec", {"risk_class": "LOW_RISK_STATE_CHANGE",
                                           "actor": ActorKind.RESEARCHER})
        self.assertTrue(res2.is_allowed())


class HiddenWindow(unittest.TestCase):
    def test_hidden_window_flag_present_on_windows(self):
        kw = hidden_process_kwargs()
        if sys.platform == "win32":
            import subprocess
            self.assertTrue(kw["creationflags"] & subprocess.CREATE_NO_WINDOW)
            self.assertIn("startupinfo", kw)
        else:
            self.assertTrue(kw.get("start_new_session"))


class Cancel(unittest.TestCase):
    def test_cancel_terminates_a_running_process_tree(self):
        # Spawn a real, long-lived child through the executor on a background thread,
        # then cancel it and assert it is reaped as CANCELLED.
        import threading
        ex = ProcessExecutor(default_timeout_s=30.0)
        argv = [sys.executable, "-c", "import time; time.sleep(30)"]
        result_box = {}

        def _run():
            result_box["res"] = ex.execute(ProcessSpec(argv=argv, actor=ActorKind.RESEARCHER,
                                                       new_process_group=True))

        th = threading.Thread(target=_run, daemon=True)
        th.start()
        # Wait for the child to register as active, then cancel it.
        eid = None
        for _ in range(200):
            ids = ex.active_ids()
            if ids:
                eid = ids[0]
                break
            import time
            time.sleep(0.01)
        self.assertIsNotNone(eid, "process did not register as active")
        self.assertTrue(ex.cancel(eid))
        th.join(timeout=10)
        self.assertFalse(th.is_alive(), "cancelled process did not return")
        self.assertEqual(result_box["res"].status, ToolStatus.CANCELLED)


if __name__ == "__main__":
    unittest.main(verbosity=2)

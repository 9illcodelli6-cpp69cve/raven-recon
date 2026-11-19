"""GOLDEN / characterization tests — chat-unavailable, workspace bind, terminal.

Locks the CURRENT behaviour that Wave 3 will migrate into ChatService /
WorkspaceService and the ProcessExecutor-backed terminal. All behaviour-preserving
(RUNTIME_ARCHITECTURE.md §10).

Locked invariants:
  * Chat with no model reachable returns its TYPED failure (HTTP 503, an
    "[Model unavailable: ...]" error) — it never crashes and never fabricates a
    `response` — and the conversation (user + assistant turn) is still persisted.
  * Workspace `set_scope`/`use_workspace` (the V5 bind) binds the active
    workspace: it opens the per-workspace Store, writes scope.json + recon.db,
    and wires the CanonicalService. (We only characterize what the V5 bind does
    today; the V7 UI-switch no-op is a separate, deliberately-unlocked defect.)
  * Terminal guards (UPDATED, Wave 6 / A6-TERM): the substring `_BLOCKED_COMMANDS`
    denylist is REMOVED as a security control — an INTENTIONAL, documented
    architecture change (SECURITY_ARCHITECTURE §2.3 / §3.3: denylist -> capability +
    provenance + ProcessExecutor). The equal-or-stronger invariants locked here:
      - a disallowed SHELL id is still refused WITHOUT spawning (`blocked=True`);
      - a command is no longer refused by substring match — it now flows through the
        provenance-stamped (RESEARCHER), argv-only, hidden-window ProcessExecutor
        (asserted via an injected recording executor so nothing is actually spawned);
      - `api_terminal_run` requires a command (400) and still returns the stable
        TerminalResult envelope (a gate refusal / disallowed shell -> `blocked=True`).

Loopback/in-memory only; no external host is contacted.

Run:  python -m pytest tests/test_golden_terminal_chat_workspace.py -q
"""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from raven.api import server
from raven.agent_env.terminal import TerminalTool
from raven.runtime.model import ModelService
from raven.runtime.conversation import ConversationContext


class ChatUnavailable(unittest.TestCase):
    """No provider registered == the honest default state: RAVEN ships no native
    generative model and the OPTIONAL third-party provider (Ollama) is OFF by default,
    so _ensure_ai registers zero providers.

    WAVE 13 / A13-NATIVE — INTENTIONAL, DOCUMENTED golden-assertion change
    (directive §49 / reconstruction/NATIVE_AI_FOUNDATION.md §3.1, CANONICAL_ARCHITECTURE
    §1 row 22). Making Ollama OFF-by-default changes the chat-unavailable message from
    the old generic "[Model unavailable: PROVIDER_UNAVAILABLE]" to the honest typed
    "[Native generative model unavailable …]" / error_code
    NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE. Only the unavailable *text/code* assertion is
    updated; the invariants this golden test protects are PRESERVED and still asserted:
    (1) a TYPED, non-crashing HTTP 503, (2) NO fabricated `response` text, and (3) the
    conversation (user + assistant turn) is still persisted."""

    def setUp(self):
        self._db = sqlite3.connect(":memory:", check_same_thread=False)
        self._ctx = ConversationContext(self._db)       # auto-migrates schema
        self._svc = ModelService()                      # no providers -> PROVIDER_UNAVAILABLE
        self._saved_ensure_ai = server._ensure_ai
        server._ensure_ai = lambda: (self._svc, self._ctx)

    def tearDown(self):
        server._ensure_ai = self._saved_ensure_ai
        server._CHAT_SESSIONS.pop("golden-sess", None)
        self._db.close()

    def test_returns_typed_503_without_fabricating_text(self):
        data, code = server.api_chat({"message": "hello", "session_id": "golden-sess"})
        self.assertEqual(code, 503)                         # typed, non-crashing
        self.assertIn("error", data)
        # Honest typed signal (replaces old "[Model unavailable: PROVIDER_UNAVAILABLE]").
        self.assertEqual(data.get("error_code"), "NATIVE_GENERATIVE_MODEL_NOT_AVAILABLE", data)
        self.assertTrue(data["error"].startswith("[Native generative model unavailable"), data)
        self.assertNotIn("response", data)                  # no fabricated assistant text

    def test_conversation_is_still_persisted(self):
        server.api_chat({"message": "hello", "session_id": "golden-sess"})
        rows = self._db.execute("SELECT role, content FROM v7_messages").fetchall()
        contents = [c for _, c in rows]
        self.assertEqual(len(rows), 2, "user + assistant turn persisted")
        self.assertIn("hello", contents)
        self.assertTrue(any(c.startswith("[Native generative model unavailable") for c in contents),
                        "the persisted assistant turn is the honest typed marker, not fabricated")


class WorkspaceBind(unittest.TestCase):
    def setUp(self):
        self._saved_state = dict(server.STATE)
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp(prefix="raven-golden-ws-")
        os.chdir(self._tmp)

    def tearDown(self):
        store = server.STATE.get("store")
        if store is not None:
            try:
                store.close()
            except Exception:
                pass
        server.STATE.clear()
        server.STATE.update(self._saved_state)
        os.chdir(self._cwd)

    def test_set_scope_binds_workspace_and_opens_store(self):
        result = server.set_scope({"name": "bindws",
                                   "include": ["bind.example.com"],
                                   "ports": [80, 443]})
        # scope_dict envelope
        self.assertEqual(result["name"], "bindws")
        self.assertIn("bind.example.com", result["include"])
        self.assertEqual(sorted(result["ports"]), [80, 443])
        # active bind: Store opened + on-disk workspace materialized
        self.assertIsNotNone(server.STATE.get("store"))
        self.assertEqual(server.STATE["name"], "bindws")
        ws_dir = Path(server.STATE["ws_dir"])
        self.assertEqual(ws_dir.name, "bindws")
        self.assertTrue((ws_dir / "scope.json").is_file())
        self.assertTrue((ws_dir / "recon.db").is_file())
        # V5 canonical service wired for this workspace
        self.assertIsNotNone(server.STATE.get("canonical_svc"))

    def test_switch_rebinds_store_to_new_workspace(self):
        server.set_scope({"name": "wsA", "include": ["a.example.com"], "ports": [80]})
        store_a = server.STATE.get("store")
        dir_a = Path(server.STATE["ws_dir"])
        server.set_scope({"name": "wsB", "include": ["b.example.com"], "ports": [80]})
        store_b = server.STATE.get("store")
        dir_b = Path(server.STATE["ws_dir"])
        self.assertIsNot(store_a, store_b)           # store rebound
        self.assertNotEqual(dir_a.name, dir_b.name)  # to a different workspace dir
        self.assertEqual(dir_b.name, "wsb")


from raven.runtime.execution import ActorKind, ToolStatus
from raven.runtime.process_executor import ProcessResult


class _RecordingExecutor:
    """A fake ProcessExecutor that records the ProcessSpec and returns a canned
    SUCCESS result WITHOUT spawning anything. Lets us assert the new "command flows
    through the provenance-stamped executor" model without running the command
    (critical: the old denylist test string `shutdown /r /t 0` must never spawn)."""
    def __init__(self):
        self.specs = []

    def execute(self, spec):
        self.specs.append(spec)
        return ProcessResult(execution_id="rec", argv=list(spec.argv),
                             return_code=0, stdout="", stderr="",
                             status=ToolStatus.SUCCESS)


class TerminalGuards(unittest.TestCase):
    # UPDATED for Wave 6 / A6-TERM. SECURITY_ARCHITECTURE §2.3/§3.3: the substring
    # `_BLOCKED_COMMANDS` denylist was removed as a (bypassable, false-assurance)
    # security control. Protection is now capability + provenance + ProcessExecutor.
    # These assertions therefore assert the NEW, equal-or-stronger model; the old
    # "shutdown is substring-blocked" assertions are deliberately replaced. A
    # disallowed SHELL id is STILL refused without spawning (not weakened).

    def test_command_flows_through_provenance_stamped_executor(self):
        # Formerly: asserted `shutdown ...` is substring-blocked. NEW model: there is
        # no content denylist — the command is handed to the RESEARCHER-provenance,
        # argv-only executor (hidden window, env scrub, caps, audit upstream). We
        # inject a recording executor so nothing is actually spawned.
        rec = _RecordingExecutor()
        res = TerminalTool(executor=rec).run("shutdown /r /t 0", shell="cmd")
        self.assertFalse(res.blocked, "no substring denylist anymore")
        self.assertEqual(len(rec.specs), 1)
        spec = rec.specs[0]
        self.assertEqual(spec.actor, ActorKind.RESEARCHER)   # provenance stamped
        self.assertEqual(spec.argv[0], "cmd")                # argv form, shell=False
        self.assertIn("shutdown /r /t 0", spec.argv)         # passed through, not blocked

    def test_disallowed_shell_blocked(self):
        # Not weakened: a disallowed shell id is still refused WITHOUT spawning.
        res = TerminalTool(allowed_shells=["powershell"]).run("echo hi", shell="ruby")
        self.assertTrue(res.blocked)
        self.assertIn("not in allowed list", res.stderr)

    def test_result_to_dict_envelope(self):
        # Use a disallowed shell (refused without spawn) to exercise the stable
        # envelope shape without running any command.
        res = TerminalTool(allowed_shells=["powershell"]).run("echo hi", shell="cmd")
        self.assertTrue(res.blocked)
        self.assertEqual(set(res.to_dict()), {
            "command", "stdout", "stderr", "exit_code",
            "duration_ms", "timed_out", "blocked", "shell"})

    def test_api_terminal_run_requires_command(self):
        data, code = server.api_terminal_run({"command": "   "})
        self.assertEqual(code, 400)
        self.assertIn("error", data)

    def test_api_terminal_run_refusal_returns_200_envelope(self):
        # Formerly ran `shutdown now` relying on the denylist. NEW model: a refusal
        # (here a disallowed shell id; the gate path is covered in test_terminal_gated)
        # still returns the stable 200 TerminalResult envelope with blocked=True, and
        # never spawns the command.
        data, code = server.api_terminal_run({"command": "echo hi", "shell": "ruby"})
        self.assertEqual(code, 200)
        self.assertTrue(data["blocked"])
        self.assertEqual(set(data), {
            "command", "stdout", "stderr", "exit_code",
            "duration_ms", "timed_out", "blocked", "shell"})


if __name__ == "__main__":
    unittest.main(verbosity=2)

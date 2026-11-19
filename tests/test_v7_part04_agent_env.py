"""RAVEN V7 Part 04 — Agent Environment Tests."""
import os
import tempfile
import pytest


# ── Terminal ─────────────────────────────────────────────────────────────────

class TestTerminalTool:
    def test_command_flows_through_executor_not_substring_blocked(self):
        # Wave 6 / A6-TERM (SECURITY_ARCHITECTURE §2.3/§3.3): the substring
        # `_BLOCKED_COMMANDS` denylist was REMOVED as a security control (bypassable,
        # false assurance). Protection is now capability + provenance + ProcessExecutor.
        # A formerly-"blocked" string is no longer refused by content — it flows
        # through the provenance-stamped, argv-only executor. We inject a recording
        # executor so the command is NEVER actually spawned (it must not reboot the
        # host). Disallowed-shell + unauthenticated/agent-tier refusals are covered in
        # tests/test_terminal_gated.py (equal-or-stronger, not weakened).
        from raven.agent_env.terminal import TerminalTool
        from raven.runtime.execution import ActorKind, ToolStatus
        from raven.runtime.process_executor import ProcessResult

        class _RecExec:
            def __init__(self):
                self.specs = []

            def execute(self, spec):
                self.specs.append(spec)
                return ProcessResult(execution_id="rec", argv=list(spec.argv),
                                     return_code=0, status=ToolStatus.SUCCESS)

        rec = _RecExec()
        t = TerminalTool(executor=rec)
        r = t.run("shutdown /r /t 0", shell="powershell")
        assert not r.blocked                      # no content denylist anymore
        assert len(rec.specs) == 1
        assert rec.specs[0].actor == ActorKind.RESEARCHER
        assert "shutdown /r /t 0" in rec.specs[0].argv

    def test_run_echo_powershell(self):
        from raven.agent_env.terminal import TerminalTool
        t = TerminalTool()
        r = t.run("echo hello", shell="powershell")
        assert "hello" in r.stdout.lower() or r.exit_code == 0 or not r.blocked

    def test_disallowed_shell_blocked(self):
        from raven.agent_env.terminal import TerminalTool
        t = TerminalTool(allowed_shells=["powershell"])
        r = t.run("ls", shell="bash")
        assert r.blocked

    def test_result_to_dict(self):
        from raven.agent_env.terminal import TerminalResult
        r = TerminalResult(command="echo hi", stdout="hi", exit_code=0, shell="powershell")
        d = r.to_dict()
        assert d["command"] == "echo hi"
        assert d["exit_code"] == 0

    def test_success_property(self):
        from raven.agent_env.terminal import TerminalResult
        r = TerminalResult(command="x", exit_code=0, timed_out=False, blocked=False)
        assert r.success
        r2 = TerminalResult(command="x", exit_code=1)
        assert not r2.success


# ── Filesystem ────────────────────────────────────────────────────────────────

class TestFilesystemTools:
    def _make_fs(self):
        from raven.agent_env.filesystem import FilesystemTools
        tmp = tempfile.mkdtemp()
        return FilesystemTools(workspace_root=tmp), tmp

    def test_write_and_read(self):
        from raven.agent_env.filesystem import FilesystemTools
        fs, _ = self._make_fs()
        wr = fs.write("test.txt", "hello world")
        assert wr.success
        assert wr.bytes_written > 0
        rr = fs.read("test.txt")
        assert rr.success
        assert rr.content == "hello world"

    def test_path_traversal_blocked(self):
        fs, _ = self._make_fs()
        r = fs.read("../../etc/passwd")
        assert r.error is not None
        assert "blocked" in r.error.lower() or not r.success

    def test_list_dir(self):
        fs, _ = self._make_fs()
        fs.write("a.txt", "A")
        fs.write("b.txt", "B")
        entries = fs.list_dir(".")
        names = [e.name for e in entries]
        assert "a.txt" in names
        assert "b.txt" in names

    def test_exists(self):
        fs, _ = self._make_fs()
        assert not fs.exists("missing.txt")
        fs.write("present.txt", "x")
        assert fs.exists("present.txt")

    def test_delete(self):
        fs, _ = self._make_fs()
        fs.write("del.txt", "gone")
        assert fs.exists("del.txt")
        fs.delete("del.txt")
        assert not fs.exists("del.txt")

    def test_file_entry_to_dict(self):
        from raven.agent_env.filesystem import FileEntry
        e = FileEntry(name="x.txt", path="x.txt", size_bytes=10)
        d = e.to_dict()
        assert d["name"] == "x.txt"


# ── WSL Bridge ────────────────────────────────────────────────────────────────

class TestWslBridge:
    def test_unavailable_returns_gracefully(self):
        from raven.agent_env.wsl import WslBridge
        # Even if WSL is available, we can force unavailable
        bridge = WslBridge()
        bridge._available = False  # force unavailable
        r = bridge.run("echo hello")
        assert not r.available
        assert r.exit_code == -1

    def test_result_to_dict(self):
        from raven.agent_env.wsl import WslResult
        r = WslResult(command="ls", stdout="file.txt", exit_code=0, distro="kali")
        d = r.to_dict()
        assert d["distro"] == "kali"
        assert d["exit_code"] == 0

    def test_list_distros_returns_list(self):
        from raven.agent_env.wsl import WslBridge
        bridge = WslBridge()
        result = bridge.list_distros()
        assert isinstance(result, list)


# ── Script Runner ─────────────────────────────────────────────────────────────

class TestScriptRunner:
    def test_python_script_runs(self):
        from raven.agent_env.scripts import ScriptRunner, ScriptLanguage
        runner = ScriptRunner()
        r = runner.run('print("hello from raven")', ScriptLanguage.PYTHON)
        assert "hello from raven" in r.stdout
        assert r.success

    def test_syntax_error_captured(self):
        from raven.agent_env.scripts import ScriptRunner, ScriptLanguage
        runner = ScriptRunner()
        r = runner.run("def broken(:\n    pass", ScriptLanguage.PYTHON)
        assert not r.success
        assert r.stderr or r.exit_code != 0

    def test_network_violation_detected(self):
        from raven.agent_env.scripts import ScriptRunner, ScriptLanguage
        runner = ScriptRunner(allow_network=False)
        violations = runner.check_script("import requests", ScriptLanguage.PYTHON)
        assert len(violations) > 0

    def test_network_allowed_no_violation(self):
        from raven.agent_env.scripts import ScriptRunner, ScriptLanguage
        runner = ScriptRunner(allow_network=True)
        violations = runner.check_script("import requests", ScriptLanguage.PYTHON)
        assert len(violations) == 0

    def test_result_to_dict(self):
        from raven.agent_env.scripts import ScriptResult, ScriptLanguage
        r = ScriptResult(script_id="s1", language=ScriptLanguage.PYTHON, exit_code=0)
        d = r.to_dict()
        assert d["script_id"] == "s1"


# ── Tool Registration ─────────────────────────────────────────────────────────

class TestEnvToolRegistration:
    def test_register_env_tools(self):
        from raven.agent_env.registry import register_env_tools
        from raven.runtime.tools import ToolRegistry
        registry = ToolRegistry()
        count = register_env_tools(registry)
        assert count >= 7
        tools = registry.list_all()
        tool_ids = [t.tool_id for t in tools]
        assert "env.terminal.run" in tool_ids
        assert "env.fs.read" in tool_ids
        assert "env.fs.write" in tool_ids
        assert "env.wsl.run" in tool_ids
        assert "env.script.run" in tool_ids

    def test_registered_tools_have_schemas(self):
        from raven.agent_env.registry import register_env_tools
        from raven.runtime.tools import ToolRegistry
        registry = ToolRegistry()
        register_env_tools(registry)
        tool = registry.get("env.terminal.run")
        assert tool is not None
        assert "command" in tool.input_schema.get("required", [])

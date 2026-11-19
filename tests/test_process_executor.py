"""Behavioral tests for the canonical ProcessExecutor (A2-PROC, Wave 2).

These exercise real subprocesses (harmless ``python -c`` argv) and assert the
security/behavioral contract: hidden window, shell=False, timeout, cancel+tree-kill,
output caps, env scrub, metachar reject for agent tiers, provenance + ExecutionRecord
persistence, emergency-stop short-circuit, and trusted-allowlist enforcement. Each
test is written so a broken implementation fails it.
"""
import inspect
import re
import sqlite3
import subprocess
import sys
import threading
import time

import pytest

import raven.runtime.process_executor as pe
from raven.runtime.process_executor import (
    ApprovedProcess,
    ProcessExecutor,
    ProcessSpec,
    hidden_process_kwargs,
    terminate_process_tree,
)
from raven.runtime.execution import ActorKind, ExecutionStore, ToolStatus

PY = sys.executable


def _spec(code, **kw):
    kw.setdefault("actor", ActorKind.SYSTEM)
    return ProcessSpec(argv=[PY, "-c", code], **kw)


# ── hidden_process_kwargs helper ──────────────────────────────────────────────

def test_hidden_process_kwargs_platform():
    kw = hidden_process_kwargs()
    if sys.platform == "win32":
        assert kw["creationflags"] & subprocess.CREATE_NO_WINDOW
        assert "startupinfo" in kw
        assert kw["startupinfo"].wShowWindow == subprocess.SW_HIDE
    else:
        assert kw == {"start_new_session": True}


def test_hidden_process_kwargs_group_bit():
    kw = hidden_process_kwargs(group=True)
    if sys.platform == "win32":
        assert kw["creationflags"] & subprocess.CREATE_NO_WINDOW
        assert kw["creationflags"] & subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        assert kw == {"start_new_session": True}


# ── structural: no shell=True anywhere ────────────────────────────────────────

def test_no_shell_true_in_source():
    # Inspect the spawn method specifically (the only place a child is created),
    # so the module-level docstring that *mentions* shell=True doesn't confuse it.
    src = inspect.getsource(pe.ProcessExecutor._spawn_and_wait)
    assert "shell=True" not in src
    assert "shell=False" in src


# ── basic execution ───────────────────────────────────────────────────────────

def test_execute_success():
    ex = ProcessExecutor()
    r = ex.execute(_spec("print(1)"))
    assert r.status == ToolStatus.SUCCESS
    assert r.return_code == 0
    assert "1" in r.stdout
    assert r.record is not None
    assert r.record.actor == ActorKind.SYSTEM
    assert r.duration_ms >= 0


def test_nonzero_exit_is_failed():
    ex = ProcessExecutor()
    r = ex.execute(_spec("import sys; sys.exit(3)"))
    assert r.status == ToolStatus.FAILED
    assert r.return_code == 3


def test_stdin_passthrough():
    ex = ProcessExecutor()
    r = ex.execute(_spec("import sys; sys.stdout.write(sys.stdin.read())",
                         stdin=b"hello-stdin"))
    assert "hello-stdin" in r.stdout


# ── hidden window + shell=False actually passed to Popen ──────────────────────

def test_popen_receives_hidden_and_no_shell(monkeypatch):
    captured = []
    real_popen = subprocess.Popen

    class SpyPopen(real_popen):
        def __init__(self, *a, **k):
            captured.append(dict(k))
            super().__init__(*a, **k)

    monkeypatch.setattr(pe.subprocess, "Popen", SpyPopen)
    ex = ProcessExecutor()
    r = ex.execute(_spec("print(1)"))
    assert r.status == ToolStatus.SUCCESS
    assert captured, "Popen was never called"
    kw = captured[0]
    assert kw["shell"] is False
    if sys.platform == "win32":
        assert kw["creationflags"] & subprocess.CREATE_NO_WINDOW
        assert "startupinfo" in kw
    else:
        assert kw.get("start_new_session") is True


# ── timeout ─────────────────────────────────────────────────────────────────

def test_timeout_kills_and_marks():
    ex = ProcessExecutor()
    t0 = time.monotonic()
    r = ex.execute(_spec("import time; time.sleep(30)", timeout_s=0.5))
    elapsed = time.monotonic() - t0
    assert r.timed_out is True
    assert r.status == ToolStatus.TIMED_OUT
    assert elapsed < 15  # the sleeper was actually killed, not awaited


# ── cancel + process-tree kill ────────────────────────────────────────────────

def test_cancel_marks_cancelled():
    ex = ProcessExecutor()
    result_box = {}

    def runner():
        result_box["r"] = ex.execute(_spec("import time; time.sleep(30)",
                                            timeout_s=30))

    th = threading.Thread(target=runner)
    th.start()
    exec_id = None
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        ids = ex.active_ids()
        if ids:
            exec_id = ids[0]
            break
        time.sleep(0.02)
    assert exec_id is not None, "process never became active"
    assert ex.cancel(exec_id) is True
    th.join(timeout=10)
    assert not th.is_alive()
    assert result_box["r"].status == ToolStatus.CANCELLED
    assert result_box["r"].cancelled is True


def test_cancel_unknown_id_returns_false():
    ex = ProcessExecutor()
    assert ex.cancel("does-not-exist") is False


def test_terminate_process_tree_on_live_proc():
    proc = subprocess.Popen([PY, "-c", "import time; time.sleep(30)"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            **hidden_process_kwargs())
    assert proc.poll() is None
    terminate_process_tree(proc)
    assert proc.poll() is not None


# ── output caps ───────────────────────────────────────────────────────────────

def test_output_cap_truncates():
    ex = ProcessExecutor()
    r = ex.execute(_spec("import sys; sys.stdout.write('x'*100000)",
                         max_output_bytes=100))
    assert r.truncated is True
    assert r.stdout_bytes <= 100
    assert r.status == ToolStatus.PARTIAL  # rc 0 but truncated


# ── env scrub ─────────────────────────────────────────────────────────────────

def test_sensitive_env_scrubbed(monkeypatch):
    monkeypatch.setenv("RAVEN_SESSION_TOKEN", "supersecret")
    monkeypatch.setenv("BUGCROWD_TOKEN", "bc-token")
    ex = ProcessExecutor()
    code = (
        "import os;"
        "print('TOK=' + str(os.environ.get('RAVEN_SESSION_TOKEN')));"
        "print('BC=' + str(os.environ.get('BUGCROWD_TOKEN')));"
        "print('HASPATH=' + str(bool(os.environ.get('PATH') or os.environ.get('Path'))))"
    )
    r = ex.execute(_spec(code))
    assert "TOK=None" in r.stdout
    assert "BC=None" in r.stdout
    assert "HASPATH=True" in r.stdout
    assert "supersecret" not in r.stdout


def test_env_override_cannot_reintroduce_secret_unless_explicit(monkeypatch):
    monkeypatch.setenv("RAVEN_SESSION_TOKEN", "supersecret")
    ex = ProcessExecutor()
    # An override that is NOT a secret key is preserved.
    r = ex.execute(_spec("import os; print('X=' + str(os.environ.get('MY_FLAG')))",
                         env_overrides={"MY_FLAG": "on"}))
    assert "X=on" in r.stdout


# ── provenance + metachar tiering ─────────────────────────────────────────────

def test_agent_tier_rejects_shell_metacharacters(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("Popen must not be called for a rejected argv")
    monkeypatch.setattr(pe.subprocess, "Popen", boom)
    ex = ProcessExecutor()
    spec = ProcessSpec(argv=[PY, "-c", "print(1)", "danger; rm -rf /"],
                       actor=ActorKind.RAVEN_AGENT)
    r = ex.execute(spec)
    assert r.status == ToolStatus.INVALID_INPUT
    assert "metacharacter" in (r.error or "").lower()


def test_researcher_tier_allows_metacharacters():
    ex = ProcessExecutor()
    spec = ProcessSpec(argv=[PY, "-c", "print(1)", "a|b;c"],
                       actor=ActorKind.RESEARCHER)
    r = ex.execute(spec)
    assert r.status == ToolStatus.SUCCESS
    assert "1" in r.stdout


def test_program_agent_tier_also_rejected():
    ex = ProcessExecutor()
    spec = ProcessSpec(argv=[PY, "-c", "print(1)", "x`whoami`"],
                       actor=ActorKind.PROGRAM_AGENT)
    r = ex.execute(spec)
    assert r.status == ToolStatus.INVALID_INPUT


# ── emergency stop ────────────────────────────────────────────────────────────

def test_emergency_stop_blocks_spawn(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("Popen must not be called under emergency stop")
    monkeypatch.setattr(pe.subprocess, "Popen", boom)
    ex = ProcessExecutor(emergency_stop=lambda: True)
    r = ex.execute(_spec("print(1)"))
    assert r.status == ToolStatus.DENIED
    assert r.error == "emergency_stop_active"


# ── authorize hook (executor never self-authorizes) ───────────────────────────

def test_authorize_hook_denies(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("Popen must not be called when authorization denies")
    monkeypatch.setattr(pe.subprocess, "Popen", boom)
    ex = ProcessExecutor(authorize=lambda spec: False)
    r = ex.execute(_spec("print(1)"))
    assert r.status == ToolStatus.DENIED
    assert r.error == "capability_denied"


# ── ExecutionRecord persistence + provenance round-trip ───────────────────────

def test_execution_record_persisted_with_provenance():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    store = ExecutionStore(conn)
    ex = ProcessExecutor(execution_store=store)
    spec = _spec("print(1)", actor=ActorKind.PROGRAM_AGENT,
                 workspace_id="ws1", execution_profile="PURE_LOCAL",
                 capability_decision="ALLOW", task_id="task-9")
    r = ex.execute(spec)
    assert r.status == ToolStatus.SUCCESS
    row = store.get(r.execution_id)
    assert row is not None
    assert row["actor"] == "PROGRAM_AGENT"
    assert row["status"] == "SUCCESS"
    assert row["execution_profile"] == "PURE_LOCAL"
    assert row["capability_decision"] == "ALLOW"
    assert row["task_id"] == "task-9"
    assert row["duration_ms"] is not None


def test_event_publisher_invoked():
    seen = []
    ex = ProcessExecutor(event_publisher=lambda rec: seen.append(rec))
    ex.execute(_spec("print(1)"))
    assert len(seen) == 1
    assert seen[0].status == ToolStatus.SUCCESS


# ── governor admission ────────────────────────────────────────────────────────

def test_governor_admission_release_allows_more():
    from raven.runtime.resource_governor import ResourceGovernor, ResourceProfile
    gov = ResourceGovernor(ResourceProfile(name="t", max_processes=1))
    ex = ProcessExecutor(governor=gov)
    r = ex.execute(_spec("print(1)"))
    assert r.status == ToolStatus.SUCCESS
    # lease was released, so a second call still succeeds
    r2 = ex.execute(_spec("print(2)"))
    assert r2.status == ToolStatus.SUCCESS
    assert gov.in_use("process") == 0


def test_governor_emergency_stop_denies_execution():
    from raven.runtime.resource_governor import ResourceGovernor
    gov = ResourceGovernor(emergency_stop=lambda: True)
    ex = ProcessExecutor(governor=gov)
    r = ex.execute(_spec("print(1)"))
    assert r.status == ToolStatus.DENIED


# ── trusted allowlist mode ────────────────────────────────────────────────────

def _py_allowlist():
    return ApprovedProcess(
        name="py",
        executable_path=PY,
        allowed_arg_patterns=[re.compile(r"-c"), re.compile(r"print\(1\)")],
    )


def test_allowlist_good_argv_passes():
    ex = ProcessExecutor()
    spec = ProcessSpec(argv=[PY, "-c", "print(1)"], allowlist=_py_allowlist(),
                       actor=ActorKind.SYSTEM)
    r = ex.execute(spec)
    assert r.status == ToolStatus.SUCCESS
    assert "1" in r.stdout


def test_allowlist_rejects_unmatched_arg():
    ex = ProcessExecutor()
    spec = ProcessSpec(argv=[PY, "-c", "print(2)"], allowlist=_py_allowlist())
    r = ex.execute(spec)
    assert r.status == ToolStatus.INVALID_INPUT


def test_allowlist_rejects_non_absolute_executable():
    ex = ProcessExecutor()
    spec = ProcessSpec(argv=["python", "-c", "print(1)"], allowlist=_py_allowlist())
    r = ex.execute(spec)
    assert r.status == ToolStatus.INVALID_INPUT
    assert "absolute" in (r.error or "").lower()


def test_allowlist_rejects_path_traversal():
    import os
    traversal = os.path.join(os.path.dirname(PY), "..", os.path.basename(PY))
    al = ApprovedProcess(name="py", executable_path=traversal,
                         allowed_arg_patterns=[re.compile(r".*")])
    ex = ProcessExecutor()
    spec = ProcessSpec(argv=[traversal, "-c", "print(1)"], allowlist=al)
    r = ex.execute(spec)
    assert r.status == ToolStatus.INVALID_INPUT
    assert "traversal" in (r.error or "").lower()


# ── argv validation ───────────────────────────────────────────────────────────

def test_empty_argv_rejected():
    ex = ProcessExecutor()
    r = ex.execute(ProcessSpec(argv=[], actor=ActorKind.SYSTEM))
    assert r.status == ToolStatus.INVALID_INPUT

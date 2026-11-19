"""RAVEN canonical ProcessExecutor (Wave 2 — A2-PROC).

This is the ONE trusted process-execution choke point for the server path
(CANONICAL_ARCHITECTURE §1 row 2 / §2 C-1, PROCESS_ARCHITECTURE §3.1). No second
launcher survives: the hardening of ``security.process_guard.SafeProcessLauncher``
(env scrub, shell-metacharacter reject, absolute-path/no-``..`` allowlist, output
caps, ``shell=False``) is MIGRATED in here, the Windows hidden-window pattern from
``engine.py``/``server.py::_run_tool`` is the shared :func:`hidden_process_kwargs`
helper (C-4), and the proven tree-kill from ``engine.py`` is migrated into
:func:`terminate_process_tree`.

ADDITIVE ONLY: nothing on the live path imports this yet. Later waves reroute
``terminal.py``, ``server.py::_run_tool`` and the recon ``ExternalToolCollector``
onto it (see INTEGRATION REQUIREMENTS in the hand-off).

Design invariants enforced here:

* ``shell=False`` always — there is no code path to a shell interpreter, so model
  output can never structurally reach a raw shell. Callers pass an **argv list**.
* Agent tiers (``RAVEN_AGENT`` / ``PROGRAM_AGENT``) are argv-only and every arg is
  rejected if it contains a shell metacharacter. The trusted tiers (``RESEARCHER``,
  ``SYSTEM``) construct their own argv (e.g. ``["powershell","-Command", ...]``)
  and are not metachar-filtered — but still never use ``shell=True``.
* Hidden window by default (CREATE_NO_WINDOW + STARTUPINFO/SW_HIDE on Windows).
* Scrubbed environment (``SENSITIVE_ENV_VARS`` never reach the child).
* Output byte caps, hard timeout, cancel, and process-tree termination.
* An emergency-stop predicate is checked **before** every spawn.
* Every execution emits an :class:`~raven.runtime.execution.ExecutionRecord`
  stamped with :class:`~raven.runtime.execution.ActorKind` provenance, and (when an
  ``ExecutionStore`` / event publisher is injected) persists + publishes it.

The executor never self-authorizes: it accepts an upstream capability decision via
``ProcessSpec.capability_decision`` / an injected ``authorize`` hook and records it;
the actual CapabilityGate wiring is a later wave.

Public API
----------
``ProcessExecutor(*, governor=None, execution_store=None, event_publisher=None,
                  emergency_stop=None, authorize=None, default_cwd=None,
                  default_timeout_s=60.0, default_max_output_bytes=1_048_576,
                  admit_timeout_s=None)``

``execute(spec: ProcessSpec) -> ProcessResult``    (alias ``run``)
``cancel(execution_id: str) -> bool``
``active_ids() -> list[str]``
"""
from __future__ import annotations

import contextlib
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .execution import ActorKind, ExecutionRecord, ToolStatus
from .resource_governor import (
    ResourceAdmissionTimeout,
    ResourceDenied,
    ResourceGovernor,
)

# ── Migrated hardening constants (single canonical home) ──────────────────────

# Environment variables that must never be passed to child processes
# (migrated verbatim from security.process_guard.SENSITIVE_ENV_VARS).
SENSITIVE_ENV_VARS = frozenset({
    "RAVEN_API_KEY", "RAVEN_SESSION_TOKEN", "RAVEN_SECRET",
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GITHUB_TOKEN", "GH_TOKEN",
    "BUGCROWD_TOKEN", "HACKERONE_TOKEN",
    # LLM provider credentials (Claude is wired into RAVEN) — never inherited by children.
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY",
})

# Any argv element containing one of these is rejected for agent tiers / allowlist
# mode (migrated from security.process_guard.SHELL_METACHARACTERS).
SHELL_METACHARACTERS = re.compile(r"[;&|`$><\n\r\\]")

# A minimal, non-secret env used by env_mode="minimal" (filtered to what exists).
_MINIMAL_ENV_KEYS = (
    "PATH", "PATHEXT", "SYSTEMROOT", "SystemRoot", "WINDIR",
    "TEMP", "TMP", "TMPDIR", "COMSPEC",
    "LANG", "LC_ALL", "LC_CTYPE", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
)

MAX_DEFAULT_TIMEOUT_S = 60.0
MAX_ALLOWED_TIMEOUT_S = 300.0
MAX_DEFAULT_OUTPUT    = 1 * 1024 * 1024    # 1 MiB
MAX_ALLOWED_OUTPUT    = 50 * 1024 * 1024   # 50 MiB

# Actor tiers that are argv-only + shell-metacharacter rejected.
_AGENT_TIERS = frozenset({ActorKind.RAVEN_AGENT, ActorKind.PROGRAM_AGENT})


# ── Shared hidden-window helper (C-4: the ONLY source of these flags) ─────────

def hidden_process_kwargs(group: bool = False) -> dict:
    """Return the subprocess kwargs that keep a child window hidden.

    On Windows: ``CREATE_NO_WINDOW`` plus a ``STARTUPINFO`` with ``SW_HIDE`` as a
    belt-and-suspenders guard against a child that would otherwise show its own
    window. With ``group=True`` also sets ``CREATE_NEW_PROCESS_GROUP`` (needed for
    a ``CTRL_BREAK`` cancel). On non-Windows returns ``{"start_new_session": True}``
    so the child leads its own session/process-group and can be killed as a tree.

    This is the single source of truth imported by ``engine.py``, ``_run_tool``,
    ``rust_bridge.py`` and the terminal path (per CANONICAL §2 C-4).
    """
    if sys.platform == "win32":
        flags = subprocess.CREATE_NO_WINDOW
        if group:
            flags |= subprocess.CREATE_NEW_PROCESS_GROUP
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        return {"creationflags": flags, "startupinfo": si}
    return {"start_new_session": True}


def terminate_process_tree(proc: "subprocess.Popen", timeout: float = 2.0,
                           pgid: Optional[int] = None) -> None:
    """Kill ``proc`` and all of its descendants (migrated from engine.py).

    Windows: ``taskkill /PID <pid> /T /F`` (spawned hidden), then ``proc.kill()``
    as a fallback. POSIX: ``SIGTERM`` then ``SIGKILL`` to the child's process group.
    Reaps the process so no zombie remains.
    """
    pid = proc.pid
    if sys.platform != "win32" and pgid is not None:
        # POSIX with a known process group (start_new_session ⇒ pgid == leader pid):
        # signal the WHOLE group even if the leader already exited — a backgrounded
        # descendant (`sleep 600 &`, `setsid …`) otherwise survives timeouts/cancel
        # and keeps the output pipes open.
        import signal as _signal
        with contextlib.suppress(ProcessLookupError, OSError):
            os.killpg(pgid, _signal.SIGTERM)
        with contextlib.suppress(Exception):
            proc.wait(timeout=timeout)
        with contextlib.suppress(ProcessLookupError, OSError):
            os.killpg(pgid, _signal.SIGKILL)
        with contextlib.suppress(Exception):
            proc.wait(timeout=timeout)
        return
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout, **hidden_process_kwargs(),
            )
        except (OSError, subprocess.SubprocessError):
            pass
        if proc.poll() is None:
            with contextlib.suppress(OSError):
                proc.kill()
    else:
        import signal as _signal
        with contextlib.suppress(ProcessLookupError, OSError):
            os.killpg(os.getpgid(pid), _signal.SIGTERM)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError, OSError):
                os.killpg(os.getpgid(pid), _signal.SIGKILL)
    with contextlib.suppress(Exception):
        proc.wait(timeout=timeout)


# ── Allowlist spec (migrated from SafeProcessLauncher.ApprovedProcess) ────────

@dataclass
class ApprovedProcess:
    """A pre-approved executable spec for trusted-allowlist mode.

    When a :class:`ProcessSpec` carries one of these, the executor enforces the
    full ``SafeProcessLauncher`` contract before spawn: absolute executable path,
    no ``..``, every arg free of shell metacharacters, and (when patterns are
    given) every arg ``fullmatch``-ing one allowed pattern.
    """
    name:                 str
    executable_path:      str
    allowed_arg_patterns: List["re.Pattern"] = field(default_factory=list)
    max_timeout_s:        float = MAX_DEFAULT_TIMEOUT_S
    max_output_bytes:     int   = MAX_DEFAULT_OUTPUT


# ── Spec / Result ─────────────────────────────────────────────────────────────

@dataclass
class ProcessSpec:
    """Everything needed to run one child process."""
    argv:               List[str]
    cwd:                Optional[str] = None
    env_mode:           str = "scrubbed_inherit"   # scrubbed_inherit|minimal|explicit
    env_overrides:      Dict[str, str] = field(default_factory=dict)
    stdin:              Optional[bytes] = None
    timeout_s:          Optional[float] = None
    max_output_bytes:   Optional[int] = None
    allowlist:          Optional[ApprovedProcess] = None
    new_process_group:  bool = False
    # provenance / audit
    actor:              ActorKind = ActorKind.SYSTEM
    tool_id:            str = "process.exec"
    task_id:            Optional[str] = None
    agent_session_id:   Optional[str] = None
    workspace_id:       Optional[str] = None
    correlation_id:     Optional[str] = None
    execution_profile:  Optional[str] = None
    capability_decision: Optional[str] = None   # set by an upstream CapabilityGate
    execution_id:       Optional[str] = None     # optional override (else generated)


@dataclass
class ProcessResult:
    """Outcome of one execution."""
    execution_id:  str
    argv:          List[str]
    return_code:   int = -1
    stdout:        str = ""
    stderr:        str = ""
    stdout_bytes:  int = 0
    stderr_bytes:  int = 0
    duration_ms:   int = 0
    timed_out:     bool = False
    cancelled:     bool = False
    truncated:     bool = False
    status:        ToolStatus = ToolStatus.FAILED
    error:         Optional[str] = None
    resource_usage: Dict = field(default_factory=dict)
    record:        Optional[ExecutionRecord] = None

    @property
    def success(self) -> bool:
        return self.status == ToolStatus.SUCCESS

    def to_dict(self) -> dict:
        return {
            "execution_id": self.execution_id,
            "return_code": self.return_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "truncated": self.truncated,
            "status": self.status.value,
            "error": self.error,
        }


class ProcessExecutorError(Exception):
    pass


# ── Executor ──────────────────────────────────────────────────────────────────

class ProcessExecutor:
    """The one canonical trusted process executor (see module docstring)."""

    def __init__(
        self,
        *,
        governor: Optional[ResourceGovernor] = None,
        execution_store=None,
        event_publisher: Optional[Callable[[ExecutionRecord], None]] = None,
        emergency_stop: Optional[Callable[[], bool]] = None,
        authorize: Optional[Callable[[ProcessSpec], bool]] = None,
        default_cwd: Optional[str] = None,
        default_timeout_s: float = MAX_DEFAULT_TIMEOUT_S,
        default_max_output_bytes: int = MAX_DEFAULT_OUTPUT,
        admit_timeout_s: Optional[float] = None,
    ):
        self._governor = governor
        self._store = execution_store
        self._publish = event_publisher
        self._emergency_stop = emergency_stop or (lambda: False)
        self._authorize = authorize
        self._default_cwd = default_cwd
        self._default_timeout = float(default_timeout_s)
        self._default_max_output = int(default_max_output_bytes)
        self._admit_timeout = admit_timeout_s
        self._active: Dict[str, subprocess.Popen] = {}
        self._pgids: Dict[str, Optional[int]] = {}
        self._task_of: Dict[str, Optional[str]] = {}
        self._cancelled: set[str] = set()
        self._lock = threading.RLock()

    # -- public API ------------------------------------------------------------

    def execute(self, spec: ProcessSpec) -> ProcessResult:
        rec = ExecutionRecord(
            tool_id=spec.tool_id,
            actor=spec.actor,
            task_id=spec.task_id,
            agent_session_id=spec.agent_session_id,
            workspace_id=spec.workspace_id,
            correlation_id=spec.correlation_id,
            execution_profile=spec.execution_profile,
            capability_decision=spec.capability_decision,
            input_summary=self._input_summary(spec.argv),
        )
        if spec.execution_id:
            rec.execution_id = spec.execution_id

        # 1) Structural validation of the argv.
        err = self._validate_argv(spec)
        if err is not None:
            return self._finalize(spec, rec, ToolStatus.INVALID_INPUT, error=err)

        # 2) Emergency stop — checked BEFORE any spawn.
        if self._emergency_stop():
            return self._finalize(spec, rec, ToolStatus.DENIED,
                                  error="emergency_stop_active")

        # 3) Upstream authorization hook (executor never self-authorizes).
        if self._authorize is not None and not self._authorize(spec):
            return self._finalize(spec, rec, ToolStatus.DENIED,
                                  error="capability_denied")

        # 4) Resource admission (acquired before spawn, released after).
        timeout = self._resolve_timeout(spec)
        max_out = self._resolve_max_output(spec)
        try:
            if self._governor is not None:
                with self._governor.admit("process", timeout=self._admit_timeout,
                                          profile=spec.execution_profile):
                    return self._spawn_and_wait(spec, rec, timeout, max_out)
            return self._spawn_and_wait(spec, rec, timeout, max_out)
        except (ResourceDenied, ResourceAdmissionTimeout) as exc:
            return self._finalize(spec, rec, ToolStatus.DENIED, error=str(exc))

    run = execute  # alias for callers that prefer .run(...)

    def cancel(self, execution_id: str) -> bool:
        """Terminate a running execution (and its process tree). Returns True if
        a live process was found and signalled."""
        with self._lock:
            proc = self._active.get(execution_id)
            pgid = self._pgids.get(execution_id)
            if proc is not None:
                self._cancelled.add(execution_id)
        if proc is None:
            return False
        terminate_process_tree(proc, pgid=pgid)
        return True

    def active_ids(self) -> List[str]:
        with self._lock:
            return list(self._active)

    def cancel_all(self) -> int:
        """Terminate every running execution (Emergency Stop / app shutdown).
        Returns how many were signalled."""
        return sum(1 for eid in self.active_ids() if self.cancel(eid))

    shutdown = cancel_all

    def cancel_task(self, task_id: str) -> int:
        """Terminate every running execution spawned for ``task_id`` (agent run cancel)."""
        if not task_id:
            return 0
        with self._lock:
            ids = [eid for eid, tid in self._task_of.items() if tid == task_id]
        return sum(1 for eid in ids if self.cancel(eid))

    # -- validation ------------------------------------------------------------

    def _validate_argv(self, spec: ProcessSpec) -> Optional[str]:
        argv = spec.argv
        if not isinstance(argv, (list, tuple)) or not argv:
            return "argv must be a non-empty list"
        for a in argv:
            if not isinstance(a, str):
                return f"argv elements must be str, got {type(a).__name__}"

        if spec.allowlist is not None:
            return self._validate_allowlist(spec)

        # Agent tiers: argv-only + shell-metacharacter reject on the ARGUMENTS
        # (argv[1:]). The executable (argv[0]) is the tool identity — it is a
        # resolved program path (which on Windows legitimately contains
        # backslashes) and is validated by abs-path/no-``..`` rules in allowlist
        # mode, exactly as SafeProcessLauncher did; it is never metachar-checked.
        if spec.actor in _AGENT_TIERS:
            for a in argv[1:]:
                if SHELL_METACHARACTERS.search(a):
                    return f"argument contains shell metacharacters: {a!r}"
        return None

    def _validate_allowlist(self, spec: ProcessSpec) -> Optional[str]:
        spec_al = spec.allowlist
        exe = spec.argv[0]
        if not os.path.isabs(exe):
            return f"executable path must be absolute: {exe!r}"
        if ".." in exe:
            return "path traversal ('..') in executable path is not allowed"
        if os.path.normcase(os.path.abspath(exe)) != os.path.normcase(
                os.path.abspath(spec_al.executable_path)):
            return (f"executable {exe!r} does not match approved "
                    f"{spec_al.executable_path!r}")
        for a in spec.argv[1:]:
            if SHELL_METACHARACTERS.search(a):
                return f"argument contains shell metacharacters: {a!r}"
            if spec_al.allowed_arg_patterns and not any(
                    p.fullmatch(a) for p in spec_al.allowed_arg_patterns):
                return f"argument {a!r} not permitted by spec {spec_al.name!r}"
        return None

    # -- spawn -----------------------------------------------------------------

    def _spawn_and_wait(self, spec: ProcessSpec, rec: ExecutionRecord,
                        timeout: float, max_out: int) -> ProcessResult:
        env = self._build_env(spec)
        cwd = spec.cwd or self._default_cwd
        stdin_data = spec.stdin
        popen_kwargs = dict(
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            cwd=cwd,
            env=env,
            shell=False,                      # argv only; never a shell interpreter
            **hidden_process_kwargs(group=spec.new_process_group),
        )
        t0 = time.monotonic()
        try:
            proc = subprocess.Popen(list(spec.argv), **popen_kwargs)
        except (OSError, ValueError) as exc:
            return self._finalize(spec, rec, ToolStatus.FAILED,
                                  error=f"spawn failed: {exc}")

        exec_id = rec.execution_id
        # start_new_session ⇒ the child leads its own group (pgid == pid). Recorded
        # now because os.getpgid() fails once the leader has been reaped, while its
        # backgrounded descendants may still be running.
        pgid = proc.pid if (sys.platform != "win32" and popen_kwargs.get("start_new_session")) else None
        with self._lock:
            self._active[exec_id] = proc
            self._pgids[exec_id] = pgid
            self._task_of[exec_id] = spec.task_id

        # Output is read INCREMENTALLY and capped while reading — communicate() would
        # buffer everything first (`yes`, `cat /dev/zero` → GBs of RAM before the cap).
        out_buf, err_buf = bytearray(), bytearray()
        over = {"stdout": False, "stderr": False}

        def _drain(stream, buf, key):
            try:
                while True:
                    chunk = stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536)
                    if not chunk:
                        break
                    room = max_out - len(buf)
                    if room > 0:
                        buf.extend(chunk[:room])
                    if len(chunk) > room:
                        over[key] = True
            except (OSError, ValueError):
                pass

        readers = [threading.Thread(target=_drain, args=(proc.stdout, out_buf, "stdout"), daemon=True),
                   threading.Thread(target=_drain, args=(proc.stderr, err_buf, "stderr"), daemon=True)]
        for t in readers:
            t.start()
        if stdin_data is not None and proc.stdin is not None:
            def _feed():
                with contextlib.suppress(OSError, ValueError):
                    proc.stdin.write(stdin_data)
                with contextlib.suppress(OSError, ValueError):
                    proc.stdin.close()
            threading.Thread(target=_feed, daemon=True).start()

        timed_out = False
        try:
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                terminate_process_tree(proc, pgid=pgid)
            # The leader has exited; give the readers a bounded moment. If a
            # descendant still holds the pipes (it was backgrounded), kill the group
            # and stop waiting — never block the request thread indefinitely.
            deadline = time.monotonic() + max(0.0, timeout - (time.monotonic() - t0)) + 1.0
            for t in readers:
                t.join(max(0.0, deadline - time.monotonic()))
            if any(t.is_alive() for t in readers):
                timed_out = True  # descendants outlived the time budget
                terminate_process_tree(proc, pgid=pgid)
                for t in readers:
                    t.join(0.5)
                # A descendant that left our process group (e.g. `setsid`) can keep
                # the pipe open. Do NOT close the stream here — close() blocks on the
                # reader's buffer lock. The daemon readers keep draining (output stays
                # capped) and exit at EOF; the request returns now.
        finally:
            with self._lock:
                self._active.pop(exec_id, None)
                self._pgids.pop(exec_id, None)
                self._task_of.pop(exec_id, None)
                cancelled = exec_id in self._cancelled
                self._cancelled.discard(exec_id)

        duration_ms = int((time.monotonic() - t0) * 1000)
        out, err = bytes(out_buf), bytes(err_buf)
        truncated = over["stdout"] or over["stderr"]

        rc = proc.returncode if proc.returncode is not None else -1
        if cancelled:
            status = ToolStatus.CANCELLED
        elif timed_out:
            status = ToolStatus.TIMED_OUT
        elif rc == 0:
            status = ToolStatus.PARTIAL if truncated else ToolStatus.SUCCESS
        else:
            status = ToolStatus.FAILED

        result = ProcessResult(
            execution_id=exec_id,
            argv=list(spec.argv),
            return_code=rc,
            stdout=out.decode("utf-8", errors="replace"),
            stderr=err.decode("utf-8", errors="replace"),
            stdout_bytes=len(out),
            stderr_bytes=len(err),
            duration_ms=duration_ms,
            timed_out=timed_out,
            cancelled=cancelled,
            truncated=truncated,
            status=status,
        )
        return self._finalize(spec, rec, status, result=result,
                              duration_ms=duration_ms)

    # -- env -------------------------------------------------------------------

    def _build_env(self, spec: ProcessSpec) -> Dict[str, str]:
        mode = spec.env_mode
        if mode == "explicit":
            env = dict(spec.env_overrides)
        elif mode == "minimal":
            env = {k: os.environ[k] for k in _MINIMAL_ENV_KEYS if k in os.environ}
            env.update(spec.env_overrides)
        else:  # scrubbed_inherit (default)
            env = {k: v for k, v in os.environ.items()
                   if k not in SENSITIVE_ENV_VARS}
            env.update(spec.env_overrides)
        # Never let an override smuggle a scrubbed secret back in.
        for secret in SENSITIVE_ENV_VARS:
            if secret in env and secret not in spec.env_overrides:
                env.pop(secret, None)
        return env

    # -- finalize / record -----------------------------------------------------

    def _finalize(self, spec: ProcessSpec, rec: ExecutionRecord,
                  status: ToolStatus, *, result: Optional[ProcessResult] = None,
                  error: Optional[str] = None, duration_ms: Optional[int] = None
                  ) -> ProcessResult:
        rec.finish(status, error=error or (result.error if result else None))
        if duration_ms is not None:
            rec.duration_ms = duration_ms
        if result is not None:
            rec.resource_usage = {
                "duration_ms": result.duration_ms,
                "stdout_bytes": result.stdout_bytes,
                "stderr_bytes": result.stderr_bytes,
                "return_code": result.return_code,
                "timed_out": result.timed_out,
                "cancelled": result.cancelled,
                "truncated": result.truncated,
            }
        else:
            result = ProcessResult(
                execution_id=rec.execution_id,
                argv=list(spec.argv),
                status=status,
                error=error,
                duration_ms=rec.duration_ms or 0,
            )
        rec.capability_decision = spec.capability_decision
        result.resource_usage = rec.resource_usage
        result.record = rec

        # Persist + publish (best-effort; never let audit failure mask the result).
        if self._store is not None:
            with contextlib.suppress(Exception):
                self._store.save(rec)
        if self._publish is not None:
            with contextlib.suppress(Exception):
                self._publish(rec)
        return result

    # -- helpers ---------------------------------------------------------------

    def _resolve_timeout(self, spec: ProcessSpec) -> float:
        t = spec.timeout_s if spec.timeout_s is not None else self._default_timeout
        if spec.allowlist is not None:
            t = min(t, spec.allowlist.max_timeout_s)
        return max(0.0, min(float(t), MAX_ALLOWED_TIMEOUT_S))

    def _resolve_max_output(self, spec: ProcessSpec) -> int:
        m = spec.max_output_bytes if spec.max_output_bytes is not None \
            else self._default_max_output
        if spec.allowlist is not None:
            m = min(m, spec.allowlist.max_output_bytes)
        return max(0, min(int(m), MAX_ALLOWED_OUTPUT))

    @staticmethod
    def _input_summary(argv: List[str]) -> str:
        """A human-readable, secret-free summary (basename + arg count)."""
        if not argv:
            return "<empty argv>"
        base = os.path.basename(argv[0]) or argv[0]
        return f"{base} ({max(0, len(argv) - 1)} args)"

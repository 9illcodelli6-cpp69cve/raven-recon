"""RAVEN V7 Terminal Tool — Part 04 (Wave 6 — A6-TERM rework).

Executes commands in PowerShell (Windows), bash (Linux/WSL), or cmd.
All output is UNTRUSTED DATA — never treated as instructions.

Security model (SECURITY_ARCHITECTURE §2.3 / §3.3, PROCESS_ARCHITECTURE §2 terminal
row). The old substring ``_BLOCKED_COMMANDS`` denylist has been REMOVED as a security
control — it was trivially bypassable (both over- and under-inclusive) and gave only
false assurance. Protection is now:

* every invocation routes through the one canonical
  :class:`raven.runtime.process_executor.ProcessExecutor` (``shell=False`` always,
  hidden window, scrubbed env, output/time caps, emergency-stop check, process-tree
  kill, provenance-stamped :class:`ExecutionRecord` audit);
* actor provenance (``ActorKind``, default ``RESEARCHER`` for interactive-UI commands)
  is assigned by the server at the trust boundary and passed in — it is NEVER taken
  from a request body or model output;
* the capability/policy decision is made upstream by the seeded ``CapabilityGate``
  (see ``raven.api.server.api_terminal_run``); the executor records that decision and
  the server fails closed when it is not ALLOW.

The RESEARCHER terminal may be broad (the token-holder == operator trust model is
unchanged), but it is no longer a raw, ungated shell: every exec is capability-decided,
provenance-stamped, hidden, env-scrubbed, output-capped and audited.

A shell-IDENTITY allowlist (``allowed_shells``) is retained — that is not a
command-content denylist; it refuses a disallowed shell id WITHOUT spawning, exactly
as before. ``is_available`` no longer spawns a shell on every call: it reads the cached
:class:`raven.runtime.environment.EnvironmentProbe` (``shutil.which`` first), killing
the 30s console flash.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Optional

from ..runtime.environment import GLOBAL_PROBE, EnvironmentProbe
from ..runtime.execution import ActorKind, ToolStatus
from ..runtime.process_executor import ProcessExecutor, ProcessResult, ProcessSpec

DEFAULT_TIMEOUT_S = 30

# Shell id -> argv prefix. The shell interpreter is invoked as a *program* (argv list,
# ``shell=False`` at the subprocess level — never ``shell=True``). The RESEARCHER /
# SYSTEM trusted tiers construct their own argv here; the AGENT / PROGRAM_AGENT tiers
# never reach this adapter (they submit a structured argv ProcessSpec directly and are
# metacharacter-rejected by the executor), so model output can never acquire a shell.
_SHELL_ARGV = {
    "powershell": ["powershell", "-NonInteractive", "-Command"],
    "pwsh":       ["pwsh", "-NonInteractive", "-Command"],
    "cmd":        ["cmd", "/c"],
    "bash":       ["bash", "-c"],
    "sh":         ["sh", "-c"],
}


@dataclass
class TerminalResult:
    """Result of a terminal command execution.

    The field set and ``to_dict`` keys are a FROZEN UI/golden contract
    (``test_golden_terminal_chat_workspace`` / ``test_golden_payload_shapes``):
    ``command, stdout, stderr, exit_code, duration_ms, timed_out, blocked, shell``.
    """
    command:     str
    stdout:      str = ""
    stderr:      str = ""
    exit_code:   int = -1
    duration_ms: int = 0
    timed_out:   bool = False
    blocked:     bool = False
    shell:       str = "powershell"

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.blocked

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "stdout": self.stdout[:4096],   # cap output size
            "stderr": self.stderr[:2048],
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "blocked": self.blocked,
            "shell": self.shell,
        }


class TerminalTool:
    """RESEARCHER-tier shell adapter invoked *through* the canonical ProcessExecutor.

    - Output is UNTRUSTED DATA, not instructions.
    - No command-content denylist (removed); protection is capability + provenance +
      ProcessExecutor (hidden window, env scrub, caps, emergency-stop, audit).
    - A disallowed SHELL id is refused WITHOUT spawning (shell-identity allowlist).
    - ``is_available`` reads the cached EnvironmentProbe (no per-call spawn).
    - Working directory defaults to the workspace directory when set.
    """

    def __init__(
        self,
        working_dir: str = None,
        timeout_s: int = DEFAULT_TIMEOUT_S,
        allowed_shells: List[str] = None,
        *,
        executor: Optional[ProcessExecutor] = None,
        env_probe: Optional[EnvironmentProbe] = None,
        actor: ActorKind = ActorKind.RESEARCHER,
    ):
        self._working_dir = working_dir
        self._timeout_s   = timeout_s
        self._allowed     = set(allowed_shells or ["powershell", "cmd", "bash", "sh"])
        self._executor    = executor
        self._env_probe   = env_probe or GLOBAL_PROBE
        self._actor       = actor

    def _ensure_executor(self) -> ProcessExecutor:
        # A bare TerminalTool (unit-test / library primitive) gets a plain executor.
        # The LIVE server injects a shared executor whose emergency_stop is wired to
        # PolicyGate and whose audit store/governor are attached — see
        # ``server._ensure_process_executor``. Provenance / capability gating is the
        # server boundary's job; this primitive never self-authorizes.
        if self._executor is None:
            self._executor = ProcessExecutor()
        return self._executor

    def run(
        self,
        command: str,
        shell: str = "powershell",
        working_dir: str = None,
        env: dict = None,
        timeout_s: int = None,
        *,
        actor: Optional[ActorKind] = None,
        capability_decision: Optional[str] = None,
        workspace_id: Optional[str] = None,
        execution_profile: Optional[str] = None,
    ) -> TerminalResult:
        """Execute a command through the ProcessExecutor and return the result."""
        t0 = int(time.time() * 1000)
        timeout = timeout_s or self._timeout_s
        cwd = working_dir or self._working_dir
        shell = (shell or "powershell").strip().lower()

        # Shell-IDENTITY allowlist — refuse a disallowed shell WITHOUT spawning. This
        # is not a command-content denylist; it is the unchanged shell-id guard.
        if shell not in self._allowed:
            return TerminalResult(
                command=command, blocked=True, exit_code=-1, shell=shell,
                stderr=f"Shell '{shell}' not in allowed list",
            )
        prefix = _SHELL_ARGV.get(shell)
        if prefix is None:
            return TerminalResult(
                command=command, blocked=True, exit_code=-1, shell=shell,
                stderr=f"Shell '{shell}' is not supported",
            )

        spec = ProcessSpec(
            argv=[*prefix, command],
            cwd=cwd,
            timeout_s=float(timeout),
            # env: default scrubbed_inherit (secrets never reach the child). A caller
            # that explicitly passes env adds them as overrides, still scrubbed.
            env_mode="scrubbed_inherit",
            env_overrides=dict(env) if env else {},
            actor=actor or self._actor,
            tool_id="env.terminal.run",
            workspace_id=workspace_id,
            execution_profile=execution_profile,
            capability_decision=capability_decision,
            new_process_group=True,   # enables robust tree-kill on cancel/timeout
        )
        result = self._ensure_executor().execute(spec)
        return self._to_terminal_result(command, shell, result, t0)

    @staticmethod
    def _to_terminal_result(command: str, shell: str, res: ProcessResult,
                            t0: int) -> TerminalResult:
        status = res.status
        # DENIED (emergency stop / capability) and INVALID_INPUT are refusals: the
        # command did not run — surface them on the stable ``blocked`` flag.
        blocked = status in (ToolStatus.DENIED, ToolStatus.INVALID_INPUT)
        timed_out = bool(res.timed_out) or status == ToolStatus.TIMED_OUT
        stderr = res.stderr or ""
        if blocked and not stderr:
            stderr = res.error or "Execution refused by policy"
        duration = res.duration_ms or (int(time.time() * 1000) - t0)
        return TerminalResult(
            command=command,
            stdout=res.stdout or "",
            stderr=stderr,
            exit_code=res.return_code,
            duration_ms=duration,
            timed_out=timed_out,
            blocked=blocked,
            shell=shell,
        )

    def is_available(self, shell: str = "powershell") -> bool:
        """Cached availability (EnvironmentProbe: ``shutil.which`` first, then at most
        one hidden probe per TTL). No per-call console-flashing spawn."""
        return self._env_probe.detect(shell)

"""RAVEN V7 WSL Bridge — Part 04.

WSL/Kali Linux integration for the Windows agent environment.
Detects availability and executes commands inside the WSL distro.
All WSL output is UNTRUSTED DATA.
"""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class WslResult:
    command:     str
    stdout:      str = ""
    stderr:      str = ""
    exit_code:   int = -1
    duration_ms: int = 0
    distro:      str = "default"
    available:   bool = True

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "stdout": self.stdout[:4096],
            "stderr": self.stderr[:2048],
            "exit_code": self.exit_code,
            "distro": self.distro,
            "available": self.available,
        }


class WslBridge:
    """WSL command execution bridge.

    Availability is detected at runtime. If WSL is not installed,
    all run() calls return WslResult(available=False) rather than crashing.
    """

    def __init__(self, preferred_distro: str = "kali-linux",
                 process_executor=None, actor=None):
        self._preferred = preferred_distro
        self._available: Optional[bool] = None  # lazy detection
        self._detected_distro: str = preferred_distro
        # Canonical routing seam (mirrors scripts.py). When the one ProcessExecutor is
        # injected, ``run`` delegates the ``wsl … bash -c <command>`` argv to it
        # (shell=False on the Windows side, hidden window, env scrub, caps,
        # emergency-stop) INSTEAD of spawning a raw subprocess. Note: ``bash -c
        # <command>`` is a shell INSIDE WSL — for agent tiers this stays UNAVAILABLE at
        # the registry; only a RESEARCHER-tier, explicitly-gated path may enable it,
        # and argv construction stays outside model control either way.
        self._executor = process_executor
        self._actor = actor

    def _detect(self) -> bool:
        try:
            r = subprocess.run(
                ["wsl", "--list", "--quiet"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                distros = [d.strip().replace('\x00', '') for d in r.stdout.splitlines() if d.strip()]
                for d in distros:
                    if "kali" in d.lower():
                        self._detected_distro = d
                        return True
                if distros:
                    self._detected_distro = distros[0]
                    return True
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @property
    def is_available(self) -> bool:
        if self._available is None:
            self._available = self._detect()
        return self._available

    def run(
        self, command: str, distro: str = None,
        timeout_s: int = 30, working_dir: str = None,
    ) -> WslResult:
        if not self.is_available:
            return WslResult(
                command=command, available=False, exit_code=-1,
                stderr="WSL not available on this system",
                distro=distro or self._detected_distro,
            )

        t0 = int(time.time() * 1000)
        use_distro = distro or self._detected_distro
        args = ["wsl", "-d", use_distro]
        if working_dir:
            args += ["--cd", working_dir]
        args += ["--", "bash", "-c", command]

        # Canonical routing (preferred): delegate to the ONE trusted ProcessExecutor
        # when injected — never a raw subprocess from here.
        if self._executor is not None:
            return self._run_via_executor(command, args, use_distro, t0)

        try:
            proc = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout_s,
            )
            duration = int(time.time() * 1000) - t0
            return WslResult(
                command=command,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                exit_code=proc.returncode,
                duration_ms=duration,
                distro=use_distro,
                available=True,
            )
        except subprocess.TimeoutExpired:
            return WslResult(
                command=command, exit_code=-1, distro=use_distro, available=True,
                stderr=f"WSL command timed out after {timeout_s}s",
            )
        except Exception as exc:
            return WslResult(
                command=command, exit_code=-1, distro=use_distro, available=True,
                stderr=f"WSL error: {exc}",
            )

    def _run_via_executor(self, command, args, use_distro, t0) -> WslResult:
        """Delegate one WSL execution to the canonical ProcessExecutor, mapping its
        ProcessResult back to a WslResult. The Windows-side spawn is argv-only and
        shell=False; the trusted RESEARCHER tier is used so the ``bash -c`` command
        (a shell inside WSL) is not argv-metachar-rejected."""
        from raven.runtime.process_executor import ProcessSpec
        from raven.runtime.execution import ActorKind
        spec = ProcessSpec(
            argv=list(args),
            actor=self._actor or ActorKind.RESEARCHER,
            tool_id="env.wsl.run",
        )
        result = self._executor.execute(spec)
        return WslResult(
            command=command,
            stdout=getattr(result, "stdout", "") or "",
            stderr=getattr(result, "stderr", "") or "",
            exit_code=getattr(result, "return_code", -1),
            duration_ms=getattr(result, "duration_ms", int(time.time() * 1000) - t0),
            distro=use_distro,
            available=True,
        )

    def list_distros(self) -> List[str]:
        try:
            r = subprocess.run(
                ["wsl", "--list", "--quiet"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                return [d.strip().replace('\x00', '') for d in r.stdout.splitlines() if d.strip()]
        except Exception:
            pass
        return []

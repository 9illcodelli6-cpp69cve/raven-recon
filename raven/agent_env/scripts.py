"""RAVEN V7 Script Runner — Part 04.

DEPRECATED / OFF by default. This runner is not wired into the live server path.
In production, script execution MUST be routed through the canonical
ProcessExecutor (raven/runtime/process_executor.py) under the PROCESS_ANALYZER
capability, with capability + actor-provenance gating — not executed here as a
raw subprocess. An optional `process_executor` may be injected (see __init__);
until it is, direct execution remains a RESEARCHER-only legacy path.

Scripts are RESEARCHER content — still validated before execution. The old
"violations logged but not blocked" behavior has been replaced by fail-closed
gating: detected sandbox violations now BLOCK execution. Output is UNTRUSTED DATA.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class ScriptLanguage(str, Enum):
    PYTHON     = "python"
    POWERSHELL = "powershell"
    BASH       = "bash"
    BATCH      = "batch"


@dataclass
class ScriptResult:
    script_id:   str
    language:    ScriptLanguage
    stdout:      str = ""
    stderr:      str = ""
    exit_code:   int = -1
    duration_ms: int = 0
    timed_out:   bool = False
    sandbox_violations: List[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.sandbox_violations

    def to_dict(self) -> dict:
        return {
            "script_id": self.script_id,
            "language": self.language.value,
            "stdout": self.stdout[:8192],
            "stderr": self.stderr[:2048],
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "sandbox_violations": self.sandbox_violations,
        }


# Patterns in script code that require additional scrutiny
_SENSITIVE_PATTERNS = [
    ("import socket", "network_access"),
    ("import requests", "network_access"),
    ("subprocess.run", "subprocess_execution"),
    ("os.system", "subprocess_execution"),
    ("open(", "file_access"),
    ("__import__", "dynamic_import"),
]


class ScriptRunner:
    """Executes scripts from the Script Workshop with safety checks."""

    def __init__(
        self,
        workspace_dir: str = None,
        timeout_s: int = 60,
        allow_network: bool = False,
        process_executor=None,
        actor=None,
    ):
        self._workspace  = workspace_dir or tempfile.gettempdir()
        self._timeout_s  = timeout_s
        self._allow_net  = allow_network
        # Canonical routing seam. When the one ProcessExecutor is injected, ``run``
        # delegates to it (shell=False, argv-only, hidden window, env scrub,
        # output/time caps, emergency-stop predicate) INSTEAD of spawning a raw
        # subprocess — removing the raw-subprocess hazard before this path is ever
        # flipped to reachable. Without it, the legacy RESEARCHER-only raw fallback
        # stays (and ``env.script.run`` stays UNAVAILABLE at the registry).
        self._executor   = process_executor
        self._actor      = actor

    def check_script(self, code: str, language: ScriptLanguage) -> List[str]:
        """Return list of policy violations found in the script."""
        violations = []
        if language == ScriptLanguage.PYTHON:
            for pattern, category in _SENSITIVE_PATTERNS:
                if pattern in code:
                    if category == "network_access" and not self._allow_net:
                        violations.append(f"Network access detected: '{pattern}'")
        return violations

    def run(
        self, code: str, language: ScriptLanguage,
        script_id: str = "script",
        env: Dict[str, str] = None,
    ) -> ScriptResult:
        t0 = int(time.time() * 1000)

        violations = self.check_script(code, language)
        # FAIL-CLOSED (replaces the old "logged but not blocked" design):
        # detected sandbox violations now BLOCK execution instead of being
        # ignored. Blocking also still happens at the CapabilityGate level.
        if violations:
            return ScriptResult(
                script_id=script_id, language=language, exit_code=-1,
                stderr="Blocked by sandbox policy: " + "; ".join(violations),
                sandbox_violations=violations,
            )

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=self._suffix(language),
                dir=self._workspace,
                delete=False,
                encoding="utf-8",
            ) as f:
                f.write(code)
                tmp_path = f.name

            args = self._build_args(tmp_path, language)

            # Canonical routing (preferred): run through the ONE trusted
            # ProcessExecutor when injected — never a raw subprocess from here.
            if self._executor is not None:
                return self._run_via_executor(args, script_id, language, violations,
                                              env, t0)

            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self._timeout_s,
                cwd=self._workspace,
                env={**os.environ, **(env or {})},
            )
            duration = int(time.time() * 1000) - t0
            return ScriptResult(
                script_id=script_id,
                language=language,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                exit_code=proc.returncode,
                duration_ms=duration,
                sandbox_violations=violations,
            )
        except subprocess.TimeoutExpired:
            return ScriptResult(
                script_id=script_id, language=language,
                timed_out=True, exit_code=-1,
                stderr=f"Script timed out after {self._timeout_s}s",
                sandbox_violations=violations,
            )
        except FileNotFoundError as exc:
            return ScriptResult(
                script_id=script_id, language=language, exit_code=-1,
                stderr=f"Runtime not found: {exc}",
                sandbox_violations=violations,
            )
        except Exception as exc:
            return ScriptResult(
                script_id=script_id, language=language, exit_code=-1,
                stderr=f"Script error: {exc}",
                sandbox_violations=violations,
            )
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    def _run_via_executor(self, args, script_id, language, violations, env, t0):
        """Delegate one script execution to the canonical ProcessExecutor and map its
        ProcessResult back to a ScriptResult. argv-only, shell=False, hidden window,
        env scrub, caps, emergency-stop — all enforced inside the executor."""
        from raven.runtime.process_executor import ProcessSpec
        from raven.runtime.execution import ActorKind
        spec = ProcessSpec(
            argv=list(args),
            cwd=self._workspace,
            env_overrides=dict(env or {}),
            timeout_s=float(self._timeout_s),
            actor=self._actor or ActorKind.RESEARCHER,
            tool_id="env.script.run",
        )
        result = self._executor.execute(spec)
        duration = int(time.time() * 1000) - t0
        return ScriptResult(
            script_id=script_id,
            language=language,
            stdout=getattr(result, "stdout", "") or "",
            stderr=getattr(result, "stderr", "") or "",
            exit_code=getattr(result, "return_code", -1),
            duration_ms=getattr(result, "duration_ms", duration) or duration,
            timed_out=getattr(result, "timed_out", False),
            sandbox_violations=violations,
        )

    @staticmethod
    def _suffix(lang: ScriptLanguage) -> str:
        return {
            ScriptLanguage.PYTHON: ".py",
            ScriptLanguage.POWERSHELL: ".ps1",
            ScriptLanguage.BASH: ".sh",
            ScriptLanguage.BATCH: ".bat",
        }.get(lang, ".txt")

    @staticmethod
    def _build_args(path: str, lang: ScriptLanguage) -> List[str]:
        if lang == ScriptLanguage.PYTHON:
            return ["python", path]
        if lang == ScriptLanguage.POWERSHELL:
            return ["powershell", "-NonInteractive", "-File", path]
        if lang == ScriptLanguage.BASH:
            return ["bash", path]
        if lang == ScriptLanguage.BATCH:
            return [path]
        return ["python", path]

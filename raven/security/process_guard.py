"""RAVEN Safe Process Launcher.

Executes pre-approved analysis tools only. Never uses shell=True.
Never accepts executable content from target responses.

INVARIANTS:
- Only whitelisted executables may be launched.
- Arguments are validated against an allowlist.
- No shell=True (prevents shell metacharacter injection).
- Output is capped (max_output_bytes).
- Timeout is enforced (max_timeout_s).
- No sensitive env vars passed to child processes.
- Target-controlled strings are NEVER used directly as argument values.
"""
from __future__ import annotations

import os
import re
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# Environment variables that must never be passed to child processes.
SENSITIVE_ENV_VARS = frozenset({
    "RAVEN_API_KEY", "RAVEN_SESSION_TOKEN", "RAVEN_SECRET",
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GITHUB_TOKEN", "GH_TOKEN",
    "BUGCROWD_TOKEN", "HACKERONE_TOKEN",
})

# Shell metacharacters — any arg containing these is rejected.
SHELL_METACHARACTERS = re.compile(r'[;&|`$><\n\r\\]')

MAX_DEFAULT_TIMEOUT_S  = 60
MAX_ALLOWED_TIMEOUT_S  = 300
MAX_DEFAULT_OUTPUT     = 1 * 1024 * 1024   # 1 MB
MAX_ALLOWED_OUTPUT     = 50 * 1024 * 1024  # 50 MB


@dataclass
class ApprovedProcess:
    """A pre-approved executable spec."""
    name:            str
    executable_path: str                    # absolute path only
    allowed_arg_patterns: List[re.Pattern]  # each arg must match one
    max_timeout_s:   int   = MAX_DEFAULT_TIMEOUT_S
    max_output_bytes: int  = MAX_DEFAULT_OUTPUT
    capture_stderr:  bool  = True


@dataclass
class ProcessResult:
    process_name:   str
    return_code:    int
    stdout_bytes:   int
    stderr_bytes:   int
    stdout:         str
    stderr:         str
    timed_out:      bool
    truncated:      bool


class SafeProcessLauncher:
    """Launch pre-approved analysis processes safely.

    Enforces: no shell injection, no credential leakage to children,
    output limits, and strict executable allowlist.
    """

    def __init__(self) -> None:
        self._registry: Dict[str, ApprovedProcess] = {}

    def register(self, spec: ApprovedProcess) -> None:
        if not os.path.isabs(spec.executable_path):
            raise ValueError(
                f"Executable path must be absolute: {spec.executable_path!r}"
            )
        # Reject path traversal
        if ".." in spec.executable_path:
            raise ValueError("Path traversal in executable path is not allowed")
        self._registry[spec.name] = spec

    def launch(self, name: str, args: List[str]) -> ProcessResult:
        """Launch a pre-approved process with the given args.

        Raises KeyError if 'name' is not registered.
        Raises ValueError if any arg contains shell metacharacters or
        does not match the spec's allowed patterns.
        """
        if name not in self._registry:
            raise KeyError(f"Process '{name}' is not in the approved registry")

        spec = self._registry[name]

        # Validate args
        for arg in args:
            if not isinstance(arg, str):
                raise ValueError(f"Argument must be a string, got {type(arg)}")
            if SHELL_METACHARACTERS.search(arg):
                raise ValueError(
                    f"Argument contains shell metacharacters: {arg!r}"
                )
            if spec.allowed_arg_patterns:
                if not any(p.fullmatch(arg) for p in spec.allowed_arg_patterns):
                    raise ValueError(
                        f"Argument {arg!r} not permitted by spec '{name}'"
                    )

        # Build safe environment (filter out sensitive vars)
        safe_env = {
            k: v for k, v in os.environ.items()
            if k not in SENSITIVE_ENV_VARS
        }

        timeout = min(spec.max_timeout_s, MAX_ALLOWED_TIMEOUT_S)
        timed_out = False
        truncated = False

        try:
            result = subprocess.run(
                [spec.executable_path] + args,
                capture_output=True,
                timeout=timeout,
                env=safe_env,
                shell=False,   # NEVER shell=True
            )
            raw_stdout = result.stdout
            raw_stderr = result.stderr if spec.capture_stderr else b""
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            raw_stdout = (exc.stdout or b"")
            raw_stderr = (exc.stderr or b"")
            return_code = -1
        else:
            return_code = result.returncode

        max_out = min(spec.max_output_bytes, MAX_ALLOWED_OUTPUT)
        if len(raw_stdout) > max_out:
            raw_stdout = raw_stdout[:max_out]
            truncated = True

        return ProcessResult(
            process_name  = name,
            return_code   = return_code,
            stdout_bytes  = len(raw_stdout),
            stderr_bytes  = len(raw_stderr),
            stdout        = raw_stdout.decode("utf-8", errors="replace"),
            stderr        = raw_stderr.decode("utf-8", errors="replace"),
            timed_out     = timed_out,
            truncated     = truncated,
        )

    def registered_names(self) -> List[str]:
        return list(self._registry)

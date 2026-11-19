"""RAVEN cached environment / shell probe (Wave 2 — A2-PROC).

This kills the "30s console flash": today ``TerminalTool.is_available`` runs a fresh
``subprocess.run(["powershell",...])`` (and a bash probe) on *every* ``/api/v7/status``
poll — once every 30 seconds for the app's lifetime, each spawning a visible console
on a window-less pywebview host (PROCESS_ARCHITECTURE §1.2).

:class:`EnvironmentProbe` detects available shells/tools **at most once per TTL**,
thread-safely, preferring :func:`shutil.which` (no spawn at all) and only falling
back to a hidden, short-lived probe when a definitive answer is needed. The status
poll then reads the cache and spawns nothing.

ADDITIVE ONLY: this module provides the cached probe that A6-TERM will adopt in a
later wave in place of ``TerminalTool.is_available`` — it does NOT edit terminal.py.

Public API
----------
``EnvironmentProbe(*, ttl_s=600.0, which=shutil.which, prober=None, clock=time.monotonic,
                   shells=DEFAULT_SHELLS)``
``detect(shell) -> bool``            cached per-shell availability
``snapshot() -> dict``               cached {shell: bool} for the default shell set
``invalidate(shell=None) -> None``   drop one or all cache entries
``refresh() -> dict``                invalidate all then re-probe the default set
``probe_count`` / ``which_count``    instrumentation (for the explosion regression test)
"""
from __future__ import annotations

import shutil
import subprocess
import threading
import time
from typing import Callable, Dict, List, Optional

from .process_executor import hidden_process_kwargs

# Default shells/interpreters we report on. ``cmd`` is Windows-only but harmless to
# probe elsewhere (which() simply returns None).
DEFAULT_SHELLS: tuple = ("powershell", "pwsh", "bash", "cmd", "sh")

# How each shell is probed when a spawn fallback is actually needed.
_PROBE_ARGV: Dict[str, List[str]] = {
    "powershell": ["powershell", "-NonInteractive", "-NoProfile", "-Command", "echo ok"],
    "pwsh":       ["pwsh", "-NonInteractive", "-NoProfile", "-Command", "echo ok"],
    "bash":       ["bash", "-c", "echo ok"],
    "sh":         ["sh", "-c", "echo ok"],
    "cmd":        ["cmd", "/c", "echo ok"],
}

_PROBE_TIMEOUT_S = 2.0


def _default_prober(shell: str) -> bool:
    """Spawn a hidden, 2s ``echo ok`` probe for ``shell`` (fallback path only).

    Always uses :func:`hidden_process_kwargs` so even this fallback never pops a
    console window.
    """
    argv = _PROBE_ARGV.get(shell)
    if argv is None:
        return False
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
            timeout=_PROBE_TIMEOUT_S, shell=False,
            **hidden_process_kwargs(),
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class EnvironmentProbe:
    """Thread-safe, TTL-cached shell/tool availability detector."""

    def __init__(
        self,
        *,
        ttl_s: float = 600.0,
        which: Callable[[str], Optional[str]] = shutil.which,
        prober: Optional[Callable[[str], bool]] = None,
        clock: Callable[[], float] = time.monotonic,
        shells: tuple = DEFAULT_SHELLS,
    ):
        self._ttl = float(ttl_s)
        self._which = which
        self._prober = prober or _default_prober
        self._clock = clock
        self._shells = tuple(shells)
        self._cache: Dict[str, tuple] = {}   # shell -> (available: bool, stamped: float)
        self._lock = threading.RLock()
        # Instrumentation for tests / observability.
        self.probe_count = 0
        self.which_count = 0

    # -- queries ---------------------------------------------------------------

    def detect(self, shell: str) -> bool:
        """Return whether ``shell`` is available, using the cache when fresh.

        Resolution order: a fresh cache hit → ``shutil.which`` (no spawn) → a
        single hidden spawn probe. The result is cached with a timestamp, so
        repeated calls within the TTL spawn nothing.
        """
        shell = (shell or "").strip().lower()
        now = self._clock()
        with self._lock:
            hit = self._cache.get(shell)
            if hit is not None and (now - hit[1]) < self._ttl:
                return hit[0]

        available = self._resolve(shell)

        with self._lock:
            self._cache[shell] = (available, self._clock())
        return available

    def snapshot(self) -> Dict[str, bool]:
        """Cached availability for the default shell set (no spawn when warm)."""
        return {shell: self.detect(shell) for shell in self._shells}

    # -- resolution ------------------------------------------------------------

    def _resolve(self, shell: str) -> bool:
        # which() first: a definitive "available" with zero processes spawned.
        self.which_count += 1
        try:
            found = self._which(shell)
        except Exception:
            found = None
        if found:
            return True
        # Not on PATH: fall back to exactly one hidden probe for a definitive answer.
        self.probe_count += 1
        try:
            return bool(self._prober(shell))
        except Exception:
            return False

    # -- cache control ---------------------------------------------------------

    def invalidate(self, shell: Optional[str] = None) -> None:
        with self._lock:
            if shell is None:
                self._cache.clear()
            else:
                self._cache.pop((shell or "").strip().lower(), None)

    def refresh(self) -> Dict[str, bool]:
        """Drop the whole cache and re-probe the default set once."""
        self.invalidate()
        return self.snapshot()

    def cached_shells(self) -> Dict[str, bool]:
        with self._lock:
            return {k: v[0] for k, v in self._cache.items()}


# Process-global default instance (governor-owned in a later wave). Importers that
# just want "the one cache" can use this; tests construct their own with injected
# which/prober/clock for determinism.
GLOBAL_PROBE = EnvironmentProbe()

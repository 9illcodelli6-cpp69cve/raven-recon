"""RAVEN V7 Scope Guard — Part 05.

DEPRECATED / UNWIRED (see raven/browser_engine/__init__.py). Duplicates the
canonical scope engine raven.scope (Scope.allows_url, fail-closed), which is what
the live sender enforces. Kept importable for the legacy test; do NOT wire it in.

All outbound HTTP requests must pass scope validation.
Out-of-scope targets are always blocked — the engine cannot override this.
"""
from __future__ import annotations

__deprecated__ = True
__canonical_replacement__ = "raven.scope.Scope.allows_url"

import re
from typing import List, Optional, Set
from urllib.parse import urlparse


class ScopeViolation(Exception):
    """Raised when a request targets a host that is out of scope."""
    def __init__(self, url: str, reason: str = ""):
        self.url = url
        self.reason = reason
        super().__init__(f"Scope violation: {url} — {reason}")


class ScopeGuard:
    """Enforces that all HTTP requests target in-scope hosts.

    Scope is defined as a set of allowed hostnames/patterns.
    Empty scope = DENY ALL (fail-closed).
    """

    def __init__(self, allowed_hosts: List[str] = None):
        self._allowed: List[str] = list(allowed_hosts or [])

    def add(self, pattern: str) -> None:
        self._allowed.append(pattern)

    def is_in_scope(self, url: str) -> bool:
        if not self._allowed:
            return False  # empty scope = deny all
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            return False
        for pattern in self._allowed:
            if self._match(host, pattern):
                return True
        return False

    def check(self, url: str) -> None:
        """Raise ScopeViolation if url is out of scope."""
        if not self.is_in_scope(url):
            raise ScopeViolation(url, reason=f"Not in allowed scope: {self._allowed[:5]}")

    @staticmethod
    def _match(host: str, pattern: str) -> bool:
        """Match host against a pattern. Supports wildcards (*.)."""
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return host == suffix or host.endswith("." + suffix)
        return host == pattern or host.endswith("." + pattern)

    @property
    def scope_count(self) -> int:
        return len(self._allowed)

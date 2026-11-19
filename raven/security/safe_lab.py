"""RAVEN Safe Lab — controlled execution environment.

INVARIANTS:
- LAB_OFF: no outbound connections (default for adversarial parser tests).
- LAB_LOCAL_ONLY: only loopback 127.0.0.1 / ::1.
- LAB_ALLOWLIST: explicit set of allowed destinations.
- Loopback services bind ONLY to 127.0.0.1 (never 0.0.0.0).
- Target-controlled data cannot create new listeners.
- Downloaded content is never executed.
- All requests are bounded (timeout, max bytes, max redirects).
"""
from __future__ import annotations

import enum
import re
import socket
from dataclasses import dataclass, field
from typing import Optional, List


class LabMode(str, enum.Enum):
    LAB_OFF        = "LAB_OFF"        # default — no outbound connections
    LAB_LOCAL_ONLY = "LAB_LOCAL_ONLY" # loopback fixtures only
    LAB_ALLOWLIST  = "LAB_ALLOWLIST"  # explicit allowlist only


LOOPBACK_PREFIXES = (
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
)

# Addresses that RAVEN services must NEVER bind to (only loopback allowed)
FORBIDDEN_BIND_ADDRESSES = frozenset({
    "0.0.0.0", "::", "",
})


@dataclass
class LabBudget:
    timeout_s:         float = 10.0
    max_response_bytes: int  = 1 * 1024 * 1024  # 1 MB
    max_redirects:      int  = 3
    max_requests:       int  = 10
    max_decompressed:   int  = 50 * 1024 * 1024  # 50 MB

    def is_valid(self) -> bool:
        return (
            0 < self.timeout_s <= 120
            and 0 < self.max_response_bytes <= 100 * 1024 * 1024
            and 0 <= self.max_redirects <= 20
            and 0 < self.max_requests <= 1000
            and 0 < self.max_decompressed <= 200 * 1024 * 1024
        )


class SafeLab:
    """Safe execution environment for adversarial testing.

    Purpose: run parser/analysis/PoC-development tests without exposing the host.

    SECURITY: loopback services bind only to 127.0.0.1, never 0.0.0.0.
    """

    def __init__(self, mode: LabMode = LabMode.LAB_OFF,
                 allowlist: Optional[List[str]] = None,
                 budget: Optional[LabBudget] = None):
        self.mode      = mode
        self.allowlist = list(allowlist or [])
        self.budget    = budget or LabBudget()
        if not self.budget.is_valid():
            raise ValueError("LabBudget exceeds safe limits")

    def permits_destination(self, url: str) -> bool:
        """Returns True if this URL is permitted by the current lab mode."""
        if not url or not isinstance(url, str):
            return False

        if self.mode == LabMode.LAB_OFF:
            return False

        if self.mode == LabMode.LAB_LOCAL_ONLY:
            return any(url.startswith(p) for p in LOOPBACK_PREFIXES)

        if self.mode == LabMode.LAB_ALLOWLIST:
            return any(url.startswith(allowed) for allowed in self.allowlist)

        return False

    def permits_bind_address(self, address: str) -> bool:
        """Check if a bind address is safe (loopback only)."""
        return address in ("127.0.0.1", "::1", "localhost")

    def check_bind_address(self, address: str) -> None:
        """Raise ValueError if address is not a safe loopback bind address."""
        if address in FORBIDDEN_BIND_ADDRESSES:
            raise ValueError(
                f"RAVEN services must not bind to '{address}'. "
                "Use 127.0.0.1 or ::1 only."
            )
        if not self.permits_bind_address(address):
            raise ValueError(
                f"Non-loopback bind address '{address}' is not permitted."
            )

    def validate_external_request(self, url: str) -> None:
        """Raise if URL is not permitted in current lab mode."""
        if not self.permits_destination(url):
            raise PermissionError(
                f"Safe Lab ({self.mode.value}) denies connection to: {url!r}"
            )

    @staticmethod
    def verify_socket_loopback(host: str, port: int) -> bool:
        """Check that a bound service is on loopback (post-bind verification)."""
        try:
            addr = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                       socket.SOCK_STREAM)
            if not addr:
                return False
            ip = addr[0][4][0]
            return ip.startswith("127.") or ip == "::1"
        except Exception:
            return False

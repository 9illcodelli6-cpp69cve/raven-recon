"""RAVEN Policy Gate — the sole Python ALLOW authority.

This pure-Python gate is the canonical, authoritative decision kernel. It does
NOT delegate to Rust: the Rust Trusted Core is BUILD_ONLY and, when present, is
only ever consulted as an OPTIONAL, off-by-default, fail-closed, *tighten-only*
cross-check (see raven/runtime/capabilities.py::CapabilityGate). The Rust core
can never widen a decision this gate makes, and RAVEN runs identically with the
Rust binary absent.

INVARIANTS:
- Default DENY: only an explicit pass reaches allowed=True.
- Unknown / unmapped risk is treated as SENSITIVE by the adapter (fail-closed);
  it is never silently treated as safe.
- ML/AI cannot call PolicyGate.allow() — only this gate's decisions count.
- Destructive and Exfiltrative actions are always DENIED.
- Emergency stop denies all sensitive actions immediately.
- Scope is decided by the one canonical authority (raven.scope.Scope), not a
  duplicate matcher.
"""
from __future__ import annotations

import enum
import threading
import uuid
from dataclasses import dataclass
from typing import Optional


class Capability(str, enum.Enum):
    HTTP_READ             = "HttpRead"
    HTTP_STATE_CHANGE     = "HttpStateChange"
    LOCAL_FIXTURE_CONNECT = "LocalFixtureConnect"
    PROCESS_ANALYZER      = "ProcessAnalyzer"
    FILE_READ_WORKSPACE   = "FileReadWorkspace"
    FILE_WRITE_WORKSPACE  = "FileWriteWorkspace"
    CALLBACK_COLLECTOR    = "CallbackCollector"
    REPORT_EXPORT         = "ReportExport"
    SCOPE_READ            = "ScopeRead"
    SCOPE_WRITE           = "ScopeWrite"


class RiskClass(str, enum.Enum):
    SAFE_READ_ONLY       = "SafeReadOnly"
    LOW_RISK_STATE_CHANGE = "LowRiskStateChange"
    SENSITIVE            = "Sensitive"
    DESTRUCTIVE          = "Destructive"   # always denied
    EXFILTRATIVE         = "Exfiltrative"  # always denied


# Risk classes that are ALWAYS denied, regardless of capabilities.
ALWAYS_DENIED_RISK_CLASSES = frozenset({
    RiskClass.DESTRUCTIVE,
    RiskClass.EXFILTRATIVE,
})

# Risk classes that require human approval.
REQUIRES_APPROVAL_RISK_CLASSES = frozenset({
    RiskClass.SENSITIVE,
})


@dataclass
class PolicyDecision:
    action_id:  str
    allowed:    bool
    reason:     str
    message:    str = ""
    requires_approval: bool = False


class PolicyGate:
    """The sole Python policy decision kernel that enforces security boundaries.

    Python is the authority. Rust is NOT consulted here; it is an optional,
    off-by-default, tighten-only cross-check wired in the CapabilityGate adapter.

    INVARIANT: A sensitive action that cannot be verified is DENIED.
    """

    _emergency_stop = threading.Event()
    _emergency_stop_active = False
    _lock = threading.Lock()

    def __init__(self, workspace_id: str, granted_capabilities: set,
                 allowed_scope_hosts: set):
        self.workspace_id          = workspace_id
        self._granted_capabilities = frozenset(granted_capabilities)
        self._allowed_scope_hosts  = frozenset(allowed_scope_hosts)

    @classmethod
    def trigger_emergency_stop(cls) -> None:
        """Trigger emergency stop — all future sensitive actions are denied."""
        with cls._lock:
            cls._emergency_stop_active = True
        cls._emergency_stop.set()

    @classmethod
    def is_emergency_stop_active(cls) -> bool:
        return cls._emergency_stop_active

    @classmethod
    def clear_emergency_stop(cls) -> None:
        """Explicit user "Resume" after an Emergency Stop (the scheduler's clear_stop
        succeeded). Without this the terminal/knowledge/agent capabilities stayed
        denied until the process restarted."""
        with cls._lock:
            cls._emergency_stop_active = False
        cls._emergency_stop.clear()

    @classmethod
    def _reset_emergency_stop_for_test(cls) -> None:
        with cls._lock:
            cls._emergency_stop_active = False
        cls._emergency_stop.clear()

    def evaluate(self, capability: Capability, destination: str,
                  method: str, reason: str, risk_class: RiskClass,
                  workspace_id: Optional[str] = None) -> PolicyDecision:
        """Evaluate an action request.

        Returns PolicyDecision with `allowed=False` by default.
        Only explicit passes reach `allowed=True`.
        """
        action_id = str(uuid.uuid4())
        # Explicit workspace_id="" is an error; None means "use own workspace"
        ws_id = workspace_id if workspace_id is not None else self.workspace_id

        # 0. Input validation — empty strings are always denied (matches Rust PolicyEngine)
        if not ws_id.strip():
            return PolicyDecision(
                action_id=action_id, allowed=False,
                reason="EmptyWorkspaceId",
                message="workspace_id must not be empty or whitespace",
            )
        if not (method or "").strip():
            return PolicyDecision(
                action_id=action_id, allowed=False,
                reason="EmptyMethod",
                message="method must not be empty or whitespace",
            )

        # 1. Emergency stop
        if self.__class__._emergency_stop_active:
            return PolicyDecision(
                action_id=action_id, allowed=False,
                reason="EmergencyStopActive",
                message="Emergency stop is active — all sensitive actions denied",
            )

        # 2. Workspace check
        if ws_id != self.workspace_id:
            return PolicyDecision(
                action_id=action_id, allowed=False,
                reason="WorkspaceMismatch",
                message=f"Workspace '{ws_id}' not authorized",
            )

        # 3. Always-denied risk classes
        if risk_class in ALWAYS_DENIED_RISK_CLASSES:
            return PolicyDecision(
                action_id=action_id, allowed=False,
                reason="RiskClassBlocked",
                message=f"Risk class '{risk_class.value}' is blocked by default policy",
            )

        # 4. Sensitive → require approval
        if risk_class in REQUIRES_APPROVAL_RISK_CLASSES:
            return PolicyDecision(
                action_id=action_id, allowed=False,
                reason="RequiresHumanApproval",
                message="Sensitive action requires explicit human approval",
                requires_approval=True,
            )

        # 5. Capability check
        if capability not in self._granted_capabilities:
            return PolicyDecision(
                action_id=action_id, allowed=False,
                reason="CapabilityMissing",
                message=f"Capability '{capability.value}' is not granted",
            )

        # 6. Destination scope check for HTTP capabilities
        if capability in (Capability.HTTP_READ, Capability.HTTP_STATE_CHANGE):
            host = self._extract_host(destination)
            if not host or not self._host_in_scope(host):
                return PolicyDecision(
                    action_id=action_id, allowed=False,
                    reason="DestinationOutOfScope",
                    message=f"Destination '{destination}' is not in authorized scope",
                )

        # 7. All checks passed
        return PolicyDecision(
            action_id=action_id, allowed=True,
            reason="PolicyAllowed", message="",
        )

    def _extract_host(self, url: str) -> Optional[str]:
        """Host of an http(s) URL, or None (=> DestinationOutOfScope, fail-closed).

        Parsed with ``urllib.parse.urlsplit`` — the authority parsing HTTP clients
        use — so ``https://target.com:443@evil.com/`` yields ``evil.com`` (the host
        the request really goes to), never ``target.com``. URLs that carry userinfo
        (``user[:pass]@``), a malformed port, a backslash, or whitespace/control
        characters are ambiguous between parsers and are refused outright.
        """
        from urllib.parse import urlsplit

        if not isinstance(url, str):
            return None
        url = url.strip()
        if not url or "\\" in url or any(
                ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
            return None
        try:
            parts = urlsplit(url)
            if parts.scheme.lower() not in ("http", "https"):
                return None
            if ("@" in parts.netloc or parts.username is not None
                    or parts.password is not None):
                return None
            _ = parts.port      # ValueError on a malformed / out-of-range port
            host = parts.hostname
        except ValueError:
            return None
        return host.lower() if host else None

    def _host_in_scope(self, host: str) -> bool:
        """Decide host-in-scope using the ONE canonical scope authority
        (raven.scope) rather than a duplicate matcher.

        Behavior-preserving: a host is in scope if it equals an allowed host OR
        is a subdomain of one — exactly the legacy
        ``host == allowed or host.endswith('.'+allowed)`` rule, now expressed via
        ``raven.scope.matches``. Normalizes the host through ``raven.scope.hostname``
        and fails closed (False) on any parse error or empty scope. Robust for
        allowed IPs and ``*.`` wildcard entries (no exceptions, no silent widening).
        """
        if not self._allowed_scope_hosts:
            return False
        from raven import scope as _scope
        try:
            norm = _scope.hostname(host)
        except (ValueError, UnicodeError):
            return False
        for allowed in self._allowed_scope_hosts:
            # exact match (pattern without '*.'), then subdomain match ('*.host').
            if _scope.matches(norm, allowed) or _scope.matches(norm, "*." + allowed):
                return True
        return False

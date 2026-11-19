"""Python→Rust Trusted Core bridge.

Protocol: one JSON IpcRequest written to subprocess stdin;
          one JSON IpcResponse read from stdout.
          subprocess.run with list args — no shell=True.

FAIL-CLOSED GUARANTEE:
    If the Rust binary is unavailable, subprocess fails, or returns a malformed
    response, every call to evaluate_action() returns a DENY decision.
    There is NO fallback to permissive execution.

DISTINCTION:
    C++ analysis unavailable  → Python analysis fallback ALLOWED.
    Rust security core unavailable → sensitive execution DENIED.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

# Shared Windows hidden-window kwargs (C-4: single source of truth in the
# ProcessExecutor). Folded in here so the bridge subprocess never flashes a
# console window in the frozen windowed app. Guarded so the fail-closed security
# core stays importable even if the runtime package cannot load for any reason.
try:
    from .runtime.process_executor import hidden_process_kwargs as _hidden_process_kwargs
except Exception:  # pragma: no cover - keep the bridge importable in isolation
    def _hidden_process_kwargs(group: bool = False) -> dict:  # type: ignore[misc]
        return {}

IPC_SCHEMA_VERSION = 1

# Locate the compiled bridge binary relative to this file.
_BRIDGE_BINARY: Optional[Path] = None


def _find_bridge_binary() -> Optional[Path]:
    """Return the path to raven-bridge.exe (or None if not found).

    Frozen-aware: when running inside a PyInstaller bundle (``sys.frozen``) the
    bridge is shipped under ``raven/_bridge/`` and is resolved from
    ``sys._MEIPASS`` (onefile extraction root) or next to the executable BEFORE
    the source-tree project-root layout is tried. When the binary is genuinely
    absent every lookup returns ``None`` and the caller fails closed to DENY —
    the security contract is unchanged.
    """
    candidates: list[Path] = []

    # 1) Frozen bundle (PyInstaller): raven-bridge.exe bundled under raven/_bridge.
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            base = Path(meipass)
            candidates += [
                base / "raven" / "_bridge" / "raven-bridge.exe",
                base / "raven" / "_bridge" / "raven-bridge",
            ]
        exe_dir = Path(sys.executable).parent
        candidates += [
            exe_dir / "raven" / "_bridge" / "raven-bridge.exe",
            exe_dir / "raven" / "_bridge" / "raven-bridge",
            exe_dir / "raven-bridge.exe",
        ]

    # 2) Source / dev tree: relative to the project root (two levels up).
    here = Path(__file__).parent.parent  # project root
    candidates += [
        here / "rust" / "target" / "release" / "raven-bridge.exe",
        here / "rust" / "target" / "release" / "raven-bridge",
    ]

    for c in candidates:
        try:
            if c.is_file():
                return c
        except OSError:  # pragma: no cover - defensive against odd paths
            continue
    return None


def _get_bridge_binary() -> Optional[Path]:
    global _BRIDGE_BINARY
    if _BRIDGE_BINARY is None:
        _BRIDGE_BINARY = _find_bridge_binary()
    return _BRIDGE_BINARY


# ──────────────────────────────────────────────────────────────────────────────
# Public types mirroring the Rust schema
# ──────────────────────────────────────────────────────────────────────────────

class BridgeDecisionKind(Enum):
    ALLOW             = "allow"
    DENY              = "deny"
    REQUIRE_APPROVAL  = "require_approval"
    ERROR             = "error"            # protocol / parse error → treated as DENY


@dataclass(frozen=True)
class BridgeDecision:
    """Result of evaluating an action through the Rust Trusted Core."""
    kind: BridgeDecisionKind
    allowed: bool
    reason: str
    message: str
    rust_invoked: bool  # True iff a real Rust binary was called

    def is_allowed(self) -> bool:
        return self.allowed

    @classmethod
    def deny_fail_closed(cls, message: str) -> "BridgeDecision":
        """Fail-closed DENY when the Rust core is unavailable."""
        return cls(
            kind=BridgeDecisionKind.DENY,
            allowed=False,
            reason="RUST_CORE_UNAVAILABLE",
            message=message,
            rust_invoked=False,
        )


# ──────────────────────────────────────────────────────────────────────────────
# Core bridge call
# ──────────────────────────────────────────────────────────────────────────────

def evaluate_action(
    *,
    workspace_id: str,
    capability: str,
    destination: str,
    method: str,
    reason: str,
    risk_class: str,
    provenance: str = "Scheduler",
    granted_capabilities: list[str],
    allowed_hosts: list[str],
    timeout_seconds: float = 5.0,
) -> BridgeDecision:
    """Call the Rust PolicyEngine and return a binding decision.

    SECURITY CONTRACT:
    - This function NEVER returns ALLOW if the Rust binary is unavailable.
    - A non-zero exit code from the binary is treated as DENY.
    - A malformed JSON response is treated as DENY.
    - timeout_seconds prevents a stalled binary from blocking indefinitely.
    """
    binary = _get_bridge_binary()
    if binary is None:
        return BridgeDecision.deny_fail_closed(
            "Rust bridge binary not found — sensitive action denied fail-closed"
        )

    request = {
        "schema_version": IPC_SCHEMA_VERSION,
        "session_id":     str(uuid.uuid4()),
        "message_id":     str(uuid.uuid4()),
        "payload": {
            "EvaluateAction": {
                "workspace_id":        workspace_id,
                "capability":          capability,
                "destination":         destination,
                "method":              method,
                "reason":              reason,
                "risk_class":          risk_class,
                "provenance":          provenance,
                "granted_capabilities": granted_capabilities,
                "allowed_hosts":       allowed_hosts,
            }
        },
    }

    request_json = json.dumps(request, separators=(",", ":"))

    try:
        result = subprocess.run(
            [str(binary)],
            input=request_json.encode("utf-8"),
            capture_output=True,
            timeout=timeout_seconds,
            shell=False,  # Never shell=True
            **_hidden_process_kwargs(),  # hidden window in the frozen app
        )
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as exc:
        return BridgeDecision.deny_fail_closed(
            f"Rust bridge invocation failed: {type(exc).__name__}: {exc}"
        )

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        return BridgeDecision.deny_fail_closed(
            f"Rust bridge exited {result.returncode}: {stderr}"
        )

    raw = result.stdout.decode("utf-8", errors="replace").strip()
    return _parse_response(raw)


def _parse_response(raw: str) -> BridgeDecision:
    """Parse an IpcResponse JSON string into a BridgeDecision.

    Any parse failure → DENY fail-closed.
    """
    if not raw:
        return BridgeDecision.deny_fail_closed("Rust bridge returned empty response")

    try:
        resp = json.loads(raw)
    except json.JSONDecodeError as exc:
        return BridgeDecision.deny_fail_closed(
            f"Rust bridge returned malformed JSON: {exc}"
        )

    payload = resp.get("payload")
    if payload is None:
        return BridgeDecision.deny_fail_closed("Rust bridge response missing 'payload'")

    # "Ok" — HealthCheck response
    if payload == "Ok":
        return BridgeDecision(
            kind=BridgeDecisionKind.ALLOW,
            allowed=True,
            reason="HealthCheckOk",
            message="",
            rust_invoked=True,
        )

    # {"Decision": {"allowed": bool, "reason": str, "message": str}}
    if isinstance(payload, dict) and "Decision" in payload:
        d = payload["Decision"]
        allowed = bool(d.get("allowed", False))
        reason = str(d.get("reason", ""))
        message = str(d.get("message", ""))
        if "RequireApproval" in reason:
            kind = BridgeDecisionKind.REQUIRE_APPROVAL
            allowed = False  # RequireApproval is not an ALLOW
        elif allowed:
            kind = BridgeDecisionKind.ALLOW
        else:
            kind = BridgeDecisionKind.DENY
        return BridgeDecision(
            kind=kind,
            allowed=allowed,
            reason=reason,
            message=message,
            rust_invoked=True,
        )

    # {"Error": {"code": str, "message": str}} — protocol/parse error
    if isinstance(payload, dict) and "Error" in payload:
        err = payload["Error"]
        code = str(err.get("code", "UNKNOWN"))
        msg  = str(err.get("message", ""))
        return BridgeDecision(
            kind=BridgeDecisionKind.ERROR,
            allowed=False,
            reason=code,
            message=msg,
            rust_invoked=True,
        )

    # {"EmergencyStopStatus": {"active": bool}}
    if isinstance(payload, dict) and "EmergencyStopStatus" in payload:
        active = bool(payload["EmergencyStopStatus"].get("active", True))
        return BridgeDecision(
            kind=BridgeDecisionKind.DENY if active else BridgeDecisionKind.ALLOW,
            allowed=not active,
            reason="EmergencyStopStatus",
            message=f"active={active}",
            rust_invoked=True,
        )

    return BridgeDecision.deny_fail_closed(
        f"Unrecognized Rust bridge response payload: {str(payload)[:100]}"
    )


def health_check() -> bool:
    """Return True iff the Rust bridge binary is present and responds to HealthCheck."""
    binary = _get_bridge_binary()
    if binary is None:
        return False
    request_json = json.dumps({
        "schema_version": IPC_SCHEMA_VERSION,
        "session_id": "00000000-0000-0000-0000-000000000000",
        "message_id": "00000000-0000-0000-0000-000000000001",
        "payload": "HealthCheck",
    })
    try:
        result = subprocess.run(
            [str(binary)],
            input=request_json.encode("utf-8"),
            capture_output=True,
            timeout=5.0,
            shell=False,
            **_hidden_process_kwargs(),  # hidden window in the frozen app
        )
        if result.returncode != 0:
            return False
        resp = json.loads(result.stdout.decode("utf-8"))
        return resp.get("payload") == "Ok"
    except Exception:  # noqa: BLE001 — health check must not raise
        return False


def bridge_status() -> str:
    """Return a human-readable status string for the Rust bridge."""
    binary = _get_bridge_binary()
    if binary is None:
        return "RUST_BRIDGE_BINARY_NOT_FOUND"
    if not health_check():
        return "RUST_BRIDGE_HEALTH_CHECK_FAILED"
    return f"RUST_BRIDGE_OK:{binary}"

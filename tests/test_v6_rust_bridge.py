"""RAVEN V6 — Python→Rust bridge integration tests.

Tests the end-to-end chain:
    Python test → rust_bridge.evaluate_action() → raven-bridge.exe → PolicyEngine
    → IpcResponse → BridgeDecision

FAIL-CLOSED CONTRACT:
    If the Rust binary is missing or broken → every call returns DENY.
    allowed=True is only returned when the compiled Rust binary explicitly
    produces a Decision{allowed: true} response.

Phase 2 verification of the RAVEN V6 Rust Runtime Closure.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from raven.rust_bridge import (
    BridgeDecision,
    BridgeDecisionKind,
    bridge_status,
    evaluate_action,
    health_check,
)


# ─── fixtures ────────────────────────────────────────────────────────────────

WORKSPACE = "ws-bridge-test"
ALLOWED_HOSTS = ["example.com", "api.target.example"]
GRANTED_CAPS = ["HttpRead"]


def _eval(
    capability="HttpRead",
    destination="https://example.com/api",
    method="GET",
    reason="bridge test",
    risk_class="SafeReadOnly",
    provenance="TestHarness",
    granted_capabilities=None,
    allowed_hosts=None,
) -> BridgeDecision:
    return evaluate_action(
        workspace_id=WORKSPACE,
        capability=capability,
        destination=destination,
        method=method,
        reason=reason,
        risk_class=risk_class,
        provenance=provenance,
        granted_capabilities=granted_capabilities if granted_capabilities is not None else GRANTED_CAPS,
        allowed_hosts=allowed_hosts if allowed_hosts is not None else ALLOWED_HOSTS,
    )


# ─── bridge availability ──────────────────────────────────────────────────────

from raven.rust_bridge import _find_bridge_binary as _fbb

_NEEDS_BRIDGE = pytest.mark.skipif(
    _fbb() is None,
    reason="Rust bridge not built — run build-linux.sh (cargo build --release -p raven-bridge)")


@_NEEDS_BRIDGE
class TestBridgeAvailability:
    def test_health_check_returns_true(self):
        """The compiled Rust binary must respond to HealthCheck."""
        assert health_check(), "Rust bridge health check failed — binary missing or broken"

    def test_bridge_status_contains_ok(self):
        status = bridge_status()
        assert status.startswith("RUST_BRIDGE_OK"), (
            f"Expected RUST_BRIDGE_OK status, got: {status}"
        )

    def test_health_check_result_has_rust_invoked(self):
        """health_check() should return a real bool, not a BridgeDecision."""
        result = health_check()
        assert isinstance(result, bool)
        assert result is True


# ─── policy scenarios — mirrors Phase 2 verification ─────────────────────────

@_NEEDS_BRIDGE
class TestPolicyScenarios:
    def test_safe_readonly_with_capability_allowed(self):
        d = _eval(
            capability="HttpRead",
            destination="https://example.com/api",
            risk_class="SafeReadOnly",
        )
        assert d.rust_invoked, "Rust must have been invoked"
        assert d.allowed, f"Expected ALLOW; got: {d}"
        assert d.kind == BridgeDecisionKind.ALLOW

    def test_unknown_capability_denied_with_error(self):
        d = _eval(capability="UnknownCapabilityXYZ")
        assert not d.allowed
        assert d.kind in (BridgeDecisionKind.DENY, BridgeDecisionKind.ERROR)
        assert "UNKNOWN_CAPABILITY" in d.reason or "UNKNOWN" in d.reason.upper()

    def test_empty_workspace_id_denied(self):
        d = evaluate_action(
            workspace_id="",
            capability="HttpRead",
            destination="https://example.com/api",
            method="GET",
            reason="test",
            risk_class="SafeReadOnly",
            granted_capabilities=GRANTED_CAPS,
            allowed_hosts=ALLOWED_HOSTS,
        )
        assert not d.allowed, "Empty workspace_id must be denied"

    def test_destructive_risk_denied(self):
        d = _eval(
            capability="HttpStateChange",
            risk_class="Destructive",
            granted_capabilities=["HttpRead", "HttpStateChange"],
        )
        assert not d.allowed
        assert d.kind == BridgeDecisionKind.DENY
        assert "RiskClass" in d.reason or "Blocked" in d.reason

    def test_exfiltrative_risk_denied(self):
        d = _eval(
            capability="HttpRead",
            risk_class="Exfiltrative",
        )
        assert not d.allowed
        assert d.kind == BridgeDecisionKind.DENY

    def test_sensitive_risk_requires_approval(self):
        d = _eval(
            capability="HttpStateChange",
            destination="https://example.com/admin",
            risk_class="Sensitive",
            granted_capabilities=["HttpRead", "HttpStateChange"],
        )
        assert not d.allowed
        assert d.kind == BridgeDecisionKind.REQUIRE_APPROVAL

    def test_out_of_scope_destination_denied(self):
        d = _eval(
            destination="https://evil.com/exfil",
            risk_class="SafeReadOnly",
        )
        assert not d.allowed
        assert d.kind == BridgeDecisionKind.DENY
        assert "Scope" in d.reason or "scope" in d.reason.lower()

    def test_missing_granted_capability_denied(self):
        d = _eval(
            capability="HttpRead",
            granted_capabilities=[],  # no caps granted
        )
        assert not d.allowed
        assert d.kind == BridgeDecisionKind.DENY

    def test_wrong_capability_granted_denied(self):
        d = _eval(
            capability="HttpRead",
            granted_capabilities=["HttpStateChange"],  # wrong cap
        )
        assert not d.allowed

    def test_emergency_stop_trigger_returns_active_status(self):
        """TriggerEmergencyStop payload returns EmergencyStopStatus{active:true}."""
        from raven.rust_bridge import _get_bridge_binary, IPC_SCHEMA_VERSION
        import uuid
        binary = _get_bridge_binary()
        if binary is None:
            pytest.skip("Rust binary not found")
        request = {
            "schema_version": IPC_SCHEMA_VERSION,
            "session_id": str(uuid.uuid4()),
            "message_id": str(uuid.uuid4()),
            "payload": "TriggerEmergencyStop",
        }
        result = subprocess.run(
            [str(binary)],
            input=json.dumps(request).encode("utf-8"),
            capture_output=True,
            timeout=5.0,
            shell=False,
        )
        assert result.returncode == 0
        resp = json.loads(result.stdout.decode("utf-8"))
        payload = resp.get("payload", {})
        assert isinstance(payload, dict)
        assert "EmergencyStopStatus" in payload
        assert payload["EmergencyStopStatus"]["active"] is True

    def test_subdomain_of_allowed_host_allowed(self):
        d = _eval(
            destination="https://api.example.com/v1",
            risk_class="SafeReadOnly",
        )
        assert d.allowed, f"api.example.com should be in scope for example.com; got: {d}"

    def test_malformed_url_denied(self):
        d = _eval(
            destination="javascript:alert(1)",
            risk_class="SafeReadOnly",
        )
        assert not d.allowed

    def test_unknown_risk_class_denied(self):
        d = _eval(risk_class="WeirdRiskClassXYZ")
        assert not d.allowed
        assert d.kind in (BridgeDecisionKind.DENY, BridgeDecisionKind.ERROR)


# ─── fail-closed guarantee ───────────────────────────────────────────────────

class TestFailClosed:
    def test_missing_binary_returns_deny(self, tmp_path):
        """When the bridge binary is missing, evaluate_action() returns DENY
        with rust_invoked=False.  This is the core fail-closed guarantee.
        """
        import raven.rust_bridge as rb

        original_binary = rb._BRIDGE_BINARY
        try:
            rb._BRIDGE_BINARY = tmp_path / "nonexistent-raven-bridge.exe"
            d = evaluate_action(
                workspace_id=WORKSPACE,
                capability="HttpRead",
                destination="https://example.com/api",
                method="GET",
                reason="fail-closed test",
                risk_class="SafeReadOnly",
                granted_capabilities=GRANTED_CAPS,
                allowed_hosts=ALLOWED_HOSTS,
            )
        finally:
            rb._BRIDGE_BINARY = original_binary

        assert not d.allowed, "Missing binary must return DENY"
        assert d.rust_invoked is False, "rust_invoked must be False when binary missing"
        assert d.kind == BridgeDecisionKind.DENY
        assert "RUST_CORE_UNAVAILABLE" in d.reason

    def test_corrupted_response_returns_deny(self, tmp_path):
        """A binary that returns garbage JSON → DENY fail-closed."""
        import raven.rust_bridge as rb

        # Write a tiny script that outputs garbage
        echo_garbage = tmp_path / "raven-bridge.exe"
        # Use a real executable that writes bad output
        import struct
        # Write a minimal PE stub that just echoes garbage — instead,
        # create a Python-based fake binary via a .cmd wrapper
        fake_cmd = tmp_path / "raven-bridge.cmd"
        fake_cmd.write_text("@echo THIS IS NOT JSON\r\n")
        # On Windows, .cmd files are executables
        original_binary = rb._BRIDGE_BINARY
        try:
            rb._BRIDGE_BINARY = fake_cmd
            d = evaluate_action(
                workspace_id=WORKSPACE,
                capability="HttpRead",
                destination="https://example.com/api",
                method="GET",
                reason="garbage test",
                risk_class="SafeReadOnly",
                granted_capabilities=GRANTED_CAPS,
                allowed_hosts=ALLOWED_HOSTS,
            )
        finally:
            rb._BRIDGE_BINARY = original_binary

        assert not d.allowed, "Garbage response must return DENY"
        assert d.kind == BridgeDecisionKind.DENY

    def test_empty_response_returns_deny(self, tmp_path):
        """A binary that returns empty stdout → DENY fail-closed."""
        import raven.rust_bridge as rb

        fake_cmd = tmp_path / "raven-bridge.cmd"
        fake_cmd.write_text("@rem empty output\r\n")
        original_binary = rb._BRIDGE_BINARY
        try:
            rb._BRIDGE_BINARY = fake_cmd
            d = evaluate_action(
                workspace_id=WORKSPACE,
                capability="HttpRead",
                destination="https://example.com/api",
                method="GET",
                reason="empty test",
                risk_class="SafeReadOnly",
                granted_capabilities=GRANTED_CAPS,
                allowed_hosts=ALLOWED_HOSTS,
            )
        finally:
            rb._BRIDGE_BINARY = original_binary

        assert not d.allowed, "Empty response must return DENY"
        assert d.kind == BridgeDecisionKind.DENY

    def test_nonzero_exit_code_returns_deny(self, tmp_path):
        """Binary that exits with non-zero → DENY fail-closed."""
        import raven.rust_bridge as rb

        fake_cmd = tmp_path / "raven-bridge.cmd"
        fake_cmd.write_text("@exit 1\r\n")
        original_binary = rb._BRIDGE_BINARY
        try:
            rb._BRIDGE_BINARY = fake_cmd
            d = evaluate_action(
                workspace_id=WORKSPACE,
                capability="HttpRead",
                destination="https://example.com/api",
                method="GET",
                reason="exit1 test",
                risk_class="SafeReadOnly",
                granted_capabilities=GRANTED_CAPS,
                allowed_hosts=ALLOWED_HOSTS,
            )
        finally:
            rb._BRIDGE_BINARY = original_binary

        assert not d.allowed, "Non-zero exit code must return DENY"
        assert d.kind == BridgeDecisionKind.DENY


# ─── schema version mismatch ─────────────────────────────────────────────────

class TestSchemaVersion:
    def test_schema_version_in_response(self):
        """IpcResponse.schema_version must equal IPC_SCHEMA_VERSION=1."""
        from raven.rust_bridge import _get_bridge_binary, IPC_SCHEMA_VERSION
        import uuid
        binary = _get_bridge_binary()
        if binary is None:
            pytest.skip("Rust binary not found")
        request = {
            "schema_version": IPC_SCHEMA_VERSION,
            "session_id": str(uuid.uuid4()),
            "message_id": str(uuid.uuid4()),
            "payload": "HealthCheck",
        }
        result = subprocess.run(
            [str(binary)],
            input=json.dumps(request).encode("utf-8"),
            capture_output=True,
            timeout=5.0,
            shell=False,
        )
        assert result.returncode == 0
        resp = json.loads(result.stdout.decode("utf-8"))
        assert resp["schema_version"] == IPC_SCHEMA_VERSION

    def test_wrong_schema_version_exits_nonzero(self):
        """Binary must exit 1 when schema_version mismatches."""
        from raven.rust_bridge import _get_bridge_binary
        import uuid
        binary = _get_bridge_binary()
        if binary is None:
            pytest.skip("Rust binary not found")
        request = {
            "schema_version": 99,
            "session_id": str(uuid.uuid4()),
            "message_id": str(uuid.uuid4()),
            "payload": "HealthCheck",
        }
        result = subprocess.run(
            [str(binary)],
            input=json.dumps(request).encode("utf-8"),
            capture_output=True,
            timeout=5.0,
            shell=False,
        )
        assert result.returncode != 0, (
            f"Schema version mismatch must exit non-zero; got {result.returncode}"
        )

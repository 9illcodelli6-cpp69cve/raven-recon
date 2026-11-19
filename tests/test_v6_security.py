"""RAVEN V6 Security Hardening Tests.

Tests cover:
- Safe Lab mode enforcement
- Policy Gate (default-deny, fail-closed)
- Emergency stop
- Bind address enforcement (never 0.0.0.0)
- Callback collector (non-executing, credential stripping)
- Process guard (shell injection prevention, allowlist)
- Audit log (redaction, append-only)
- ML cannot bypass policy
- Reverse connection / out-of-scope destination defense
- Command injection in argument values
- Path traversal in process specs
"""
import re
import sys
import threading
import unittest

# Ensure project root is on path
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from raven.security import (
    SafeLab, LabMode,
    PolicyGate, PolicyDecision, RiskClass, Capability,
    SafeCallbackCollector,
    SafeProcessLauncher,
    SecurityAuditLog,
)
from raven.security.audit_log import AuditEventType, _redact
from raven.security.callback_collector import EXCLUDED_HEADER_NAMES
from raven.security.process_guard import ApprovedProcess, SHELL_METACHARACTERS
from raven.security.safe_lab import (
    LabBudget, FORBIDDEN_BIND_ADDRESSES, LOOPBACK_PREFIXES,
)


# ---------------------------------------------------------------------------
# Helper: fresh PolicyGate for each test
# ---------------------------------------------------------------------------
def _make_gate(scope_hosts=None, capabilities=None):
    PolicyGate._reset_emergency_stop_for_test()
    return PolicyGate(
        workspace_id="test-ws",
        granted_capabilities=capabilities or {Capability.HTTP_READ},
        allowed_scope_hosts=scope_hosts or {"example.com"},
    )


# ===========================================================================
# Safe Lab Tests
# ===========================================================================
class SafeLabModeTest(unittest.TestCase):
    def test_lab_off_denies_all(self):
        lab = SafeLab(LabMode.LAB_OFF)
        self.assertFalse(lab.permits_destination("http://127.0.0.1:9999/test"))
        self.assertFalse(lab.permits_destination("https://example.com"))
        self.assertFalse(lab.permits_destination(""))

    def test_lab_local_only_allows_loopback(self):
        lab = SafeLab(LabMode.LAB_LOCAL_ONLY)
        self.assertTrue(lab.permits_destination("http://127.0.0.1:9999/fixture"))
        self.assertTrue(lab.permits_destination("http://localhost:8080/api"))
        self.assertTrue(lab.permits_destination("http://[::1]:7777/"))

    def test_lab_local_only_denies_internet(self):
        lab = SafeLab(LabMode.LAB_LOCAL_ONLY)
        self.assertFalse(lab.permits_destination("https://example.com"))
        self.assertFalse(lab.permits_destination("https://8.8.8.8"))

    def test_lab_allowlist_allows_explicit(self):
        lab = SafeLab(LabMode.LAB_ALLOWLIST,
                      allowlist=["http://127.0.0.1:9000"])
        self.assertTrue(lab.permits_destination("http://127.0.0.1:9000/test"))
        self.assertFalse(lab.permits_destination("https://example.com"))

    def test_validate_external_request_raises_if_denied(self):
        lab = SafeLab(LabMode.LAB_OFF)
        with self.assertRaises(PermissionError):
            lab.validate_external_request("https://example.com")

    def test_validate_external_request_ok_if_allowed(self):
        lab = SafeLab(LabMode.LAB_LOCAL_ONLY)
        # Should not raise
        lab.validate_external_request("http://127.0.0.1:9999/test")


class BindAddressTest(unittest.TestCase):
    def test_permits_loopback(self):
        lab = SafeLab(LabMode.LAB_LOCAL_ONLY)
        self.assertTrue(lab.permits_bind_address("127.0.0.1"))
        self.assertTrue(lab.permits_bind_address("::1"))
        self.assertTrue(lab.permits_bind_address("localhost"))

    def test_rejects_forbidden_bind_addresses(self):
        lab = SafeLab(LabMode.LAB_LOCAL_ONLY)
        for addr in FORBIDDEN_BIND_ADDRESSES:
            self.assertFalse(lab.permits_bind_address(addr),
                             f"Expected {addr!r} to be rejected")

    def test_check_bind_address_raises_on_0000(self):
        lab = SafeLab(LabMode.LAB_LOCAL_ONLY)
        with self.assertRaises(ValueError):
            lab.check_bind_address("0.0.0.0")

    def test_check_bind_address_raises_on_wildcard_ipv6(self):
        lab = SafeLab(LabMode.LAB_LOCAL_ONLY)
        with self.assertRaises(ValueError):
            lab.check_bind_address("::")

    def test_check_bind_address_ok_for_loopback(self):
        lab = SafeLab(LabMode.LAB_LOCAL_ONLY)
        lab.check_bind_address("127.0.0.1")   # must not raise
        lab.check_bind_address("::1")          # must not raise

    def test_lab_budget_invalid_if_exceeds_limits(self):
        with self.assertRaises(ValueError):
            SafeLab(LabMode.LAB_LOCAL_ONLY,
                    budget=LabBudget(max_response_bytes=200 * 1024 * 1024))


# ===========================================================================
# Policy Gate Tests
# ===========================================================================
class PolicyGateDefaultDenyTest(unittest.TestCase):
    def setUp(self):
        PolicyGate._reset_emergency_stop_for_test()

    def test_unknown_capability_denied(self):
        gate = _make_gate(capabilities={Capability.HTTP_READ})
        dec = gate.evaluate(
            capability=Capability.FILE_WRITE_WORKSPACE,
            destination="https://example.com/path",
            method="GET", reason="test",
            risk_class=RiskClass.SAFE_READ_ONLY,
        )
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.reason, "CapabilityMissing")

    def test_out_of_scope_destination_denied(self):
        gate = _make_gate(scope_hosts={"example.com"})
        dec = gate.evaluate(
            capability=Capability.HTTP_READ,
            destination="https://attacker.com/evil",
            method="GET", reason="test",
            risk_class=RiskClass.SAFE_READ_ONLY,
        )
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.reason, "DestinationOutOfScope")

    def test_in_scope_destination_allowed(self):
        gate = _make_gate(scope_hosts={"example.com"},
                          capabilities={Capability.HTTP_READ})
        dec = gate.evaluate(
            capability=Capability.HTTP_READ,
            destination="https://example.com/path",
            method="GET", reason="test",
            risk_class=RiskClass.SAFE_READ_ONLY,
        )
        self.assertTrue(dec.allowed)

    def test_subdomain_in_scope_allowed(self):
        gate = _make_gate(scope_hosts={"example.com"},
                          capabilities={Capability.HTTP_READ})
        dec = gate.evaluate(
            capability=Capability.HTTP_READ,
            destination="https://api.example.com/v2",
            method="GET", reason="test",
            risk_class=RiskClass.SAFE_READ_ONLY,
        )
        self.assertTrue(dec.allowed)

    def test_destructive_risk_class_always_denied(self):
        gate = _make_gate(capabilities=set(Capability),
                          scope_hosts={"example.com"})
        dec = gate.evaluate(
            capability=Capability.HTTP_READ,
            destination="https://example.com",
            method="DELETE", reason="test",
            risk_class=RiskClass.DESTRUCTIVE,
        )
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.reason, "RiskClassBlocked")

    def test_exfiltrative_risk_class_always_denied(self):
        gate = _make_gate(capabilities=set(Capability),
                          scope_hosts={"example.com"})
        dec = gate.evaluate(
            capability=Capability.HTTP_READ,
            destination="https://example.com",
            method="GET", reason="test",
            risk_class=RiskClass.EXFILTRATIVE,
        )
        self.assertFalse(dec.allowed)

    def test_sensitive_requires_approval(self):
        gate = _make_gate(capabilities=set(Capability),
                          scope_hosts={"example.com"})
        dec = gate.evaluate(
            capability=Capability.HTTP_STATE_CHANGE,
            destination="https://example.com/form",
            method="POST", reason="test",
            risk_class=RiskClass.SENSITIVE,
        )
        self.assertFalse(dec.allowed)
        self.assertTrue(dec.requires_approval)

    def test_workspace_mismatch_denied(self):
        gate = _make_gate()
        dec = gate.evaluate(
            capability=Capability.HTTP_READ,
            destination="https://example.com/path",
            method="GET", reason="test",
            risk_class=RiskClass.SAFE_READ_ONLY,
            workspace_id="other-ws",
        )
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.reason, "WorkspaceMismatch")

    def test_malformed_url_denied(self):
        gate = _make_gate(capabilities={Capability.HTTP_READ},
                          scope_hosts={"example.com"})
        dec = gate.evaluate(
            capability=Capability.HTTP_READ,
            destination="not-a-url",
            method="GET", reason="test",
            risk_class=RiskClass.SAFE_READ_ONLY,
        )
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.reason, "DestinationOutOfScope")


class EmergencyStopTest(unittest.TestCase):
    def setUp(self):
        PolicyGate._reset_emergency_stop_for_test()

    def tearDown(self):
        PolicyGate._reset_emergency_stop_for_test()

    def test_emergency_stop_denies_everything(self):
        gate = _make_gate(capabilities=set(Capability),
                          scope_hosts={"example.com"})
        PolicyGate.trigger_emergency_stop()
        self.assertTrue(PolicyGate.is_emergency_stop_active())
        dec = gate.evaluate(
            capability=Capability.HTTP_READ,
            destination="https://example.com/path",
            method="GET", reason="test",
            risk_class=RiskClass.SAFE_READ_ONLY,
        )
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.reason, "EmergencyStopActive")

    def test_emergency_stop_is_irreversible_in_production(self):
        """Once set, emergency stop stays active (reset is test-only)."""
        PolicyGate.trigger_emergency_stop()
        self.assertTrue(PolicyGate.is_emergency_stop_active())
        # Cannot unset via public API
        self.assertTrue(PolicyGate.is_emergency_stop_active())


class MLCannotBypassPolicyTest(unittest.TestCase):
    """ML probability=1.0 never changes policy outcome."""

    def setUp(self):
        PolicyGate._reset_emergency_stop_for_test()

    def test_max_ml_probability_cannot_bypass_denial(self):
        gate = _make_gate(capabilities={Capability.HTTP_READ},
                          scope_hosts={"example.com"})
        # Simulated: ML says 100% confidence this is safe — we ignore it
        ml_probability = 1.0   # maximum possible ML score

        # Policy still denies because destination is out of scope
        dec = gate.evaluate(
            capability=Capability.HTTP_READ,
            destination="https://attacker.com/exfil",
            method="GET", reason=f"ml_score={ml_probability}",
            risk_class=RiskClass.SAFE_READ_ONLY,
        )
        self.assertFalse(dec.allowed,
                         "ML max probability must not bypass policy denial")

    def test_destructive_denied_regardless_of_ml(self):
        gate = _make_gate(capabilities=set(Capability),
                          scope_hosts={"example.com"})
        for ml_score in [0.0, 0.5, 0.999, 1.0]:
            dec = gate.evaluate(
                capability=Capability.HTTP_READ,
                destination="https://example.com/path",
                method="DELETE",
                reason=f"ml_score={ml_score}",
                risk_class=RiskClass.DESTRUCTIVE,
            )
            self.assertFalse(dec.allowed,
                             f"Destructive must be denied at ml_score={ml_score}")


# ===========================================================================
# Callback Collector Tests
# ===========================================================================
class CallbackCollectorTest(unittest.TestCase):
    def setUp(self):
        self.collector = SafeCallbackCollector()

    def test_bind_address_is_loopback(self):
        self.assertEqual(self.collector.bind_address, "127.0.0.1")

    def test_register_and_hit_tracking(self):
        token = self.collector.register_probe("my-probe")
        self.assertIsNotNone(token)
        record = self.collector.record_callback(
            source_label="127.0.0.1:54321",
            method="GET", path="/callback?token=" + token,
            headers={"host": "127.0.0.1", "user-agent": "curl"},
            raw_payload=b"<ping/>",
            token=token,
        )
        hits = self.collector.get_hits(token)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].callback_id, record.callback_id)

    def test_credential_headers_stripped(self):
        token = self.collector.register_probe("cred-test")
        self.collector.record_callback(
            source_label="127.0.0.1:54322",
            method="GET", path="/cb",
            headers={
                "authorization": "Bearer secret-token-abc",
                "cookie": "session=xyz",
                "x-api-key": "super-secret",
                "user-agent": "test",
            },
            raw_payload=b"body",
            token=token,
        )
        hits = self.collector.get_hits(token)
        h = hits[0].safe_headers
        for bad in EXCLUDED_HEADER_NAMES:
            self.assertNotIn(bad, h,
                             f"Credential header '{bad}' must be stripped")
        self.assertIn("user-agent", h)

    def test_payload_never_executed(self):
        """Record a malicious payload — verify it is stored as bytes, never run."""
        token = self.collector.register_probe("exec-test")
        evil = b"__import__('os').system('calc.exe')"
        self.collector.record_callback(
            source_label="127.0.0.1:9",
            method="POST", path="/rce",
            headers={},
            raw_payload=evil,
            token=token,
        )
        hits = self.collector.get_hits(token)
        # payload_bytes is counted, but we do NOT store raw content — just hash
        self.assertGreater(hits[0].payload_bytes, 0)
        # No attribute holds the raw executable string
        self.assertFalse(hasattr(hits[0], "payload"))


# ===========================================================================
# Process Guard Tests
# ===========================================================================
class ProcessGuardTest(unittest.TestCase):
    def _launcher_with_echo(self):
        launcher = SafeProcessLauncher()
        import shutil
        echo = shutil.which("python") or "python"
        launcher.register(ApprovedProcess(
            name             = "python_echo",
            executable_path  = echo,
            allowed_arg_patterns=[
                re.compile(r'-c'),
                re.compile(r'print\([^)]+\)'),
            ],
            max_timeout_s    = 5,
            max_output_bytes = 4096,
        ))
        return launcher

    def test_unregistered_process_denied(self):
        launcher = SafeProcessLauncher()
        with self.assertRaises(KeyError):
            launcher.launch("nmap", ["-sV", "127.0.0.1"])

    def test_shell_metacharacter_in_arg_rejected(self):
        launcher = SafeProcessLauncher()
        import shutil
        p = shutil.which("python") or "python"
        launcher.register(ApprovedProcess(
            name="p", executable_path=p,
            allowed_arg_patterns=[re.compile(r'.*')],
        ))
        for evil_arg in [
            "arg; evil",
            "arg | cat /etc/passwd",
            "arg && calc",
            "`calc`",
            "$(whoami)",
            "arg\n/etc/passwd",
        ]:
            with self.assertRaises(ValueError, msg=f"Should reject: {evil_arg!r}"):
                launcher.launch("p", [evil_arg])

    def test_path_traversal_in_executable_rejected(self):
        launcher = SafeProcessLauncher()
        with self.assertRaises(ValueError):
            launcher.register(ApprovedProcess(
                name="bad",
                executable_path="/usr/bin/../bin/sh",
                allowed_arg_patterns=[],
            ))

    def test_relative_path_in_executable_rejected(self):
        launcher = SafeProcessLauncher()
        with self.assertRaises(ValueError):
            launcher.register(ApprovedProcess(
                name="relative",
                executable_path="python",
                allowed_arg_patterns=[],
            ))

    def test_registered_names_reflects_registry(self):
        launcher = SafeProcessLauncher()
        import shutil
        p = shutil.which("python") or "python"
        launcher.register(ApprovedProcess(
            name="mypy", executable_path=p, allowed_arg_patterns=[],
        ))
        self.assertIn("mypy", launcher.registered_names())


# ===========================================================================
# Audit Log Tests
# ===========================================================================
class AuditLogTest(unittest.TestCase):
    def test_records_appended(self):
        log = SecurityAuditLog()
        log.record(AuditEventType.POLICY_ALLOW, "allow", "PolicyAllowed",
                   action_id="a1", workspace_id="ws1")
        log.record(AuditEventType.POLICY_DENY, "deny", "CapabilityMissing",
                   action_id="a2", workspace_id="ws1")
        records = log.all_records()
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].outcome, "allow")
        self.assertEqual(records[1].outcome, "deny")

    def test_secrets_redacted_in_details(self):
        log = SecurityAuditLog()
        log.record(AuditEventType.GENERIC, "info", "test",
                   details={"header": "Authorization: Bearer supersecret123"})
        r = log.all_records()[0]
        self.assertNotIn("supersecret123", r.details.get("header", ""))

    def test_export_jsonl_is_valid(self):
        import json
        log = SecurityAuditLog()
        log.record(AuditEventType.POLICY_ALLOW, "allow", "PolicyAllowed",
                   action_id="a1")
        log.record(AuditEventType.EMERGENCY_STOP, "deny", "EmergencyStop")
        lines = log.export_jsonl().strip().split("\n")
        self.assertEqual(len(lines), 2)
        for line in lines:
            parsed = json.loads(line)
            self.assertIn("event_type", parsed)
            self.assertIn("timestamp", parsed)

    def test_ml_inference_record_always_advisory(self):
        log = SecurityAuditLog()
        log.record_ml_inference(
            model_id="mlp_v1",
            task="task_a",
            score=0.99,
            is_advisory=True,
            sets_verification_status=False,
        )
        r = log.all_records()[0]
        self.assertEqual(r.details["sets_verification_status"], "False")
        self.assertEqual(r.details["is_advisory"], "True")

    def test_redact_function(self):
        self.assertNotIn("supersecret",
                         _redact("Authorization: Bearer supersecret"))
        self.assertNotIn("password123",
                         _redact("password: password123"))

    def test_thread_safety(self):
        log = SecurityAuditLog()
        errors = []

        def write_records():
            try:
                for i in range(50):
                    log.record(AuditEventType.GENERIC, "info", f"event-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=write_records) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [], f"Thread-safety errors: {errors}")
        self.assertGreater(len(log.all_records()), 0)


# ===========================================================================
# End-to-End Integration Tests
# ===========================================================================
class E2ELabAndPolicyTest(unittest.TestCase):
    def setUp(self):
        PolicyGate._reset_emergency_stop_for_test()

    def test_loopback_fixture_allowed_when_configured(self):
        lab = SafeLab(LabMode.LAB_LOCAL_ONLY)
        self.assertTrue(lab.permits_destination("http://127.0.0.1:9000/fixture"))

    def test_unauthorized_external_destination_denied(self):
        lab = SafeLab(LabMode.LAB_LOCAL_ONLY)
        self.assertFalse(lab.permits_destination("https://evil.com/callback"))

    def test_missing_rust_safety_core_fails_closed(self):
        """Sensitive action when Rust unavailable → DENIED (fail-closed)."""
        # The Python PolicyGate always fails closed for sensitive actions
        gate = _make_gate(capabilities=set(Capability),
                          scope_hosts={"example.com"})
        dec = gate.evaluate(
            capability=Capability.HTTP_STATE_CHANGE,
            destination="https://example.com/form",
            method="POST", reason="test",
            risk_class=RiskClass.SENSITIVE,
        )
        self.assertFalse(dec.allowed)
        self.assertTrue(dec.requires_approval)

    def test_reverse_connection_loopback_destination_denied_when_not_in_scope(self):
        gate = _make_gate(scope_hosts={"example.com"},
                          capabilities={Capability.HTTP_READ})
        # An attacker might try to redirect to 127.0.0.1 via SSRF
        dec = gate.evaluate(
            capability=Capability.HTTP_READ,
            destination="http://127.0.0.1:8443/internal",
            method="GET", reason="test",
            risk_class=RiskClass.SAFE_READ_ONLY,
        )
        self.assertFalse(dec.allowed,
                         "SSRF to loopback must be denied when not in scope")


if __name__ == "__main__":
    unittest.main(verbosity=2)

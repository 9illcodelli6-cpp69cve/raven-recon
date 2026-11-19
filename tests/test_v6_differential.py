"""RAVEN V6 — Phase 4: Differential policy testing.

Runs a deterministic corpus through both Python PolicyGate and Rust
evaluate_action() bridge.  Compares the allow/deny decision.

Mismatch classification:
    PYTHON_BUG                  — Python ALLOWs something Rust DENYs
    RUST_BUG                    — Rust ALLOWs something Python DENYs
    SPEC_AMBIGUITY              — both engines disagree on the same case
                                  and the spec is unclear
    INTENTIONAL_SECURITY_HARDENING — Rust is deliberately stricter
                                     (e.g. budget validation, structural checks)
    REASON_ONLY                 — same allow/deny, different reason code (not a bug)

SECURITY INVARIANT: PYTHON_BUG entries are blocking defects.
                    RUST_BUG entries are blocking defects.
                    All other categories are informational.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from raven.rust_bridge import BridgeDecisionKind, evaluate_action
from raven.security.policy_gate import Capability, PolicyGate, RiskClass


# ─── corpus ──────────────────────────────────────────────────────────────────

WORKSPACE = "ws-diff"
ALLOWED  = ["example.com", "api.target.example"]
CAPS     = {Capability.HTTP_READ}

# Each tuple: (label, cap_str, dest, method, risk_str, provenance,
#              granted_cap_strs, allowed_hosts)
CORPUS = [
    # ── standard allow ─────────────────────────────────────────────────────
    (
        "safe_readonly_http_read",
        "HttpRead", "https://example.com/api", "GET", "SafeReadOnly", "TestHarness",
        ["HttpRead"], ["example.com"],
    ),
    (
        "low_risk_state_change_with_cap",
        "HttpStateChange", "https://example.com/update", "POST", "LowRiskStateChange", "TestHarness",
        ["HttpRead", "HttpStateChange"], ["example.com"],
    ),
    (
        "subdomain_in_scope",
        "HttpRead", "https://api.example.com/v1", "GET", "SafeReadOnly", "TestHarness",
        ["HttpRead"], ["example.com"],
    ),

    # ── capability failures ─────────────────────────────────────────────────
    (
        "missing_capability",
        "HttpRead", "https://example.com/api", "GET", "SafeReadOnly", "TestHarness",
        [], ["example.com"],
    ),
    (
        "wrong_capability_granted",
        "HttpRead", "https://example.com/api", "GET", "SafeReadOnly", "TestHarness",
        ["HttpStateChange"], ["example.com"],
    ),

    # ── scope failures ──────────────────────────────────────────────────────
    (
        "out_of_scope_destination",
        "HttpRead", "https://evil.com/exfil", "GET", "SafeReadOnly", "TestHarness",
        ["HttpRead"], ["example.com"],
    ),
    (
        "empty_scope",
        "HttpRead", "https://example.com/api", "GET", "SafeReadOnly", "TestHarness",
        ["HttpRead"], [],
    ),
    (
        "exampleevil_not_in_scope",
        "HttpRead", "https://exampleevil.com/api", "GET", "SafeReadOnly", "TestHarness",
        ["HttpRead"], ["example.com"],
    ),

    # ── risk class failures ─────────────────────────────────────────────────
    (
        "destructive_always_denied",
        "HttpStateChange", "https://example.com/delete", "DELETE", "Destructive", "TestHarness",
        ["HttpRead", "HttpStateChange"], ["example.com"],
    ),
    (
        "exfiltrative_always_denied",
        "HttpRead", "https://example.com/dump", "GET", "Exfiltrative", "TestHarness",
        ["HttpRead"], ["example.com"],
    ),
    (
        "sensitive_requires_approval",
        "HttpStateChange", "https://example.com/admin", "POST", "Sensitive", "TestHarness",
        ["HttpRead", "HttpStateChange"], ["example.com"],
    ),

    # ── URL validation ──────────────────────────────────────────────────────
    (
        "javascript_url_denied",
        "HttpRead", "javascript:alert(1)", "GET", "SafeReadOnly", "TestHarness",
        ["HttpRead"], ["example.com"],
    ),
    (
        "ftp_url_denied",
        "HttpRead", "ftp://example.com/file", "GET", "SafeReadOnly", "TestHarness",
        ["HttpRead"], ["example.com"],
    ),
    (
        "file_url_denied",
        "HttpRead", "file:///etc/passwd", "GET", "SafeReadOnly", "TestHarness",
        ["HttpRead"], ["example.com"],
    ),

    # ── workspace mismatch ──────────────────────────────────────────────────
    (
        "wrong_workspace_id",
        "HttpRead", "https://example.com/api", "GET", "SafeReadOnly", "TestHarness",
        ["HttpRead"], ["example.com"],
        # workspace_id will be overridden below
    ),

    # ── ML provenance + destructive ─────────────────────────────────────────
    (
        "ml_provenance_destructive_denied",
        "HttpStateChange", "https://example.com/nuke", "DELETE", "Destructive", "MlPlanner",
        ["HttpRead", "HttpStateChange"], ["example.com"],
    ),
    (
        "ml_provenance_safe_readonly_allowed",
        "HttpRead", "https://example.com/scan", "GET", "SafeReadOnly", "MlPlanner",
        ["HttpRead"], ["example.com"],
    ),

    # ── destination edge cases ──────────────────────────────────────────────
    (
        "loopback_not_in_scope",
        "HttpRead", "https://127.0.0.1/api", "GET", "SafeReadOnly", "TestHarness",
        ["HttpRead"], ["example.com"],
    ),
    (
        "ipv6_loopback_not_in_scope",
        "HttpRead", "https://[::1]/api", "GET", "SafeReadOnly", "TestHarness",
        ["HttpRead"], ["example.com"],
    ),

    # ── structural validation (Rust-only checks → INTENTIONAL_SECURITY_HARDENING) ──
    (
        "empty_destination_denied",
        "HttpRead", "", "GET", "SafeReadOnly", "TestHarness",
        ["HttpRead"], ["example.com"],
    ),
    (
        "empty_method_denied",
        "HttpRead", "https://example.com/api", "", "SafeReadOnly", "TestHarness",
        ["HttpRead"], ["example.com"],
    ),
    (
        "empty_workspace_id_denied",
        "HttpRead", "https://example.com/api", "GET", "SafeReadOnly", "TestHarness",
        ["HttpRead"], ["example.com"],
        # workspace_id overridden to "" below
    ),
]

# Known INTENTIONAL_SECURITY_HARDENING: Rust has structural validation that
# Python's PolicyGate doesn't implement.  These cases produce Python ALLOW
# but Rust DENY — that is correct, not a bug.
KNOWN_HARDENING = frozenset({
    "empty_destination_denied",
    "empty_method_denied",
    "empty_workspace_id_denied",
})


@dataclass
class DiffResult:
    label: str
    python_allowed: bool
    rust_allowed: bool
    python_reason: str
    rust_reason: str
    mismatch_class: Optional[str]


def _python_evaluate(label: str, cap_str: str, dest: str, method: str,
                     risk_str: str, granted_cap_strs: list[str],
                     allowed_hosts: list[str],
                     workspace_id: str = WORKSPACE) -> tuple[bool, str]:
    cap = Capability(cap_str)
    risk = RiskClass(risk_str)
    granted = {Capability(c) for c in granted_cap_strs if c in [e.value for e in Capability]}
    gate = PolicyGate(workspace_id, granted, set(allowed_hosts))
    d = gate.evaluate(cap, dest, method, "diff test", risk)
    return d.allowed, d.reason


def _rust_evaluate(label: str, cap_str: str, dest: str, method: str,
                   risk_str: str, provenance: str, granted_cap_strs: list[str],
                   allowed_hosts: list[str],
                   workspace_id: str = WORKSPACE) -> tuple[bool, str]:
    d = evaluate_action(
        workspace_id=workspace_id,
        capability=cap_str,
        destination=dest,
        method=method,
        reason="diff test",
        risk_class=risk_str,
        provenance=provenance,
        granted_capabilities=granted_cap_strs,
        allowed_hosts=allowed_hosts,
    )
    return d.allowed, d.reason


# ─── differential test ───────────────────────────────────────────────────────

class TestDifferential:
    """Run CORPUS through both engines; fail on PYTHON_BUG or RUST_BUG."""

    def _run_one(self, entry: tuple) -> DiffResult:
        if len(entry) == 8:
            label, cap_str, dest, method, risk_str, provenance, granted, hosts = entry
            ws = WORKSPACE
        else:
            # no override
            label, cap_str, dest, method, risk_str, provenance, granted, hosts = entry[:8]
            ws = WORKSPACE

        # Override workspace_id for specific tests
        if label == "wrong_workspace_id":
            ws_py = "wrong-workspace-id"
            ws_rs = "wrong-workspace-id"
        elif label == "empty_workspace_id_denied":
            ws_py = ""
            ws_rs = ""
        else:
            ws_py = WORKSPACE
            ws_rs = WORKSPACE

        try:
            py_allowed, py_reason = _python_evaluate(
                label, cap_str, dest, method, risk_str, granted, hosts, ws_py
            )
        except Exception as exc:
            py_allowed = False
            py_reason = f"PYTHON_EXCEPTION:{exc}"

        try:
            rs_allowed, rs_reason = _rust_evaluate(
                label, cap_str, dest, method, risk_str, provenance, granted, hosts, ws_rs
            )
        except Exception as exc:
            rs_allowed = False
            rs_reason = f"RUST_EXCEPTION:{exc}"

        if py_allowed == rs_allowed:
            mismatch = None
        elif label in KNOWN_HARDENING and not py_allowed and rs_allowed:
            mismatch = "REASON_ONLY"  # same DENY, shouldn't happen
        elif label in KNOWN_HARDENING and py_allowed and not rs_allowed:
            mismatch = "INTENTIONAL_SECURITY_HARDENING"
        elif not py_allowed and rs_allowed:
            mismatch = "RUST_BUG"
        elif py_allowed and not rs_allowed:
            mismatch = "PYTHON_BUG"
        else:
            mismatch = "SPEC_AMBIGUITY"

        return DiffResult(
            label=label,
            python_allowed=py_allowed,
            rust_allowed=rs_allowed,
            python_reason=py_reason,
            rust_reason=rs_reason,
            mismatch_class=mismatch,
        )

    @pytest.mark.skipif(__import__("raven.rust_bridge", fromlist=["x"])._find_bridge_binary() is None,
                        reason="Rust bridge not built — run build-linux.sh")
    def test_no_blocking_mismatches(self):
        """PYTHON_BUG and RUST_BUG are blocking defects."""
        blocking = []
        informational = []

        for entry in CORPUS:
            result = self._run_one(entry)
            if result.mismatch_class in ("PYTHON_BUG", "RUST_BUG"):
                blocking.append(result)
            elif result.mismatch_class not in (None, "INTENTIONAL_SECURITY_HARDENING", "REASON_ONLY"):
                informational.append(result)

        if informational:
            lines = [f"  SPEC_AMBIGUITY: {r.label} py={r.python_allowed} rs={r.rust_allowed}" for r in informational]
            print("\n[INFORMATIONAL SPEC_AMBIGUITY mismatches]\n" + "\n".join(lines))

        assert not blocking, (
            f"Blocking policy mismatches found:\n"
            + "\n".join(
                f"  [{r.mismatch_class}] {r.label}: "
                f"python={r.python_allowed}({r.python_reason}) "
                f"rust={r.rust_allowed}({r.rust_reason})"
                for r in blocking
            )
        )

    def test_all_destructive_denied_by_both(self):
        destructive = [e for e in CORPUS if e[4] == "Destructive"]
        for entry in destructive:
            r = self._run_one(entry)
            assert not r.python_allowed, f"Python ALLOWed Destructive: {r.label}"
            assert not r.rust_allowed, f"Rust ALLOWed Destructive: {r.label}"

    def test_all_exfiltrative_denied_by_both(self):
        exfiltrative = [e for e in CORPUS if e[4] == "Exfiltrative"]
        for entry in exfiltrative:
            r = self._run_one(entry)
            assert not r.python_allowed, f"Python ALLOWed Exfiltrative: {r.label}"
            assert not r.rust_allowed, f"Rust ALLOWed Exfiltrative: {r.label}"

    def test_hardening_entries_python_allow_rust_deny(self):
        """Intentional security hardening: Rust is strictly tighter than Python
        on structural validity.  Python can't check Rust's internal constraints;
        Rust adds empty-field checks Python doesn't have."""
        for label in KNOWN_HARDENING:
            entry = next((e for e in CORPUS if e[0] == label), None)
            if entry is None:
                continue
            r = self._run_one(entry)
            # Rust must DENY
            assert not r.rust_allowed, (
                f"HARDENING entry '{label}' expected Rust DENY but got ALLOW"
            )
            # Python may or may not deny — accept either
            assert r.mismatch_class in (
                "INTENTIONAL_SECURITY_HARDENING", None
            ), f"Unexpected mismatch class for hardening entry '{label}': {r.mismatch_class}"

    def test_corpus_report(self, capsys):
        """Print a summary table (informational, always passes)."""
        rows = [self._run_one(e) for e in CORPUS]
        header = f"{'Label':<45} {'Py':>4} {'Rs':>4} {'Class':<35}"
        lines = [header, "-" * len(header)]
        for r in rows:
            py = "ALLOW" if r.python_allowed else "DENY "
            rs = "ALLOW" if r.rust_allowed else "DENY "
            cls = r.mismatch_class or "MATCH"
            lines.append(f"{r.label:<45} {py:>4} {rs:>4} {cls:<35}")
        with capsys.disabled():
            print("\n\nPHASE 4 DIFFERENTIAL CORPUS REPORT")
            print("\n".join(lines))
        # This test always passes — it's a reporting test only

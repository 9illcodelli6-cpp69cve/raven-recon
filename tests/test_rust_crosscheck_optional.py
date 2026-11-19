"""A4-SEC — Optional Rust cross-check: OFF by default, fail-closed, tighten-only.

Python PolicyGate is the sole authority. When RAVEN_RUST_VERIFY is set, the
CapabilityGate adapter consults the Rust bridge ONLY for SENSITIVE /
HTTP_STATE_CHANGE decisions that Python already ALLOWed, and only to tighten:
- OFF by default           → the bridge is NEVER called; decision is pure Python.
- ON + bridge unavailable  → fail-closed DENY.
- ON + Rust DENY           → DENY (tightened).
- ON + Rust ALLOW          → no-op (stays ALLOW).
- tighten-only             → Rust can never widen a Python DENY, and is never
                             consulted outside the SENSITIVE/HTTP_STATE_CHANGE scope.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import raven.rust_bridge as rust_bridge
from raven.rust_bridge import BridgeDecision, BridgeDecisionKind
from raven.runtime.capabilities import CapabilityGate, CapabilityDecision
from raven.security.policy_gate import Capability, PolicyGate

WS = "ws-rust-xcheck"
ENV = "RAVEN_RUST_VERIFY"


class _Recorder:
    """Stand-in for rust_bridge.evaluate_action that records calls."""
    def __init__(self, decision=None, raises=None):
        self.decision = decision
        self.raises = raises
        self.calls = 0

    def __call__(self, **kwargs):
        self.calls += 1
        self.last_kwargs = kwargs
        if self.raises is not None:
            raise self.raises
        return self.decision


def _allow_decision():
    return BridgeDecision(kind=BridgeDecisionKind.ALLOW, allowed=True,
                          reason="ok", message="", rust_invoked=True)


def _deny_decision():
    return BridgeDecision(kind=BridgeDecisionKind.DENY, allowed=False,
                          reason="RustSaysNo", message="denied by rust",
                          rust_invoked=True)


def _state_change_gate():
    """Gate whose HTTP_STATE_CHANGE + LowRiskStateChange decision Python ALLOWs."""
    return CapabilityGate(
        workspace_id=WS,
        granted_capabilities={Capability.HTTP_STATE_CHANGE, Capability.HTTP_READ},
        allowed_scope_hosts={"example.com"},
    )


_STATE_CHANGE_CTX = {
    "destination": "https://example.com/update",
    "method": "POST",
    "risk_class": "LowRiskStateChange",
}


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    PolicyGate._reset_emergency_stop_for_test()
    monkeypatch.delenv(ENV, raising=False)
    yield
    PolicyGate._reset_emergency_stop_for_test()


class TestOffByDefault:
    def test_bridge_never_called_when_disabled(self, monkeypatch):
        rec = _Recorder(raises=AssertionError("bridge must not be called when OFF"))
        monkeypatch.setattr(rust_bridge, "evaluate_action", rec)
        gate = _state_change_gate()
        res = gate.check("http_state_change", _STATE_CHANGE_CTX)
        assert res.is_allowed()           # pure-Python ALLOW
        assert rec.calls == 0             # bridge not consulted


class TestEnabledTightens:
    def test_bridge_missing_fails_closed(self, monkeypatch):
        rec = _Recorder(decision=BridgeDecision.deny_fail_closed("binary missing"))
        monkeypatch.setattr(rust_bridge, "evaluate_action", rec)
        monkeypatch.setenv(ENV, "1")
        gate = _state_change_gate()
        res = gate.check("http_state_change", _STATE_CHANGE_CTX)
        assert res.decision == CapabilityDecision.DENY
        assert rec.calls == 1

    def test_rust_deny_downgrades_allow(self, monkeypatch):
        rec = _Recorder(decision=_deny_decision())
        monkeypatch.setattr(rust_bridge, "evaluate_action", rec)
        monkeypatch.setenv(ENV, "1")
        gate = _state_change_gate()
        res = gate.check("http_state_change", _STATE_CHANGE_CTX)
        assert res.decision == CapabilityDecision.DENY
        assert "RUST_CROSSCHECK" in res.reason

    def test_rust_allow_is_noop(self, monkeypatch):
        rec = _Recorder(decision=_allow_decision())
        monkeypatch.setattr(rust_bridge, "evaluate_action", rec)
        monkeypatch.setenv(ENV, "1")
        gate = _state_change_gate()
        res = gate.check("http_state_change", _STATE_CHANGE_CTX)
        assert res.is_allowed()
        assert res.decision == CapabilityDecision.ALLOW
        assert rec.calls == 1

    def test_bridge_exception_fails_closed(self, monkeypatch):
        rec = _Recorder(raises=RuntimeError("bridge exploded"))
        monkeypatch.setattr(rust_bridge, "evaluate_action", rec)
        monkeypatch.setenv(ENV, "1")
        gate = _state_change_gate()
        res = gate.check("http_state_change", _STATE_CHANGE_CTX)
        assert res.decision == CapabilityDecision.DENY
        assert res.reason == "RUST_CROSSCHECK_ERROR"


class TestTightenOnly:
    def test_cannot_widen_a_python_deny(self, monkeypatch):
        # Rust would ALLOW, but Python already DENYs (missing capability) → stays DENY.
        rec = _Recorder(decision=_allow_decision())
        monkeypatch.setattr(rust_bridge, "evaluate_action", rec)
        monkeypatch.setenv(ENV, "1")
        gate = CapabilityGate(
            workspace_id=WS, granted_capabilities=set(),  # no HTTP_STATE_CHANGE grant
            allowed_scope_hosts={"example.com"},
        )
        res = gate.check("http_state_change", _STATE_CHANGE_CTX)
        assert res.decision == CapabilityDecision.DENY
        assert rec.calls == 0   # cross-check never consulted for a non-ALLOW

    def test_not_consulted_outside_scope(self, monkeypatch):
        # HTTP_READ + SafeReadOnly is ALLOWed by Python but is out of cross-check
        # scope (not SENSITIVE, not HTTP_STATE_CHANGE) → Rust not consulted.
        rec = _Recorder(decision=_deny_decision())
        monkeypatch.setattr(rust_bridge, "evaluate_action", rec)
        monkeypatch.setenv(ENV, "1")
        gate = _state_change_gate()
        res = gate.check("http_read", {
            "destination": "https://example.com/read",
            "method": "GET", "risk_class": "SafeReadOnly",
        })
        assert res.is_allowed()
        assert rec.calls == 0

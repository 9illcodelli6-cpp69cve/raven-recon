"""A4-SEC — Capability authority: fail-closed risk + actor provenance + seeded grants.

Behavioral tests that fail against a broken implementation:
- unknown / unmapped risk is fail-closed (never a silent ALLOW);
- provenance is resolved at the boundary and cannot be escalated by the request
  body / model output;
- the live-workspace seed grants the capabilities the shipped terminal/send/recon
  paths need, so fail-closed gating does not regress them to 403.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from raven.runtime.capabilities import (
    CapabilityGate, CapabilityDecision,
    LIVE_WORKSPACE_GRANTS, seed_live_workspace_grants, seed_live_workspace_gate,
)
from raven.security.policy_gate import Capability, PolicyGate
from raven.security.actor_context import (
    ActorSource, resolve_actor, resolve_actor_ignoring_body,
    body_claims_provenance, ActorContext, ProvenanceError,
)
from raven.runtime.execution import ActorKind

WS = "ws-prov-test"


def _gate(caps=None, hosts=None):
    return CapabilityGate(
        workspace_id=WS,
        granted_capabilities=caps or set(),
        allowed_scope_hosts=hosts or set(),
    )


# ── Fail-closed risk classification ──────────────────────────────────────────

class TestFailClosedRisk:
    def setup_method(self):
        PolicyGate._reset_emergency_stop_for_test()

    def test_missing_risk_is_not_a_silent_allow(self):
        gate = _gate(caps={Capability.FILE_READ_WORKSPACE})
        res = gate.check("local_read")  # no risk declared
        assert not res.is_allowed()
        assert res.decision != CapabilityDecision.ALLOW
        assert res.decision == CapabilityDecision.REQUIRE_RESEARCHER_APPROVAL

    def test_unknown_risk_string_is_not_a_silent_allow(self):
        gate = _gate(caps={Capability.FILE_READ_WORKSPACE})
        res = gate.check("local_read", {"risk_class": "WeirdUnmappedClass"})
        assert not res.is_allowed()
        assert res.decision == CapabilityDecision.REQUIRE_RESEARCHER_APPROVAL

    def test_declared_safe_risk_allows(self):
        # Declaring the risk explicitly is the one way a safe read is allowed.
        gate = _gate(caps={Capability.FILE_READ_WORKSPACE})
        res = gate.check("local_read", {"risk_class": "SafeReadOnly"})
        assert res.is_allowed()
        assert res.decision == CapabilityDecision.ALLOW

    def test_unmapped_capability_is_unavailable_not_allowed(self):
        gate = _gate(caps=set(Capability))
        res = gate.check("totally_unknown_capability")
        assert not res.is_allowed()
        assert res.decision == CapabilityDecision.UNAVAILABLE


# ── Actor provenance resolution (C-3) ────────────────────────────────────────

class TestActorProvenance:
    def test_interactive_authenticated_is_researcher(self):
        assert resolve_actor(ActorSource.INTERACTIVE_UI, authenticated=True) \
            == ActorKind.RESEARCHER

    def test_interactive_unauthenticated_fails_closed(self):
        with pytest.raises(ProvenanceError):
            resolve_actor(ActorSource.INTERACTIVE_UI, authenticated=False)

    def test_agent_program_system_sources(self):
        assert resolve_actor(ActorSource.AGENT_LOOP, authenticated=True) \
            == ActorKind.RAVEN_AGENT
        assert resolve_actor(ActorSource.PROGRAM_MODE, authenticated=True) \
            == ActorKind.PROGRAM_AGENT
        assert resolve_actor(ActorSource.INTERNAL, authenticated=True) \
            == ActorKind.SYSTEM

    def test_body_cannot_escalate_provenance(self):
        body = {"actor": "RESEARCHER", "provenance": "RESEARCHER"}
        resolved = resolve_actor_ignoring_body(
            ActorSource.AGENT_LOOP, authenticated=True, request_body=body,
        )
        assert resolved == ActorKind.RAVEN_AGENT      # NOT RESEARCHER
        assert body_claims_provenance(body) is True   # attempt is detectable

    def test_actorcontext_at_boundary_ignores_body(self):
        body = {"actor_kind": "RESEARCHER"}            # escalation attempt
        ctx = ActorContext.at_boundary(
            ActorSource.PROGRAM_MODE, authenticated=True, workspace_id=WS,
            granted_capabilities={Capability.HTTP_READ}, request_body=body,
        )
        assert ctx.actor == ActorKind.PROGRAM_AGENT
        assert ctx.workspace_id == WS
        assert ctx.to_dict()["actor"] == "PROGRAM_AGENT"

    def test_reuses_single_actorkind_enum(self):
        # C-3: actor_context defines no competing enum; it reuses ActorKind.
        import raven.security.actor_context as ac
        from raven.runtime.execution import ActorKind as RealActorKind
        assert ac.ActorKind is RealActorKind


# ── Seeded live-workspace grants (no 403 regression) ─────────────────────────

class TestSeededLiveGrants:
    def setup_method(self):
        PolicyGate._reset_emergency_stop_for_test()

    def test_seed_set_contents(self):
        assert Capability.PROCESS_ANALYZER in LIVE_WORKSPACE_GRANTS
        assert Capability.HTTP_READ in LIVE_WORKSPACE_GRANTS
        assert Capability.HTTP_STATE_CHANGE in LIVE_WORKSPACE_GRANTS
        assert Capability.PROCESS_ANALYZER in seed_live_workspace_grants()

    def test_seeded_gate_allows_live_terminal_capability(self):
        gate = seed_live_workspace_gate(WS, allowed_scope_hosts={"example.com"})
        res = gate.check("process_exec", {"risk_class": "SafeReadOnly"})
        assert res.is_allowed()  # researcher terminal must not regress to 403

    def test_seeded_gate_allows_in_scope_http(self):
        gate = seed_live_workspace_gate(WS, allowed_scope_hosts={"example.com"})
        res = gate.check("http_read", {
            "destination": "https://api.example.com/v1",
            "method": "GET", "risk_class": "SafeReadOnly",
        })
        assert res.is_allowed()  # subdomain in scope, capability seeded

    def test_seeded_gate_still_denies_out_of_scope_http(self):
        gate = seed_live_workspace_gate(WS, allowed_scope_hosts={"example.com"})
        res = gate.check("http_read", {
            "destination": "https://evil.test/x",
            "method": "GET", "risk_class": "SafeReadOnly",
        })
        assert not res.is_allowed()  # seeding grants capability, NOT scope

    def test_ungated_workspace_denies_process_exec(self):
        gate = _gate(caps=set())  # nothing seeded
        res = gate.check("process_exec", {"risk_class": "SafeReadOnly"})
        assert not res.is_allowed()
        assert res.decision == CapabilityDecision.DENY


# ── Model/body output can never self-grant through the gate ──────────────────

class TestNoEscalationThroughGate:
    def setup_method(self):
        PolicyGate._reset_emergency_stop_for_test()

    def test_context_actor_cannot_grant_missing_capability(self):
        gate = _gate(caps=set())  # no grants at all
        res = gate.check("process_exec", {
            "risk_class": "SafeReadOnly",
            "actor": "RESEARCHER",     # attacker-style escalation attempt
            "provenance": "RESEARCHER",
        })
        assert not res.is_allowed()    # provenance in the payload grants nothing

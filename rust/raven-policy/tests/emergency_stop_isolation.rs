//! EmergencyStop integration tests — run in an isolated process.
//!
//! Because EmergencyStop::reset_for_test() is #[cfg(test)] (library-only),
//! these tests are in their own binary so each test file gets a fresh process.
//! Within this binary, emergency stop is triggered ONCE at the start of the
//! relevant tests; tests that must run before the trigger come first.
//!
//! Unit tests for reset/trigger/is_active live in
//! raven-policy/src/emergency.rs.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use raven_core::{
    action::{Provenance, RiskClass},
    ActionRequest, Capability, CapabilitySet, ResourceBudget, WorkspaceContext,
};
use raven_policy::scope_policy::ScopePolicy;
use raven_policy::{EmergencyStop, PolicyEngine};
use uuid::Uuid;

fn make_engine() -> PolicyEngine {
    let mut caps = CapabilitySet::new();
    caps.grant(Capability::HttpRead);
    caps.grant(Capability::HttpStateChange);
    let ws = WorkspaceContext::new("ws-es", std::env::temp_dir());
    let mut scope = ScopePolicy::new();
    scope.allowed_hosts.insert("example.com".into());
    PolicyEngine::new(caps, ws, scope)
}

fn make_req(risk: RiskClass) -> ActionRequest {
    ActionRequest {
        action_id: Uuid::new_v4(),
        workspace_id: "ws-es".into(),
        required_capability: Capability::HttpRead,
        destination: "https://example.com/api".into(),
        method: "GET".into(),
        reason: "emergency stop test".into(),
        budget: ResourceBudget::default(),
        provenance: Provenance::TestHarness,
        risk_class: risk,
    }
}

// ── Emergency stop: trigger then deny ────────────────────────────────────────
// Normal behavior (safe action allowed before trigger) is verified by all 39
// tests in adversarial_policy.rs, which run in a separate binary that never
// triggers the stop.  This file only tests post-trigger behavior.

#[test]
fn z_after_trigger_safe_action_denied() {
    EmergencyStop::trigger();
    let engine = make_engine();
    let req = make_req(RiskClass::SafeReadOnly);
    assert!(
        !engine.evaluate(&req).is_allowed(),
        "safe action must be DENY after emergency stop"
    );
}

#[test]
fn z_after_trigger_destructive_denied() {
    EmergencyStop::trigger();
    let engine = make_engine();
    let req = make_req(RiskClass::Destructive);
    assert!(
        !engine.evaluate(&req).is_allowed(),
        "destructive action must be DENY after emergency stop"
    );
}

#[test]
fn z_after_trigger_exfiltrative_denied() {
    EmergencyStop::trigger();
    let engine = make_engine();
    let req = make_req(RiskClass::Exfiltrative);
    assert!(
        !engine.evaluate(&req).is_allowed(),
        "exfiltrative action must be DENY after emergency stop"
    );
}

#[test]
fn z_after_trigger_sensitive_denied() {
    EmergencyStop::trigger();
    let engine = make_engine();
    let req = make_req(RiskClass::Sensitive);
    assert!(
        !engine.evaluate(&req).is_allowed(),
        "sensitive action must be DENY after emergency stop"
    );
}

#[test]
fn z_after_trigger_is_active_true() {
    EmergencyStop::trigger();
    assert!(
        EmergencyStop::is_active(),
        "is_active() must be true after trigger"
    );
}

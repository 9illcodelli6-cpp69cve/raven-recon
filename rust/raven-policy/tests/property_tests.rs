//! Phase 6 — property tests for raven-policy primitives.
//!
//! INVARIANTS under test:
//! 1. validate_url_structure: any non-http(s) scheme → Err (never ALLOW)
//! 2. ScopePolicy::host_in_scope: empty host → false (never in scope)
//! 3. PolicyEngine: Destructive/Exfiltrative risk → always DENY
//! 4. PolicyEngine: unknown capabilities never produce ALLOW

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use proptest::prelude::*;
use raven_core::{
    action::{Provenance, RiskClass},
    ActionRequest, Capability, CapabilitySet, ResourceBudget, WorkspaceContext,
};
use raven_policy::network_guard::validate_url_structure;
use raven_policy::scope_policy::ScopePolicy;
use raven_policy::PolicyEngine;
use uuid::Uuid;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn make_engine_open() -> PolicyEngine {
    let mut caps = CapabilitySet::new();
    caps.grant(Capability::HttpRead);
    caps.grant(Capability::HttpStateChange);
    let ws = WorkspaceContext::new("ws-prop", std::env::temp_dir());
    let mut scope = ScopePolicy::new();
    scope.allowed_hosts.insert("example.com".into());
    PolicyEngine::new(caps, ws, scope)
}

fn make_req(cap: Capability, dest: &str, risk: RiskClass) -> ActionRequest {
    ActionRequest {
        action_id: Uuid::new_v4(),
        workspace_id: "ws-prop".into(),
        required_capability: cap,
        destination: dest.to_owned(),
        method: "GET".into(),
        reason: "prop test".into(),
        budget: ResourceBudget::default(),
        provenance: Provenance::TestHarness,
        risk_class: risk,
    }
}

// ─── Property 1: non-http(s) scheme → validate_url_structure Err ─────────────

proptest! {
    #[test]
    fn prop_non_https_scheme_always_fails(
        // Generate strings that do NOT start with "http://" or "https://"
        prefix in "[a-z]{1,10}://",
        suffix in "[a-z0-9.]{0,30}(/[a-z0-9/]{0,20})?"
    ) {
        let url = format!("{}{}", prefix, suffix);
        // http:// and https:// would pass; anything else must fail
        let lower = url.to_lowercase();
        if !lower.starts_with("http://") && !lower.starts_with("https://") {
            prop_assert!(
                validate_url_structure(&url).is_err(),
                "non-http scheme {url:?} must fail validate_url_structure"
            );
        }
    }
}

// ─── Property 2: empty or whitespace host → ScopePolicy::host_in_scope false ─

proptest! {
    #[test]
    fn prop_empty_or_whitespace_host_never_in_scope(
        host in "[ \t\n\r]{0,10}"
    ) {
        let mut policy = ScopePolicy::new();
        policy.allowed_hosts.insert("example.com".into());
        // Whitespace-only or empty strings should never be in scope
        // (scope check trims in Python; Rust checks is_empty)
        let trimmed = host.trim();
        if trimmed.is_empty() {
            prop_assert!(
                !policy.host_in_scope(&host),
                "empty/whitespace host {host:?} must not be in scope"
            );
        }
    }
}

// ─── Property 3: Destructive/Exfiltrative always denied regardless of input ──

proptest! {
    #[test]
    fn prop_destructive_always_denied(
        dest_suffix in "[a-z0-9/]{0,30}"
    ) {
        let engine = make_engine_open();
        let dest = format!("https://example.com/{dest_suffix}");
        let req = make_req(Capability::HttpStateChange, &dest, RiskClass::Destructive);
        prop_assert!(
            !engine.evaluate(&req).is_allowed(),
            "Destructive must always be denied regardless of destination"
        );
    }
}

proptest! {
    #[test]
    fn prop_exfiltrative_always_denied(
        dest_suffix in "[a-z0-9/]{0,30}"
    ) {
        let engine = make_engine_open();
        let dest = format!("https://example.com/{dest_suffix}");
        let req = make_req(Capability::HttpRead, &dest, RiskClass::Exfiltrative);
        prop_assert!(
            !engine.evaluate(&req).is_allowed(),
            "Exfiltrative must always be denied regardless of destination"
        );
    }
}

// ─── Property 4: valid https URL with allowed host + safe risk → ALLOW ───────

proptest! {
    #[test]
    fn prop_valid_https_url_safe_risk_allowed(
        path in "/[a-z0-9/_-]{0,30}"
    ) {
        let engine = make_engine_open();
        let dest = format!("https://example.com{path}");
        let req = make_req(Capability::HttpRead, &dest, RiskClass::SafeReadOnly);
        prop_assert!(
            engine.evaluate(&req).is_allowed(),
            "Valid URL in scope with correct caps must ALLOW; dest={dest:?}"
        );
    }
}

// ─── Property 5: ScopePolicy subdomain matching is consistent ────────────────

proptest! {
    #[test]
    fn prop_scope_subdomain_parent_never_matches_without_dot(
        // Generate strings that end with the allowed host but not as ".host"
        suffix in "[a-z]{1,10}"
    ) {
        let mut policy = ScopePolicy::new();
        policy.allowed_hosts.insert("example.com".into());
        // "evil-example.com" should NOT be in scope, only "*.example.com"
        let host = format!("{suffix}example.com");
        // This host ends with "example.com" but NOT with ".example.com"
        if !host.ends_with(".example.com") {
            prop_assert!(
                !policy.host_in_scope(&host),
                "host {host:?} must NOT be in scope (no dot separator)"
            );
        }
    }
}

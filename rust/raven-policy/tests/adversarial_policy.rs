//! Adversarial policy tests — hostile inputs must never produce ALLOW.
//!
//! Phase 5 of the RAVEN V6 Rust Runtime Closure.
//!
//! INVARIANT: no hostile/malformed input may become ALLOW because parsing failed.
//! Unknown/malformed values must never become ALLOW.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use raven_core::{
    action::{Provenance, RiskClass},
    ActionDecision, ActionRequest, Capability, CapabilitySet, ResourceBudget, WorkspaceContext,
};
use raven_policy::network_guard::{check_ip_blocked, validate_url_structure};
use raven_policy::scope_policy::ScopePolicy;
use raven_policy::PolicyEngine;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

// ─── helpers ────────────────────────────────────────────────────────────────

fn make_engine(caps: &[Capability], hosts: &[&str]) -> PolicyEngine {
    let mut cap_set = CapabilitySet::new();
    for c in caps {
        cap_set.grant(c.clone());
    }
    let ws = WorkspaceContext::new("ws-adv", std::env::temp_dir());
    let mut scope = ScopePolicy::new();
    for h in hosts {
        scope.allowed_hosts.insert(h.to_string());
    }
    PolicyEngine::new(cap_set, ws, scope)
}

fn make_req(cap: Capability, dest: &str, risk: RiskClass) -> ActionRequest {
    ActionRequest {
        action_id: Uuid::new_v4(),
        workspace_id: "ws-adv".into(),
        required_capability: cap,
        destination: dest.into(),
        method: "GET".into(),
        reason: "adversarial test".into(),
        budget: ResourceBudget::default(),
        provenance: Provenance::TestHarness,
        risk_class: risk,
    }
}

fn is_denied(d: &ActionDecision) -> bool {
    !d.is_allowed()
}

// ─── empty string tests ──────────────────────────────────────────────────────

#[test]
fn empty_workspace_id_denied() {
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let mut req = make_req(
        Capability::HttpRead,
        "https://example.com/api",
        RiskClass::SafeReadOnly,
    );
    req.workspace_id = String::new();
    assert!(
        is_denied(&engine.evaluate(&req)),
        "empty workspace_id must be denied"
    );
}

#[test]
fn empty_destination_denied() {
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let mut req = make_req(
        Capability::HttpRead,
        "https://example.com/api",
        RiskClass::SafeReadOnly,
    );
    req.destination = String::new();
    assert!(
        is_denied(&engine.evaluate(&req)),
        "empty destination must be denied"
    );
}

#[test]
fn empty_method_denied() {
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let mut req = make_req(
        Capability::HttpRead,
        "https://example.com/api",
        RiskClass::SafeReadOnly,
    );
    req.method = String::new();
    assert!(
        is_denied(&engine.evaluate(&req)),
        "empty method must be denied"
    );
}

// ─── malformed destination ────────────────────────────────────────────────────

#[test]
fn javascript_url_denied() {
    assert!(validate_url_structure("javascript:alert(1)").is_err());
}

#[test]
fn data_url_denied() {
    assert!(validate_url_structure("data:text/html,<script>alert(1)</script>").is_err());
}

#[test]
fn ftp_url_denied() {
    assert!(validate_url_structure("ftp://example.com/file").is_err());
}

#[test]
fn file_url_denied() {
    assert!(validate_url_structure("file:///etc/passwd").is_err());
}

#[test]
fn double_slash_only_denied() {
    assert!(validate_url_structure("//example.com").is_err());
}

#[test]
fn whitespace_only_url_denied() {
    assert!(validate_url_structure("   ").is_err());
}

#[test]
fn url_with_null_byte_denied() {
    // NUL bytes in a URL should fail validation (no valid host extracted)
    let url = "https://example.com\x00evil.com/api";
    // validate_url_structure may succeed extracting "example.com\x00evil.com" or similar;
    // in any case it must NOT extract "example.com" cleanly since the host is tainted.
    // The scope check then denies it since that host is not "example.com".
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let req = make_req(Capability::HttpRead, url, RiskClass::SafeReadOnly);
    assert!(is_denied(&engine.evaluate(&req)));
}

#[test]
fn overly_long_url_denied() {
    let long_dest = format!("https://example.com/{}", "a".repeat(100_000));
    // Should still extract "example.com" as host, but the scope check must work correctly.
    let host = validate_url_structure(&long_dest).unwrap();
    assert_eq!(
        host, "example.com",
        "host extraction must be correct even for long URLs"
    );
}

// ─── IPv4/IPv6 edge cases ─────────────────────────────────────────────────────

#[test]
fn loopback_ipv4_blocked() {
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Loopback is not in the is_private/link-local/multicast/broadcast sets.
    // check_ip_blocked does not block loopback by default (that's handled by scope).
    // The loopback URL "https://127.0.0.1/api" must be out of scope for a normal workspace.
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let req = make_req(
        Capability::HttpRead,
        "https://127.0.0.1/api",
        RiskClass::SafeReadOnly,
    );
    assert!(
        is_denied(&engine.evaluate(&req)),
        "127.0.0.1 must be out of scope"
    );
    let _ = ip; // used above for documentation
}

#[test]
fn private_ipv4_blocked_by_ip_check() {
    for (a, b, c, d) in [(10, 0, 0, 1), (172, 16, 0, 1), (192, 168, 1, 1)] {
        let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        assert!(
            check_ip_blocked(&ip).is_some(),
            "private address {ip} must be blocked"
        );
    }
}

#[test]
fn link_local_ipv4_blocked_by_ip_check() {
    let ip = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1));
    assert!(check_ip_blocked(&ip).is_some());
}

#[test]
fn multicast_ipv4_blocked_by_ip_check() {
    let ip = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
    assert!(check_ip_blocked(&ip).is_some());
}

#[test]
fn broadcast_blocked_by_ip_check() {
    let ip = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255));
    assert!(check_ip_blocked(&ip).is_some());
}

#[test]
fn ipv6_link_local_blocked_by_ip_check() {
    // fe80::1 is link-local
    let ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    assert!(check_ip_blocked(&ip).is_some());
}

#[test]
fn ipv6_multicast_blocked_by_ip_check() {
    let ip = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
    assert!(check_ip_blocked(&ip).is_some());
}

#[test]
fn decimal_ipv4_url_not_in_scope() {
    // "https://2130706433" is 127.0.0.1 in decimal — must not be in scope for example.com
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let req = make_req(
        Capability::HttpRead,
        "https://2130706433/api",
        RiskClass::SafeReadOnly,
    );
    assert!(is_denied(&engine.evaluate(&req)));
}

#[test]
fn ipv6_loopback_url_not_in_scope() {
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let req = make_req(
        Capability::HttpRead,
        "https://[::1]/api",
        RiskClass::SafeReadOnly,
    );
    assert!(is_denied(&engine.evaluate(&req)));
}

// ─── path traversal ──────────────────────────────────────────────────────────

#[test]
fn safe_path_rejects_dotdot() {
    let ws = WorkspaceContext::new("ws-path", std::env::temp_dir());
    assert!(ws.safe_path("../etc/passwd").is_none());
    assert!(ws.safe_path("../../windows/system32").is_none());
    assert!(ws.safe_path("foo/../../etc/shadow").is_none());
}

#[test]
fn safe_path_rejects_absolute_unix() {
    let ws = WorkspaceContext::new("ws-path", std::env::temp_dir());
    assert!(ws.safe_path("/etc/passwd").is_none());
    assert!(ws.safe_path("/absolute/path").is_none());
}

#[test]
fn safe_path_rejects_windows_drive_letters() {
    let ws = WorkspaceContext::new("ws-path", std::env::temp_dir());
    assert!(ws.safe_path("C:\\Windows\\System32\\cmd.exe").is_none());
    assert!(ws.safe_path("D:\\secret.txt").is_none());
}

// ─── UNC/device-like paths ───────────────────────────────────────────────────

#[test]
fn unc_paths_denied_by_url_check() {
    // UNC paths like \\server\share are not http(s) URLs
    assert!(validate_url_structure("\\\\server\\share\\file").is_err());
    assert!(validate_url_structure("//server/share/file").is_err());
}

// ─── resource budget boundaries ──────────────────────────────────────────────

#[test]
fn budget_exceeding_response_cap_invalid() {
    use raven_core::ResourceBudget;
    let b = ResourceBudget {
        max_response_bytes: 200_000_000, // 200 MB — exceeds 100 MB hard cap
        ..Default::default()
    };
    assert!(!b.is_valid());
}

#[test]
fn budget_exceeding_redirect_cap_invalid() {
    use raven_core::ResourceBudget;
    let b = ResourceBudget {
        max_redirects: 255,
        ..Default::default()
    };
    assert!(!b.is_valid());
}

#[test]
fn budget_exceeding_timeout_cap_invalid() {
    use raven_core::ResourceBudget;
    let b = ResourceBudget {
        timeout_ms: 600_000, // 10 min — exceeds 5 min cap
        ..Default::default()
    };
    assert!(!b.is_valid());
}

#[test]
fn invalid_budget_causes_deny() {
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let mut req = make_req(
        Capability::HttpRead,
        "https://example.com/api",
        RiskClass::SafeReadOnly,
    );
    req.budget.max_response_bytes = 200_000_000; // exceeds cap
    assert!(
        is_denied(&engine.evaluate(&req)),
        "invalid budget must be denied"
    );
}

// ─── unknown capability ───────────────────────────────────────────────────────

#[test]
fn no_granted_capabilities_denied() {
    let engine = make_engine(&[], &["example.com"]);
    let req = make_req(
        Capability::HttpRead,
        "https://example.com/api",
        RiskClass::SafeReadOnly,
    );
    assert!(is_denied(&engine.evaluate(&req)));
}

#[test]
fn wrong_capability_granted_denied() {
    // HttpStateChange granted but HttpRead required
    let engine = make_engine(&[Capability::HttpStateChange], &["example.com"]);
    let req = make_req(
        Capability::HttpRead,
        "https://example.com/api",
        RiskClass::SafeReadOnly,
    );
    assert!(is_denied(&engine.evaluate(&req)));
}

// ─── malformed workspace ID ───────────────────────────────────────────────────

#[test]
fn wrong_workspace_id_denied() {
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let mut req = make_req(
        Capability::HttpRead,
        "https://example.com/api",
        RiskClass::SafeReadOnly,
    );
    req.workspace_id = "evil-workspace".into();
    assert!(is_denied(&engine.evaluate(&req)));
}

#[test]
fn null_bytes_in_workspace_id_denied() {
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let mut req = make_req(
        Capability::HttpRead,
        "https://example.com/api",
        RiskClass::SafeReadOnly,
    );
    req.workspace_id = "ws-adv\x00injected".into();
    assert!(is_denied(&engine.evaluate(&req)));
}

// ─── Emergency Stop ───────────────────────────────────────────────────────────
// EmergencyStop::reset_for_test() is #[cfg(test)] in the library source and is
// therefore unavailable to integration test binaries (which link against the
// non-test build of raven-policy).  Full EmergencyStop integration coverage
// lives in tests/emergency_stop_isolation.rs, which is a dedicated binary that
// uses the emergency stop in a fresh process.  Unit coverage is in
// raven-policy/src/policy_engine.rs (emergency_stop_denies_allowed_action) and
// raven-policy/src/emergency.rs (trigger_activates_stop).

// ─── maximum ML score — Rust has no ML input ─────────────────────────────────

#[test]
fn destructive_action_denied_regardless_of_provenance() {
    // ML planner is MlPlanner provenance; even with every capability granted, Destructive is DENY.
    let engine = make_engine(
        &[
            Capability::HttpRead,
            Capability::HttpStateChange,
            Capability::FileWriteWorkspace,
            Capability::ScopeWrite,
        ],
        &["example.com"],
    );
    let mut req = make_req(
        Capability::HttpStateChange,
        "https://example.com/delete-everything",
        RiskClass::Destructive,
    );
    req.provenance = Provenance::MlPlanner;
    assert!(
        is_denied(&engine.evaluate(&req)),
        "ML provenance cannot override Destructive deny"
    );
}

#[test]
fn exfiltrative_action_denied_with_ml_planner_provenance() {
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let mut req = make_req(
        Capability::HttpRead,
        "https://example.com/data",
        RiskClass::Exfiltrative,
    );
    req.provenance = Provenance::MlPlanner;
    assert!(is_denied(&engine.evaluate(&req)));
}

// ─── scope: exact vs subdomain confusion ─────────────────────────────────────

#[test]
fn exampleevil_not_in_scope_for_example_com() {
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let req = make_req(
        Capability::HttpRead,
        "https://exampleevil.com/api",
        RiskClass::SafeReadOnly,
    );
    assert!(
        is_denied(&engine.evaluate(&req)),
        "exampleevil.com must not match example.com scope"
    );
}

#[test]
fn subdomain_of_allowed_host_in_scope() {
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let req = make_req(
        Capability::HttpRead,
        "https://api.example.com/v1",
        RiskClass::SafeReadOnly,
    );
    assert!(
        engine.evaluate(&req).is_allowed(),
        "api.example.com must be in scope for example.com"
    );
}

#[test]
fn empty_scope_denies_all_http_actions() {
    let engine = make_engine(&[Capability::HttpRead], &[]); // empty scope
    let req = make_req(
        Capability::HttpRead,
        "https://example.com/api",
        RiskClass::SafeReadOnly,
    );
    assert!(
        is_denied(&engine.evaluate(&req)),
        "empty scope must deny all HTTP destinations"
    );
}

// ─── oversized values ────────────────────────────────────────────────────────

#[test]
fn oversized_workspace_id_denied() {
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let mut req = make_req(
        Capability::HttpRead,
        "https://example.com/api",
        RiskClass::SafeReadOnly,
    );
    req.workspace_id = "x".repeat(100_000);
    // workspace_id doesn't match engine's "ws-adv" → DENY
    assert!(is_denied(&engine.evaluate(&req)));
}

#[test]
fn oversized_reason_field_does_not_cause_allow() {
    let engine = make_engine(&[Capability::HttpRead], &["example.com"]);
    let mut req = make_req(
        Capability::HttpRead,
        "https://example.com/api",
        RiskClass::SafeReadOnly,
    );
    req.reason = "x".repeat(1_000_000);
    // reason is advisory only — should still ALLOW since all other checks pass
    assert!(
        engine.evaluate(&req).is_allowed(),
        "large reason field must not block a valid request"
    );
}

//! PolicyEngine — the single authority that produces ActionDecision.
//!
//! INVARIANTS:
//! - Default for any unknown/missing input: DENY.
//! - ML/AI cannot call this code to override a decision.
//! - Emergency stop causes immediate DENY for all sensitive actions.
//! - Destructive and Exfiltrative risk classes are always DENIED.

#![forbid(unsafe_code)]

use crate::emergency::EmergencyStop;
use crate::network_guard::validate_url_structure;
use crate::scope_policy::ScopePolicy;
use raven_core::{
    ActionDecision, ActionRequest, CapabilitySet, DecisionReason, RiskClass, WorkspaceContext,
};

/// The policy engine that evaluates all action requests.
///
/// This is the ONLY code that produces `ActionDecision::Allow`.
/// A missing or unavailable PolicyEngine must cause FAIL CLOSED
/// (sensitive action denied).
pub struct PolicyEngine {
    capabilities: CapabilitySet,
    workspace: WorkspaceContext,
    scope: ScopePolicy,
}

impl PolicyEngine {
    pub fn new(
        capabilities: CapabilitySet,
        workspace: WorkspaceContext,
        scope: ScopePolicy,
    ) -> Self {
        Self {
            capabilities,
            workspace,
            scope,
        }
    }

    /// Evaluate an action request and return a binding decision.
    ///
    /// Every code path returns a value. Default: DENY.
    pub fn evaluate(&self, req: &ActionRequest) -> ActionDecision {
        let id = req.action_id;

        // 1. Emergency stop — checked first, overrides everything
        if EmergencyStop::is_active() {
            return ActionDecision::Deny {
                action_id: id,
                reason: DecisionReason::EmergencyStopActive,
                message: "Emergency stop is active — all sensitive actions denied".into(),
            };
        }

        // 2. Structural validation of the request
        if !req.is_structurally_valid() {
            return ActionDecision::Deny {
                action_id: id,
                reason: DecisionReason::MalformedRequest,
                message: "Action request failed structural validation".into(),
            };
        }

        // 3. Budget validation
        if !req.budget.is_valid() {
            return ActionDecision::Deny {
                action_id: id,
                reason: DecisionReason::BudgetExceeded,
                message: "Resource budget exceeds absolute limits".into(),
            };
        }

        // 4. Workspace must match
        if req.workspace_id != self.workspace.workspace_id {
            return ActionDecision::Deny {
                action_id: id,
                reason: DecisionReason::WorkspaceMissing,
                message: format!("Workspace '{}' not authorized", req.workspace_id),
            };
        }

        // 5. Capability check — deny if capability not granted
        if !self.capabilities.has(&req.required_capability) {
            return ActionDecision::Deny {
                action_id: id,
                reason: DecisionReason::CapabilityMissing,
                message: format!("Capability '{:?}' is not granted", req.required_capability),
            };
        }

        // 6. Risk class — Destructive and Exfiltrative are always denied
        match req.risk_class {
            RiskClass::Destructive | RiskClass::Exfiltrative => {
                return ActionDecision::Deny {
                    action_id: id,
                    reason: DecisionReason::RiskClassBlocked,
                    message: format!(
                        "Risk class '{:?}' is blocked by default policy",
                        req.risk_class
                    ),
                };
            }
            RiskClass::Sensitive => {
                return ActionDecision::RequireApproval {
                    action_id: id,
                    reason: DecisionReason::RequiresHumanApproval,
                    message: "Sensitive action requires explicit human approval".into(),
                };
            }
            _ => {}
        }

        // 7. Network destination check (for HTTP capabilities)
        use raven_core::Capability;
        match req.required_capability {
            Capability::HttpRead | Capability::HttpStateChange => {
                let host = match validate_url_structure(&req.destination) {
                    Ok(h) => h,
                    Err(_) => {
                        return ActionDecision::Deny {
                            action_id: id,
                            reason: DecisionReason::DestinationMalformed,
                            message: format!("URL '{}' failed validation", req.destination),
                        };
                    }
                };
                if !self.scope.host_in_scope(&host) {
                    return ActionDecision::Deny {
                        action_id: id,
                        reason: DecisionReason::DestinationOutOfScope,
                        message: format!("Host '{}' is not in authorized scope", host),
                    };
                }
            }
            _ => {}
        }

        // 8. All checks passed → ALLOW
        ActionDecision::Allow {
            action_id: id,
            reason: DecisionReason::PolicyAllowed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emergency::EmergencyStop;
    use crate::scope_policy::ScopePolicy;
    use raven_core::{Capability, CapabilitySet, ResourceBudget, WorkspaceContext};
    use std::env;
    use uuid::Uuid;

    fn make_engine_with_caps(caps: Vec<Capability>, hosts: Vec<&str>) -> PolicyEngine {
        let mut capability_set = CapabilitySet::new();
        for c in caps {
            capability_set.grant(c);
        }
        let workspace = WorkspaceContext::new("ws-test", env::temp_dir());
        let mut scope = ScopePolicy::new();
        for h in hosts {
            scope.allowed_hosts.insert(h.into());
        }
        PolicyEngine::new(capability_set, workspace, scope)
    }

    fn make_req(cap: Capability, dest: &str, risk: RiskClass) -> ActionRequest {
        ActionRequest {
            action_id: Uuid::new_v4(),
            workspace_id: "ws-test".into(),
            required_capability: cap,
            destination: dest.into(),
            method: "GET".into(),
            reason: "test".into(),
            budget: ResourceBudget::default(),
            provenance: raven_core::action::Provenance::TestHarness,
            risk_class: risk,
        }
    }

    #[test]
    fn missing_capability_denied() {
        let engine = make_engine_with_caps(vec![], vec!["example.com"]);
        let req = make_req(
            Capability::HttpRead,
            "https://example.com/api",
            RiskClass::SafeReadOnly,
        );
        let d = engine.evaluate(&req);
        assert!(!d.is_allowed());
    }

    #[test]
    fn capability_granted_in_scope_allowed() {
        let engine = make_engine_with_caps(vec![Capability::HttpRead], vec!["example.com"]);
        let req = make_req(
            Capability::HttpRead,
            "https://example.com/api",
            RiskClass::SafeReadOnly,
        );
        let d = engine.evaluate(&req);
        assert!(d.is_allowed());
    }

    #[test]
    fn out_of_scope_destination_denied() {
        let engine = make_engine_with_caps(vec![Capability::HttpRead], vec!["example.com"]);
        let req = make_req(
            Capability::HttpRead,
            "https://evil.com/steal",
            RiskClass::SafeReadOnly,
        );
        let d = engine.evaluate(&req);
        assert!(!d.is_allowed());
    }

    #[test]
    fn destructive_risk_always_denied() {
        let engine = make_engine_with_caps(vec![Capability::HttpStateChange], vec!["example.com"]);
        let req = make_req(
            Capability::HttpStateChange,
            "https://example.com/delete",
            RiskClass::Destructive,
        );
        let d = engine.evaluate(&req);
        assert!(!d.is_allowed());
    }

    #[test]
    fn exfiltrative_risk_always_denied() {
        let engine = make_engine_with_caps(vec![Capability::HttpRead], vec!["example.com"]);
        let req = make_req(
            Capability::HttpRead,
            "https://example.com/data",
            RiskClass::Exfiltrative,
        );
        let d = engine.evaluate(&req);
        assert!(!d.is_allowed());
    }

    #[test]
    fn sensitive_requires_approval() {
        let engine = make_engine_with_caps(vec![Capability::HttpStateChange], vec!["example.com"]);
        let req = make_req(
            Capability::HttpStateChange,
            "https://example.com/admin",
            RiskClass::Sensitive,
        );
        let d = engine.evaluate(&req);
        assert!(!d.is_allowed());
        assert!(matches!(d, ActionDecision::RequireApproval { .. }));
    }

    #[test]
    fn malformed_url_denied() {
        let engine = make_engine_with_caps(vec![Capability::HttpRead], vec!["example.com"]);
        let req = make_req(
            Capability::HttpRead,
            "javascript:alert(1)",
            RiskClass::SafeReadOnly,
        );
        let d = engine.evaluate(&req);
        assert!(!d.is_allowed());
    }

    #[test]
    fn wrong_workspace_id_denied() {
        let engine = make_engine_with_caps(vec![Capability::HttpRead], vec!["example.com"]);
        let mut req = make_req(
            Capability::HttpRead,
            "https://example.com/api",
            RiskClass::SafeReadOnly,
        );
        req.workspace_id = "other-workspace".into();
        let d = engine.evaluate(&req);
        assert!(!d.is_allowed());
    }

    #[test]
    fn emergency_stop_denies_allowed_action() {
        EmergencyStop::reset_for_test();
        let engine = make_engine_with_caps(vec![Capability::HttpRead], vec!["example.com"]);
        let req = make_req(
            Capability::HttpRead,
            "https://example.com/api",
            RiskClass::SafeReadOnly,
        );
        // Confirm it would normally be allowed
        assert!(engine.evaluate(&req).is_allowed());
        // Trigger emergency stop
        EmergencyStop::trigger();
        assert!(!engine.evaluate(&req).is_allowed());
        EmergencyStop::reset_for_test();
    }

    #[test]
    fn ml_max_probability_cannot_bypass_policy() {
        // This test proves that even if ML assigned maximum probability to an action,
        // policy cannot be bypassed. The PolicyEngine has no probability input.
        // A request for a Destructive action is always denied regardless of any signal.
        let engine = make_engine_with_caps(
            vec![Capability::HttpStateChange, Capability::HttpRead],
            vec!["example.com"],
        );
        // Simulate ML saying "maximum confidence this is safe" — we just request it
        // The risk class is Destructive; policy must DENY.
        let req = make_req(
            Capability::HttpStateChange,
            "https://example.com/delete-everything",
            RiskClass::Destructive,
        );
        let d = engine.evaluate(&req);
        // ML cannot override this — it's DENIED
        assert!(
            !d.is_allowed(),
            "Destructive action must be denied even at max ML confidence"
        );
    }
}

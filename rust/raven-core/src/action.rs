//! Action envelope and decision types.
//!
//! Every controlled action in RAVEN must be described in an `ActionRequest`
//! and evaluated by the policy core before execution.
//!
//! INVARIANT: ML/AI may populate the `reason` field but never changes `decision`.
//!            Only policy logic produces `ActionDecision`.

#![forbid(unsafe_code)]

use crate::budget::ResourceBudget;
use crate::capability::Capability;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Classification of an action's potential impact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RiskClass {
    /// Read-only, no external state change.
    SafeReadOnly,
    /// Minor state change within authorized scope.
    LowRiskStateChange,
    /// Sensitive operation requiring policy approval.
    Sensitive,
    /// Potentially destructive — blocked by default.
    Destructive,
    /// Could exfiltrate data — blocked by default.
    Exfiltrative,
}

/// Which subsystem is requesting the action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provenance {
    Scheduler,
    MlPlanner,
    ResearcherDirect,
    TestHarness,
    SafeLab,
}

/// A fully-described request for a controlled action.
///
/// All fields are required. Malformed requests are DENIED.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    /// Unique ID for this request (used in audit log).
    pub action_id: Uuid,
    /// Workspace this action belongs to.
    pub workspace_id: String,
    /// Capability this action requires.
    pub required_capability: Capability,
    /// Human-readable destination (URL, path, or process name).
    pub destination: String,
    /// Operation method (GET, POST, read, write, execute, etc.).
    pub method: String,
    /// Human-readable reason for this action (from requesting subsystem).
    pub reason: String,
    /// Resource budget for this action.
    pub budget: ResourceBudget,
    /// Who/what is requesting this action.
    pub provenance: Provenance,
    /// Risk classification of this action.
    pub risk_class: RiskClass,
}

impl ActionRequest {
    /// Returns true if this request is structurally valid (all fields non-empty).
    pub fn is_structurally_valid(&self) -> bool {
        !self.workspace_id.is_empty() && !self.destination.is_empty() && !self.method.is_empty()
    }
}

/// Machine-readable reason for an ALLOW or DENY decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DecisionReason {
    CapabilityGranted,
    CapabilityMissing,
    WorkspaceMissing,
    DestinationOutOfScope,
    DestinationMalformed,
    DestinationBlockedByPolicy,
    RiskClassBlocked,
    BudgetExceeded,
    MalformedRequest,
    EmergencyStopActive,
    RequiresHumanApproval,
    PolicyAllowed,
    UnknownCapability,
}

/// The result of evaluating an `ActionRequest` through the policy core.
///
/// INVARIANT: ML/AI cannot produce an `ActionDecision`.
///            Only policy evaluation code returns this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionDecision {
    Allow {
        action_id: Uuid,
        reason: DecisionReason,
    },
    Deny {
        action_id: Uuid,
        reason: DecisionReason,
        message: String,
    },
    RequireApproval {
        action_id: Uuid,
        reason: DecisionReason,
        message: String,
    },
}

impl ActionDecision {
    /// Returns true iff this decision permits execution.
    pub fn is_allowed(&self) -> bool {
        matches!(self, ActionDecision::Allow { .. })
    }

    /// Returns the action_id for correlation with the audit log.
    pub fn action_id(&self) -> Uuid {
        match self {
            ActionDecision::Allow { action_id, .. } => *action_id,
            ActionDecision::Deny { action_id, .. } => *action_id,
            ActionDecision::RequireApproval { action_id, .. } => *action_id,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::budget::ResourceBudget;

    fn make_request(cap: Capability, risk: RiskClass) -> ActionRequest {
        ActionRequest {
            action_id: Uuid::new_v4(),
            workspace_id: "ws-test".into(),
            required_capability: cap,
            destination: "https://example.com/api".into(),
            method: "GET".into(),
            reason: "test".into(),
            budget: ResourceBudget::default(),
            provenance: Provenance::TestHarness,
            risk_class: risk,
        }
    }

    #[test]
    fn valid_request_passes_structural_check() {
        let r = make_request(Capability::HttpRead, RiskClass::SafeReadOnly);
        assert!(r.is_structurally_valid());
    }

    #[test]
    fn empty_workspace_id_fails_structural_check() {
        let mut r = make_request(Capability::HttpRead, RiskClass::SafeReadOnly);
        r.workspace_id = String::new();
        assert!(!r.is_structurally_valid());
    }

    #[test]
    fn deny_is_not_allowed() {
        let id = Uuid::new_v4();
        let d = ActionDecision::Deny {
            action_id: id,
            reason: DecisionReason::CapabilityMissing,
            message: "no cap".into(),
        };
        assert!(!d.is_allowed());
        assert_eq!(d.action_id(), id);
    }

    #[test]
    fn allow_is_allowed() {
        let id = Uuid::new_v4();
        let d = ActionDecision::Allow {
            action_id: id,
            reason: DecisionReason::CapabilityGranted,
        };
        assert!(d.is_allowed());
    }

    #[test]
    fn destructive_risk_class_serializes_correctly() {
        let json = serde_json::to_string(&RiskClass::Destructive).unwrap();
        assert_eq!(json, "\"Destructive\"");
    }
}

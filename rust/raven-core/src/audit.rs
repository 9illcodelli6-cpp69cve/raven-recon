//! Audit log — structured records of policy decisions.
//!
//! INVARIANT: Audit records never contain secrets (tokens, passwords, cookies).

#![forbid(unsafe_code)]

use crate::action::{ActionDecision, DecisionReason, RiskClass};
use crate::capability::Capability;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single policy decision event.
///
/// Stored append-only. Never modified after creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub record_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub workspace_id: String,
    pub action_id: Uuid,
    pub capability: Capability,
    /// Sanitized destination — credentials and query params MUST be stripped
    /// by the caller before populating this field.
    pub destination_sanitized: String,
    pub method: String,
    pub risk_class: RiskClass,
    pub decision: AuditDecisionKind,
    pub reason: DecisionReason,
    pub provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditDecisionKind {
    Allow,
    Deny,
    RequireApproval,
}

impl AuditRecord {
    pub fn from_decision(
        decision: &ActionDecision,
        workspace_id: impl Into<String>,
        capability: Capability,
        destination_sanitized: impl Into<String>,
        method: impl Into<String>,
        risk_class: RiskClass,
        provenance: impl Into<String>,
    ) -> Self {
        let (decision_kind, reason) = match decision {
            ActionDecision::Allow { reason, .. } => (AuditDecisionKind::Allow, reason.clone()),
            ActionDecision::Deny { reason, .. } => (AuditDecisionKind::Deny, reason.clone()),
            ActionDecision::RequireApproval { reason, .. } => {
                (AuditDecisionKind::RequireApproval, reason.clone())
            }
        };

        Self {
            record_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            workspace_id: workspace_id.into(),
            action_id: decision.action_id(),
            capability,
            destination_sanitized: destination_sanitized.into(),
            method: method.into(),
            risk_class,
            decision: decision_kind,
            reason,
            provenance: provenance.into(),
        }
    }

    /// Serialize to JSON for log output.
    ///
    /// Panics in production code are unacceptable for this module; use `?` instead.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::action::{ActionDecision, DecisionReason};

    #[test]
    fn deny_produces_deny_audit_record() {
        let id = Uuid::new_v4();
        let decision = ActionDecision::Deny {
            action_id: id,
            reason: DecisionReason::CapabilityMissing,
            message: "no cap".into(),
        };
        let rec = AuditRecord::from_decision(
            &decision,
            "ws1",
            Capability::HttpRead,
            "https://example.com",
            "GET",
            RiskClass::SafeReadOnly,
            "TestHarness",
        );
        assert_eq!(rec.decision, AuditDecisionKind::Deny);
        assert_eq!(rec.action_id, id);
    }

    #[test]
    fn audit_record_serializes_to_json() {
        let id = Uuid::new_v4();
        let d = ActionDecision::Allow {
            action_id: id,
            reason: DecisionReason::CapabilityGranted,
        };
        let rec = AuditRecord::from_decision(
            &d,
            "ws1",
            Capability::HttpRead,
            "https://example.com/api",
            "GET",
            RiskClass::SafeReadOnly,
            "Scheduler",
        );
        let json = rec.to_json_line().unwrap();
        assert!(json.contains("Allow"));
        assert!(json.contains("CapabilityGranted"));
    }
}

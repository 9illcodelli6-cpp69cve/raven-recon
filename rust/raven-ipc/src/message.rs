//! IPC message schema — versioned, bounded, non-executable.
//!
//! INVARIANTS:
//! - Messages never contain executable objects.
//! - Message sizes are bounded.
//! - Schema is versioned for forward/backward safety.
//! - session_id + nonce provide replay protection.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const IPC_SCHEMA_VERSION: u32 = 1;
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024; // 1 MB

/// A request from Python to the Rust policy core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub schema_version: u32,
    pub session_id: Uuid,
    pub message_id: Uuid,
    pub payload: IpcPayload,
}

/// Parameters for an EvaluateAction IPC request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateActionParams {
    pub workspace_id: String,
    pub capability: String,
    pub destination: String,
    pub method: String,
    pub reason: String,
    pub risk_class: String,
    pub provenance: String,
    /// Capabilities that have been granted to this workspace.
    pub granted_capabilities: Vec<String>,
    /// Hostnames in scope for this workspace.
    pub allowed_hosts: Vec<String>,
}

/// The payload types the policy core handles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IpcPayload {
    EvaluateAction(Box<EvaluateActionParams>),
    CheckEmergencyStop,
    TriggerEmergencyStop,
    HealthCheck,
}

/// Response from the Rust policy core to Python.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub schema_version: u32,
    pub request_id: Uuid,
    pub payload: IpcResponsePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IpcResponsePayload {
    Decision {
        allowed: bool,
        reason: String,
        message: String,
    },
    EmergencyStopStatus {
        active: bool,
    },
    Ok,
    Error(IpcError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcError {
    pub code: String,
    pub message: String,
}

impl IpcRequest {
    /// Validate schema version.
    pub fn is_supported_version(&self) -> bool {
        self.schema_version == IPC_SCHEMA_VERSION
    }
}

// Compile-time invariants on constants.
const _: () = assert!(IPC_SCHEMA_VERSION > 0);
const _: () = assert!(MAX_MESSAGE_BYTES <= 10_485_760); // <= 10 MB

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn request_serializes_roundtrip() {
        let req = IpcRequest {
            schema_version: IPC_SCHEMA_VERSION,
            session_id: Uuid::new_v4(),
            message_id: Uuid::new_v4(),
            payload: IpcPayload::HealthCheck,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, IPC_SCHEMA_VERSION);
        assert!(back.is_supported_version());
    }

    #[test]
    fn wrong_schema_version_rejected() {
        let req = IpcRequest {
            schema_version: 99,
            session_id: Uuid::new_v4(),
            message_id: Uuid::new_v4(),
            payload: IpcPayload::HealthCheck,
        };
        assert!(!req.is_supported_version());
    }
}

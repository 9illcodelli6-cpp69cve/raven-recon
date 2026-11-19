//! Explicit error types for the RAVEN Core.

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("capability '{0}' is not granted")]
    CapabilityDenied(String),

    #[error("workspace '{0}' not found or not authorized")]
    WorkspaceNotFound(String),

    #[error("destination is out of scope: {0}")]
    DestinationOutOfScope(String),

    #[error("malformed destination: {0}")]
    MalformedDestination(String),

    #[error("resource budget exceeded: {0}")]
    BudgetExceeded(String),

    #[error("malformed action request: {0}")]
    MalformedRequest(String),

    #[error("emergency stop is active — all sensitive actions denied")]
    EmergencyStopActive,

    #[error("path traversal attempt: {0}")]
    PathTraversal(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

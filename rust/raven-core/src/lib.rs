//! RAVEN Core — fundamental types for the Trusted Safety Core.
//!
//! # Design Principles
//!
//! - `#![forbid(unsafe_code)]` — no unsafe Rust in this crate.
//! - All types are `Send + Sync`; no hidden global mutable state.
//! - Errors are explicit typed enums, never panics from hostile input.
//! - Checked arithmetic for all size/budget fields.
//! - Default for any sensitive policy decision is DENY.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::arithmetic_side_effects)]

pub mod action;
pub mod audit;
pub mod budget;
pub mod capability;
pub mod error;
pub mod workspace;

pub use action::{ActionDecision, ActionRequest, DecisionReason, RiskClass};
pub use audit::AuditRecord;
pub use budget::ResourceBudget;
pub use capability::{Capability, CapabilitySet};
pub use error::CoreError;
pub use workspace::WorkspaceContext;

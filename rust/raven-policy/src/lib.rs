//! RAVEN Policy Core — the only code that may produce ActionDecision.
//!
//! INVARIANTS:
//! - Default decision for any unknown/missing input: DENY.
//! - ML/AI cannot call into this module to override a decision.
//! - Emergency stop causes all sensitive actions to be denied.
//! - Network destinations are canonicalized and validated before policy check.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod emergency;
pub mod network_guard;
pub mod policy_engine;
pub mod process_guard;
pub mod scope_policy;

pub use emergency::EmergencyStop;
pub use policy_engine::PolicyEngine;

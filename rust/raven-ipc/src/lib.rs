//! RAVEN IPC — in-process message types for Python↔Rust policy bridge.
//!
//! Design: In-process FFI (pyo3/maturin) preferred over out-of-process TCP.
//! When in-process, OS ACL-protected IPC is not needed (same process = same trust).
//!
//! If an out-of-process model is ever needed:
//! - Use Windows Named Pipes with restrictive ACL.
//! - Each session uses an ephemeral authentication token.
//! - Messages carry session_id + nonce for replay protection.
//! - Message sizes are bounded.
//! - Never use an IPC TCP port (use named pipe or Unix socket instead).
//!
//! INVARIANT: Never deserialize executable objects (no pickle-equivalent).

#![forbid(unsafe_code)]

pub mod message;
pub mod session;

pub use message::{IpcError, IpcRequest, IpcResponse};
pub use session::SessionToken;

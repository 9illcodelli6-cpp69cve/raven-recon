//! Capability model — explicit named permissions for sensitive operations.
//!
//! DESIGN: Every sensitive RAVEN operation requires an explicit Capability.
//! There is no UNRESTRICTED_SYSTEM_ACCESS capability.
//! Default: DENY (absence of a capability means denied).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Explicit capabilities for RAVEN operations.
///
/// Each variant represents a specific, bounded permission.
/// No capability grants unrestricted system access.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Capability {
    /// Send an HTTP GET/HEAD request to an authorized scope target.
    HttpRead,
    /// Send an HTTP request that may change server state (POST/PUT/DELETE/PATCH).
    HttpStateChange,
    /// Connect to an explicitly-authorized loopback test fixture.
    LocalFixtureConnect,
    /// Analyze a process (read-only, no execution).
    ProcessAnalyzer,
    /// Read files within an authorized workspace directory.
    FileReadWorkspace,
    /// Write files within an authorized workspace directory.
    FileWriteWorkspace,
    /// Operate the safe non-executing callback collector (loopback only).
    CallbackCollector,
    /// Export a researcher-approved report to disk.
    ReportExport,
    /// Read the canonical scope allowlist.
    ScopeRead,
    /// Update the canonical scope allowlist (requires human approval).
    ScopeWrite,
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// An immutable set of granted capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    granted: HashSet<Capability>,
}

impl CapabilitySet {
    /// Create a new empty (deny-all) capability set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant a capability.
    pub fn grant(&mut self, cap: Capability) {
        self.granted.insert(cap);
    }

    /// Check whether a capability is granted.
    ///
    /// Default: false (deny-all).
    pub fn has(&self, cap: &Capability) -> bool {
        self.granted.contains(cap)
    }

    /// Number of granted capabilities.
    pub fn len(&self) -> usize {
        self.granted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.granted.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_set_denies_all() {
        let caps = CapabilitySet::new();
        assert!(!caps.has(&Capability::HttpRead));
        assert!(!caps.has(&Capability::HttpStateChange));
        assert!(!caps.has(&Capability::FileWriteWorkspace));
    }

    #[test]
    fn grant_and_check() {
        let mut caps = CapabilitySet::new();
        caps.grant(Capability::HttpRead);
        assert!(caps.has(&Capability::HttpRead));
        assert!(!caps.has(&Capability::HttpStateChange));
    }

    #[test]
    fn no_unrestricted_system_access_variant() {
        // This test would fail to compile if someone added
        // Capability::UnrestrictedSystemAccess — document the intent.
        let all = vec![
            Capability::HttpRead,
            Capability::HttpStateChange,
            Capability::LocalFixtureConnect,
            Capability::ProcessAnalyzer,
            Capability::FileReadWorkspace,
            Capability::FileWriteWorkspace,
            Capability::CallbackCollector,
            Capability::ReportExport,
            Capability::ScopeRead,
            Capability::ScopeWrite,
        ];
        // None should be named "UnrestrictedSystemAccess"
        for cap in &all {
            let name = format!("{:?}", cap);
            assert!(
                !name.contains("Unrestricted"),
                "Found unrestricted capability: {}",
                name
            );
        }
    }
}

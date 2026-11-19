//! Scope policy — which destinations are authorized for a workspace.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScopePolicy {
    /// Explicit allowlist of authorized hostnames (e.g. "example.com").
    pub allowed_hosts: HashSet<String>,
    /// Explicit allowlist of loopback test fixture ports.
    pub allowed_fixture_ports: HashSet<u16>,
}

impl ScopePolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a hostname is within the authorized scope.
    ///
    /// Returns false for empty hostname, IPs not in allowlist, etc.
    pub fn host_in_scope(&self, host: &str) -> bool {
        if host.is_empty() {
            return false;
        }
        // Exact match
        if self.allowed_hosts.contains(host) {
            return true;
        }
        // Subdomain match
        for allowed in &self.allowed_hosts {
            if host.ends_with(&format!(".{}", allowed)) {
                return true;
            }
        }
        false
    }

    /// Check if a loopback fixture port is allowed.
    pub fn fixture_port_allowed(&self, port: u16) -> bool {
        self.allowed_fixture_ports.contains(&port)
    }

    /// Returns true if the policy contains at least one allowed host.
    pub fn has_scope(&self) -> bool {
        !self.allowed_hosts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_denies_all() {
        let p = ScopePolicy::new();
        assert!(!p.host_in_scope("example.com"));
        assert!(!p.fixture_port_allowed(8080));
    }

    #[test]
    fn explicit_host_allowed() {
        let mut p = ScopePolicy::new();
        p.allowed_hosts.insert("example.com".into());
        assert!(p.host_in_scope("example.com"));
        assert!(p.host_in_scope("api.example.com"));
        assert!(!p.host_in_scope("notexample.com"));
    }

    #[test]
    fn fixture_port_allowed() {
        let mut p = ScopePolicy::new();
        p.allowed_fixture_ports.insert(9999);
        assert!(p.fixture_port_allowed(9999));
        assert!(!p.fixture_port_allowed(80));
    }
}

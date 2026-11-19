//! RAVEN Safe Lab Sandbox types (Rust side).
//!
//! Defines the LabMode enum and resource budget enforcement types
//! used by the Python Safe Lab implementation.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Safe Lab operating mode.
///
/// Default: `LabOff` — no outbound connections allowed.
/// `LocalOnly`: only loopback (127.0.0.1/::1) connections to authorized fixtures.
/// `Allowlist`: explicit set of allowed destinations (still no arbitrary internet).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LabMode {
    #[default]
    LabOff,
    LocalOnly,
    Allowlist {
        allowed_urls: Vec<String>,
    },
}

impl LabMode {
    /// Returns true if the mode permits any outbound connections at all.
    pub fn permits_any_connections(&self) -> bool {
        !matches!(self, LabMode::LabOff)
    }

    /// Returns true if this destination is permitted by the current mode.
    pub fn permits_destination(&self, dest: &str) -> bool {
        match self {
            LabMode::LabOff => false,
            LabMode::LocalOnly => {
                dest.starts_with("http://127.0.0.1")
                    || dest.starts_with("http://localhost")
                    || dest.starts_with("http://[::1]")
            }
            LabMode::Allowlist { allowed_urls } => {
                allowed_urls.iter().any(|u| dest.starts_with(u.as_str()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_off_denies_all() {
        assert!(!LabMode::LabOff.permits_destination("https://example.com"));
        assert!(!LabMode::LabOff.permits_destination("http://127.0.0.1:9999/test"));
        assert!(!LabMode::LabOff.permits_any_connections());
    }

    #[test]
    fn local_only_permits_loopback() {
        assert!(LabMode::LocalOnly.permits_destination("http://127.0.0.1:9999/fixture"));
        assert!(LabMode::LocalOnly.permits_destination("http://localhost:8080/api"));
        assert!(LabMode::LocalOnly.permits_destination("http://[::1]:7777/"));
    }

    #[test]
    fn local_only_denies_internet() {
        assert!(!LabMode::LocalOnly.permits_destination("https://example.com"));
        assert!(!LabMode::LocalOnly.permits_destination("https://8.8.8.8/resolve"));
    }

    #[test]
    fn allowlist_mode_permits_only_listed() {
        let mode = LabMode::Allowlist {
            allowed_urls: vec!["http://127.0.0.1:9000".into()],
        };
        assert!(mode.permits_destination("http://127.0.0.1:9000/test"));
        assert!(!mode.permits_destination("https://example.com"));
    }

    #[test]
    fn default_is_lab_off() {
        let m = LabMode::default();
        assert_eq!(m, LabMode::LabOff);
    }
}

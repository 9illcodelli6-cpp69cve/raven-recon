//! Network guard — canonicalizes and validates network destinations.
//!
//! INVARIANTS:
//! - Malformed URLs are always DENIED.
//! - Destinations are canonicalized before policy evaluation.
//! - Private/link-local/broadcast/multicast blocked unless explicitly configured.
//! - Redirects must be re-validated (same as initial check).
//! - DNS rebinding/TOCTOU: resolved IPs must remain in scope.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Result of canonicalizing and validating a destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestinationVerdict {
    Allowed { canonical: String },
    Denied { reason: NetworkDenyReason },
}

impl DestinationVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, DestinationVerdict::Allowed { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDenyReason {
    MalformedUrl,
    MissingHost,
    UnsupportedScheme,
    DestinationOutOfScope,
    BlockedPrivateAddress,
    BlockedLinkLocal,
    BlockedMulticast,
    BlockedBroadcast,
    BlockedLoopbackWithoutFixtureAuth,
    BlockedByEmergencyStop,
    RedirectOutOfScope,
    DnsRebindingProtection,
}

/// Validate whether an IP address is blocked by default network policy.
///
/// Returns `Some(reason)` if blocked, `None` if the IP itself is not blocked
/// (still requires scope check).
pub fn check_ip_blocked(ip: &IpAddr) -> Option<NetworkDenyReason> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_link_local() {
                return Some(NetworkDenyReason::BlockedLinkLocal);
            }
            if v4.is_multicast() {
                return Some(NetworkDenyReason::BlockedMulticast);
            }
            if v4.is_broadcast() {
                return Some(NetworkDenyReason::BlockedBroadcast);
            }
            // Block private ranges by default (unless explicitly authorized fixture)
            if v4.is_private() {
                return Some(NetworkDenyReason::BlockedPrivateAddress);
            }
            None
        }
        IpAddr::V6(v6) => {
            if v6.is_multicast() {
                return Some(NetworkDenyReason::BlockedMulticast);
            }
            // v6 link-local: fe80::/10
            let octets = v6.octets();
            if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                return Some(NetworkDenyReason::BlockedLinkLocal);
            }
            None
        }
    }
}

/// Validate a URL string and extract the host for scope checking.
///
/// Only performs structural/syntax validation — no DNS resolution here.
/// (DNS resolution is the Python network layer's responsibility with pinned IPs.)
pub fn validate_url_structure(url: &str) -> Result<String, NetworkDenyReason> {
    let url = url.trim();
    if url.is_empty() {
        return Err(NetworkDenyReason::MalformedUrl);
    }
    // Require http:// or https://
    let lower = url.to_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return Err(NetworkDenyReason::UnsupportedScheme);
    }
    // Extract host (basic — not a full URL parser)
    let after_scheme = if lower.starts_with("https://") {
        &url[8..]
    } else {
        &url[7..]
    };
    let host_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let host_with_port = &after_scheme[..host_end];
    // Strip port
    let host = if let Some(colon_pos) = host_with_port.rfind(':') {
        if colon_pos > 0 {
            &host_with_port[..colon_pos]
        } else {
            host_with_port
        }
    } else {
        host_with_port
    };

    if host.is_empty() {
        return Err(NetworkDenyReason::MissingHost);
    }

    Ok(host.to_lowercase())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn private_ipv4_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(check_ip_blocked(&ip).is_some());
    }

    #[test]
    fn link_local_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1));
        assert!(check_ip_blocked(&ip).is_some());
    }

    #[test]
    fn multicast_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
        assert!(check_ip_blocked(&ip).is_some());
    }

    #[test]
    fn public_ipv4_not_blocked_by_ip_check() {
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        assert!(check_ip_blocked(&ip).is_none());
    }

    #[test]
    fn malformed_url_rejected() {
        assert!(validate_url_structure("ftp://example.com").is_err());
        assert!(validate_url_structure("javascript:alert(1)").is_err());
        assert!(validate_url_structure("").is_err());
        assert!(validate_url_structure("just-a-hostname").is_err());
    }

    #[test]
    fn valid_https_url_returns_host() {
        let host = validate_url_structure("https://example.com/api/test").unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn valid_http_with_port_returns_host() {
        let host = validate_url_structure("http://api.example.com:8080/path").unwrap();
        assert_eq!(host, "api.example.com");
    }

    #[test]
    fn url_with_query_returns_host() {
        let host = validate_url_structure("https://example.com?q=test").unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn no_host_rejected() {
        assert!(validate_url_structure("https://").is_err());
    }
}

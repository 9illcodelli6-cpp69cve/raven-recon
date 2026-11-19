//! Resource budget — bounds on what a single action may consume.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

// Byte-size constants (computed once; values are correct by inspection).
const MB_10: u32 = 10_485_760; // 10 MB
const MB_50: u32 = 52_428_800; // 50 MB
const MB_1: u32 = 1_048_576; // 1 MB
const MB_100: u32 = 104_857_600; // 100 MB hard cap
const MB_200: u32 = 209_715_200; // 200 MB hard cap

/// Maximum resources a single controlled action may use.
///
/// All fields use checked arithmetic. None can overflow.
/// Defaults are conservative and safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceBudget {
    /// Maximum response body bytes (default: 10 MB).
    pub max_response_bytes: u32,
    /// Maximum decompressed body bytes (default: 50 MB).
    pub max_decompressed_bytes: u32,
    /// Maximum number of redirects (default: 5).
    pub max_redirects: u8,
    /// Maximum number of HTTP requests for this action (default: 1).
    pub max_requests: u16,
    /// Wall-clock timeout in milliseconds (default: 30_000 ms = 30 s).
    pub timeout_ms: u32,
    /// Maximum subprocess runtime in milliseconds (default: 10_000 ms).
    pub process_timeout_ms: u32,
    /// Maximum captured stdout/stderr bytes (default: 1 MB).
    pub max_process_output_bytes: u32,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            max_response_bytes: MB_10,
            max_decompressed_bytes: MB_50,
            max_redirects: 5,
            max_requests: 1,
            timeout_ms: 30_000,
            process_timeout_ms: 10_000,
            max_process_output_bytes: MB_1,
        }
    }
}

impl ResourceBudget {
    /// Validate that all budget fields are within absolute maximums.
    pub fn is_valid(&self) -> bool {
        self.max_response_bytes       <= MB_100
            && self.max_decompressed_bytes <= MB_200
            && self.max_redirects          <= 20
            && self.max_requests           <= 1000
            && self.timeout_ms             <= 300_000  // 5 min
            && self.process_timeout_ms     <= 60_000 // 1 min
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid() {
        assert!(ResourceBudget::default().is_valid());
    }

    #[test]
    fn excessive_response_bytes_invalid() {
        let b = ResourceBudget {
            max_response_bytes: 524_288_000, // 500 MB — exceeds 100 MB cap
            ..Default::default()
        };
        assert!(!b.is_valid());
    }

    #[test]
    fn excessive_redirects_invalid() {
        let b = ResourceBudget {
            max_redirects: 25,
            ..Default::default()
        };
        assert!(!b.is_valid());
    }
}

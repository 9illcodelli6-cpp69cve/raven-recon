//! Session token — ephemeral authentication secret for IPC.
//!
//! Generated once per RAVEN session. Never hardcoded. Never logged.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Ephemeral authentication token for a RAVEN session.
///
/// Generated at session start from a random UUID + SHA-256 hash.
/// Must never be logged or written to disk unprotected.
#[derive(Clone)]
pub struct SessionToken {
    token: [u8; 32],
}

impl SessionToken {
    /// Generate a new random session token.
    pub fn generate() -> Self {
        let raw = Uuid::new_v4().to_string();
        let salt = Uuid::new_v4().to_string();
        let combined = format!("{}:{}", raw, salt);
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let result = hasher.finalize();
        let mut token = [0u8; 32];
        token.copy_from_slice(&result);
        Self { token }
    }

    /// Constant-time comparison to prevent timing attacks.
    pub fn matches(&self, other: &[u8]) -> bool {
        if other.len() != 32 {
            return false;
        }
        let mut diff: u8 = 0;
        for (a, b) in self.token.iter().zip(other.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Return token as hex string (for internal use only — never log this).
    pub fn as_hex(&self) -> String {
        hex::encode(self.token)
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionToken([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_tokens_differ() {
        let a = SessionToken::generate();
        let b = SessionToken::generate();
        assert_ne!(a.as_hex(), b.as_hex());
    }

    #[test]
    fn token_matches_itself() {
        let t = SessionToken::generate();
        let bytes = hex::decode(t.as_hex()).unwrap();
        assert!(t.matches(&bytes));
    }

    #[test]
    fn token_does_not_match_wrong_bytes() {
        let t = SessionToken::generate();
        let wrong = vec![0u8; 32];
        assert!(!t.matches(&wrong));
    }

    #[test]
    fn debug_does_not_leak_token() {
        let t = SessionToken::generate();
        let debug = format!("{:?}", t);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(&t.as_hex()));
    }
}

//! Emergency Stop — when triggered, all sensitive actions are denied immediately.
//!
//! INVARIANT:
//! - Emergency stop can only be SET (triggered), not cleared by ML/AI.
//! - Only developer/researcher reset via explicit session restart clears it.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};

/// Global emergency stop flag.
///
/// Once set to true, all sensitive action policy evaluations return DENY.
/// Uses SeqCst ordering for correctness across threads.
static EMERGENCY_STOP: AtomicBool = AtomicBool::new(false);

pub struct EmergencyStop;

impl EmergencyStop {
    /// Trigger emergency stop. This cannot be undone in the current process.
    ///
    /// Effects:
    /// - PolicyEngine denies all new controlled actions.
    /// - Safe Lab stops accepting new requests.
    /// - Existing in-flight work is not aborted (do that separately).
    pub fn trigger() {
        EMERGENCY_STOP.store(true, Ordering::SeqCst);
        log::warn!("RAVEN EMERGENCY STOP triggered — all sensitive actions denied");
    }

    /// Returns true if emergency stop is active.
    pub fn is_active() -> bool {
        EMERGENCY_STOP.load(Ordering::SeqCst)
    }

    /// FOR TESTING ONLY — resets emergency stop state.
    ///
    /// This must never be called from production policy code.
    #[cfg(test)]
    pub fn reset_for_test() {
        EMERGENCY_STOP.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initially_not_active() {
        EmergencyStop::reset_for_test();
        assert!(!EmergencyStop::is_active());
    }

    #[test]
    fn trigger_activates_stop() {
        EmergencyStop::reset_for_test();
        assert!(!EmergencyStop::is_active());
        EmergencyStop::trigger();
        assert!(EmergencyStop::is_active());
        EmergencyStop::reset_for_test();
    }
}

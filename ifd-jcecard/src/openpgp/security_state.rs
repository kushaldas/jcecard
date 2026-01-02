//! Security State for OpenPGP card
//!
//! Tracks which PINs have been verified in the current session.

/// Security conditions for OpenPGP card operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityCondition {
    /// PW1 verified for signing (mode 81)
    PW1_81,
    /// PW1 verified for decryption/authentication (mode 82)
    PW1_82,
    /// PW3 (admin PIN) verified
    PW3,
}

/// Tracks security state for the current session
pub struct SecurityState {
    /// PW1 verified for signing
    pw1_81_verified: bool,
    /// PW1 verified for decrypt/auth
    pw1_82_verified: bool,
    /// PW3 verified
    pw3_verified: bool,
    /// Whether PW1 verification persists across commands
    pw1_valid_multiple: bool,
}

impl SecurityState {
    /// Create a new security state
    pub fn new() -> Self {
        Self {
            pw1_81_verified: false,
            pw1_82_verified: false,
            pw3_verified: false,
            pw1_valid_multiple: true,
        }
    }

    /// Set a security condition as verified
    pub fn set_verified(&mut self, condition: SecurityCondition) {
        match condition {
            SecurityCondition::PW1_81 => self.pw1_81_verified = true,
            SecurityCondition::PW1_82 => self.pw1_82_verified = true,
            SecurityCondition::PW3 => self.pw3_verified = true,
        }
    }

    /// Check if a security condition is satisfied
    pub fn is_verified(&self, condition: SecurityCondition) -> bool {
        match condition {
            SecurityCondition::PW1_81 => self.pw1_81_verified,
            SecurityCondition::PW1_82 => self.pw1_82_verified,
            SecurityCondition::PW3 => self.pw3_verified,
        }
    }

    /// Clear a specific security condition
    pub fn clear(&mut self, condition: SecurityCondition) {
        match condition {
            SecurityCondition::PW1_81 => self.pw1_81_verified = false,
            SecurityCondition::PW1_82 => self.pw1_82_verified = false,
            SecurityCondition::PW3 => self.pw3_verified = false,
        }
    }

    /// Clear all security conditions (on card reset or power cycle)
    pub fn clear_all(&mut self) {
        self.pw1_81_verified = false;
        self.pw1_82_verified = false;
        self.pw3_verified = false;
    }

    /// Called after a signing operation
    /// If PW1 is not set to "valid for multiple commands", clear PW1_81
    pub fn after_sign(&mut self) {
        if !self.pw1_valid_multiple {
            self.pw1_81_verified = false;
        }
    }

    /// Set whether PW1 verification persists across commands
    pub fn set_pw1_valid_multiple(&mut self, valid: bool) {
        self.pw1_valid_multiple = valid;
    }

    /// Get whether PW1 verification persists across commands
    pub fn pw1_valid_multiple(&self) -> bool {
        self.pw1_valid_multiple
    }
}

impl Default for SecurityState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let state = SecurityState::new();
        assert!(!state.is_verified(SecurityCondition::PW1_81));
        assert!(!state.is_verified(SecurityCondition::PW1_82));
        assert!(!state.is_verified(SecurityCondition::PW3));
    }

    #[test]
    fn test_set_verified() {
        let mut state = SecurityState::new();
        state.set_verified(SecurityCondition::PW1_81);
        assert!(state.is_verified(SecurityCondition::PW1_81));
        assert!(!state.is_verified(SecurityCondition::PW1_82));
    }

    #[test]
    fn test_clear_all() {
        let mut state = SecurityState::new();
        state.set_verified(SecurityCondition::PW1_81);
        state.set_verified(SecurityCondition::PW3);
        state.clear_all();
        assert!(!state.is_verified(SecurityCondition::PW1_81));
        assert!(!state.is_verified(SecurityCondition::PW3));
    }

    #[test]
    fn test_after_sign_single() {
        let mut state = SecurityState::new();
        state.set_pw1_valid_multiple(false);
        state.set_verified(SecurityCondition::PW1_81);
        state.after_sign();
        assert!(!state.is_verified(SecurityCondition::PW1_81));
    }

    #[test]
    fn test_after_sign_multiple() {
        let mut state = SecurityState::new();
        state.set_pw1_valid_multiple(true);
        state.set_verified(SecurityCondition::PW1_81);
        state.after_sign();
        assert!(state.is_verified(SecurityCondition::PW1_81));
    }
}

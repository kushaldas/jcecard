//! PIV Security State
//!
//! Tracks authentication state for PIV operations.

/// PIV security conditions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PIVSecurityCondition {
    /// PIN verified
    PINVerified,
    /// Management key authenticated
    ManagementKeyAuthenticated,
}

/// PIV Security State
pub struct PIVSecurityState {
    pin_verified: bool,
    management_key_authenticated: bool,
}

impl PIVSecurityState {
    /// Create a new security state
    pub fn new() -> Self {
        Self {
            pin_verified: false,
            management_key_authenticated: false,
        }
    }

    /// Set PIN as verified
    pub fn set_pin_verified(&mut self, verified: bool) {
        self.pin_verified = verified;
    }

    /// Check if PIN is verified
    pub fn is_pin_verified(&self) -> bool {
        self.pin_verified
    }

    /// Set management key as authenticated
    pub fn set_management_key_authenticated(&mut self, authenticated: bool) {
        self.management_key_authenticated = authenticated;
    }

    /// Check if management key is authenticated
    pub fn is_management_key_authenticated(&self) -> bool {
        self.management_key_authenticated
    }

    /// Clear all security conditions
    pub fn clear_all(&mut self) {
        self.pin_verified = false;
        self.management_key_authenticated = false;
    }
}

impl Default for PIVSecurityState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let state = PIVSecurityState::new();
        assert!(!state.is_pin_verified());
        assert!(!state.is_management_key_authenticated());
    }

    #[test]
    fn test_set_verified() {
        let mut state = PIVSecurityState::new();
        state.set_pin_verified(true);
        assert!(state.is_pin_verified());
    }

    #[test]
    fn test_clear_all() {
        let mut state = PIVSecurityState::new();
        state.set_pin_verified(true);
        state.set_management_key_authenticated(true);
        state.clear_all();
        assert!(!state.is_pin_verified());
        assert!(!state.is_management_key_authenticated());
    }
}

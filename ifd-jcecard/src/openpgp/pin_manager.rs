//! PIN Manager for OpenPGP card
//!
//! Handles PIN verification, change, and retry counter management.

use sha2::{Sha256, Digest};
use crate::card::PINData;

/// PIN types for OpenPGP card
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PINType {
    /// User PIN (PW1) for signing (0x81)
    PW1_81,
    /// User PIN (PW1) for decrypt/auth (0x82)
    PW1_82,
    /// Admin PIN (PW3) (0x83)
    PW3,
    /// Reset Code (RC)
    RC,
}

/// PIN Manager handles PIN verification and management
pub struct PINManager {
    /// Whether PIN verification results should persist across commands
    pw1_valid_multiple: bool,
}

impl PINManager {
    /// Create a new PIN manager
    pub fn new() -> Self {
        Self {
            pw1_valid_multiple: true,
        }
    }

    /// Hash a PIN using SHA-256
    pub fn hash_pin(pin: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(pin);
        hasher.finalize().to_vec()
    }

    /// Verify a PIN
    pub fn verify_pin(&self, pin_type: PINType, pin: &[u8], pin_data: &mut PINData) -> bool {
        let (stored_hash, retry_counter, min_len, max_len) = match pin_type {
            PINType::PW1_81 | PINType::PW1_82 => (
                &pin_data.pw1_hash,
                &mut pin_data.pw1_retry_counter,
                pin_data.pw1_min_length,
                pin_data.pw1_max_length,
            ),
            PINType::PW3 => (
                &pin_data.pw3_hash,
                &mut pin_data.pw3_retry_counter,
                pin_data.pw3_min_length,
                pin_data.pw3_max_length,
            ),
            PINType::RC => (
                &pin_data.rc_hash,
                &mut pin_data.rc_retry_counter,
                pin_data.rc_min_length,
                pin_data.rc_max_length,
            ),
        };

        // Check retry counter
        if *retry_counter == 0 {
            return false;
        }

        // Check PIN length
        let pin_len = pin.len() as u8;
        if pin_len < min_len || pin_len > max_len {
            *retry_counter = retry_counter.saturating_sub(1);
            return false;
        }

        // Compare hashes
        let pin_hash = Self::hash_pin(pin);
        if pin_hash == *stored_hash {
            // Reset retry counter on success
            match pin_type {
                PINType::PW1_81 | PINType::PW1_82 => {
                    pin_data.pw1_retry_counter = pin_data.pw1_max_retries;
                }
                PINType::PW3 => {
                    pin_data.pw3_retry_counter = pin_data.pw3_max_retries;
                }
                PINType::RC => {
                    pin_data.rc_retry_counter = pin_data.rc_max_retries;
                }
            }
            true
        } else {
            *retry_counter = retry_counter.saturating_sub(1);
            false
        }
    }

    /// Change a PIN
    pub fn change_pin(
        &self,
        pin_type: PINType,
        old_pin: &[u8],
        new_pin: &[u8],
        pin_data: &mut PINData,
    ) -> bool {
        // First verify the old PIN
        if !self.verify_pin(pin_type, old_pin, pin_data) {
            return false;
        }

        // Get min/max lengths for new PIN
        let (min_len, max_len) = match pin_type {
            PINType::PW1_81 | PINType::PW1_82 => {
                (pin_data.pw1_min_length, pin_data.pw1_max_length)
            }
            PINType::PW3 => (pin_data.pw3_min_length, pin_data.pw3_max_length),
            PINType::RC => (pin_data.rc_min_length, pin_data.rc_max_length),
        };

        // Check new PIN length
        let new_len = new_pin.len() as u8;
        if new_len < min_len || new_len > max_len {
            return false;
        }

        // Set new PIN
        let new_hash = Self::hash_pin(new_pin);
        match pin_type {
            PINType::PW1_81 | PINType::PW1_82 => {
                pin_data.pw1_hash = new_hash;
                pin_data.pw1_length = new_len;
            }
            PINType::PW3 => {
                pin_data.pw3_hash = new_hash;
                pin_data.pw3_length = new_len;
            }
            PINType::RC => {
                pin_data.rc_hash = new_hash;
                pin_data.rc_length = new_len;
            }
        }

        true
    }

    /// Reset PW1 using Reset Code
    pub fn reset_pw1_with_rc(
        &self,
        reset_code: &[u8],
        new_pin: &[u8],
        pin_data: &mut PINData,
    ) -> bool {
        // Verify reset code
        if pin_data.rc_hash.is_empty() {
            return false;
        }

        if !self.verify_pin(PINType::RC, reset_code, pin_data) {
            return false;
        }

        // Check new PIN length
        let new_len = new_pin.len() as u8;
        if new_len < pin_data.pw1_min_length || new_len > pin_data.pw1_max_length {
            return false;
        }

        // Set new PIN
        pin_data.pw1_hash = Self::hash_pin(new_pin);
        pin_data.pw1_length = new_len;
        pin_data.pw1_retry_counter = pin_data.pw1_max_retries;

        true
    }

    /// Reset PW1 using PW3 (admin PIN)
    pub fn reset_pw1_with_pw3(&self, new_pin: &[u8], pin_data: &mut PINData) -> bool {
        // Note: PW3 verification should be done externally via security_state

        // Check new PIN length
        let new_len = new_pin.len() as u8;
        if new_len < pin_data.pw1_min_length || new_len > pin_data.pw1_max_length {
            return false;
        }

        // Set new PIN
        pin_data.pw1_hash = Self::hash_pin(new_pin);
        pin_data.pw1_length = new_len;
        pin_data.pw1_retry_counter = pin_data.pw1_max_retries;

        true
    }

    /// Get retry counter for a PIN type
    pub fn get_retry_counter(&self, pin_type: PINType, pin_data: &PINData) -> u8 {
        match pin_type {
            PINType::PW1_81 | PINType::PW1_82 => pin_data.pw1_retry_counter,
            PINType::PW3 => pin_data.pw3_retry_counter,
            PINType::RC => pin_data.rc_retry_counter,
        }
    }
}

impl Default for PINManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::storage::CardDataStore;

    fn create_test_pin_data() -> PINData {
        let mut pin_data = PINData::default();
        pin_data.pw1_hash = PINManager::hash_pin(b"123456");
        pin_data.pw3_hash = PINManager::hash_pin(b"12345678");
        pin_data
    }

    #[test]
    fn test_hash_pin() {
        let hash1 = PINManager::hash_pin(b"123456");
        let hash2 = PINManager::hash_pin(b"123456");
        let hash3 = PINManager::hash_pin(b"654321");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 32); // SHA-256
    }

    #[test]
    fn test_verify_pin_success() {
        let manager = PINManager::new();
        let mut pin_data = create_test_pin_data();

        assert!(manager.verify_pin(PINType::PW1_81, b"123456", &mut pin_data));
        assert_eq!(pin_data.pw1_retry_counter, 3);
    }

    #[test]
    fn test_verify_pin_failure() {
        let manager = PINManager::new();
        let mut pin_data = create_test_pin_data();

        assert!(!manager.verify_pin(PINType::PW1_81, b"wrong", &mut pin_data));
        assert_eq!(pin_data.pw1_retry_counter, 2);
    }

    #[test]
    fn test_change_pin() {
        let manager = PINManager::new();
        let mut pin_data = create_test_pin_data();

        assert!(manager.change_pin(PINType::PW1_81, b"123456", b"newpin", &mut pin_data));
        assert!(manager.verify_pin(PINType::PW1_81, b"newpin", &mut pin_data));
    }
}

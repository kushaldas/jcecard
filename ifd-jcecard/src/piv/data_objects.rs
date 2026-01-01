//! PIV Data Objects
//!
//! Manages PIV data objects (certificates, keys, etc.)

use serde::{Deserialize, Serialize};

/// PIV key slot identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PIVKeySlot {
    /// PIV Authentication (9A)
    Authentication = 0x9A,
    /// Card Management Key (9B)
    CardManagement = 0x9B,
    /// Digital Signature (9C)
    DigitalSignature = 0x9C,
    /// Key Management (9D)
    KeyManagement = 0x9D,
    /// Card Authentication (9E)
    CardAuthentication = 0x9E,
}

impl PIVKeySlot {
    /// Try to convert from a byte value
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x9A => Some(Self::Authentication),
            0x9B => Some(Self::CardManagement),
            0x9C => Some(Self::DigitalSignature),
            0x9D => Some(Self::KeyManagement),
            0x9E => Some(Self::CardAuthentication),
            _ => None,
        }
    }
}

/// PIV algorithm identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PIVAlgorithm {
    /// 3DES-ECB
    TDES = 0x03,
    /// RSA 2048
    RSA2048 = 0x07,
    /// ECC P-256
    ECCP256 = 0x11,
    /// ECC P-384
    ECCP384 = 0x14,
}

impl PIVAlgorithm {
    /// Try to convert from a byte value
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x03 => Some(Self::TDES),
            0x07 => Some(Self::RSA2048),
            0x11 => Some(Self::ECCP256),
            0x14 => Some(Self::ECCP384),
            _ => None,
        }
    }
}

/// Key data for a PIV slot
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PIVKeyData {
    pub algorithm: u8,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub certificate: Vec<u8>,
}

/// PIV Data Objects storage
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PIVDataObjects {
    /// Card Holder Unique Identifier (CHUID)
    pub chuid: Vec<u8>,
    /// Cardholder Capability Container (CCC)
    pub ccc: Vec<u8>,
    /// Key for slot 9A (Authentication)
    pub key_9a: PIVKeyData,
    /// Key for slot 9C (Digital Signature)
    pub key_9c: PIVKeyData,
    /// Key for slot 9D (Key Management)
    pub key_9d: PIVKeyData,
    /// Key for slot 9E (Card Authentication)
    pub key_9e: PIVKeyData,
    /// Card Management Key (3DES, slot 9B)
    pub management_key: Vec<u8>,
    /// PIN (Card Holder PIN)
    pub pin: Vec<u8>,
    /// PUK (PIN Unblocking Key)
    pub puk: Vec<u8>,
    /// PIN retry counter
    pub pin_retries: u8,
    /// PUK retry counter
    pub puk_retries: u8,
    /// Printed information
    pub printed_info: Vec<u8>,
    /// Discovery object
    pub discovery: Vec<u8>,
    /// Key history
    pub key_history: Vec<u8>,
}

impl PIVDataObjects {
    /// Default management key (3DES)
    pub const DEFAULT_MGMT_KEY: &'static [u8] = &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];

    /// Default PIN
    pub const DEFAULT_PIN: &'static [u8] = b"123456";

    /// Default PUK
    pub const DEFAULT_PUK: &'static [u8] = b"12345678";

    /// Create new PIV data objects with defaults
    pub fn new() -> Self {
        Self {
            chuid: Vec::new(),
            ccc: Vec::new(),
            key_9a: PIVKeyData::default(),
            key_9c: PIVKeyData::default(),
            key_9d: PIVKeyData::default(),
            key_9e: PIVKeyData::default(),
            management_key: Self::DEFAULT_MGMT_KEY.to_vec(),
            pin: Self::DEFAULT_PIN.to_vec(),
            puk: Self::DEFAULT_PUK.to_vec(),
            pin_retries: 3,
            puk_retries: 3,
            printed_info: Vec::new(),
            discovery: Vec::new(),
            key_history: Vec::new(),
        }
    }

    /// Get key data for a slot
    pub fn get_key(&self, slot: PIVKeySlot) -> Option<&PIVKeyData> {
        match slot {
            PIVKeySlot::Authentication => Some(&self.key_9a),
            PIVKeySlot::DigitalSignature => Some(&self.key_9c),
            PIVKeySlot::KeyManagement => Some(&self.key_9d),
            PIVKeySlot::CardAuthentication => Some(&self.key_9e),
            PIVKeySlot::CardManagement => None, // Management key is special
        }
    }

    /// Get mutable key data for a slot
    pub fn get_key_mut(&mut self, slot: PIVKeySlot) -> Option<&mut PIVKeyData> {
        match slot {
            PIVKeySlot::Authentication => Some(&mut self.key_9a),
            PIVKeySlot::DigitalSignature => Some(&mut self.key_9c),
            PIVKeySlot::KeyManagement => Some(&mut self.key_9d),
            PIVKeySlot::CardAuthentication => Some(&mut self.key_9e),
            PIVKeySlot::CardManagement => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_slot_from_byte() {
        assert_eq!(PIVKeySlot::from_byte(0x9A), Some(PIVKeySlot::Authentication));
        assert_eq!(PIVKeySlot::from_byte(0x9C), Some(PIVKeySlot::DigitalSignature));
        assert_eq!(PIVKeySlot::from_byte(0xFF), None);
    }

    #[test]
    fn test_default_credentials() {
        let data = PIVDataObjects::new();
        assert_eq!(data.management_key.len(), 24);
        assert_eq!(data.pin, b"123456");
        assert_eq!(data.puk, b"12345678");
    }
}

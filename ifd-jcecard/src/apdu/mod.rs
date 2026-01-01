//! APDU (Application Protocol Data Unit) handling
//!
//! This module provides simple, beginner-friendly structs and functions for
//! working with ISO 7816-4 APDUs. The design is inspired by the talktosc crate.
//!
//! # Example
//! ```ignore
//! use ifd_jcecard::apdu::{parse_apdu, Response};
//!
//! // Parse an incoming APDU
//! let raw = &[0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
//! let apdu = parse_apdu(raw).unwrap();
//! println!("INS: 0x{:02X}", apdu.ins);
//!
//! // Create a success response
//! let response = Response::success(vec![0x01, 0x02, 0x03]);
//! assert!(response.is_okay());
//! ```

mod response;
mod status;

pub use response::Response;
pub use status::SW;

use thiserror::Error;

/// Errors that can occur during APDU parsing
#[derive(Debug, Error, PartialEq, Eq)]
pub enum APDUError {
    #[error("APDU too short: expected at least 4 bytes, got {0}")]
    TooShort(usize),

    #[error("Invalid APDU length")]
    InvalidLength,

    #[error("Invalid extended APDU format")]
    InvalidExtendedFormat,
}

/// A parsed APDU command
///
/// This struct contains all the fields from an incoming APDU command.
/// It's designed to be simple and flat for easy understanding.
///
/// # Fields
/// - `cla`: Class byte (indicates secure messaging, logical channel, etc.)
/// - `ins`: Instruction byte (the command to execute)
/// - `p1`, `p2`: Parameter bytes (command-specific)
/// - `data`: Command data (may be empty)
/// - `le`: Expected response length (None if not specified)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct APDU {
    /// Class byte (CLA)
    pub cla: u8,
    /// Instruction byte (INS)
    pub ins: u8,
    /// Parameter 1 (P1)
    pub p1: u8,
    /// Parameter 2 (P2)
    pub p2: u8,
    /// Command data (may be empty)
    pub data: Vec<u8>,
    /// Expected response length (Le), None if not specified
    pub le: Option<u32>,
}

impl APDU {
    /// Create a new APDU with just the header (CLA, INS, P1, P2)
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: None,
        }
    }

    /// Create a new APDU with data
    pub fn with_data(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le: None,
        }
    }

    /// Check if this is a chained APDU (CLA bit 4 set)
    pub fn is_chained(&self) -> bool {
        (self.cla & 0x10) != 0
    }

    /// Get P1-P2 combined as a u16 (useful for PSO commands)
    pub fn p1p2(&self) -> u16 {
        ((self.p1 as u16) << 8) | (self.p2 as u16)
    }
}

/// Parse raw bytes into an APDU
///
/// Supports both short and extended APDU formats:
/// - Short: CLA INS P1 P2 [Lc Data] [Le]
/// - Extended: CLA INS P1 P2 00 Lc1 Lc2 Data [Le1 Le2]
///
/// # Example
/// ```ignore
/// let raw = &[0x00, 0xCA, 0x00, 0x6E, 0x00];  // GET DATA with Le=256
/// let apdu = parse_apdu(raw).unwrap();
/// assert_eq!(apdu.ins, 0xCA);
/// assert_eq!(apdu.le, Some(256));
/// ```
pub fn parse_apdu(data: &[u8]) -> Result<APDU, APDUError> {
    if data.len() < 4 {
        return Err(APDUError::TooShort(data.len()));
    }

    let cla = data[0];
    let ins = data[1];
    let p1 = data[2];
    let p2 = data[3];

    // Case 1: CLA INS P1 P2 (no data, no Le)
    if data.len() == 4 {
        return Ok(APDU::new(cla, ins, p1, p2));
    }

    let remaining = &data[4..];

    // Check for extended APDU format (first byte after header is 0x00 and more bytes follow)
    // Extended format: 00 Lc1 Lc2 [Data] [Le1 Le2]
    if !remaining.is_empty() && remaining[0] == 0x00 && remaining.len() > 2 {
        // Validate that this is actually extended format by checking if Lc makes sense
        let ext_remaining = &remaining[1..];
        if ext_remaining.len() >= 2 {
            let potential_lc = ((ext_remaining[0] as usize) << 8) | (ext_remaining[1] as usize);
            // Extended format is valid if:
            // - Case 2E: Lc absent, just Le (potential_lc would be Le, and ext_remaining.len() == 2)
            // - Case 3E: Lc + Data only (ext_remaining.len() == 2 + potential_lc)
            // - Case 4E: Lc + Data + Le (ext_remaining.len() == 2 + potential_lc + 2)
            let is_valid_extended = ext_remaining.len() == 2  // Case 2E: Le only
                || ext_remaining.len() == 2 + potential_lc   // Case 3E: Lc + Data
                || ext_remaining.len() == 2 + potential_lc + 2; // Case 4E: Lc + Data + Le

            if is_valid_extended {
                return parse_extended_apdu(cla, ins, p1, p2, ext_remaining);
            }

            // Special case: T=1 protocol may send 00 as "extended response" indicator
            // followed by a short-format APDU. Try parsing the rest as short format.
            // Format: 00 Lc [Data] [Le] where the leading 00 just indicates extended Le capability
            if let Ok(apdu) = parse_short_apdu(cla, ins, p1, p2, ext_remaining) {
                return Ok(apdu);
            }
        }
        // If extended format doesn't make sense, fall through to short format
        // This handles cases where the leading 00 might be part of short format data
    }

    // Short APDU format
    parse_short_apdu(cla, ins, p1, p2, remaining)
}

/// Parse short format APDU (Lc/Le up to 255 bytes)
fn parse_short_apdu(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    remaining: &[u8],
) -> Result<APDU, APDUError> {
    if remaining.is_empty() {
        return Ok(APDU::new(cla, ins, p1, p2));
    }

    let first_byte = remaining[0];

    // Case 2: Only Le (1 byte) - Le=0 means 256
    if remaining.len() == 1 {
        let le = if first_byte == 0 { 256 } else { first_byte as u32 };
        return Ok(APDU {
            cla, ins, p1, p2,
            data: Vec::new(),
            le: Some(le),
        });
    }

    // first_byte is Lc
    let lc = first_byte as usize;

    // Case 3: Lc + Data (no Le)
    if remaining.len() == 1 + lc {
        return Ok(APDU {
            cla, ins, p1, p2,
            data: remaining[1..1 + lc].to_vec(),
            le: None,
        });
    }

    // Case 4: Lc + Data + Le
    if remaining.len() == 1 + lc + 1 {
        let le_byte = remaining[1 + lc];
        let le = if le_byte == 0 { 256 } else { le_byte as u32 };
        return Ok(APDU {
            cla, ins, p1, p2,
            data: remaining[1..1 + lc].to_vec(),
            le: Some(le),
        });
    }

    Err(APDUError::InvalidLength)
}

/// Parse extended format APDU (Lc/Le up to 65535 bytes)
fn parse_extended_apdu(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    remaining: &[u8],
) -> Result<APDU, APDUError> {
    if remaining.len() < 2 {
        return Err(APDUError::InvalidExtendedFormat);
    }

    let first_word = ((remaining[0] as u32) << 8) | (remaining[1] as u32);

    // Case 2E: Only extended Le (no data) - Le=0 means 65536
    if remaining.len() == 2 {
        let le = if first_word == 0 { 65536 } else { first_word };
        return Ok(APDU {
            cla, ins, p1, p2,
            data: Vec::new(),
            le: Some(le),
        });
    }

    // first_word is Lc (extended)
    let lc = first_word as usize;

    if remaining.len() < 2 + lc {
        return Err(APDUError::InvalidLength);
    }

    let cmd_data = remaining[2..2 + lc].to_vec();

    // Case 3E: Extended Lc + Data (no Le)
    if remaining.len() == 2 + lc {
        return Ok(APDU {
            cla, ins, p1, p2,
            data: cmd_data,
            le: None,
        });
    }

    // Case 4E: Extended Lc + Data + Extended Le
    if remaining.len() == 2 + lc + 2 {
        let le_word = ((remaining[2 + lc] as u32) << 8) | (remaining[2 + lc + 1] as u32);
        let le = if le_word == 0 { 65536 } else { le_word };
        return Ok(APDU {
            cla, ins, p1, p2,
            data: cmd_data,
            le: Some(le),
        });
    }

    Err(APDUError::InvalidExtendedFormat)
}

/// OpenPGP Instruction bytes
pub mod ins {
    pub const SELECT: u8 = 0xA4;
    pub const GET_DATA: u8 = 0xCA;
    pub const GET_NEXT_DATA: u8 = 0xCC;
    pub const VERIFY: u8 = 0x20;
    pub const CHANGE_REFERENCE_DATA: u8 = 0x24;
    pub const RESET_RETRY_COUNTER: u8 = 0x2C;
    pub const PUT_DATA: u8 = 0xDA;
    pub const PUT_DATA_ODD: u8 = 0xDB;
    pub const GENERATE_ASYMMETRIC_KEY_PAIR: u8 = 0x47;
    pub const PSO: u8 = 0x2A;
    pub const INTERNAL_AUTHENTICATE: u8 = 0x88;
    pub const GET_CHALLENGE: u8 = 0x84;
    pub const GET_RESPONSE: u8 = 0xC0;
    pub const TERMINATE_DF: u8 = 0xE6;
    pub const ACTIVATE_FILE: u8 = 0x44;
}

/// PSO (Perform Security Operation) P1-P2 values
pub mod pso {
    /// Compute Digital Signature (P1=0x9E, P2=0x9A)
    pub const CDS: u16 = 0x9E9A;
    /// Decipher (P1=0x80, P2=0x86)
    pub const DECIPHER: u16 = 0x8086;
    /// Encipher (P1=0x86, P2=0x80)
    pub const ENCIPHER: u16 = 0x8680;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case1_no_data_no_le() {
        let apdu = parse_apdu(&[0x00, 0xA4, 0x04, 0x00]).unwrap();
        assert_eq!(apdu.cla, 0x00);
        assert_eq!(apdu.ins, 0xA4);
        assert_eq!(apdu.p1, 0x04);
        assert_eq!(apdu.p2, 0x00);
        assert!(apdu.data.is_empty());
        assert!(apdu.le.is_none());
    }

    #[test]
    fn test_case2_le_only() {
        let apdu = parse_apdu(&[0x00, 0xCA, 0x00, 0x6E, 0x00]).unwrap();
        assert_eq!(apdu.ins, 0xCA);
        assert!(apdu.data.is_empty());
        assert_eq!(apdu.le, Some(256)); // 0x00 means 256
    }

    #[test]
    fn test_case3_lc_data() {
        let apdu = parse_apdu(&[0x00, 0x20, 0x00, 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36]).unwrap();
        assert_eq!(apdu.ins, 0x20);
        assert_eq!(apdu.data, vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);
        assert!(apdu.le.is_none());
    }

    #[test]
    fn test_case4_lc_data_le() {
        let apdu = parse_apdu(&[0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00]).unwrap();
        assert_eq!(apdu.ins, 0xA4);
        assert_eq!(apdu.data, vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]);
        assert_eq!(apdu.le, Some(256));
    }

    #[test]
    fn test_chained_command() {
        let apdu = parse_apdu(&[0x10, 0xDB, 0x3F, 0xFF, 0x04, 0x01, 0x02, 0x03, 0x04]).unwrap();
        assert!(apdu.is_chained());
        assert_eq!(apdu.cla, 0x10);
    }

    #[test]
    fn test_p1p2_helper() {
        let apdu = parse_apdu(&[0x00, 0x2A, 0x9E, 0x9A]).unwrap();
        assert_eq!(apdu.p1p2(), 0x9E9A);
        assert_eq!(apdu.p1p2(), pso::CDS);
    }

    #[test]
    fn test_too_short() {
        assert!(matches!(
            parse_apdu(&[0x00, 0xA4, 0x04]),
            Err(APDUError::TooShort(3))
        ));
    }
}

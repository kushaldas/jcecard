//! TLV (Tag-Length-Value) encoding and decoding
//!
//! This module implements ISO7816 TLV format, following patterns from the talktosc crate.
//! TLVs are used extensively in smartcard communication for structured data.
//!
//! # Example
//! ```ignore
//! use ifd_jcecard::tlv::{read_list, TLV};
//!
//! let data = vec![0x4F, 0x07, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04];
//! let tlvs = read_list(&data, true);
//!
//! if let Some(aid) = tlvs[0].get_aid() {
//!     println!("AID: {:?}", aid);
//! }
//! ```

mod parser;
mod encoder;

pub use parser::{TLV, TLVError, TLVParser};
pub use encoder::{TLVEncoder, TLVBuilder};

/// Parse TLV data and return a list of TLV structures
///
/// This is the main entry point for parsing, following the talktosc pattern.
///
/// # Arguments
/// * `data` - Raw bytes to parse
/// * `recursive` - If true, parse nested TLVs in constructed tags
///
/// # Example
/// ```ignore
/// let tlvs = read_list(&data, true);
/// for tlv in &tlvs {
///     println!("Tag: 0x{:X}, Length: {}", tlv.tag, tlv.value.len());
/// }
/// ```
pub fn read_list(data: &[u8], recursive: bool) -> Vec<TLV> {
    parser::read_list(data, recursive)
}

/// Parse a single TLV from data
///
/// Returns the TLV and any remaining unparsed bytes.
pub fn read_single(data: &[u8], recursive: bool) -> Result<(TLV, Vec<u8>), String> {
    parser::read_single(data.to_vec(), recursive)
}

/// Convert a value to hex string for display
pub fn hex<T: std::fmt::UpperHex>(value: T) -> String {
    format!("0x{:X}", value)
}

/// Convert a byte vector to hex string
pub fn hexify(value: &[u8]) -> String {
    value.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

/// Parse the card serial number from AID response
pub fn parse_card_serial(data: &[u8]) -> String {
    if data.len() < 14 {
        return String::new();
    }
    format!("{:02X}{:02X}{:02X}{:02X}", data[10], data[11], data[12], data[13])
}

/// Parse 60 bytes of fingerprints into 3 separate fingerprints
pub fn parse_fingerprints(data: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    if data.len() < 60 {
        return (Vec::new(), Vec::new(), Vec::new());
    }
    (
        data[0..20].to_vec(),   // Signature key fingerprint
        data[20..40].to_vec(),  // Decryption key fingerprint
        data[40..60].to_vec(),  // Authentication key fingerprint
    )
}

/// OpenPGP-specific tag constants
pub mod tags {
    // Application identification
    pub const AID: u16 = 0x004F;
    pub const HISTORICAL_BYTES: u16 = 0x5F52;

    // Cardholder data
    pub const CARDHOLDER_RELATED_DATA: u16 = 0x0065;
    pub const NAME: u16 = 0x005B;
    pub const LANGUAGE: u16 = 0x5F2D;
    pub const SEX: u16 = 0x5F35;
    pub const LOGIN_DATA: u16 = 0x005E;
    pub const URL: u16 = 0x5F50;

    // Application related data
    pub const APPLICATION_RELATED_DATA: u16 = 0x006E;
    pub const DISCRETIONARY_DOS: u16 = 0x0073;
    pub const EXTENDED_CAPABILITIES: u16 = 0x00C0;
    pub const ALGORITHM_ATTRIBUTES_SIG: u16 = 0x00C1;
    pub const ALGORITHM_ATTRIBUTES_DEC: u16 = 0x00C2;
    pub const ALGORITHM_ATTRIBUTES_AUT: u16 = 0x00C3;
    pub const PW_STATUS_BYTES: u16 = 0x00C4;
    pub const FINGERPRINTS: u16 = 0x00C5;
    pub const CA_FINGERPRINTS: u16 = 0x00C6;
    pub const KEY_TIMESTAMPS: u16 = 0x00CD;

    // Individual fingerprints
    pub const FINGERPRINT_SIG: u16 = 0x00C7;
    pub const FINGERPRINT_DEC: u16 = 0x00C8;
    pub const FINGERPRINT_AUT: u16 = 0x00C9;
    pub const CA_FINGERPRINT_1: u16 = 0x00CA;
    pub const CA_FINGERPRINT_2: u16 = 0x00CB;
    pub const CA_FINGERPRINT_3: u16 = 0x00CC;

    // Key timestamps
    pub const TIMESTAMP_SIG: u16 = 0x00CE;
    pub const TIMESTAMP_DEC: u16 = 0x00CF;
    pub const TIMESTAMP_AUT: u16 = 0x00D0;

    // Security support template
    pub const SECURITY_SUPPORT_TEMPLATE: u16 = 0x007A;
    pub const DIGITAL_SIG_COUNTER: u16 = 0x0093;

    // Private use DOs
    pub const PRIVATE_DO_1: u16 = 0x0101;
    pub const PRIVATE_DO_2: u16 = 0x0102;
    pub const PRIVATE_DO_3: u16 = 0x0103;
    pub const PRIVATE_DO_4: u16 = 0x0104;

    // Key data
    pub const CARDHOLDER_CERTIFICATE: u16 = 0x7F21;
    pub const PUBLIC_KEY_TEMPLATE: u16 = 0x7F49;
    pub const EXTENDED_HEADER_LIST: u16 = 0x004D;
    pub const PRIVATE_KEY_TEMPLATE: u16 = 0x7F48;
    pub const CONCATENATED_KEY_DATA: u16 = 0x5F48;

    // CRT (Control Reference Template) tags
    pub const CRT_SIG: u8 = 0xB6;
    pub const CRT_DEC: u8 = 0xB8;
    pub const CRT_AUT: u8 = 0xA4;

    // Key component tags (within 7F49)
    pub const RSA_MODULUS: u8 = 0x81;
    pub const RSA_EXPONENT: u8 = 0x82;
    pub const ECC_PUBLIC_KEY: u8 = 0x86;
    pub const PRIVATE_EXPONENT: u8 = 0x92;

    // UIF (User Interaction Flag)
    pub const UIF_SIG: u16 = 0x00D6;
    pub const UIF_DEC: u16 = 0x00D7;
    pub const UIF_AUT: u16 = 0x00D8;

    // Reset code
    pub const RESET_CODE: u16 = 0x00D3;

    // General feature management
    pub const GENERAL_FEATURE_MANAGEMENT: u16 = 0x7F74;
}

//! BER-TLV Parser
//!
//! Parses BER-TLV (Basic Encoding Rules - Tag Length Value) structures
//! as used in smart card applications. Follows the talktosc crate patterns.

use thiserror::Error;

/// Errors that can occur during TLV parsing
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TLVError {
    #[error("Unexpected end of data while parsing tag")]
    UnexpectedEndTag,

    #[error("Unexpected end of data while parsing length")]
    UnexpectedEndLength,

    #[error("Unexpected end of data while parsing value")]
    UnexpectedEndValue,

    #[error("Invalid length encoding")]
    InvalidLength,

    #[error("Length too large: {0}")]
    LengthTooLarge(usize),

    #[error("Only two bytes for tags supported")]
    TagTooLong,
}

/// A TLV (Tag-Length-Value) structure
///
/// Following the talktosc pattern, this struct contains:
/// - `tag`: The tag value (stored as u32 to support 1-3 byte tags)
/// - `value`: The actual data bytes
/// - `subs`: Child TLVs for composite (constructed) data objects
///
/// # Example
/// ```ignore
/// let tlvs = read_list(&data, true);
/// if let Some(aid) = tlvs[0].get_aid() {
///     println!("AID: {:?}", aid);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TLV {
    /// The tag (1-3 bytes encoded as u32)
    pub tag: u32,
    /// The raw value bytes
    pub value: Vec<u8>,
    /// Child TLVs if this is a constructed (composite) tag
    pub subs: Vec<TLV>,
}

impl TLV {
    /// Create a new primitive TLV
    pub fn new(tag: u32, value: Vec<u8>) -> Self {
        Self {
            tag,
            value,
            subs: Vec::new(),
        }
    }

    /// Create a new constructed TLV with children
    pub fn constructed(tag: u32, children: Vec<TLV>) -> Self {
        Self {
            tag,
            value: Vec::new(),
            subs: children,
        }
    }

    /// Get the tag value as u16 (like talktosc)
    pub fn get_t(&self) -> u16 {
        self.tag as u16
    }

    /// Get the length of the value
    pub fn get_l(&self) -> u16 {
        self.value.len() as u16
    }

    /// Get the value as a slice (like talktosc)
    pub fn get_v(&self) -> &[u8] {
        &self.value
    }

    /// Check if this TLV has nested children (composite DO)
    ///
    /// This matches the talktosc `if_recursive()` method.
    pub fn if_recursive(&self) -> bool {
        !self.subs.is_empty()
    }

    /// Check if this is a constructed (container) tag based on the tag bits
    pub fn is_constructed(&self) -> bool {
        let first_byte = self.first_tag_byte();
        (first_byte & 0x20) != 0
    }

    /// Get the first byte of the tag
    fn first_tag_byte(&self) -> u8 {
        if self.tag > 0xFFFF {
            ((self.tag >> 16) & 0xFF) as u8
        } else if self.tag > 0xFF {
            ((self.tag >> 8) & 0xFF) as u8
        } else {
            (self.tag & 0xFF) as u8
        }
    }

    /// Recursively search for a tag (depth-first)
    ///
    /// This matches the talktosc `find_tag()` method.
    pub fn find_tag(&self, tag: u16) -> Option<TLV> {
        if self.tag == tag as u32 {
            return Some(self.clone());
        }
        for tlv in &self.subs {
            if let Some(found) = tlv.find_tag(tag) {
                return Some(found);
            }
        }
        None
    }

    /// Find a tag and return a reference (non-cloning version)
    pub fn find(&self, tag: u32) -> Option<&TLV> {
        if self.tag == tag {
            return Some(self);
        }
        for child in &self.subs {
            if let Some(found) = child.find(tag) {
                return Some(found);
            }
        }
        None
    }

    /// Find a direct child by tag (non-recursive)
    pub fn find_child(&self, tag: u32) -> Option<&TLV> {
        self.subs.iter().find(|c| c.tag == tag)
    }

    // =========================================================================
    // OpenPGP-specific helper methods (following talktosc pattern)
    // =========================================================================

    /// Get the Application Identifier (AID) - tag 0x4F
    pub fn get_aid(&self) -> Option<Vec<u8>> {
        self.find_tag(0x4F).map(|t| t.value.clone())
    }

    /// Get the historical bytes - tag 0x5F52
    pub fn get_historical_bytes(&self) -> Option<Vec<u8>> {
        self.find_tag(0x5F52).map(|t| t.value.clone())
    }

    /// Get the 60 bytes of fingerprints (3 x 20 bytes) - tag 0xC5
    pub fn get_fingerprints(&self) -> Option<Vec<u8>> {
        self.find_tag(0xC5).map(|t| t.value.clone())
    }

    /// Get the cardholder name - tag 0x5B
    pub fn get_name(&self) -> Option<Vec<u8>> {
        self.find_tag(0x5B).map(|t| t.value.clone())
    }

    /// Get the signature algorithm attributes - tag 0xC1
    pub fn get_signature_algo_attributes(&self) -> Option<Vec<u8>> {
        self.find_tag(0xC1).map(|t| t.value.clone())
    }

    /// Get the encryption algorithm attributes - tag 0xC2
    pub fn get_encryption_algo_attributes(&self) -> Option<Vec<u8>> {
        self.find_tag(0xC2).map(|t| t.value.clone())
    }

    /// Get the authentication algorithm attributes - tag 0xC3
    pub fn get_authentication_algo_attributes(&self) -> Option<Vec<u8>> {
        self.find_tag(0xC3).map(|t| t.value.clone())
    }

    /// Get the PIN retry counts - tag 0xC4
    pub fn get_pin_tries(&self) -> Option<Vec<u8>> {
        self.find_tag(0xC4).map(|t| t.value.clone())
    }

    /// Get the key information - tag 0xDE
    pub fn get_key_information(&self) -> Option<Vec<u8>> {
        self.find_tag(0xDE).map(|t| t.value.clone())
    }

    /// Get the number of signatures - tag 0x93
    pub fn get_number_of_signatures(&self) -> Option<Vec<u8>> {
        self.find_tag(0x93).map(|t| t.value.clone())
    }
}

// For backwards compatibility, keep these as aliases
impl TLV {
    /// Alias for subs (backwards compatibility)
    pub fn children(&self) -> &Vec<TLV> {
        &self.subs
    }

    /// Alias for value (backwards compatibility)
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Parse multiple TLVs from raw bytes
///
/// This is the talktosc-style entry point for parsing.
///
/// # Arguments
/// * `data` - Raw bytes to parse
/// * `recursive` - If true, parse nested TLVs in constructed tags
pub fn read_list(data: &[u8], recursive: bool) -> Vec<TLV> {
    let mut result = Vec::new();
    let mut remaining = data.to_vec();

    while !remaining.is_empty() {
        // Skip filler bytes (0x00, 0xFF)
        if remaining[0] == 0x00 || remaining[0] == 0xFF {
            remaining.remove(0);
            continue;
        }

        match read_single(remaining.clone(), recursive) {
            Ok((tlv, rest)) => {
                result.push(tlv);
                remaining = rest;
            }
            Err(_) => break,
        }
    }

    result
}

/// Parse a single TLV and return it with remaining bytes
///
/// This matches the talktosc `read_single()` function signature.
pub fn read_single(data: Vec<u8>, recursive: bool) -> Result<(TLV, Vec<u8>), String> {
    if data.is_empty() {
        return Err("Empty data".to_string());
    }

    let mut offset = 0;

    // Parse tag
    let (tag, tag_len) = parse_tag(&data[offset..])
        .map_err(|e| e.to_string())?;
    offset += tag_len;

    // Parse length
    if offset >= data.len() {
        return Err("Unexpected end of data while parsing length".to_string());
    }
    let (length, len_len) = parse_length(&data[offset..])
        .map_err(|e| e.to_string())?;
    offset += len_len;

    // Parse value
    if offset + length > data.len() {
        return Err("Unexpected end of data while parsing value".to_string());
    }
    let value = data[offset..offset + length].to_vec();
    offset += length;

    // Check if constructed and parse children
    let first_byte = if tag > 0xFFFF {
        ((tag >> 16) & 0xFF) as u8
    } else if tag > 0xFF {
        ((tag >> 8) & 0xFF) as u8
    } else {
        (tag & 0xFF) as u8
    };

    let subs = if recursive && (first_byte & 0x20) != 0 && !value.is_empty() {
        read_list(&value, true)
    } else {
        Vec::new()
    };

    let remaining = data[offset..].to_vec();
    Ok((TLV { tag, value, subs }, remaining))
}

/// Parse a BER tag (1-3 bytes)
fn parse_tag(data: &[u8]) -> Result<(u32, usize), TLVError> {
    if data.is_empty() {
        return Err(TLVError::UnexpectedEndTag);
    }

    let first = data[0];

    // Check if multi-byte tag (low 5 bits all set)
    if (first & 0x1F) != 0x1F {
        // Single byte tag
        return Ok((first as u32, 1));
    }

    // Multi-byte tag
    if data.len() < 2 {
        return Err(TLVError::UnexpectedEndTag);
    }

    let second = data[1];

    // Check if there's a third byte (bit 7 set means more bytes)
    if (second & 0x80) == 0 {
        // Two byte tag
        let tag = ((first as u32) << 8) | (second as u32);
        return Ok((tag, 2));
    }

    // Three byte tag
    if data.len() < 3 {
        return Err(TLVError::UnexpectedEndTag);
    }

    let third = data[2];
    let tag = ((first as u32) << 16) | ((second as u32) << 8) | (third as u32);
    Ok((tag, 3))
}

/// Parse a BER length (1-5 bytes)
fn parse_length(data: &[u8]) -> Result<(usize, usize), TLVError> {
    if data.is_empty() {
        return Err(TLVError::UnexpectedEndLength);
    }

    let first = data[0];

    // Short form (0-127)
    if (first & 0x80) == 0 {
        return Ok((first as usize, 1));
    }

    // Long form
    let num_bytes = (first & 0x7F) as usize;

    if num_bytes == 0 {
        // Indefinite length - not supported
        return Err(TLVError::InvalidLength);
    }

    if num_bytes > 4 {
        return Err(TLVError::LengthTooLarge(num_bytes));
    }

    if data.len() < 1 + num_bytes {
        return Err(TLVError::UnexpectedEndLength);
    }

    let mut length: usize = 0;
    for i in 0..num_bytes {
        length = (length << 8) | (data[1 + i] as usize);
    }

    Ok((length, 1 + num_bytes))
}

// Keep the TLVParser for backwards compatibility
pub struct TLVParser;

impl TLVParser {
    /// Parse multiple TLVs from raw bytes
    pub fn parse(data: &[u8]) -> Result<Vec<TLV>, TLVError> {
        Ok(read_list(data, true))
    }

    /// Parse a single TLV
    pub fn parse_one(data: &[u8]) -> Result<(TLV, usize), TLVError> {
        match read_single(data.to_vec(), true) {
            Ok((tlv, remaining)) => {
                let consumed = data.len() - remaining.len();
                Ok((tlv, consumed))
            }
            Err(_) => Err(TLVError::InvalidLength), // Map string error to TLVError
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_tlv() {
        // 4F = tag, 08 = length (8 bytes), D276000124010304 = value (8 bytes)
        let data = hex::decode("4F08D276000124010304").unwrap();
        let tlvs = read_list(&data, true);
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0x4F);
        assert_eq!(tlvs[0].get_t(), 0x4F);
        assert_eq!(tlvs[0].value, hex::decode("D276000124010304").unwrap());
    }

    #[test]
    fn test_two_byte_tag() {
        // 5F50 = tag, 0B = length (11 bytes), "example.com" = 11 bytes
        let data = hex::decode("5F500B6578616D706C652E636F6D").unwrap();
        let tlvs = read_list(&data, true);
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0x5F50);
        assert_eq!(tlvs[0].value, b"example.com");
    }

    #[test]
    fn test_constructed_tlv() {
        let data = hex::decode("65085B06446F65203C3C").unwrap();
        let tlvs = read_list(&data, true);
        assert_eq!(tlvs.len(), 1);
        assert!(tlvs[0].is_constructed());
        assert!(tlvs[0].if_recursive());
        assert_eq!(tlvs[0].subs.len(), 1);
        assert_eq!(tlvs[0].subs[0].tag, 0x5B);
    }

    #[test]
    fn test_find_tag() {
        // 6E = tag, 0A = length (10 bytes), 4F08D276000124010304 = nested TLV (10 bytes)
        let data = hex::decode("6E0A4F08D276000124010304").unwrap();
        let tlvs = read_list(&data, true);
        let found = tlvs[0].find_tag(0x4F);
        assert!(found.is_some());
        assert_eq!(found.unwrap().tag, 0x4F);
    }

    #[test]
    fn test_get_aid() {
        // 6E = tag, 0A = length (10 bytes), 4F08D276000124010304 = nested TLV (10 bytes)
        let data = hex::decode("6E0A4F08D276000124010304").unwrap();
        let tlvs = read_list(&data, true);
        let aid = tlvs[0].get_aid();
        assert!(aid.is_some());
        assert_eq!(aid.unwrap(), hex::decode("D276000124010304").unwrap());
    }

    #[test]
    fn test_multiple_tlvs() {
        let data = hex::decode("4F0201025B03414243").unwrap();
        let tlvs = read_list(&data, true);
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0].tag, 0x4F);
        assert_eq!(tlvs[1].tag, 0x5B);
    }

    #[test]
    fn test_long_length() {
        let mut data = vec![0xC0, 0x81, 0x80];
        data.extend(vec![0x00; 128]);
        let tlvs = read_list(&data, true);
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].value.len(), 128);
    }

    #[test]
    fn test_filler_bytes() {
        // Data with filler bytes at start
        let data = hex::decode("00FF4F020102").unwrap();
        let tlvs = read_list(&data, true);
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0x4F);
    }
}

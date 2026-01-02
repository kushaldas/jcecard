//! BER-TLV Encoder
//!
//! Encodes TLV structures to bytes for smart card responses.

use super::TLV;

/// TLV Encoder for building BER-TLV structures
pub struct TLVEncoder;

impl TLVEncoder {
    /// Encode a tag-value pair to bytes
    pub fn encode(tag: u32, value: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend(Self::encode_tag(tag));
        result.extend(Self::encode_length(value.len()));
        result.extend_from_slice(value);
        result
    }

    /// Encode just the tag bytes
    pub fn encode_tag(tag: u32) -> Vec<u8> {
        if tag > 0xFFFF {
            vec![
                ((tag >> 16) & 0xFF) as u8,
                ((tag >> 8) & 0xFF) as u8,
                (tag & 0xFF) as u8,
            ]
        } else if tag > 0xFF {
            vec![((tag >> 8) & 0xFF) as u8, (tag & 0xFF) as u8]
        } else {
            vec![(tag & 0xFF) as u8]
        }
    }

    /// Encode just the length bytes
    pub fn encode_length(length: usize) -> Vec<u8> {
        if length < 128 {
            // Short form
            vec![length as u8]
        } else if length < 256 {
            // Long form, 1 byte
            vec![0x81, length as u8]
        } else if length < 65536 {
            // Long form, 2 bytes
            vec![0x82, (length >> 8) as u8, (length & 0xFF) as u8]
        } else if length < 16777216 {
            // Long form, 3 bytes
            vec![
                0x83,
                (length >> 16) as u8,
                ((length >> 8) & 0xFF) as u8,
                (length & 0xFF) as u8,
            ]
        } else {
            // Long form, 4 bytes
            vec![
                0x84,
                (length >> 24) as u8,
                ((length >> 16) & 0xFF) as u8,
                ((length >> 8) & 0xFF) as u8,
                (length & 0xFF) as u8,
            ]
        }
    }

    /// Encode a TLV structure to bytes
    pub fn encode_tlv(tlv: &TLV) -> Vec<u8> {
        let value = if !tlv.subs.is_empty() {
            // Constructed: encode children
            let mut child_bytes = Vec::new();
            for child in &tlv.subs {
                child_bytes.extend(Self::encode_tlv(child));
            }
            child_bytes
        } else {
            tlv.value.clone()
        };

        Self::encode(tlv.tag, &value)
    }

    /// Build a constructed TLV from multiple child TLVs
    pub fn build_constructed(tag: u32, children: &[&[u8]]) -> Vec<u8> {
        let mut value = Vec::new();
        for child in children {
            value.extend_from_slice(child);
        }
        Self::encode(tag, &value)
    }
}

/// Builder for constructing complex TLV structures
pub struct TLVBuilder {
    data: Vec<u8>,
}

impl TLVBuilder {
    /// Create a new TLV builder
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Add a primitive TLV
    pub fn add(mut self, tag: u32, value: &[u8]) -> Self {
        self.data.extend(TLVEncoder::encode(tag, value));
        self
    }

    /// Add raw bytes (pre-encoded TLV)
    pub fn add_raw(mut self, data: &[u8]) -> Self {
        self.data.extend_from_slice(data);
        self
    }

    /// Wrap current content in a constructed tag
    pub fn wrap(self, tag: u32) -> Self {
        let wrapped = TLVEncoder::encode(tag, &self.data);
        Self { data: wrapped }
    }

    /// Build the final byte vector
    pub fn build(self) -> Vec<u8> {
        self.data
    }

    /// Get current length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for TLVBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_simple() {
        let encoded = TLVEncoder::encode(0x4F, &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]);
        assert_eq!(encoded, vec![0x4F, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]);
    }

    #[test]
    fn test_encode_two_byte_tag() {
        let encoded = TLVEncoder::encode(0x5F50, b"test");
        assert_eq!(encoded[0..2], [0x5F, 0x50]);
        assert_eq!(encoded[2], 4); // length
        assert_eq!(&encoded[3..], b"test");
    }

    #[test]
    fn test_encode_short_length() {
        assert_eq!(TLVEncoder::encode_length(0), vec![0x00]);
        assert_eq!(TLVEncoder::encode_length(127), vec![0x7F]);
    }

    #[test]
    fn test_encode_long_length() {
        assert_eq!(TLVEncoder::encode_length(128), vec![0x81, 0x80]);
        assert_eq!(TLVEncoder::encode_length(255), vec![0x81, 0xFF]);
        assert_eq!(TLVEncoder::encode_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(TLVEncoder::encode_length(65535), vec![0x82, 0xFF, 0xFF]);
    }

    #[test]
    fn test_builder() {
        let data = TLVBuilder::new()
            .add(0x5B, b"Doe<<John")
            .add(0x5F2D, b"en")
            .wrap(0x65)
            .build();

        // Should be: 65 len [5B len "Doe<<John"] [5F2D len "en"]
        assert_eq!(data[0], 0x65);
        // Parse to verify structure
        let tlvs = super::super::TLVParser::parse(&data).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0x65);
        assert_eq!(tlvs[0].subs.len(), 2);
    }

    #[test]
    fn test_encode_tlv_struct() {
        let tlv = TLV::new(0x4F, vec![0x01, 0x02, 0x03]);
        let encoded = TLVEncoder::encode_tlv(&tlv);
        assert_eq!(encoded, vec![0x4F, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_encode_constructed_tlv() {
        let child1 = TLV::new(0x5B, b"Test".to_vec());
        let child2 = TLV::new(0x5F2D, b"en".to_vec());
        let parent = TLV::constructed(0x65, vec![child1, child2]);
        let encoded = TLVEncoder::encode_tlv(&parent);

        let parsed = super::super::TLVParser::parse(&encoded).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].tag, 0x65);
        assert_eq!(parsed[0].subs.len(), 2);
    }
}

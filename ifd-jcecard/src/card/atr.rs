//! ATR (Answer To Reset) handling
//!
//! Provides default ATR and ATR building functions for the virtual card.

/// Default ATR for the virtual OpenPGP card
/// This matches the format used by Yubikey and similar devices
pub const DEFAULT_ATR: &[u8] = &[
    0x3B, // TS: Direct convention
    0xDA, // T0: TD1 present, 10 historical bytes
    0x18, // TD1: T=1 protocol, TD2 present
    0xFF, // TD2: More interface bytes
    0x81, // T1: IFSC = 254
    0xB1, // More TD bytes
    0xFE, // IFSC
    0x75, // Historical bytes start
    0x1F, 0x03, // Card capabilities
    0x00, 0x31, // Card issuer data
    0xC5, 0x73, // Application identifier
    0xC0, 0x01, // Additional info
    0x40, 0x00, // Status indicator
    0x90, 0x00, // Status word
    0x0C, // TCK (checksum)
];

/// Simple ATR for basic compatibility
pub const SIMPLE_ATR: &[u8] = &[
    0x3B, // TS: Direct convention
    0x80, // T0: No TA1, TB1, TC1, TD1; 0 historical bytes
    0x80, // T0 continuation
    0x01, // T=1 protocol indicator
    0x01, // Historical byte
];

/// Build an ATR with specific historical bytes
pub fn build_atr(historical_bytes: &[u8]) -> Vec<u8> {
    let mut atr = Vec::with_capacity(32);

    // TS - Initial character (direct convention)
    atr.push(0x3B);

    // T0 - Format character
    // High nibble: presence of TA1, TB1, TC1, TD1
    // Low nibble: number of historical bytes (max 15)
    let hist_len = historical_bytes.len().min(15) as u8;
    atr.push(0x80 | hist_len); // TD1 present, K historical bytes

    // TD1 - Protocol indicator
    // High nibble: presence of TA2, TB2, TC2, TD2
    // Low nibble: protocol type (0 = T=0, 1 = T=1)
    // T=1 supports extended APDUs natively
    atr.push(0x01); // T=1 protocol, no more interface bytes

    // Historical bytes
    atr.extend_from_slice(&historical_bytes[..hist_len as usize]);

    // TCK - Check character (XOR of all bytes from T0 to last historical byte)
    // Required for T=1 protocol
    let tck: u8 = atr[1..].iter().fold(0u8, |acc, &b| acc ^ b);
    atr.push(tck);

    atr
}

/// Create an OpenPGP-compatible ATR
pub fn create_openpgp_atr() -> Vec<u8> {
    // Historical bytes for OpenPGP card
    // Based on ISO 7816-4 Annex A
    let historical = [
        0x00, // Category indicator (compact TLV)
        0x73, // Card service data
        0x00, // Card capabilities (selection methods)
        0x00, // Card capabilities (data coding)
        0xE0, // Status indicator (life cycle + status bytes follow)
        0x05, // Life cycle: operational state
        0x90, 0x00, // Status word: success
    ];

    build_atr(&historical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_atr() {
        // ATR should start with 0x3B (direct convention)
        assert_eq!(DEFAULT_ATR[0], 0x3B);
        // ATR should be reasonable length
        assert!(DEFAULT_ATR.len() >= 4);
        assert!(DEFAULT_ATR.len() <= 33);
    }

    #[test]
    fn test_build_atr() {
        let hist = [0x01, 0x02, 0x03, 0x04];
        let atr = build_atr(&hist);

        assert_eq!(atr[0], 0x3B); // TS
        assert_eq!(atr[1] & 0x0F, 4); // 4 historical bytes
        assert_eq!(&atr[3..7], &hist); // Historical bytes present
    }

    #[test]
    fn test_create_openpgp_atr() {
        let atr = create_openpgp_atr();
        assert_eq!(atr[0], 0x3B);
        // Should contain status word 90 00 in historical bytes
        assert!(atr.windows(2).any(|w| w == [0x90, 0x00]));
    }

    #[test]
    fn test_atr_checksum() {
        let hist = [0x00, 0x73, 0x00, 0x00];
        let atr = build_atr(&hist);

        // Verify TCK (last byte) is XOR of all bytes from T0
        let calculated_tck: u8 = atr[1..atr.len() - 1].iter().fold(0u8, |acc, &b| acc ^ b);
        assert_eq!(atr[atr.len() - 1], calculated_tck);
    }
}

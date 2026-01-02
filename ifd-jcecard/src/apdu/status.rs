//! Status Word (SW) constants for APDU responses
//!
//! ISO 7816-4 status words indicating command execution results.

/// Status Word constants
#[allow(dead_code)]
pub struct SW;

#[allow(dead_code)]
impl SW {
    // Success
    pub const SUCCESS: u16 = 0x9000;

    // Warnings (62xx, 63xx)
    pub const WARNING_NO_CHANGE: u16 = 0x6200;
    pub const WARNING_CORRUPTED: u16 = 0x6281;
    pub const WARNING_EOF: u16 = 0x6282;
    pub const WARNING_SELECTED_FILE_INVALIDATED: u16 = 0x6283;
    pub const WARNING_FCI_INVALID: u16 = 0x6284;

    // Execution errors (64xx, 65xx)
    pub const EXEC_ERROR: u16 = 0x6400;
    pub const MEMORY_FAILURE: u16 = 0x6501;

    // Checking errors (67xx, 68xx, 69xx, 6Axx, 6Bxx, 6Cxx, 6Dxx, 6Exx, 6Fxx)
    pub const WRONG_LENGTH: u16 = 0x6700;

    pub const LOGICAL_CHANNEL_NOT_SUPPORTED: u16 = 0x6881;
    pub const SECURE_MESSAGING_NOT_SUPPORTED: u16 = 0x6882;

    pub const COMMAND_NOT_ALLOWED: u16 = 0x6900;
    pub const COMMAND_INCOMPATIBLE: u16 = 0x6981;
    pub const SECURITY_STATUS_NOT_SATISFIED: u16 = 0x6982;
    pub const AUTH_METHOD_BLOCKED: u16 = 0x6983;
    pub const REFERENCE_DATA_NOT_USABLE: u16 = 0x6984;
    pub const CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
    pub const COMMAND_NOT_ALLOWED_NO_EF: u16 = 0x6986;
    pub const EXPECTED_SM_DATA_OBJECTS_MISSING: u16 = 0x6987;
    pub const INCORRECT_SM_DATA_OBJECTS: u16 = 0x6988;

    pub const WRONG_DATA: u16 = 0x6A80;
    pub const FUNCTION_NOT_SUPPORTED: u16 = 0x6A81;
    pub const FILE_NOT_FOUND: u16 = 0x6A82;
    pub const RECORD_NOT_FOUND: u16 = 0x6A83;
    pub const NOT_ENOUGH_MEMORY: u16 = 0x6A84;
    pub const NC_INCONSISTENT_WITH_TLV: u16 = 0x6A85;
    pub const INCORRECT_P1_P2: u16 = 0x6A86;
    pub const NC_INCONSISTENT_WITH_P1_P2: u16 = 0x6A87;
    pub const REFERENCED_DATA_NOT_FOUND: u16 = 0x6A88;
    pub const FILE_ALREADY_EXISTS: u16 = 0x6A89;
    pub const DF_NAME_ALREADY_EXISTS: u16 = 0x6A8A;

    pub const WRONG_P1_P2: u16 = 0x6B00;

    pub const INS_NOT_SUPPORTED: u16 = 0x6D00;
    pub const CLA_NOT_SUPPORTED: u16 = 0x6E00;
    pub const UNKNOWN_ERROR: u16 = 0x6F00;

    /// Create a "more data available" status word (61xx)
    /// The low byte indicates how many more bytes are available
    #[inline]
    pub fn bytes_remaining(remaining: u8) -> u16 {
        0x6100 | (remaining as u16)
    }

    /// Create a warning with counter (63Cx)
    /// Used to indicate PIN retry count remaining
    #[inline]
    pub fn counter_warning(retries: u8) -> u16 {
        0x63C0 | ((retries & 0x0F) as u16)
    }

    /// Create a "wrong Le" status word (6Cxx)
    /// The low byte indicates the correct Le value
    #[inline]
    pub fn wrong_le(correct_le: u8) -> u16 {
        0x6C00 | (correct_le as u16)
    }

    /// Check if a status word indicates success (9000 or 61xx)
    #[inline]
    pub fn is_success(sw: u16) -> bool {
        sw == Self::SUCCESS || (sw & 0xFF00) == 0x6100
    }

    /// Check if a status word indicates more data available (61xx)
    #[inline]
    pub fn is_more_data(sw: u16) -> bool {
        (sw & 0xFF00) == 0x6100
    }

    /// Check if a status word is a counter warning (63Cx)
    #[inline]
    pub fn is_counter_warning(sw: u16) -> bool {
        (sw & 0xFFF0) == 0x63C0
    }

    /// Extract retry count from counter warning (63Cx)
    #[inline]
    pub fn get_retry_count(sw: u16) -> Option<u8> {
        if Self::is_counter_warning(sw) {
            Some((sw & 0x0F) as u8)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_remaining() {
        assert_eq!(SW::bytes_remaining(0), 0x6100);
        assert_eq!(SW::bytes_remaining(16), 0x6110);
        assert_eq!(SW::bytes_remaining(255), 0x61FF);
    }

    #[test]
    fn test_counter_warning() {
        assert_eq!(SW::counter_warning(3), 0x63C3);
        assert_eq!(SW::counter_warning(2), 0x63C2);
        assert_eq!(SW::counter_warning(1), 0x63C1);
        assert_eq!(SW::counter_warning(0), 0x63C0);
    }

    #[test]
    fn test_is_success() {
        assert!(SW::is_success(0x9000));
        assert!(SW::is_success(0x6110));
        assert!(!SW::is_success(0x6982));
    }

    #[test]
    fn test_is_counter_warning() {
        assert!(SW::is_counter_warning(0x63C3));
        assert!(SW::is_counter_warning(0x63C0));
        assert!(!SW::is_counter_warning(0x6300));
        assert!(!SW::is_counter_warning(0x9000));
    }

    #[test]
    fn test_get_retry_count() {
        assert_eq!(SW::get_retry_count(0x63C3), Some(3));
        assert_eq!(SW::get_retry_count(0x63C0), Some(0));
        assert_eq!(SW::get_retry_count(0x9000), None);
    }
}

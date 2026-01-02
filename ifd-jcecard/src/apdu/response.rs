//! APDU Response handling
//!
//! Simple response structure following the talktosc pattern.
//! A Response contains data bytes plus SW1/SW2 status words.

use super::status::SW;

/// A smartcard response
///
/// This struct contains the response data and status words from a smartcard.
/// It's designed to be simple like the talktosc crate's Response struct.
///
/// # Example
/// ```ignore
/// let response = Response::success(vec![0x01, 0x02]);
/// assert!(response.is_okay());
///
/// let error = Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
/// assert!(!error.is_okay());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Response data (without status words)
    pub data: Vec<u8>,
    /// Status word 1 (SW1)
    pub sw1: u8,
    /// Status word 2 (SW2)
    pub sw2: u8,
}

impl Response {
    /// Create a new response with data and status word
    pub fn new(data: Vec<u8>, sw: u16) -> Self {
        Self {
            data,
            sw1: (sw >> 8) as u8,
            sw2: sw as u8,
        }
    }

    /// Create a success response (0x9000) with data
    pub fn success(data: Vec<u8>) -> Self {
        Self::new(data, SW::SUCCESS)
    }

    /// Create an empty success response (0x9000)
    pub fn ok() -> Self {
        Self::success(Vec::new())
    }

    /// Create an error response (no data)
    pub fn error(sw: u16) -> Self {
        Self::new(Vec::new(), sw)
    }

    /// Create a "more data available" response (0x61xx)
    pub fn more_data(data: Vec<u8>, remaining: u8) -> Self {
        Self::new(data, SW::bytes_remaining(remaining))
    }

    /// Create a counter warning response (0x63Cx) - for PIN retries
    pub fn counter_warning(retries: u8) -> Self {
        Self::error(SW::counter_warning(retries))
    }

    /// Check if the response is okay (0x9000 or 0x61xx)
    ///
    /// This matches the talktosc `is_okay()` method.
    pub fn is_okay(&self) -> bool {
        (self.sw1 == 0x90 && self.sw2 == 0x00) || self.sw1 == 0x61
    }

    /// Get the combined status word as u16
    pub fn sw(&self) -> u16 {
        ((self.sw1 as u16) << 8) | (self.sw2 as u16)
    }

    /// Check if more data is available to read
    ///
    /// Returns Some(bytes) if SW1=0x61, None otherwise.
    /// This matches the talktosc `available_response()` method.
    pub fn available_response(&self) -> Option<u8> {
        if self.sw1 == 0x61 {
            Some(self.sw2)
        } else {
            None
        }
    }

    /// Returns a copy of the data
    ///
    /// This matches the talktosc `get_data()` method.
    pub fn get_data(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Convert to raw bytes for transmission (data + SW1 + SW2)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.data.len() + 2);
        result.extend_from_slice(&self.data);
        result.push(self.sw1);
        result.push(self.sw2);
        result
    }

    /// Get total length in bytes (data + 2 status bytes)
    pub fn len(&self) -> usize {
        self.data.len() + 2
    }

    /// Check if response has no data
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for Response {
    fn default() -> Self {
        Self::ok()
    }
}

impl From<u16> for Response {
    /// Create an error response from a status word
    fn from(sw: u16) -> Self {
        Self::error(sw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_response() {
        let resp = Response::success(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(resp.is_okay());
        assert_eq!(resp.sw(), 0x9000);
        assert_eq!(resp.get_data(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(resp.to_bytes(), vec![0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00]);
    }

    #[test]
    fn test_ok_response() {
        let resp = Response::ok();
        assert!(resp.is_okay());
        assert!(resp.is_empty());
        assert_eq!(resp.to_bytes(), vec![0x90, 0x00]);
    }

    #[test]
    fn test_error_response() {
        let resp = Response::error(SW::SECURITY_STATUS_NOT_SATISFIED);
        assert!(!resp.is_okay());
        assert_eq!(resp.sw(), 0x6982);
        assert_eq!(resp.to_bytes(), vec![0x69, 0x82]);
    }

    #[test]
    fn test_more_data_response() {
        let resp = Response::more_data(vec![0xAB], 16);
        assert!(resp.is_okay());  // 0x61xx is considered okay
        assert_eq!(resp.available_response(), Some(16));
        assert_eq!(resp.get_data(), vec![0xAB]);
    }

    #[test]
    fn test_no_more_data() {
        let resp = Response::ok();
        assert_eq!(resp.available_response(), None);
    }

    #[test]
    fn test_counter_warning() {
        let resp = Response::counter_warning(2);
        assert!(!resp.is_okay());
        assert_eq!(resp.sw(), 0x63C2);
    }

    #[test]
    fn test_from_sw() {
        let resp: Response = 0x6A82.into();
        assert_eq!(resp.sw(), SW::FILE_NOT_FOUND);
        assert!(!resp.is_okay());
    }
}

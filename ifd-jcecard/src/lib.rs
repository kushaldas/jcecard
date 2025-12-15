//! IFD Handler for jcecard virtual OpenPGP card
//!
//! This is a PC/SC IFD (Interface Device) handler that implements a virtual
//! smart card reader. It communicates with a jcecard TCP server running on
//! port 9999 for the actual card logic.
//!
//! Protocol:
//! - Connect to localhost:9999
//! - Send command as: 4-byte big-endian length + data
//! - Receive response as: 4-byte big-endian length + data
//! - Commands: "POWER_ON", "POWER_OFF", "RESET", "GET_ATR", or raw APDU bytes

#![allow(dead_code)]

use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::ffi::{c_char, c_uchar, c_ulong, CStr};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

// PC/SC lite types
type DWORD = c_ulong;
type PDWORD = *mut DWORD;
type PUCHAR = *mut c_uchar;
type LPSTR = *const c_char;
type RESPONSECODE = c_ulong;
type UCHAR = c_uchar;

// Response codes
const IFD_SUCCESS: RESPONSECODE = 0;
const IFD_ERROR_TAG: RESPONSECODE = 600;
const IFD_ERROR_NOT_SUPPORTED: RESPONSECODE = 606;
const IFD_COMMUNICATION_ERROR: RESPONSECODE = 612;
const IFD_ICC_PRESENT: RESPONSECODE = 615;
const IFD_ICC_NOT_PRESENT: RESPONSECODE = 614;

// Tags for GetCapabilities
const TAG_IFD_ATR: DWORD = 0x0303;
const TAG_IFD_SLOTS_NUMBER: DWORD = 0x0FAE;
const TAG_IFD_THREAD_SAFE: DWORD = 0x0FAD;
const TAG_IFD_SLOT_THREAD_SAFE: DWORD = 0x0FBE;

// Power actions
const IFD_POWER_UP: DWORD = 500;
const IFD_POWER_DOWN: DWORD = 501;
const IFD_RESET: DWORD = 502;

// SCARD_IO_HEADER structure (simplified)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SCARD_IO_HEADER {
    pub protocol: DWORD,
    pub length: DWORD,
}

// Maximum ATR size
const MAX_ATR_SIZE: usize = 33;

// Server address
const SERVER_ADDR: &str = "127.0.0.1:9999";

/// Holds the card state
struct CardState {
    /// TCP connection to jcecard server
    stream: Option<TcpStream>,
    /// Current ATR
    atr: Vec<u8>,
    /// Whether the card is powered
    powered: bool,
}

// Message types for protocol
const MSG_APDU: u8 = 0x01;
const MSG_POWER_ON: u8 = 0x02;
const MSG_POWER_OFF: u8 = 0x03;
const MSG_RESET: u8 = 0x04;
const MSG_GET_ATR: u8 = 0x05;
const MSG_PRESENCE: u8 = 0x06;

// Response status
const STATUS_OK: u8 = 0x00;
const STATUS_ERROR: u8 = 0x01;
const STATUS_NO_CARD: u8 = 0x02;

impl CardState {
    fn new() -> Self {
        Self {
            stream: None,
            atr: Vec::new(),
            powered: false,
        }
    }

    /// Connect to the jcecard server
    fn connect(&mut self) -> Result<(), String> {
        if self.stream.is_some() {
            return Ok(());
        }

        match TcpStream::connect(SERVER_ADDR) {
            Ok(stream) => {
                stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
                self.stream = Some(stream);
                Ok(())
            }
            Err(e) => Err(format!("Failed to connect to {}: {}", SERVER_ADDR, e)),
        }
    }

    /// Disconnect from the server
    fn disconnect(&mut self) {
        self.stream = None;
        self.powered = false;
        self.atr.clear();
    }

    /// Send a command and receive response
    fn send_command(&mut self, cmd: &[u8]) -> Result<Vec<u8>, String> {
        let stream = self.stream.as_mut().ok_or("Not connected")?;

        // Send length (4 bytes big-endian) + data
        let len = cmd.len() as u32;
        let len_bytes = len.to_be_bytes();
        
        stream.write_all(&len_bytes).map_err(|e| format!("Write length error: {}", e))?;
        stream.write_all(cmd).map_err(|e| format!("Write data error: {}", e))?;
        stream.flush().map_err(|e| format!("Flush error: {}", e))?;

        // Read response length
        let mut resp_len_bytes = [0u8; 4];
        stream.read_exact(&mut resp_len_bytes).map_err(|e| format!("Read length error: {}", e))?;
        let resp_len = u32::from_be_bytes(resp_len_bytes) as usize;

        // Read response data
        let mut response = vec![0u8; resp_len];
        stream.read_exact(&mut response).map_err(|e| format!("Read data error: {}", e))?;

        Ok(response)
    }

    /// Power on the card
    fn power_on(&mut self) -> Result<Vec<u8>, String> {
        self.connect()?;
        let response = self.send_command(&[MSG_POWER_ON])?;
        if response.is_empty() || response[0] != STATUS_OK {
            return Err(format!("Power on failed: {:?}", response));
        }
        // ATR is the rest of the response after the status byte
        self.atr = response[1..].to_vec();
        self.powered = true;
        Ok(self.atr.clone())
    }

    /// Power off the card
    fn power_off(&mut self) -> Result<(), String> {
        if self.stream.is_some() {
            let _ = self.send_command(&[MSG_POWER_OFF]);
        }
        self.powered = false;
        Ok(())
    }

    /// Reset the card
    fn reset(&mut self) -> Result<Vec<u8>, String> {
        self.connect()?;
        let response = self.send_command(&[MSG_RESET])?;
        if response.is_empty() || response[0] != STATUS_OK {
            return Err(format!("Reset failed: {:?}", response));
        }
        // ATR is the rest of the response after the status byte
        self.atr = response[1..].to_vec();
        self.powered = true;
        Ok(self.atr.clone())
    }

    /// Send APDU and get response
    fn transmit_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        if !self.powered {
            return Err("Card not powered".to_string());
        }
        // Prepend message type
        let mut cmd = Vec::with_capacity(apdu.len() + 1);
        cmd.push(MSG_APDU);
        cmd.extend_from_slice(apdu);
        
        let response = self.send_command(&cmd)?;
        if response.is_empty() || response[0] != STATUS_OK {
            return Err(format!("APDU failed: {:?}", response));
        }
        // Return response data without status byte
        Ok(response[1..].to_vec())
    }
}

/// Global state for the IFD handler
struct IfdState {
    /// Card state per slot (we support only slot 0 for now)
    slots: [Option<Arc<Mutex<CardState>>>; 1],
}

impl IfdState {
    fn new() -> Self {
        Self {
            slots: [None],
        }
    }
}

// Global state
static IFD_STATE: OnceCell<Mutex<IfdState>> = OnceCell::new();

fn get_state() -> &'static Mutex<IfdState> {
    IFD_STATE.get_or_init(|| Mutex::new(IfdState::new()))
}

fn log_info(msg: &str) {
    eprintln!("[ifd-jcecard] {}", msg);
}

fn log_error(msg: &str) {
    eprintln!("[ifd-jcecard] ERROR: {}", msg);
}

// ============================================================================
// IFD Handler API Implementation
// ============================================================================

/// Create a communication channel to the reader
#[no_mangle]
pub extern "C" fn IFDHCreateChannelByName(lun: DWORD, device_name: LPSTR) -> RESPONSECODE {
    let name = if device_name.is_null() {
        "null".to_string()
    } else {
        unsafe { CStr::from_ptr(device_name) }
            .to_string_lossy()
            .to_string()
    };
    log_info(&format!("IFDHCreateChannelByName: LUN={}, device={}", lun, name));

    let mut state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    if slot >= state.slots.len() {
        log_error(&format!("Invalid slot: {}", slot));
        return IFD_COMMUNICATION_ERROR;
    }

    // Create card state (connection will be established on power-on)
    let card_state = CardState::new();
    state.slots[slot] = Some(Arc::new(Mutex::new(card_state)));

    log_info("Channel created successfully");
    IFD_SUCCESS
}

/// Create a communication channel (legacy)
#[no_mangle]
pub extern "C" fn IFDHCreateChannel(lun: DWORD, channel: DWORD) -> RESPONSECODE {
    log_info(&format!("IFDHCreateChannel: LUN={}, channel={}", lun, channel));
    
    let mut state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    if slot >= state.slots.len() {
        log_error(&format!("Invalid slot: {}", slot));
        return IFD_COMMUNICATION_ERROR;
    }

    let card_state = CardState::new();
    state.slots[slot] = Some(Arc::new(Mutex::new(card_state)));

    log_info("Channel created successfully");
    IFD_SUCCESS
}

/// Close the communication channel
#[no_mangle]
pub extern "C" fn IFDHCloseChannel(lun: DWORD) -> RESPONSECODE {
    log_info(&format!("IFDHCloseChannel: LUN={}", lun));

    let mut state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    if slot >= state.slots.len() {
        return IFD_COMMUNICATION_ERROR;
    }

    if let Some(card_state) = state.slots[slot].take() {
        let mut cs = card_state.lock();
        cs.disconnect();
    }

    IFD_SUCCESS
}

/// Get reader capabilities
#[no_mangle]
pub extern "C" fn IFDHGetCapabilities(
    lun: DWORD,
    tag: DWORD,
    length: PDWORD,
    value: PUCHAR,
) -> RESPONSECODE {
    log_info(&format!("IFDHGetCapabilities: LUN={}, tag=0x{:04X}", lun, tag));

    if length.is_null() {
        return IFD_COMMUNICATION_ERROR;
    }

    let state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    match tag {
        TAG_IFD_ATR => {
            if slot >= state.slots.len() {
                return IFD_COMMUNICATION_ERROR;
            }

            if let Some(ref card_arc) = state.slots[slot] {
                let card = card_arc.lock();
                if card.powered && !card.atr.is_empty() {
                    let atr_len = card.atr.len().min(MAX_ATR_SIZE);
                    unsafe {
                        *length = atr_len as DWORD;
                        if !value.is_null() {
                            ptr::copy_nonoverlapping(card.atr.as_ptr(), value, atr_len);
                        }
                    }
                    return IFD_SUCCESS;
                }
            }
            IFD_ICC_NOT_PRESENT
        }
        TAG_IFD_SLOTS_NUMBER => {
            unsafe {
                *length = 1;
                if !value.is_null() {
                    *value = 1;
                }
            }
            IFD_SUCCESS
        }
        TAG_IFD_THREAD_SAFE => {
            unsafe {
                *length = 1;
                if !value.is_null() {
                    *value = 0; // Not thread safe at IFD level
                }
            }
            IFD_SUCCESS
        }
        TAG_IFD_SLOT_THREAD_SAFE => {
            unsafe {
                *length = 1;
                if !value.is_null() {
                    *value = 1; // Slot level is thread safe
                }
            }
            IFD_SUCCESS
        }
        _ => {
            log_info(&format!("Unknown tag: 0x{:04X}", tag));
            IFD_ERROR_TAG
        }
    }
}

/// Set reader capabilities (not supported)
#[no_mangle]
pub extern "C" fn IFDHSetCapabilities(
    _lun: DWORD,
    _tag: DWORD,
    _length: DWORD,
    _value: PUCHAR,
) -> RESPONSECODE {
    IFD_ERROR_NOT_SUPPORTED
}

/// Set protocol parameters (minimal implementation)
#[no_mangle]
pub extern "C" fn IFDHSetProtocolParameters(
    lun: DWORD,
    protocol: DWORD,
    _flags: UCHAR,
    _pts1: UCHAR,
    _pts2: UCHAR,
    _pts3: UCHAR,
) -> RESPONSECODE {
    log_info(&format!(
        "IFDHSetProtocolParameters: LUN={}, protocol={}",
        lun, protocol
    ));
    IFD_SUCCESS
}

/// Power the ICC (Integrated Circuit Card)
#[no_mangle]
pub extern "C" fn IFDHPowerICC(
    lun: DWORD,
    action: DWORD,
    atr: PUCHAR,
    atr_length: PDWORD,
) -> RESPONSECODE {
    log_info(&format!("IFDHPowerICC: LUN={}, action={}", lun, action));

    let state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    if slot >= state.slots.len() {
        return IFD_COMMUNICATION_ERROR;
    }

    let card_arc = match &state.slots[slot] {
        Some(arc) => arc.clone(),
        None => return IFD_COMMUNICATION_ERROR,
    };
    drop(state); // Release state lock before card operations

    let mut card = card_arc.lock();

    match action {
        IFD_POWER_UP => {
            log_info("Powering up card");
            match card.power_on() {
                Ok(card_atr) => {
                    log_info(&format!("Card powered on, ATR length: {}", card_atr.len()));
                    if !atr.is_null() && !atr_length.is_null() {
                        let copy_len = card_atr.len().min(MAX_ATR_SIZE);
                        unsafe {
                            ptr::copy_nonoverlapping(card_atr.as_ptr(), atr, copy_len);
                            *atr_length = copy_len as DWORD;
                        }
                    }
                    IFD_SUCCESS
                }
                Err(e) => {
                    log_error(&format!("Power on failed: {}", e));
                    IFD_COMMUNICATION_ERROR
                }
            }
        }
        IFD_POWER_DOWN => {
            log_info("Powering down card");
            match card.power_off() {
                Ok(()) => IFD_SUCCESS,
                Err(e) => {
                    log_error(&format!("Power off failed: {}", e));
                    IFD_COMMUNICATION_ERROR
                }
            }
        }
        IFD_RESET => {
            log_info("Resetting card");
            match card.reset() {
                Ok(card_atr) => {
                    log_info(&format!("Card reset, ATR length: {}", card_atr.len()));
                    if !atr.is_null() && !atr_length.is_null() {
                        let copy_len = card_atr.len().min(MAX_ATR_SIZE);
                        unsafe {
                            ptr::copy_nonoverlapping(card_atr.as_ptr(), atr, copy_len);
                            *atr_length = copy_len as DWORD;
                        }
                    }
                    IFD_SUCCESS
                }
                Err(e) => {
                    log_error(&format!("Reset failed: {}", e));
                    IFD_COMMUNICATION_ERROR
                }
            }
        }
        _ => {
            log_error(&format!("Unknown power action: {}", action));
            IFD_ERROR_NOT_SUPPORTED
        }
    }
}

/// Transmit data to the ICC
#[no_mangle]
pub extern "C" fn IFDHTransmitToICC(
    lun: DWORD,
    send_pci: SCARD_IO_HEADER,
    tx_buffer: PUCHAR,
    tx_length: DWORD,
    rx_buffer: PUCHAR,
    rx_length: PDWORD,
    _recv_pci: *mut SCARD_IO_HEADER,
) -> RESPONSECODE {
    log_info(&format!(
        "IFDHTransmitToICC: LUN={}, protocol={}, tx_len={}",
        lun, send_pci.protocol, tx_length
    ));

    if tx_buffer.is_null() || rx_buffer.is_null() || rx_length.is_null() {
        return IFD_COMMUNICATION_ERROR;
    }

    let state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    if slot >= state.slots.len() {
        return IFD_COMMUNICATION_ERROR;
    }

    let card_arc = match &state.slots[slot] {
        Some(arc) => arc.clone(),
        None => return IFD_COMMUNICATION_ERROR,
    };
    drop(state);

    // Build APDU from tx_buffer
    let apdu = unsafe { std::slice::from_raw_parts(tx_buffer, tx_length as usize) };
    log_info(&format!("APDU: {:02X?}", apdu));

    let mut card = card_arc.lock();
    match card.transmit_apdu(apdu) {
        Ok(response) => {
            log_info(&format!("Response: {:02X?}", response));
            let max_len = unsafe { *rx_length } as usize;
            let copy_len = response.len().min(max_len);
            unsafe {
                ptr::copy_nonoverlapping(response.as_ptr(), rx_buffer, copy_len);
                *rx_length = copy_len as DWORD;
            }
            IFD_SUCCESS
        }
        Err(e) => {
            log_error(&format!("Transmit failed: {}", e));
            // Return SW 6F00 (general error)
            unsafe {
                if *rx_length >= 2 {
                    *rx_buffer = 0x6F;
                    *rx_buffer.add(1) = 0x00;
                    *rx_length = 2;
                }
            }
            IFD_SUCCESS // Return success so pcscd processes the error SW
        }
    }
}

/// Check if ICC is present
#[no_mangle]
pub extern "C" fn IFDHICCPresence(lun: DWORD) -> RESPONSECODE {
    let state = get_state().lock();
    let slot = (lun & 0xFFFF) as usize;

    if slot >= state.slots.len() {
        return IFD_ICC_NOT_PRESENT;
    }

    // Try to connect to server to check if card is present
    if let Some(ref card_arc) = state.slots[slot] {
        let mut card = card_arc.lock();
        
        // If already connected and powered, card is present
        if card.powered {
            return IFD_ICC_PRESENT;
        }
        
        // Try to connect
        if card.connect().is_ok() {
            return IFD_ICC_PRESENT;
        }
    }

    IFD_ICC_NOT_PRESENT
}

/// Control the reader (not supported)
#[no_mangle]
pub extern "C" fn IFDHControl(
    _lun: DWORD,
    _control_code: DWORD,
    _tx_buffer: PUCHAR,
    _tx_length: DWORD,
    _rx_buffer: PUCHAR,
    _rx_length: DWORD,
    _bytes_returned: PDWORD,
) -> RESPONSECODE {
    IFD_ERROR_NOT_SUPPORTED
}

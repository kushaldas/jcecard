//! OpenPGP Card Applet
//!
//! Implements the OpenPGP card specification (ISO/IEC 7816-4/8).

pub mod applet;
pub mod pin_manager;
pub mod security_state;

pub use applet::OpenPGPApplet;
pub use pin_manager::PINManager;
pub use security_state::SecurityState;

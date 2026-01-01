//! Cryptographic Operations
//!
//! Provides cryptographic primitives for OpenPGP and PIV operations.

pub mod rsa;
pub mod ed25519;
pub mod x25519;
pub mod ecc_nist;
pub mod tdes;
pub mod hash;
pub mod fingerprint;

pub use self::rsa::RsaOperations;
pub use self::ed25519::Ed25519Operations;
pub use self::x25519::X25519Operations;
pub use self::ecc_nist::EccNistOperations;
pub use self::tdes::TDesOperations;
pub use self::hash::HashOperations;
pub use self::fingerprint::{calculate_fingerprint_rsa, calculate_fingerprint_eddsa, calculate_fingerprint_ecdh_x25519, calculate_fingerprint_ecdsa, current_timestamp};

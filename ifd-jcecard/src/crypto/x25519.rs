//! X25519 Operations
//!
//! X25519 key generation and ECDH using x25519-dalek.
//!
//! Note: OpenPGP Curve25519/X25519 keys use the NATIVE little-endian format,
//! which is the same format x25519-dalek uses. No byte order conversion needed.
//! (OpenPGP prefixes public keys with 0x40, but that's handled at the protocol level)

use x25519_dalek::{StaticSecret, PublicKey};
use rand::rngs::OsRng;
use log::debug;

/// X25519 operation errors
#[derive(Debug)]
pub enum X25519Error {
    KeyGenerationFailed(String),
    ECDHFailed(String),
    InvalidKey(String),
}

/// X25519 Operations
pub struct X25519Operations;

impl X25519Operations {
    /// Generate a new X25519 key pair
    /// Returns (private_key_bytes, public_key_bytes) in native little-endian format
    pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), X25519Error> {
        debug!("Generating X25519 keypair");

        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        // OpenPGP X25519 uses native little-endian format (same as x25519-dalek)
        Ok((secret.to_bytes().to_vec(), public.as_bytes().to_vec()))
    }

    /// Perform ECDH key agreement
    /// Takes keys in native little-endian format (OpenPGP X25519 format)
    pub fn ecdh(
        private_key: &[u8],
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>, X25519Error> {
        if private_key.len() != 32 {
            return Err(X25519Error::InvalidKey(
                format!("Invalid private key length: expected 32, got {}", private_key.len())
            ));
        }
        if peer_public_key.len() != 32 {
            return Err(X25519Error::InvalidKey(
                format!("Invalid public key length: expected 32, got {}", peer_public_key.len())
            ));
        }

        // Keys are already in native little-endian format
        let secret_bytes: [u8; 32] = private_key.try_into()
            .map_err(|_| X25519Error::InvalidKey("Invalid key size".to_string()))?;
        let public_bytes: [u8; 32] = peer_public_key.try_into()
            .map_err(|_| X25519Error::InvalidKey("Invalid key size".to_string()))?;

        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(public_bytes);

        let shared_secret = secret.diffie_hellman(&public);

        // Return in native format
        Ok(shared_secret.as_bytes().to_vec())
    }

    /// Get the public key from a private key
    /// Takes and returns keys in native little-endian format
    pub fn get_public_key(private_key: &[u8]) -> Result<Vec<u8>, X25519Error> {
        if private_key.len() != 32 {
            return Err(X25519Error::InvalidKey(
                format!("Invalid key length: expected 32, got {}", private_key.len())
            ));
        }

        let secret_bytes: [u8; 32] = private_key.try_into()
            .map_err(|_| X25519Error::InvalidKey("Invalid key size".to_string()))?;

        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);

        Ok(public.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (private, public) = X25519Operations::generate_keypair().unwrap();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);
    }

    #[test]
    fn test_ecdh() {
        let (private_a, public_a) = X25519Operations::generate_keypair().unwrap();
        let (private_b, public_b) = X25519Operations::generate_keypair().unwrap();

        let shared_a = X25519Operations::ecdh(&private_a, &public_b).unwrap();
        let shared_b = X25519Operations::ecdh(&private_b, &public_a).unwrap();

        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 32);
    }

    #[test]
    fn test_get_public_key() {
        let (private, public) = X25519Operations::generate_keypair().unwrap();
        let derived_public = X25519Operations::get_public_key(&private).unwrap();
        assert_eq!(public, derived_public);
    }
}

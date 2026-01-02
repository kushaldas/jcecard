//! Ed25519 Operations
//!
//! Ed25519 key generation and signing using ed25519-dalek.

use ed25519_dalek::{SigningKey, Signature, Signer};
use rand::rngs::OsRng;
use log::debug;

/// Ed25519 operation errors
#[derive(Debug)]
pub enum Ed25519Error {
    KeyGenerationFailed(String),
    SigningFailed(String),
    InvalidKey(String),
}

/// Ed25519 Operations
pub struct Ed25519Operations;

impl Ed25519Operations {
    /// Generate a new Ed25519 key pair
    /// Returns (private_key_bytes, public_key_bytes)
    pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), Ed25519Error> {
        debug!("Generating Ed25519 keypair");

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Private key is 32 bytes
        let private_data = signing_key.to_bytes().to_vec();

        // Public key is 32 bytes
        let public_data = verifying_key.to_bytes().to_vec();

        Ok((private_data, public_data))
    }

    /// Sign data with Ed25519
    pub fn sign(private_key_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>, Ed25519Error> {
        if private_key_bytes.len() != 32 {
            return Err(Ed25519Error::InvalidKey(
                format!("Invalid key length: expected 32, got {}", private_key_bytes.len())
            ));
        }

        let key_bytes: [u8; 32] = private_key_bytes.try_into()
            .map_err(|_| Ed25519Error::InvalidKey("Invalid key length".to_string()))?;

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature: Signature = signing_key.sign(data);

        Ok(signature.to_bytes().to_vec())
    }

    /// Load a signing key from bytes
    pub fn load_signing_key(private_key_bytes: &[u8]) -> Result<SigningKey, Ed25519Error> {
        if private_key_bytes.len() != 32 {
            return Err(Ed25519Error::InvalidKey(
                format!("Invalid key length: expected 32, got {}", private_key_bytes.len())
            ));
        }

        let key_bytes: [u8; 32] = private_key_bytes.try_into()
            .map_err(|_| Ed25519Error::InvalidKey("Invalid key length".to_string()))?;

        Ok(SigningKey::from_bytes(&key_bytes))
    }

    /// Get the public key from a private key
    pub fn get_public_key(private_key_bytes: &[u8]) -> Result<Vec<u8>, Ed25519Error> {
        let signing_key = Self::load_signing_key(private_key_bytes)?;
        Ok(signing_key.verifying_key().to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (private, public) = Ed25519Operations::generate_keypair().unwrap();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);
    }

    #[test]
    fn test_sign() {
        let (private, _) = Ed25519Operations::generate_keypair().unwrap();
        let data = b"test message";
        let signature = Ed25519Operations::sign(&private, data).unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_get_public_key() {
        let (private, public) = Ed25519Operations::generate_keypair().unwrap();
        let derived_public = Ed25519Operations::get_public_key(&private).unwrap();
        assert_eq!(public, derived_public);
    }
}

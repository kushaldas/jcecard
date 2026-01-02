//! secp256k1 ECC Operations
//!
//! ECDSA signing and ECDH using k256 crate.

use k256::ecdsa::{SigningKey, Signature};
use k256::ecdsa::signature::Signer;
use rand::rngs::OsRng;
use log::debug;

/// secp256k1 operation errors
#[derive(Debug)]
pub enum Secp256k1Error {
    KeyGenerationFailed(String),
    SigningFailed(String),
    ECDHFailed(String),
    InvalidKey(String),
}

/// secp256k1 ECC Operations
pub struct Secp256k1Operations;

impl Secp256k1Operations {
    /// Private key size for secp256k1 (32 bytes)
    pub const PRIVATE_KEY_SIZE: usize = 32;

    /// Public key size for secp256k1 (uncompressed: 65 bytes)
    pub const PUBLIC_KEY_SIZE: usize = 65;

    /// Generate a new secp256k1 key pair
    /// Returns (private_key_bytes, public_key_bytes)
    pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), Secp256k1Error> {
        debug!("Generating secp256k1 keypair");

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Private key is 32 bytes
        let private_data = signing_key.to_bytes().to_vec();

        // Public key in uncompressed point format (0x04 || x || y)
        let point = verifying_key.to_encoded_point(false);
        let public_data = point.as_bytes().to_vec();

        debug!("Generated secp256k1 key: private {} bytes, public {} bytes",
               private_data.len(), public_data.len());

        Ok((private_data, public_data))
    }

    /// Sign data with ECDSA secp256k1
    pub fn sign(private_key_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>, Secp256k1Error> {
        if private_key_bytes.len() != Self::PRIVATE_KEY_SIZE {
            return Err(Secp256k1Error::InvalidKey(
                format!("Invalid secp256k1 key length: expected {}, got {}",
                        Self::PRIVATE_KEY_SIZE, private_key_bytes.len())
            ));
        }

        let key_bytes: &[u8; 32] = private_key_bytes.try_into()
            .map_err(|_| Secp256k1Error::InvalidKey("Invalid key length".to_string()))?;

        let signing_key = SigningKey::from_bytes(key_bytes.into())
            .map_err(|e| Secp256k1Error::InvalidKey(e.to_string()))?;

        let signature: Signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Get the public key from a private key
    pub fn get_public_key(private_key_bytes: &[u8]) -> Result<Vec<u8>, Secp256k1Error> {
        if private_key_bytes.len() != Self::PRIVATE_KEY_SIZE {
            return Err(Secp256k1Error::InvalidKey(
                format!("Invalid secp256k1 key length: expected {}, got {}",
                        Self::PRIVATE_KEY_SIZE, private_key_bytes.len())
            ));
        }

        let key_bytes: &[u8; 32] = private_key_bytes.try_into()
            .map_err(|_| Secp256k1Error::InvalidKey("Invalid key length".to_string()))?;

        let signing_key = SigningKey::from_bytes(key_bytes.into())
            .map_err(|e| Secp256k1Error::InvalidKey(e.to_string()))?;

        let point = signing_key.verifying_key().to_encoded_point(false);
        Ok(point.as_bytes().to_vec())
    }

    /// Perform ECDH key agreement
    /// Returns shared secret
    pub fn ecdh(private_key_bytes: &[u8], public_key_bytes: &[u8]) -> Result<Vec<u8>, Secp256k1Error> {
        use k256::{SecretKey, PublicKey};
        use k256::ecdh::diffie_hellman;

        if private_key_bytes.len() != Self::PRIVATE_KEY_SIZE {
            return Err(Secp256k1Error::InvalidKey(
                format!("Invalid private key length: expected {}, got {}",
                        Self::PRIVATE_KEY_SIZE, private_key_bytes.len())
            ));
        }

        debug!("secp256k1 ECDH: private {} bytes, public {} bytes",
               private_key_bytes.len(), public_key_bytes.len());

        let secret_key = SecretKey::from_slice(private_key_bytes)
            .map_err(|e| Secp256k1Error::InvalidKey(format!("Invalid private key: {}", e)))?;

        let public_key = PublicKey::from_sec1_bytes(public_key_bytes)
            .map_err(|e| Secp256k1Error::InvalidKey(format!("Invalid public key: {}", e)))?;

        let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
        Ok(shared_secret.raw_secret_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (private, public) = Secp256k1Operations::generate_keypair().unwrap();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 65);
        assert_eq!(public[0], 0x04); // Uncompressed point
    }

    #[test]
    fn test_sign() {
        let (private, _) = Secp256k1Operations::generate_keypair().unwrap();
        let data = b"test message";
        let signature = Secp256k1Operations::sign(&private, data).unwrap();
        assert_eq!(signature.len(), 64); // r || s, each 32 bytes
    }

    #[test]
    fn test_get_public_key() {
        let (private, public) = Secp256k1Operations::generate_keypair().unwrap();
        let derived_public = Secp256k1Operations::get_public_key(&private).unwrap();
        assert_eq!(public, derived_public);
    }

    #[test]
    fn test_ecdh() {
        let (private_a, public_a) = Secp256k1Operations::generate_keypair().unwrap();
        let (private_b, public_b) = Secp256k1Operations::generate_keypair().unwrap();

        let shared_a = Secp256k1Operations::ecdh(&private_a, &public_b).unwrap();
        let shared_b = Secp256k1Operations::ecdh(&private_b, &public_a).unwrap();

        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 32);
    }
}

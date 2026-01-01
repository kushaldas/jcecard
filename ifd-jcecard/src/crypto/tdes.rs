//! Triple DES Operations
//!
//! 3DES-ECB encryption/decryption for PIV management key authentication.

use des::TdesEde3;
use des::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};
use log::debug;

/// 3DES operation errors
#[derive(Debug)]
pub enum TDesError {
    InvalidKey(String),
    InvalidData(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
}

/// Triple DES Operations
pub struct TDesOperations;

impl TDesOperations {
    /// Block size for 3DES
    pub const BLOCK_SIZE: usize = 8;

    /// Key size for 3DES (24 bytes = 192 bits)
    pub const KEY_SIZE: usize = 24;

    /// Encrypt a single block with 3DES-ECB
    pub fn encrypt_block(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TDesError> {
        if key.len() != Self::KEY_SIZE {
            return Err(TDesError::InvalidKey(
                format!("Invalid key length: expected {}, got {}", Self::KEY_SIZE, key.len())
            ));
        }
        if plaintext.len() != Self::BLOCK_SIZE {
            return Err(TDesError::InvalidData(
                format!("Invalid block length: expected {}, got {}", Self::BLOCK_SIZE, plaintext.len())
            ));
        }

        let cipher = TdesEde3::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(plaintext);
        cipher.encrypt_block(&mut block);

        Ok(block.to_vec())
    }

    /// Decrypt a single block with 3DES-ECB
    pub fn decrypt_block(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, TDesError> {
        if key.len() != Self::KEY_SIZE {
            return Err(TDesError::InvalidKey(
                format!("Invalid key length: expected {}, got {}", Self::KEY_SIZE, key.len())
            ));
        }
        if ciphertext.len() != Self::BLOCK_SIZE {
            return Err(TDesError::InvalidData(
                format!("Invalid block length: expected {}, got {}", Self::BLOCK_SIZE, ciphertext.len())
            ));
        }

        let cipher = TdesEde3::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(ciphertext);
        cipher.decrypt_block(&mut block);

        Ok(block.to_vec())
    }

    /// Encrypt multiple blocks with 3DES-ECB
    pub fn encrypt_ecb(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TDesError> {
        if key.len() != Self::KEY_SIZE {
            return Err(TDesError::InvalidKey(
                format!("Invalid key length: expected {}, got {}", Self::KEY_SIZE, key.len())
            ));
        }
        if plaintext.len() % Self::BLOCK_SIZE != 0 {
            return Err(TDesError::InvalidData(
                format!("Data length {} is not a multiple of block size {}",
                        plaintext.len(), Self::BLOCK_SIZE)
            ));
        }

        debug!("3DES-ECB encrypting {} bytes", plaintext.len());

        let cipher = TdesEde3::new(GenericArray::from_slice(key));
        let mut result = Vec::with_capacity(plaintext.len());

        for chunk in plaintext.chunks(Self::BLOCK_SIZE) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            result.extend_from_slice(&block);
        }

        Ok(result)
    }

    /// Decrypt multiple blocks with 3DES-ECB
    pub fn decrypt_ecb(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, TDesError> {
        if key.len() != Self::KEY_SIZE {
            return Err(TDesError::InvalidKey(
                format!("Invalid key length: expected {}, got {}", Self::KEY_SIZE, key.len())
            ));
        }
        if ciphertext.len() % Self::BLOCK_SIZE != 0 {
            return Err(TDesError::InvalidData(
                format!("Data length {} is not a multiple of block size {}",
                        ciphertext.len(), Self::BLOCK_SIZE)
            ));
        }

        debug!("3DES-ECB decrypting {} bytes", ciphertext.len());

        let cipher = TdesEde3::new(GenericArray::from_slice(key));
        let mut result = Vec::with_capacity(ciphertext.len());

        for chunk in ciphertext.chunks(Self::BLOCK_SIZE) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            result.extend_from_slice(&block);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_block() {
        let key = [0x01u8; 24];
        let plaintext = [0x00u8; 8];

        let ciphertext = TDesOperations::encrypt_block(&key, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), 8);

        let decrypted = TDesOperations::decrypt_block(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_ecb() {
        let key = [0x01u8; 24];
        let plaintext = [0x00u8; 16]; // Two blocks

        let ciphertext = TDesOperations::encrypt_ecb(&key, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), 16);

        let decrypted = TDesOperations::decrypt_ecb(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [0x01u8; 16]; // Wrong length
        let plaintext = [0x00u8; 8];

        let result = TDesOperations::encrypt_block(&key, &plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_block_length() {
        let key = [0x01u8; 24];
        let plaintext = [0x00u8; 7]; // Wrong length

        let result = TDesOperations::encrypt_block(&key, &plaintext);
        assert!(result.is_err());
    }
}

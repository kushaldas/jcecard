//! Hash Operations
//!
//! SHA-1 and SHA-256 hashing for various card operations.

use sha1::Sha1;
use sha2::{Sha256, Sha512};
use digest::Digest;

/// Hash algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

/// Hash Operations
pub struct HashOperations;

impl HashOperations {
    /// Compute SHA-1 hash
    pub fn sha1(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Compute SHA-256 hash
    pub fn sha256(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Compute SHA-512 hash
    pub fn sha512(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Compute hash using specified algorithm
    pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
        match algorithm {
            HashAlgorithm::SHA1 => Self::sha1(data),
            HashAlgorithm::SHA256 => Self::sha256(data),
            HashAlgorithm::SHA512 => Self::sha512(data),
        }
    }

    /// Get the output size for an algorithm
    pub fn output_size(algorithm: HashAlgorithm) -> usize {
        match algorithm {
            HashAlgorithm::SHA1 => 20,
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA512 => 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1() {
        let hash = HashOperations::sha1(b"test");
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_sha256() {
        let hash = HashOperations::sha256(b"test");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha512() {
        let hash = HashOperations::sha512(b"test");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_sha256_known_value() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = HashOperations::sha256(b"");
        assert_eq!(
            hex::encode(&hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}

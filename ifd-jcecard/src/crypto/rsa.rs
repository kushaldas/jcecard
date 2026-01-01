//! RSA Operations
//!
//! RSA key generation, signing, and decryption using the rsa crate.

use rsa::{RsaPrivateKey, RsaPublicKey, BigUint, Pkcs1v15Encrypt};
use rsa::traits::{PublicKeyParts, PrivateKeyParts};
use rand::rngs::OsRng;
use log::debug;

/// RSA operation errors
#[derive(Debug)]
pub enum RsaError {
    KeyGenerationFailed(String),
    SigningFailed(String),
    DecryptionFailed(String),
    InvalidKey(String),
    InvalidData(String),
}

/// RSA Operations
pub struct RsaOperations;

impl RsaOperations {
    /// Generate a new RSA key pair
    pub fn generate_keypair(bits: usize) -> Result<(Vec<u8>, Vec<u8>), RsaError> {
        debug!("Generating RSA-{} keypair", bits);

        let private_key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| RsaError::KeyGenerationFailed(e.to_string()))?;

        let public_key = RsaPublicKey::from(&private_key);

        // Encode private key (n, e, d, p, q)
        let private_data = Self::encode_private_key(&private_key)?;

        // Encode public key (n, e)
        let public_data = Self::encode_public_key(&public_key);

        Ok((private_data, public_data))
    }

    /// Encode private key to bytes for storage
    fn encode_private_key(key: &RsaPrivateKey) -> Result<Vec<u8>, RsaError> {
        // For OpenPGP card format, we need to store the key components
        // Format: e_len(2) || e || p_len(2) || p || q_len(2) || q
        let e = key.e().to_bytes_be();
        let primes = key.primes();
        if primes.len() < 2 {
            return Err(RsaError::InvalidKey("Missing prime factors".to_string()));
        }
        let p = primes[0].to_bytes_be();
        let q = primes[1].to_bytes_be();

        let mut data = Vec::new();
        // e length and value
        data.extend_from_slice(&(e.len() as u16).to_be_bytes());
        data.extend_from_slice(&e);
        // p length and value
        data.extend_from_slice(&(p.len() as u16).to_be_bytes());
        data.extend_from_slice(&p);
        // q length and value
        data.extend_from_slice(&(q.len() as u16).to_be_bytes());
        data.extend_from_slice(&q);

        Ok(data)
    }

    /// Encode public key to bytes
    fn encode_public_key(key: &RsaPublicKey) -> Vec<u8> {
        // Format: n_len(2) || n || e_len(2) || e
        let n = key.n().to_bytes_be();
        let e = key.e().to_bytes_be();

        let mut data = Vec::new();
        data.extend_from_slice(&(n.len() as u16).to_be_bytes());
        data.extend_from_slice(&n);
        data.extend_from_slice(&(e.len() as u16).to_be_bytes());
        data.extend_from_slice(&e);

        data
    }

    /// Decode a private key from stored bytes
    pub fn decode_private_key(data: &[u8], n_bytes: &[u8]) -> Result<RsaPrivateKey, RsaError> {
        if data.len() < 6 {
            return Err(RsaError::InvalidKey("Data too short".to_string()));
        }

        let mut offset = 0;

        // Read e
        let e_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + e_len > data.len() {
            return Err(RsaError::InvalidKey("Invalid e length".to_string()));
        }
        let e = BigUint::from_bytes_be(&data[offset..offset + e_len]);
        offset += e_len;

        // Read p
        if offset + 2 > data.len() {
            return Err(RsaError::InvalidKey("Missing p length".to_string()));
        }
        let p_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + p_len > data.len() {
            return Err(RsaError::InvalidKey("Invalid p length".to_string()));
        }
        let p = BigUint::from_bytes_be(&data[offset..offset + p_len]);
        offset += p_len;

        // Read q
        if offset + 2 > data.len() {
            return Err(RsaError::InvalidKey("Missing q length".to_string()));
        }
        let q_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + q_len > data.len() {
            return Err(RsaError::InvalidKey("Invalid q length".to_string()));
        }
        let q = BigUint::from_bytes_be(&data[offset..offset + q_len]);

        // Reconstruct n and compute d
        let n = BigUint::from_bytes_be(n_bytes);

        // Compute d = e^(-1) mod λ(n), where λ(n) = lcm(p-1, q-1)
        // For RSA, we use the Carmichael function (λ) or Euler totient (φ)
        // Using φ(n) = (p-1)(q-1) for simplicity
        let one = BigUint::from(1u64);
        let p_minus_1 = &p - &one;
        let q_minus_1 = &q - &one;
        let phi_n = &p_minus_1 * &q_minus_1;

        // Compute d = modular inverse of e mod phi_n
        // Using extended Euclidean algorithm
        let d = Self::mod_inverse(&e, &phi_n)
            .ok_or_else(|| RsaError::InvalidKey("Cannot compute private exponent d".to_string()))?;

        RsaPrivateKey::from_components(n, e, d, vec![p, q])
            .map_err(|e| RsaError::InvalidKey(e.to_string()))
    }

    /// Sign with PKCS#1 v1.5 padding
    /// Input is DigestInfo, we apply padding and do raw RSA signature
    pub fn sign_pkcs1v15(private_key: &RsaPrivateKey, digest_info: &[u8]) -> Result<Vec<u8>, RsaError> {
        let key_size = private_key.size();

        // PKCS#1 v1.5 padding: 00 01 [FF...FF] 00 [DigestInfo]
        // Minimum padding is 8 bytes of 0xFF
        if digest_info.len() + 11 > key_size {
            return Err(RsaError::InvalidData("DigestInfo too large for key size".to_string()));
        }

        let padding_len = key_size - digest_info.len() - 3;
        let mut padded = Vec::with_capacity(key_size);
        padded.push(0x00);
        padded.push(0x01);
        padded.extend(std::iter::repeat(0xFF).take(padding_len));
        padded.push(0x00);
        padded.extend_from_slice(digest_info);

        // Perform m^d mod n
        let m = BigUint::from_bytes_be(&padded);
        let d = private_key.d();
        let n = private_key.n();
        let signature = m.modpow(d, n);

        // Convert to bytes with proper padding to key size
        let mut sig_bytes = signature.to_bytes_be();
        while sig_bytes.len() < key_size {
            sig_bytes.insert(0, 0);
        }

        Ok(sig_bytes)
    }

    /// Perform raw RSA signing (for OpenPGP PSO:SIGN with pre-padded DigestInfo)
    /// Input is already PKCS#1 v1.5 padded, we just do m^d mod n
    #[allow(dead_code)]
    pub fn raw_sign(private_key: &RsaPrivateKey, padded_data: &[u8]) -> Result<Vec<u8>, RsaError> {
        let m = BigUint::from_bytes_be(padded_data);

        // Perform m^d mod n using the private key
        let d = private_key.d();
        let n = private_key.n();
        let signature = m.modpow(d, n);

        // Convert to bytes with proper padding to key size
        let key_size = (private_key.size() + 7) / 8;
        let mut sig_bytes = signature.to_bytes_be();

        // Pad to key size if needed
        while sig_bytes.len() < key_size {
            sig_bytes.insert(0, 0);
        }

        Ok(sig_bytes)
    }

    /// Decrypt RSA encrypted data
    pub fn decrypt(private_key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, RsaError> {
        private_key.decrypt(Pkcs1v15Encrypt, ciphertext)
            .map_err(|e| RsaError::DecryptionFailed(e.to_string()))
    }

    /// Get modulus bytes from public key data
    pub fn get_modulus(public_key_data: &[u8]) -> Option<Vec<u8>> {
        if public_key_data.len() < 4 {
            return None;
        }
        let n_len = u16::from_be_bytes([public_key_data[0], public_key_data[1]]) as usize;
        if public_key_data.len() < 2 + n_len {
            return None;
        }
        Some(public_key_data[2..2 + n_len].to_vec())
    }

    /// Get exponent bytes from public key data
    pub fn get_exponent(public_key_data: &[u8]) -> Option<Vec<u8>> {
        if public_key_data.len() < 4 {
            return None;
        }
        let n_len = u16::from_be_bytes([public_key_data[0], public_key_data[1]]) as usize;
        let e_offset = 2 + n_len;
        if public_key_data.len() < e_offset + 2 {
            return None;
        }
        let e_len = u16::from_be_bytes([public_key_data[e_offset], public_key_data[e_offset + 1]]) as usize;
        if public_key_data.len() < e_offset + 2 + e_len {
            return None;
        }
        Some(public_key_data[e_offset + 2..e_offset + 2 + e_len].to_vec())
    }

    /// Compute modular multiplicative inverse using extended Euclidean algorithm
    /// Returns a^(-1) mod m, or None if no inverse exists
    fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
        // Extended Euclidean Algorithm with BigUint
        // We track signs separately since BigUint is unsigned
        let one = BigUint::from(1u64);
        let zero = BigUint::from(0u64);

        let mut old_r = m.clone();
        let mut r = a.clone();
        let mut old_s = zero.clone();
        let mut s = one.clone();
        let mut old_s_neg = false;
        let mut s_neg = false;

        while r != zero {
            let quotient = &old_r / &r;

            // Update r
            let temp_r = old_r;
            old_r = r.clone();
            r = temp_r - &quotient * &r;

            // Update s with sign tracking
            // new_s = old_s - quotient * s
            let (new_s, new_s_neg) = {
                let qs = &quotient * &s;
                if old_s_neg == s_neg {
                    // Same sign: old_s - q*s (subtract)
                    if old_s >= qs {
                        (old_s.clone() - &qs, old_s_neg)
                    } else {
                        (qs - &old_s, !old_s_neg)
                    }
                } else {
                    // Different signs: old_s + q*s (add magnitudes)
                    (old_s.clone() + &qs, old_s_neg)
                }
            };
            old_s = s;
            old_s_neg = s_neg;
            s = new_s;
            s_neg = new_s_neg;
        }

        // old_r is the gcd, should be 1 for inverse to exist
        if old_r != one {
            return None;
        }

        // Convert to positive result mod m
        let result = if old_s_neg {
            m - &old_s
        } else {
            old_s
        };

        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (private, public) = RsaOperations::generate_keypair(2048).unwrap();
        assert!(!private.is_empty());
        assert!(!public.is_empty());
    }

    #[test]
    fn test_get_modulus_exponent() {
        let (_, public) = RsaOperations::generate_keypair(2048).unwrap();
        let n = RsaOperations::get_modulus(&public).unwrap();
        let e = RsaOperations::get_exponent(&public).unwrap();
        assert_eq!(n.len(), 256); // 2048 bits = 256 bytes
        assert!(!e.is_empty());
    }
}

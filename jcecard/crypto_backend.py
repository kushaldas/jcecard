"""
Cryptographic Backend Module

Provides cryptographic operations using Python's cryptography library for:
- Key generation (RSA, ECC/Curve25519)
- Digital signatures (Ed25519, RSA PKCS#1 v1.5)
- Decryption (RSA PKCS#1 v1.5, X25519 ECDH)
- Key fingerprint calculation

This implementation uses only the cryptography library.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Optional
from enum import IntEnum

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers


from .card_data import AlgorithmAttributes, AlgorithmID


logger = logging.getLogger(__name__)


class KeyType(IntEnum):
    """Key types for OpenPGP card."""
    SIGNATURE = 0xB6
    DECRYPTION = 0xB8
    AUTHENTICATION = 0xA4


@dataclass
class GeneratedKey:
    """Result of key generation."""
    public_key_data: bytes  # Public key in OpenPGP card format (TLV 7F49)
    private_key_data: bytes  # Private key data for storage (raw bytes for ECC, DER for RSA)
    fingerprint: bytes      # 20-byte SHA-1 fingerprint
    generation_time: int    # Unix timestamp
    raw_private_key: Optional[bytes] = None  # Raw 32-byte key for Ed25519/X25519
    raw_public_key: Optional[bytes] = None   # Raw 32-byte public key
    openpgp_public_key: Optional[bytes] = None  # OpenPGP public key (not available without jce)


@dataclass
class SignatureResult:
    """Result of a signing operation."""
    signature: bytes
    success: bool
    error: Optional[str] = None


@dataclass
class DecryptionResult:
    """Result of a decryption operation."""
    plaintext: bytes
    success: bool
    error: Optional[str] = None


class CryptoBackend:
    """
    Cryptographic backend using Python's cryptography library.
    
    Handles all cryptographic operations for the virtual OpenPGP card.
    """
    
    # Default password (kept for API compatibility, not used in cryptography-only implementation)
    DEFAULT_PASSWORD = "virtual-openpgp-card"
    
    def __init__(self):
        """Initialize the crypto backend."""
        # Store raw key material (32 bytes for Ed25519/X25519)
        self._raw_private_keys: dict[KeyType, Optional[bytes]] = {
            KeyType.SIGNATURE: None,
            KeyType.DECRYPTION: None,
            KeyType.AUTHENTICATION: None,
        }
        # Store DER-encoded keys (for RSA keys)
        self._der_keys: dict[KeyType, Optional[bytes]] = {
            KeyType.SIGNATURE: None,
            KeyType.DECRYPTION: None,
            KeyType.AUTHENTICATION: None,
        }
        # Store public key data (TLV encoded for card format)
        self._public_key_data: dict[KeyType, Optional[bytes]] = {
            KeyType.SIGNATURE: None,
            KeyType.DECRYPTION: None,
            KeyType.AUTHENTICATION: None,
        }
        # Store algorithm info
        self._algorithm_info: dict[KeyType, Optional[AlgorithmAttributes]] = {
            KeyType.SIGNATURE: None,
            KeyType.DECRYPTION: None,
            KeyType.AUTHENTICATION: None,
        }
    
    @staticmethod
    def is_available() -> bool:
        """Check if crypto backend is available."""
        import importlib.util
        return importlib.util.find_spec("cryptography") is not None
    
    def generate_rsa_key(
        self,
        key_type: KeyType,
        bits: int = 2048
    ) -> Optional[GeneratedKey]:
        """
        Generate an RSA key pair.
        
        Args:
            key_type: The key slot type (SIG, DEC, AUT)
            bits: Key size in bits (2048 or 4096)
            
        Returns:
            GeneratedKey with public/private data and fingerprint, or None on error
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            logger.info(f"Generating RSA-{bits} key for {key_type.name}")
            
            timestamp = int(time.time())
            
            # Generate RSA key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=bits,
                backend=default_backend()
            )
            
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()
            
            # Encode public key in OpenPGP card format (7F49 template)
            n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')
            e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')
            
            from .tlv import TLVEncoder
            content = TLVEncoder.encode(0x81, n_bytes) + TLVEncoder.encode(0x82, e_bytes)
            pub_data = TLVEncoder.encode(0x7F49, content)
            
            # Serialize private key to DER format
            priv_data = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Calculate fingerprint
            fingerprint = self._calculate_rsa_fingerprint(n_bytes, e_bytes, timestamp)
            
            # Store keys
            self._der_keys[key_type] = priv_data
            self._public_key_data[key_type] = pub_data
            
            logger.info(f"Generated RSA-{bits} key with fingerprint {fingerprint.hex()}")
            
            return GeneratedKey(
                public_key_data=pub_data,
                private_key_data=priv_data,
                fingerprint=fingerprint,
                generation_time=timestamp
            )
            
        except ImportError as e:
            logger.error(f"cryptography library not available: {e}")
            return None
        except Exception as e:
            logger.exception(f"Failed to generate RSA key: {e}")
            return None
    
    def generate_curve25519_key(
        self,
        key_type: KeyType
    ) -> Optional[GeneratedKey]:
        """
        Generate a Curve25519 key pair (Ed25519 for signing, X25519 for encryption).
        
        Args:
            key_type: The key slot type (SIG, DEC, AUT)
            
        Returns:
            GeneratedKey with public/private data and fingerprint, or None on error
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
            from cryptography.hazmat.primitives import serialization
            
            logger.info(f"Generating Curve25519 key for {key_type.name}")
            
            timestamp = int(time.time())
            
            # Generate key based on key type
            if key_type == KeyType.DECRYPTION:
                # X25519 for encryption/decryption
                private_key = x25519.X25519PrivateKey.generate()
                raw_private = private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
                raw_public = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            else:
                # Ed25519 for signing and authentication
                private_key = ed25519.Ed25519PrivateKey.generate()
                raw_private = private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
                raw_public = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            
            # Store raw key for operations
            self._raw_private_keys[key_type] = raw_private
            
            # Build OpenPGP public key structure (7F49 template with 86 tag for public key)
            from .tlv import TLVEncoder
            pub_data = TLVEncoder.encode(0x7F49, TLVEncoder.encode(0x86, raw_public))
            self._public_key_data[key_type] = pub_data
            
            # Calculate fingerprint
            fingerprint = self._calculate_ecc_fingerprint(raw_public, timestamp, key_type)
            
            logger.info(f"Generated Curve25519 key with fingerprint {fingerprint.hex()}")
            
            return GeneratedKey(
                public_key_data=pub_data,
                private_key_data=raw_private,
                fingerprint=fingerprint,
                generation_time=timestamp,
                raw_private_key=raw_private,
                raw_public_key=raw_public
            )
            
        except ImportError as e:
            logger.error(f"cryptography library not available: {e}")
            return None
        except Exception as e:
            logger.exception(f"Failed to generate Curve25519 key: {e}")
            return None
    
    def _calculate_rsa_fingerprint(self, n_bytes: bytes, e_bytes: bytes, timestamp: int) -> bytes:
        """
        Calculate OpenPGP v4 fingerprint for RSA key.
        
        The fingerprint is SHA-1 of:
        - 0x99 (public key packet tag, old format)
        - 2-byte packet length
        - Version (0x04)
        - 4-byte creation time
        - Algorithm (0x01 for RSA)
        - RSA n as MPI
        - RSA e as MPI
        """
        # Build public key packet content
        packet_content = bytes([
            0x04,  # Version 4
            (timestamp >> 24) & 0xFF,
            (timestamp >> 16) & 0xFF,
            (timestamp >> 8) & 0xFF,
            timestamp & 0xFF,
            0x01,  # RSA algorithm
        ])
        
        # Add n as MPI (bit count + data)
        n_bits = len(n_bytes) * 8
        # Find actual bit count (exclude leading zeros)
        for i, b in enumerate(n_bytes):
            if b != 0:
                n_bits = (len(n_bytes) - i) * 8 - (8 - b.bit_length())
                break
        packet_content += bytes([(n_bits >> 8) & 0xFF, n_bits & 0xFF])
        packet_content += n_bytes
        
        # Add e as MPI
        e_bits = len(e_bytes) * 8
        for i, b in enumerate(e_bytes):
            if b != 0:
                e_bits = (len(e_bytes) - i) * 8 - (8 - b.bit_length())
                break
        packet_content += bytes([(e_bits >> 8) & 0xFF, e_bits & 0xFF])
        packet_content += e_bytes
        
        # Build fingerprint input
        packet_len = len(packet_content)
        fingerprint_input = bytes([
            0x99,  # Public key packet tag (old format)
            (packet_len >> 8) & 0xFF,
            packet_len & 0xFF,
        ]) + packet_content
        
        return hashlib.sha1(fingerprint_input).digest()
    
    def _calculate_ecc_fingerprint(self, public_key: bytes, timestamp: int, key_type: KeyType) -> bytes:
        """
        Calculate a v4-style fingerprint for ECC keys.
        
        For Ed25519/X25519, the fingerprint is SHA-1 of:
        - 0x99 (public key packet tag, old format)
        - 2-byte packet length
        - Version (0x04)
        - 4-byte creation time
        - Algorithm ID (22 for EdDSA/Ed25519, 18 for ECDH/X25519)
        - Algorithm-specific data (OID + public key)
        """
        # Determine algorithm ID and OID
        if key_type == KeyType.DECRYPTION:
            algo_id = 18  # ECDH
            # X25519 OID: 1.3.6.1.4.1.3029.1.5.1
            oid = bytes([0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01])
        else:
            algo_id = 22  # EdDSA
            # Ed25519 OID: 1.3.6.1.4.1.11591.15.1
            oid = bytes([0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01])
        
        # Build public key packet content
        packet_content = bytes([
            0x04,  # Version 4
            (timestamp >> 24) & 0xFF,
            (timestamp >> 16) & 0xFF,
            (timestamp >> 8) & 0xFF,
            timestamp & 0xFF,
            algo_id,
        ])
        packet_content += oid
        
        # Add public key as MPI (with bit count prefix)
        key_bits = len(public_key) * 8
        packet_content += bytes([
            (key_bits >> 8) & 0xFF,
            key_bits & 0xFF,
        ])
        packet_content += public_key
        
        # For ECDH, add KDF parameters
        if key_type == KeyType.DECRYPTION:
            # KDF parameters: hash=SHA256, cipher=AES128
            packet_content += bytes([0x03, 0x01, 0x08, 0x07])
        
        # Build fingerprint input
        packet_len = len(packet_content)
        fingerprint_input = bytes([
            0x99,  # Public key packet tag (old format)
            (packet_len >> 8) & 0xFF,
            packet_len & 0xFF,
        ]) + packet_content
        
        return hashlib.sha1(fingerprint_input).digest()
    
    def load_key(
        self,
        key_type: KeyType,
        private_key_data: bytes,
        algorithm: AlgorithmAttributes
    ) -> bool:
        """
        Load a key from stored private key data.
        
        Args:
            key_type: The key slot type
            private_key_data: The stored private key bytes
            algorithm: Algorithm attributes for the key
            
        Returns:
            True if key was loaded successfully
        """
        if not private_key_data:
            return False
        
        self._algorithm_info[key_type] = algorithm
        
        # Handle based on algorithm
        if algorithm.algorithm_id == AlgorithmID.RSA_2048:
            # RSA key - check if it's DER or raw CRT format
            if len(private_key_data) > 500:
                # Likely DER format
                self._der_keys[key_type] = private_key_data
            else:
                # Raw CRT format
                return self.load_raw_key(key_type, private_key_data, algorithm)
        else:
            # ECC key - raw format
            return self.load_raw_key(key_type, private_key_data, algorithm)
        
        logger.info(f"Loaded key for {key_type.name}")
        return True
    
    def load_raw_key(
        self,
        key_type: KeyType,
        raw_key: bytes,
        algorithm: AlgorithmAttributes
    ) -> bool:
        """
        Load raw key material (32 bytes for Ed25519/X25519, or RSA CRT format).
        
        Args:
            key_type: The key slot type
            raw_key: The raw private key bytes
            algorithm: Algorithm attributes for the key
            
        Returns:
            True if key was loaded successfully
        """
        if not raw_key:
            return False
        
        # Handle RSA keys (algorithm_id == 0x01)
        if algorithm.algorithm_id == AlgorithmID.RSA_2048:
            return self._load_raw_rsa_key(key_type, raw_key, algorithm)
        
        # X25519 keys from OpenPGP are in big-endian (MPI format),
        # but the cryptography library expects little-endian.
        if algorithm.algorithm_id == AlgorithmID.ECDH_X25519 and len(raw_key) == 32:
            raw_key = bytes(reversed(raw_key))
            logger.debug("Reversed byte order for X25519 key")
        
        self._raw_private_keys[key_type] = raw_key
        self._algorithm_info[key_type] = algorithm
        logger.info(f"Loaded raw key for {key_type.name}, {len(raw_key)} bytes, algo={algorithm.algorithm_id}")
        return True
    
    def _load_raw_rsa_key(
        self,
        key_type: KeyType,
        raw_key: bytes,
        algorithm: AlgorithmAttributes
    ) -> bool:
        """
        Load RSA key from raw CRT format data.
        
        The format is: e (3 bytes) || p (key_size/16 bytes) || q (key_size/16 bytes)
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.rsa import (
                rsa_crt_iqmp, rsa_crt_dmp1, rsa_crt_dmq1,
                RSAPrivateNumbers, RSAPublicNumbers
            )
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            # Determine key size from algorithm attributes
            key_bits = algorithm.param1  # e.g., 4096 or 2048
            component_size = key_bits // 16  # p and q are half the key size in bytes
            
            # Parse the key data: e || p || q
            e_size = 3
            
            if len(raw_key) < e_size + 2 * component_size:
                logger.warning(f"RSA key data too short: {len(raw_key)} bytes")
                return False
            
            e = int.from_bytes(raw_key[:e_size], 'big')
            p = int.from_bytes(raw_key[e_size:e_size + component_size], 'big')
            q = int.from_bytes(raw_key[e_size + component_size:e_size + 2 * component_size], 'big')
            
            # Calculate derived values
            n = p * q
            d = pow(e, -1, (p - 1) * (q - 1))
            dp = rsa_crt_dmp1(d, p)
            dq = rsa_crt_dmq1(d, q)
            qinv = rsa_crt_iqmp(p, q)
            
            # Create RSA private key
            public_numbers = RSAPublicNumbers(e, n)
            private_numbers = RSAPrivateNumbers(p, q, d, dp, dq, qinv, public_numbers)
            private_key = private_numbers.private_key(default_backend())
            
            # Store as DER-encoded private key
            der_key = private_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
            
            self._der_keys[key_type] = der_key
            self._algorithm_info[key_type] = algorithm
            
            logger.info(f"Loaded RSA-{key_bits} key for {key_type.name}")
            return True
            
        except Exception as e:
            logger.exception(f"Failed to load RSA key: {e}")
            return False
    
    def sign(
        self,
        data: bytes,
        key_type: KeyType = KeyType.SIGNATURE
    ) -> SignatureResult:
        """
        Sign data using the specified key.
        
        For Ed25519: Signs the data directly
        For RSA: Expects DigestInfo and performs PKCS#1 v1.5 signature
        
        Args:
            data: The data to sign
            key_type: The key slot to use
            
        Returns:
            SignatureResult with signature bytes or error
        """
        # Try RSA first
        der_key = self._der_keys.get(key_type)
        if der_key is not None:
            return self._sign_rsa(data, der_key)
        
        # Try Ed25519
        raw_key = self._raw_private_keys.get(key_type)
        if raw_key is not None:
            return self._sign_ed25519(data, raw_key)
        
        return SignatureResult(b'', False, "Key not loaded")
    
    def sign_raw(
        self,
        data: bytes,
        key_type: KeyType = KeyType.SIGNATURE
    ) -> SignatureResult:
        """
        Sign using raw key (same as sign, kept for API compatibility).
        """
        return self.sign(data, key_type)
    
    def _sign_ed25519(self, data: bytes, raw_key: bytes) -> SignatureResult:
        """Sign data using Ed25519."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            
            private_key = Ed25519PrivateKey.from_private_bytes(raw_key)
            signature = private_key.sign(data)
            
            logger.debug(f"Ed25519 signature: {len(signature)} bytes")
            return SignatureResult(signature, True)
            
        except Exception as e:
            logger.exception(f"Ed25519 signing failed: {e}")
            return SignatureResult(b'', False, str(e))
    
    def _sign_rsa(self, data: bytes, der_key: bytes) -> SignatureResult:
        """
        Sign using RSA key (PKCS#1 v1.5 padding).
        
        For OpenPGP cards, we receive DigestInfo and apply raw PKCS#1 v1.5 padding.
        """
        try:
            from cryptography.hazmat.primitives.serialization import load_der_private_key
            from cryptography.hazmat.backends import default_backend
            
            private_key = load_der_private_key(der_key, password=None, backend=default_backend())
            
            # Get key size in bytes
            key_size = private_key.key_size // 8  # type: ignore[union-attr]
            
            # Build PKCS#1 v1.5 padding manually:
            # 0x00 || 0x01 || padding_bytes(0xFF) || 0x00 || DigestInfo
            padding_length = key_size - 3 - len(data)
            if padding_length < 8:
                return SignatureResult(b'', False, "DigestInfo too long for key size")
            
            padded = b'\x00\x01' + (b'\xff' * padding_length) + b'\x00' + data
            
            # Convert to integer and do raw RSA operation
            padded_int = int.from_bytes(padded, 'big')
            private_numbers = private_key.private_numbers()  # type: ignore[union-attr]
            
            # Type narrowing for RSA private numbers
            assert isinstance(private_numbers, RSAPrivateNumbers), "Expected RSA private numbers"
            
            # RSA signature: m^d mod n
            signature_int = pow(padded_int, private_numbers.d, private_numbers.public_numbers.n)
            signature = signature_int.to_bytes(key_size, 'big')
            
            logger.debug(f"RSA signature: {len(signature)} bytes")
            return SignatureResult(signature, True)
            
        except Exception as e:
            logger.exception(f"RSA signing failed: {e}")
            return SignatureResult(b'', False, str(e))
    
    def decrypt(
        self,
        ciphertext: bytes,
        key_type: KeyType = KeyType.DECRYPTION
    ) -> DecryptionResult:
        """
        Decrypt data using the decryption key.
        
        For RSA: PKCS#1 v1.5 decryption
        For X25519: Use decrypt_ecdh instead
        
        Args:
            ciphertext: The encrypted data
            key_type: The key slot to use
            
        Returns:
            DecryptionResult with plaintext or error
        """
        der_key = self._der_keys.get(key_type)
        if der_key is not None:
            return self._decrypt_rsa(ciphertext, der_key)
        
        return DecryptionResult(b'', False, "Key not loaded")
    
    def _decrypt_rsa(self, ciphertext: bytes, der_key: bytes) -> DecryptionResult:
        """Decrypt using RSA key (PKCS#1 v1.5 padding)."""
        try:
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives.serialization import load_der_private_key
            from cryptography.hazmat.backends import default_backend
            
            private_key = load_der_private_key(der_key, password=None, backend=default_backend())
            
            plaintext = private_key.decrypt(  # type: ignore[union-attr]
                ciphertext,
                padding.PKCS1v15()
            )
            
            logger.debug(f"RSA decrypted {len(ciphertext)} bytes -> {len(plaintext)} bytes")
            return DecryptionResult(plaintext, True)
            
        except Exception as e:
            logger.exception(f"RSA decryption failed: {e}")
            return DecryptionResult(b'', False, str(e))
    
    def decrypt_ecdh(
        self,
        ephemeral_public: bytes,
        key_type: KeyType = KeyType.DECRYPTION
    ) -> DecryptionResult:
        """
        Perform X25519 ECDH to derive shared secret.
        
        Args:
            ephemeral_public: The ephemeral public key (32 bytes)
            key_type: The key slot to use
            
        Returns:
            DecryptionResult with 32-byte shared secret
        """
        raw_key = self._raw_private_keys.get(key_type)
        if raw_key is None:
            return DecryptionResult(b'', False, "Key not loaded")
        
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
            
            private_key = X25519PrivateKey.from_private_bytes(raw_key)
            peer_public = X25519PublicKey.from_public_bytes(ephemeral_public)
            shared_secret = private_key.exchange(peer_public)
            
            logger.debug(f"ECDH shared secret: {len(shared_secret)} bytes")
            return DecryptionResult(shared_secret, True)
            
        except Exception as e:
            logger.exception(f"ECDH decryption failed: {e}")
            return DecryptionResult(b'', False, str(e))
    
    def authenticate(
        self,
        challenge: bytes
    ) -> SignatureResult:
        """
        Perform internal authentication (sign a challenge).
        """
        return self.sign(challenge, KeyType.AUTHENTICATION)
    
    def get_public_key(self, key_type: KeyType) -> Optional[bytes]:
        """Get the public key data for a key slot (TLV encoded)."""
        return self._public_key_data.get(key_type)
    
    def has_key(self, key_type: KeyType) -> bool:
        """Check if a key is loaded for the given slot."""
        return (self._raw_private_keys.get(key_type) is not None or 
                self._der_keys.get(key_type) is not None)
    
    def has_raw_key(self, key_type: KeyType) -> bool:
        """Check if a raw key is loaded for the given slot."""
        return self.has_key(key_type)


# Alias for compatibility
SimpleCryptoBackend = CryptoBackend


def get_crypto_backend() -> CryptoBackend:
    """Get the crypto backend instance."""
    return CryptoBackend()

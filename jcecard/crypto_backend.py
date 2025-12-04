"""
Cryptographic Backend Module

Provides cryptographic operations using johnnycanencrypt for:
- Key generation (RSA, ECC/Curve25519)
- Digital signatures
- Decryption
- Key fingerprint calculation

Usage:
    from johnnycanencrypt import Cipher, create_key, parse_cert_bytes
    from johnnycanencrypt.johnnycanencrypt import Johnny, create_key as jce_create_key
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional, Callable, Any, Union, TYPE_CHECKING
from enum import IntEnum

# Type alias matching johnnycanencrypt.pyi
# KeyData = tuple[list[dict[Any, Any]], str, bool, datetime | None, datetime, dict[Any, Any]]

# Import johnnycanencrypt - the library is fully typed
try:
    from johnnycanencrypt import Cipher
    from johnnycanencrypt.johnnycanencrypt import (
        Johnny,
        create_key as jce_create_key,
        parse_cert_bytes as jce_parse_cert_bytes,
    )
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    # Define stub types for when library is not available
    Cipher = None  # type: ignore[assignment, misc]
    Johnny = None  # type: ignore[assignment, misc]
    jce_create_key: Optional[Callable[..., tuple[str, str, str]]] = None
    jce_parse_cert_bytes: Optional[Callable[..., Any]] = None

from .card_data import KeySlot, AlgorithmAttributes, AlgorithmID, CurveOID


logger = logging.getLogger(__name__)


class KeyType(IntEnum):
    """Key types for OpenPGP card."""
    SIGNATURE = 0xB6
    DECRYPTION = 0xB8
    AUTHENTICATION = 0xA4


@dataclass
class GeneratedKey:
    """Result of key generation."""
    public_key_data: bytes  # Public key in OpenPGP card format
    private_key_data: bytes  # Private key data for storage
    fingerprint: bytes      # 20-byte SHA-1 fingerprint
    generation_time: int    # Unix timestamp


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
    Cryptographic backend using johnnycanencrypt.
    
    Handles all cryptographic operations for the virtual OpenPGP card.
    Uses Johnny class for signing/decryption and create_key for key generation.
    """
    
    # Default password for key operations (card PIN protects access)
    DEFAULT_PASSWORD = "virtual-openpgp-card"
    
    def __init__(self):
        """Initialize the crypto backend."""
        if not CRYPTO_AVAILABLE:
            logger.warning("johnnycanencrypt not available - crypto operations will fail")
        # Store secret key PEM strings for each key type
        self._secret_keys: dict[KeyType, Optional[str]] = {
            KeyType.SIGNATURE: None,
            KeyType.DECRYPTION: None,
            KeyType.AUTHENTICATION: None,
        }
        # Store public key PEM strings
        self._public_keys: dict[KeyType, Optional[str]] = {
            KeyType.SIGNATURE: None,
            KeyType.DECRYPTION: None,
            KeyType.AUTHENTICATION: None,
        }
    
    @staticmethod
    def is_available() -> bool:
        """Check if crypto backend is available."""
        return CRYPTO_AVAILABLE
    
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
        if not CRYPTO_AVAILABLE or Cipher is None:
            logger.error("johnnycanencrypt not available")
            return None
        
        try:
            logger.info(f"Generating RSA-{bits} key for {key_type.name}")
            
            timestamp = int(time.time())
            
            # Select cipher based on key size
            if bits >= 4096:
                cipher_type = Cipher.RSA4k
            else:
                cipher_type = Cipher.RSA2k
            
            # Always generate all subkeys for a complete OpenPGP key
            # The card will use the appropriate subkey for each operation
            # whichkeys: 1=signing, 2=encryption, 4=authentication, 7=all
            whichkeys = 7
            
            # Generate key using johnnycanencrypt
            # Returns: tuple[str, str, str] = (public_key_armor, secret_key_armor, fingerprint)
            if jce_create_key is None:
                logger.error("create_key function not available")
                return None
            
            pub_key_pem, sec_key_pem, fingerprint_hex = jce_create_key(
                self.DEFAULT_PASSWORD,      # password: str
                ["virtual-card@openpgp.local"],  # userids: list[str]
                cipher_type.value,          # cipher: str
                timestamp,                  # creation: int (unix timestamp)
                0,                          # expiration: int (0 = no expiration)
                True,                       # subkeys_expiration: bool
                whichkeys,                  # whichkeys: int
                True,                       # can_primary_sign: bool
                False                       # can_primary_expire: bool
            )
            
            # Get public key bytes for OpenPGP card format
            pub_data = self._encode_rsa_public_key_from_pem(pub_key_pem)
            
            # Store keys
            self._secret_keys[key_type] = sec_key_pem
            self._public_keys[key_type] = pub_key_pem
            
            # Convert fingerprint from hex string to bytes
            fingerprint_bytes = bytes.fromhex(fingerprint_hex)
            
            logger.info(f"Generated RSA key with fingerprint {fingerprint_hex}")
            
            return GeneratedKey(
                public_key_data=pub_data,
                private_key_data=sec_key_pem.encode('utf-8'),
                fingerprint=fingerprint_bytes,
                generation_time=timestamp
            )
            
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
        if not CRYPTO_AVAILABLE or Cipher is None:
            logger.error("johnnycanencrypt not available")
            return None
        
        try:
            logger.info(f"Generating Curve25519 key for {key_type.name}")
            
            timestamp = int(time.time())
            
            # Cv25519 cipher creates Ed25519 for signing and X25519 for encryption
            cipher_type = Cipher.Cv25519
            
            # Always generate all subkeys for a complete OpenPGP key
            # The card will use the appropriate subkey for each operation
            # whichkeys: 1=signing, 2=encryption, 4=authentication, 7=all
            whichkeys = 7
            
            # Generate key using johnnycanencrypt
            # Returns: tuple[str, str, str] = (public_key_armor, secret_key_armor, fingerprint)
            if jce_create_key is None:
                logger.error("create_key function not available")
                return None
            
            pub_key_pem, sec_key_pem, fingerprint_hex = jce_create_key(
                self.DEFAULT_PASSWORD,      # password: str
                ["virtual-card@openpgp.local"],  # userids: list[str]
                cipher_type.value,          # cipher: str
                timestamp,                  # creation: int
                0,                          # expiration: int (no expiration)
                True,                       # subkeys_expiration: bool
                whichkeys,                  # whichkeys: int
                True,                       # can_primary_sign: bool
                False                       # can_primary_expire: bool
            )
            
            # Get public key bytes for OpenPGP card format
            pub_data = self._encode_ecc_public_key_from_pem(pub_key_pem, key_type)
            
            # Store keys
            self._secret_keys[key_type] = sec_key_pem
            self._public_keys[key_type] = pub_key_pem
            
            # Convert fingerprint from hex string to bytes
            fingerprint_bytes = bytes.fromhex(fingerprint_hex)
            
            logger.info(f"Generated Curve25519 key with fingerprint {fingerprint_hex}")
            
            return GeneratedKey(
                public_key_data=pub_data,
                private_key_data=sec_key_pem.encode('utf-8'),
                fingerprint=fingerprint_bytes,
                generation_time=timestamp
            )
            
        except Exception as e:
            logger.exception(f"Failed to generate Curve25519 key: {e}")
            return None
    
    def load_key(
        self,
        key_type: KeyType,
        private_key_data: bytes,
        algorithm: AlgorithmAttributes
    ) -> bool:
        """
        Load a key from stored private key data (PEM format).
        
        Args:
            key_type: The key slot type
            private_key_data: The stored private key bytes (PEM encoded)
            algorithm: Algorithm attributes for the key
            
        Returns:
            True if key was loaded successfully
        """
        if not CRYPTO_AVAILABLE:
            return False
        
        if not private_key_data:
            return False
        
        try:
            # Decode PEM data and store it
            sec_key_pem = private_key_data.decode('utf-8')
            self._secret_keys[key_type] = sec_key_pem
            
            # Also extract and store public key (for verification)
            if jce_parse_cert_bytes is not None:
                _ = jce_parse_cert_bytes(private_key_data)
            logger.info(f"Loaded key for {key_type.name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to load key: {e}")
            return False
    
    def sign(
        self,
        data: bytes,
        key_type: KeyType = KeyType.SIGNATURE
    ) -> SignatureResult:
        """
        Sign data using the specified key.
        
        Args:
            data: The data to sign (typically a hash/digest)
            key_type: The key slot to use
            
        Returns:
            SignatureResult with signature bytes or error
        """
        if not CRYPTO_AVAILABLE or Johnny is None:
            return SignatureResult(b'', False, "Crypto backend not available")
        
        sec_key_pem = self._secret_keys.get(key_type)
        if sec_key_pem is None:
            return SignatureResult(b'', False, "Key not loaded")
        
        try:
            # Create Johnny instance with secret key
            j = Johnny(sec_key_pem.encode('utf-8'))
            
            # Sign the data using detached signature
            # sign_bytes_detached returns PGP armored signature (string)
            signature_pem: str = j.sign_bytes_detached(data, self.DEFAULT_PASSWORD)
            
            # Return the signature (as bytes for card compatibility)
            # The raw signature bytes are embedded in the PGP armor
            # For now, return the armored format - caller can parse if needed
            signature_bytes = signature_pem.encode('utf-8')
            
            logger.debug(f"Signed {len(data)} bytes of data")
            return SignatureResult(signature_bytes, True)
            
        except Exception as e:
            logger.exception(f"Signing failed: {e}")
            return SignatureResult(b'', False, str(e))
    
    def decrypt(
        self,
        ciphertext: bytes,
        key_type: KeyType = KeyType.DECRYPTION
    ) -> DecryptionResult:
        """
        Decrypt data using the decryption key.
        
        Args:
            ciphertext: The encrypted data (OpenPGP encrypted bytes)
            key_type: The key slot to use (usually DECRYPTION)
            
        Returns:
            DecryptionResult with plaintext or error
        """
        if not CRYPTO_AVAILABLE or Johnny is None:
            return DecryptionResult(b'', False, "Crypto backend not available")
        
        sec_key_pem = self._secret_keys.get(key_type)
        if sec_key_pem is None:
            return DecryptionResult(b'', False, "Key not loaded")
        
        try:
            # Create Johnny instance with secret key
            j = Johnny(sec_key_pem.encode('utf-8'))
            
            # Decrypt the data
            # decrypt_bytes expects PGP encrypted data and returns plaintext bytes
            plaintext: bytes = j.decrypt_bytes(ciphertext, self.DEFAULT_PASSWORD)
            
            logger.debug(f"Decrypted {len(ciphertext)} bytes")
            return DecryptionResult(plaintext, True)
            
        except Exception as e:
            logger.exception(f"Decryption failed: {e}")
            return DecryptionResult(b'', False, str(e))
    
    def authenticate(
        self,
        challenge: bytes
    ) -> SignatureResult:
        """
        Perform internal authentication (sign a challenge).
        
        Args:
            challenge: The challenge data to sign
            
        Returns:
            SignatureResult with signature bytes
        """
        return self.sign(challenge, KeyType.AUTHENTICATION)
    
    def _encode_rsa_public_key_from_pem(self, pub_key_pem: str) -> bytes:
        """
        Extract RSA public key data from PEM and encode in OpenPGP card format.
        
        Format: Tag 7F49 containing:
        - 81: Modulus (n)
        - 82: Public exponent (e)
        
        For now, returns the raw PEM as placeholder - proper implementation
        would parse the PGP public key packet.
        """
        # The PGP public key PEM contains the full certificate
        # For card response, we need to extract the raw key material
        # This is a simplified implementation
        from .tlv import TLVEncoder
        
        # Return the PEM as-is encoded - the card layer can handle it
        # A full implementation would parse the OpenPGP packet to extract n and e
        return pub_key_pem.encode('utf-8')
    
    def _encode_ecc_public_key_from_pem(self, pub_key_pem: str, key_type: KeyType) -> bytes:
        """
        Extract ECC public key data from PEM and encode in OpenPGP card format.
        
        Format: Tag 7F49 containing:
        - 86: Public key point (for ECDSA/EdDSA)
        """
        from .tlv import TLVEncoder
        
        # Return the PEM as-is encoded - the card layer can handle it
        # A full implementation would parse the OpenPGP packet to extract the point
        return pub_key_pem.encode('utf-8')
    
    def _calculate_fingerprint(self, public_key_data: bytes, timestamp: int) -> bytes:
        """
        Calculate OpenPGP v4 key fingerprint.
        
        The fingerprint is SHA-1 hash of:
        - 0x99 (public key packet tag)
        - 2-byte packet length
        - Packet content (version, timestamp, algorithm, key material)
        """
        # For simplicity, we'll hash the public key data with timestamp
        # A proper implementation would construct a full public key packet
        
        # Version 4 fingerprint
        data = bytes([
            0x99,  # Old format packet tag for public key
        ])
        
        # Packet content
        packet = bytes([
            0x04,  # Version 4
            (timestamp >> 24) & 0xFF,
            (timestamp >> 16) & 0xFF,
            (timestamp >> 8) & 0xFF,
            timestamp & 0xFF,
        ]) + public_key_data
        
        # Add length
        pkt_len = len(packet)
        data += bytes([(pkt_len >> 8) & 0xFF, pkt_len & 0xFF])
        data += packet
        
        return hashlib.sha1(data).digest()
    
    def get_public_key(self, key_type: KeyType) -> Optional[bytes]:
        """
        Get the public key data for a key slot.
        
        Args:
            key_type: The key slot
            
        Returns:
            Public key bytes (PEM encoded), or None
        """
        pub_key_pem = self._public_keys.get(key_type)
        if pub_key_pem is None:
            return None
        
        return pub_key_pem.encode('utf-8')
    
    def has_key(self, key_type: KeyType) -> bool:
        """Check if a key is loaded for the given slot."""
        return self._secret_keys.get(key_type) is not None


class SimpleCryptoBackend:
    """
    Simplified crypto backend that doesn't require johnnycanencrypt.
    
    Uses Python's built-in cryptography for basic operations.
    This is a fallback when johnnycanencrypt is not available.
    """
    
    def __init__(self):
        """Initialize simple crypto backend."""
        self._keys: dict[KeyType, bytes] = {}
        logger.info("Using SimpleCryptoBackend (limited functionality)")
    
    @staticmethod
    def is_available() -> bool:
        """Always available as fallback."""
        return True
    
    def generate_rsa_key(
        self,
        key_type: KeyType,
        bits: int = 2048
    ) -> Optional[GeneratedKey]:
        """Generate a placeholder RSA key."""
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore[import-not-found]
            from cryptography.hazmat.primitives import serialization  # type: ignore[import-not-found]
            from cryptography.hazmat.backends import default_backend  # type: ignore[import-not-found]
            
            timestamp = int(time.time())
            
            # Generate RSA key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=bits,
                backend=default_backend()
            )
            
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()
            
            # Encode public key
            n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')
            e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')
            
            from .tlv import TLVEncoder
            content = TLVEncoder.encode(0x81, n_bytes) + TLVEncoder.encode(0x82, e_bytes)
            pub_data = TLVEncoder.encode(0x7F49, content)
            
            # Serialize private key
            priv_data = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Calculate fingerprint
            fingerprint = self._calculate_fingerprint(pub_data, timestamp)
            
            # Store key
            self._keys[key_type] = priv_data
            
            return GeneratedKey(
                public_key_data=pub_data,
                private_key_data=priv_data,
                fingerprint=fingerprint,
                generation_time=timestamp
            )
            
        except ImportError:
            logger.error("cryptography library not available")
            return None
        except Exception as e:
            logger.exception(f"Failed to generate RSA key: {e}")
            return None
    
    def generate_curve25519_key(self, key_type: KeyType) -> Optional[GeneratedKey]:
        """Generate a placeholder Curve25519 key."""
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519, x25519  # type: ignore[import-not-found]
            from cryptography.hazmat.primitives import serialization  # type: ignore[import-not-found]
            
            timestamp = int(time.time())
            
            if key_type in (KeyType.SIGNATURE, KeyType.AUTHENTICATION):
                private_key = ed25519.Ed25519PrivateKey.generate()
                pub_bytes = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            else:
                private_key = x25519.X25519PrivateKey.generate()
                pub_bytes = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            
            from .tlv import TLVEncoder
            pub_data = TLVEncoder.encode(0x7F49, TLVEncoder.encode(0x86, pub_bytes))
            
            priv_data = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            fingerprint = self._calculate_fingerprint(pub_data, timestamp)
            self._keys[key_type] = priv_data
            
            return GeneratedKey(
                public_key_data=pub_data,
                private_key_data=priv_data,
                fingerprint=fingerprint,
                generation_time=timestamp
            )
            
        except ImportError:
            logger.error("cryptography library not available")
            return None
        except Exception as e:
            logger.exception(f"Failed to generate Curve25519 key: {e}")
            return None
    
    def load_key(self, key_type: KeyType, private_key_data: bytes, algorithm: AlgorithmAttributes) -> bool:
        """Load a key from stored data."""
        if private_key_data:
            self._keys[key_type] = private_key_data
            return True
        return False
    
    def sign(self, data: bytes, key_type: KeyType = KeyType.SIGNATURE) -> SignatureResult:
        """Sign data."""
        priv_data = self._keys.get(key_type)
        if not priv_data:
            return SignatureResult(b'', False, "Key not loaded")
        
        try:
            from cryptography.hazmat.primitives import hashes  # type: ignore[import-not-found]
            from cryptography.hazmat.primitives.asymmetric import padding, rsa, ed25519  # type: ignore[import-not-found]
            from cryptography.hazmat.primitives.serialization import load_der_private_key  # type: ignore[import-not-found]
            from cryptography.hazmat.backends import default_backend  # type: ignore[import-not-found]
            
            # Try loading as RSA key
            try:
                private_key = load_der_private_key(priv_data, password=None, backend=default_backend())
                if isinstance(private_key, rsa.RSAPrivateKey):
                    signature = private_key.sign(
                        data,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                    return SignatureResult(signature, True)
            except Exception:
                pass
            
            # Try loading as Ed25519 key
            try:
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_data)
                signature = private_key.sign(data)
                return SignatureResult(signature, True)
            except Exception:
                pass
            
            return SignatureResult(b'', False, "Unsupported key type")
            
        except Exception as e:
            return SignatureResult(b'', False, str(e))
    
    def decrypt(self, ciphertext: bytes, key_type: KeyType = KeyType.DECRYPTION) -> DecryptionResult:
        """Decrypt data."""
        priv_data = self._keys.get(key_type)
        if not priv_data:
            return DecryptionResult(b'', False, "Key not loaded")
        
        try:
            from cryptography.hazmat.primitives.asymmetric import padding  # type: ignore[import-not-found]
            from cryptography.hazmat.primitives.serialization import load_der_private_key  # type: ignore[import-not-found]
            from cryptography.hazmat.backends import default_backend  # type: ignore[import-not-found]
            
            private_key = load_der_private_key(priv_data, password=None, backend=default_backend())
            plaintext = private_key.decrypt(
                ciphertext,
                padding.PKCS1v15()
            )
            return DecryptionResult(plaintext, True)
            
        except Exception as e:
            return DecryptionResult(b'', False, str(e))
    
    def authenticate(self, challenge: bytes) -> SignatureResult:
        """Authenticate by signing challenge."""
        return self.sign(challenge, KeyType.AUTHENTICATION)
    
    def _calculate_fingerprint(self, public_key_data: bytes, timestamp: int) -> bytes:
        """Calculate key fingerprint."""
        data = bytes([0x99])
        packet = bytes([
            0x04,
            (timestamp >> 24) & 0xFF,
            (timestamp >> 16) & 0xFF,
            (timestamp >> 8) & 0xFF,
            timestamp & 0xFF,
        ]) + public_key_data
        pkt_len = len(packet)
        data += bytes([(pkt_len >> 8) & 0xFF, pkt_len & 0xFF])
        data += packet
        return hashlib.sha1(data).digest()
    
    def get_public_key(self, key_type: KeyType) -> Optional[bytes]:
        """Get public key data."""
        # Would need to re-derive from private key
        return None
    
    def has_key(self, key_type: KeyType) -> bool:
        """Check if key is loaded."""
        return key_type in self._keys


def get_crypto_backend() -> Union[CryptoBackend, SimpleCryptoBackend]:
    """
    Get the best available crypto backend.
    
    Returns CryptoBackend if johnnycanencrypt is available,
    otherwise returns SimpleCryptoBackend.
    """
    if CRYPTO_AVAILABLE:
        return CryptoBackend()
    else:
        return SimpleCryptoBackend()

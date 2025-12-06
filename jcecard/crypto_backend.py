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
        # Store raw key material (32 bytes for Ed25519/X25519 from key import)
        self._raw_private_keys: dict[KeyType, Optional[bytes]] = {
            KeyType.SIGNATURE: None,
            KeyType.DECRYPTION: None,
            KeyType.AUTHENTICATION: None,
        }
        # Store DER-encoded keys (for RSA imported keys)
        self._keys: dict[KeyType, bytes] = {}
        # Store algorithm info for raw keys
        self._algorithm_info: dict[KeyType, Optional[AlgorithmAttributes]] = {
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
            ciphertext: The encrypted data (for RSA, this is PKCS#1 v1.5 padded ciphertext)
            key_type: The key slot to use (usually DECRYPTION)
            
        Returns:
            DecryptionResult with plaintext or error
        """
        # Check for RSA key first (stored in self._keys as DER)
        rsa_key = self._keys.get(key_type)
        if rsa_key is not None:
            return self._decrypt_rsa(ciphertext, rsa_key)
        
        # Fall back to Johnny-based decryption for PEM keys
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
    
    def _decrypt_rsa(self, ciphertext: bytes, der_key: bytes) -> DecryptionResult:
        """
        Decrypt using RSA key (PKCS#1 v1.5 padding).
        
        Args:
            ciphertext: The ciphertext to decrypt
            der_key: The DER-encoded private key
            
        Returns:
            DecryptionResult with plaintext
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives.serialization import load_der_private_key
            from cryptography.hazmat.backends import default_backend
            
            # Load the private key from DER
            private_key = load_der_private_key(der_key, password=None, backend=default_backend())
            
            # Decrypt with PKCS#1 v1.5 padding
            plaintext = private_key.decrypt(
                ciphertext,
                padding.PKCS1v15()
            )
            
            logger.debug(f"RSA decrypted {len(ciphertext)} bytes -> {len(plaintext)} bytes")
            return DecryptionResult(plaintext, True)
            
        except Exception as e:
            logger.exception(f"RSA decryption failed: {e}")
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
        return (self._secret_keys.get(key_type) is not None or 
                self._raw_private_keys.get(key_type) is not None or
                self._keys.get(key_type) is not None)
    
    def has_raw_key(self, key_type: KeyType) -> bool:
        """Check if a raw key is loaded for the given slot (Ed25519/X25519 or RSA)."""
        # Check for Ed25519/X25519 raw keys
        if self._raw_private_keys.get(key_type) is not None:
            return True
        # Also check for RSA keys stored in _keys (as DER format)
        if self._keys.get(key_type) is not None:
            return True
        return False
    
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
        # We need to reverse the byte order for X25519 keys.
        if algorithm.algorithm_id == AlgorithmID.ECDH_X25519 and len(raw_key) == 32:
            raw_key = bytes(reversed(raw_key))
            logger.debug(f"Reversed byte order for X25519 key")
        
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
        
        The RSA key data from OpenPGP imports contains:
        - Public exponent (e) - typically 3 bytes (010001 = 65537)
        - CRT components: p, q concatenated
        
        The format is: e (3 bytes) || p (key_size/16 bytes) || q (key_size/16 bytes)
        For RSA-4096: e (3 bytes) + p (256 bytes) + q (256 bytes) = 515 bytes
        For RSA-2048: e (3 bytes) + p (128 bytes) + q (128 bytes) = 259 bytes
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.rsa import (
                rsa_crt_iqmp, rsa_crt_dmp1, rsa_crt_dmq1,
                RSAPrivateNumbers, RSAPublicNumbers
            )
            from cryptography.hazmat.backends import default_backend
            
            # Determine key size from algorithm attributes
            key_bits = algorithm.param1  # e.g., 4096 or 2048
            component_size = key_bits // 16  # p and q are half the key size in bytes
            
            # Parse the key data
            # Format: e || p || q
            e_size = 3  # Public exponent is typically 3 bytes (65537 = 010001)
            
            if len(raw_key) < e_size + 2 * component_size:
                logger.warning(f"RSA key data too short: {len(raw_key)} bytes, expected at least {e_size + 2 * component_size}")
                return False
            
            e = int.from_bytes(raw_key[:e_size], 'big')
            p = int.from_bytes(raw_key[e_size:e_size + component_size], 'big')
            q = int.from_bytes(raw_key[e_size + component_size:e_size + 2 * component_size], 'big')
            
            # Calculate derived values
            n = p * q
            d = pow(e, -1, (p - 1) * (q - 1))  # Private exponent
            dp = rsa_crt_dmp1(d, p)
            dq = rsa_crt_dmq1(d, q)
            qinv = rsa_crt_iqmp(p, q)
            
            # Create RSA private key
            public_numbers = RSAPublicNumbers(e, n)
            private_numbers = RSAPrivateNumbers(p, q, d, dp, dq, qinv, public_numbers)
            private_key = private_numbers.private_key(default_backend())
            
            # Store as DER-encoded private key for later use
            from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
            der_key = private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
            
            # Store in the keys dict for RSA operations
            self._keys[key_type] = der_key
            self._algorithm_info[key_type] = algorithm
            
            logger.info(f"Loaded RSA-{key_bits} key for {key_type.name}, {len(raw_key)} bytes -> DER {len(der_key)} bytes")
            return True
            
        except Exception as e:
            logger.exception(f"Failed to load RSA key: {e}")
            return False
    
    def sign_raw(
        self,
        data: bytes,
        key_type: KeyType = KeyType.SIGNATURE
    ) -> SignatureResult:
        """
        Sign using raw key (Ed25519 or RSA).
        
        Args:
            data: The data to sign (for RSA, this should be DigestInfo)
            key_type: The key slot to use
            
        Returns:
            SignatureResult with signature bytes
        """
        # Check for RSA key first (stored in self._keys as DER)
        rsa_key = self._keys.get(key_type)
        if rsa_key is not None:
            return self._sign_rsa(data, rsa_key)
        
        # Then check for Ed25519 raw key
        raw_key = self._raw_private_keys.get(key_type)
        if raw_key is None:
            return SignatureResult(b'', False, "No raw key loaded")
        
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            
            # Create Ed25519 private key from raw 32 bytes
            private_key = Ed25519PrivateKey.from_private_bytes(raw_key)
            signature = private_key.sign(data)
            
            logger.debug(f"Raw Ed25519 signature: {len(signature)} bytes")
            return SignatureResult(signature, True)
            
        except Exception as e:
            logger.exception(f"Raw signing failed: {e}")
            return SignatureResult(b'', False, str(e))
    
    def _sign_rsa(self, data: bytes, der_key: bytes) -> SignatureResult:
        """
        Sign using RSA key (PKCS#1 v1.5 padding).
        
        For OpenPGP cards, we receive DigestInfo and apply raw PKCS#1 v1.5 padding,
        then perform raw RSA decryption (signing = decryption with private key).
        
        Args:
            data: The DigestInfo to sign (algorithm OID + hash value)
            der_key: DER-encoded RSA private key
            
        Returns:
            SignatureResult with signature bytes
        """
        try:
            from cryptography.hazmat.primitives.serialization import load_der_private_key
            from cryptography.hazmat.backends import default_backend
            
            private_key = load_der_private_key(der_key, password=None, backend=default_backend())
            
            # Get key size in bytes
            key_size = private_key.key_size // 8  # type: ignore[union-attr]
            
            # Build PKCS#1 v1.5 padding manually:
            # 0x00 || 0x01 || padding_bytes(0xFF) || 0x00 || DigestInfo
            # Padding length = key_size - 3 - len(data)
            
            padding_length = key_size - 3 - len(data)
            if padding_length < 8:
                return SignatureResult(b'', False, f"DigestInfo too long for key size: {len(data)} + 3 > {key_size}")
            
            # Build the padded message
            padded = b'\x00\x01' + (b'\xff' * padding_length) + b'\x00' + data
            
            # Convert to integer and do raw RSA decryption (signing)
            padded_int = int.from_bytes(padded, 'big')
            
            # Get the RSA private numbers for raw operation
            private_numbers = private_key.private_numbers()  # type: ignore[union-attr]
            
            # RSA signature: m^d mod n
            signature_int = pow(padded_int, private_numbers.d, private_numbers.public_numbers.n)
            
            # Convert back to bytes
            signature = signature_int.to_bytes(key_size, 'big')
            
            logger.debug(f"RSA signature: {len(signature)} bytes (key_size={key_size}, digest_info={len(data)} bytes)")
            return SignatureResult(signature, True)
            
        except Exception as e:
            logger.exception(f"RSA signing failed: {e}")
            return SignatureResult(b'', False, str(e))
            return SignatureResult(b'', False, str(e))
    
    def decrypt_ecdh(
        self,
        ephemeral_public: bytes,
        key_type: KeyType = KeyType.DECRYPTION
    ) -> DecryptionResult:
        """
        Perform X25519 ECDH to derive shared secret.
        
        Args:
            ephemeral_public: The ephemeral public key from the encrypted message (32 bytes)
            key_type: The key slot to use
            
        Returns:
            DecryptionResult with 32-byte shared secret
        """
        raw_key = self._raw_private_keys.get(key_type)
        if raw_key is None:
            return DecryptionResult(b'', False, "No raw key loaded")
        
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
            
            # Create X25519 private key from raw 32 bytes
            private_key = X25519PrivateKey.from_private_bytes(raw_key)
            
            # Create peer's public key
            peer_public = X25519PublicKey.from_public_bytes(ephemeral_public)
            
            # Perform ECDH key exchange
            shared_secret = private_key.exchange(peer_public)
            
            logger.debug(f"ECDH shared secret: {len(shared_secret)} bytes")
            return DecryptionResult(shared_secret, True)
            
        except Exception as e:
            logger.exception(f"ECDH decryption failed: {e}")
            return DecryptionResult(b'', False, str(e))


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
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey  # type: ignore[import-not-found]
            from cryptography.hazmat.primitives.serialization import load_der_private_key  # type: ignore[import-not-found]
            from cryptography.hazmat.backends import default_backend  # type: ignore[import-not-found]
            
            private_key = load_der_private_key(priv_data, password=None, backend=default_backend())
            if not isinstance(private_key, RSAPrivateKey):
                return DecryptionResult(b'', False, "Key is not an RSA private key")
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
    
    def has_raw_key(self, key_type: KeyType) -> bool:
        """Check if a raw key is loaded."""
        return key_type in self._keys
    
    def load_raw_key(
        self,
        key_type: KeyType,
        raw_key: bytes,
        algorithm: AlgorithmAttributes
    ) -> bool:
        """Load raw key material."""
        if raw_key:
            self._keys[key_type] = raw_key
            return True
        return False
    
    def sign_raw(
        self,
        data: bytes,
        key_type: KeyType = KeyType.SIGNATURE
    ) -> SignatureResult:
        """Sign using raw Ed25519 key."""
        return self.sign(data, key_type)
    
    def decrypt_ecdh(
        self,
        ephemeral_public: bytes,
        key_type: KeyType = KeyType.DECRYPTION
    ) -> DecryptionResult:
        """Perform X25519 ECDH."""
        raw_key = self._keys.get(key_type)
        if not raw_key:
            return DecryptionResult(b'', False, "Key not loaded")
        
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
            
            private_key = X25519PrivateKey.from_private_bytes(raw_key)
            peer_public = X25519PublicKey.from_public_bytes(ephemeral_public)
            shared_secret = private_key.exchange(peer_public)
            return DecryptionResult(shared_secret, True)
            
        except Exception as e:
            return DecryptionResult(b'', False, str(e))


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

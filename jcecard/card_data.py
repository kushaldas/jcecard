"""
Card Data Storage Module

Manages persistent storage of OpenPGP card state including:
- Card identification (AID, serial number)
- PIN data and retry counters
- Key metadata (fingerprints, timestamps, algorithm attributes)
- Cardholder data (name, language, sex, URL, login)
- Private use data objects
- Digital signature counter

Storage is JSON-based for easy inspection and debugging.
"""

import json
import os
import hashlib
import logging
import base64
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from pathlib import Path


logger = logging.getLogger(__name__)


# Algorithm IDs for OpenPGP card
class AlgorithmID:
    """Algorithm identifiers for OpenPGP card."""
    # RSA
    RSA_2048 = 0x01
    RSA_3072 = 0x01
    RSA_4096 = 0x01
    
    # ECDSA/ECDH
    ECDSA_P256 = 0x13
    ECDSA_P384 = 0x13
    ECDSA_P521 = 0x13
    
    # EdDSA/ECDH with Curve25519
    EDDSA = 0x16
    ECDH_X25519 = 0x12


# OIDs for curves
class CurveOID:
    """Object Identifiers for elliptic curves."""
    # NIST curves
    NIST_P256 = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
    NIST_P384 = bytes([0x2B, 0x81, 0x04, 0x00, 0x22])
    NIST_P521 = bytes([0x2B, 0x81, 0x04, 0x00, 0x23])
    
    # Curve25519
    ED25519 = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01])
    X25519 = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01])


@dataclass
class AlgorithmAttributes:
    """Algorithm attributes for a key slot."""
    algorithm_id: int = AlgorithmID.RSA_2048
    # For RSA: modulus length in bits
    # For ECC: curve OID
    param1: int = 2048  # RSA modulus bits or 0 for ECC
    param2: int = 32    # RSA public exponent bits or 0 for ECC
    param3: int = 0     # Import format (0=standard, 1=with modulus, etc.)
    curve_oid: bytes = b''  # For ECC algorithms
    
    def to_bytes(self) -> bytes:
        """Encode to OpenPGP card format."""
        if self.algorithm_id == AlgorithmID.RSA_2048:
            # RSA: 01 || modulus_bits (2 bytes) || exponent_bits (2 bytes) || format
            return bytes([
                self.algorithm_id,
                (self.param1 >> 8) & 0xFF,
                self.param1 & 0xFF,
                (self.param2 >> 8) & 0xFF,
                self.param2 & 0xFF,
                self.param3
            ])
        else:
            # ECC: algorithm_id || OID
            return bytes([self.algorithm_id]) + self.curve_oid
    
    @classmethod
    def rsa(cls, bits: int = 2048, exponent_bits: int = 32) -> 'AlgorithmAttributes':
        """Create RSA algorithm attributes."""
        return cls(
            algorithm_id=AlgorithmID.RSA_2048,
            param1=bits,
            param2=exponent_bits,
            param3=0
        )
    
    @classmethod
    def ed25519(cls) -> 'AlgorithmAttributes':
        """Create Ed25519 algorithm attributes."""
        return cls(
            algorithm_id=AlgorithmID.EDDSA,
            curve_oid=CurveOID.ED25519
        )
    
    @classmethod
    def x25519(cls) -> 'AlgorithmAttributes':
        """Create X25519 algorithm attributes."""
        return cls(
            algorithm_id=AlgorithmID.ECDH_X25519,
            curve_oid=CurveOID.X25519
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'algorithm_id': self.algorithm_id,
            'param1': self.param1,
            'param2': self.param2,
            'param3': self.param3,
            'curve_oid': base64.b64encode(self.curve_oid).decode('ascii') if self.curve_oid else ''
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AlgorithmAttributes':
        """Create from dictionary."""
        curve_oid = data.get('curve_oid', '')
        return cls(
            algorithm_id=data.get('algorithm_id', AlgorithmID.RSA_2048),
            param1=data.get('param1', 2048),
            param2=data.get('param2', 32),
            param3=data.get('param3', 0),
            curve_oid=base64.b64decode(curve_oid) if curve_oid else b''
        )


@dataclass
class KeySlot:
    """Data for a single key slot (SIG, DEC, or AUT)."""
    # Key fingerprint (20 bytes for v4, 32 for v5)
    fingerprint: bytes = b'\x00' * 20
    
    # Key generation/import timestamp (Unix time)
    generation_time: int = 0
    
    # CA fingerprint for this slot
    ca_fingerprint: bytes = b'\x00' * 20
    
    # Algorithm attributes
    algorithm: AlgorithmAttributes = field(default_factory=AlgorithmAttributes.rsa)
    
    # UIF (User Interaction Flag): 0=disabled, 1=enabled, 2=permanent
    uif: int = 0
    
    # Private key data (encrypted or raw, depending on implementation)
    # In real implementation, this would be stored securely
    private_key_data: bytes = b''
    
    # Public key data (for key generation response)
    public_key_data: bytes = b''
    
    def has_key(self) -> bool:
        """Check if this slot has a key."""
        return self.fingerprint != b'\x00' * 20 and self.fingerprint != b'\x00' * 32
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'fingerprint': base64.b64encode(self.fingerprint).decode('ascii'),
            'generation_time': self.generation_time,
            'ca_fingerprint': base64.b64encode(self.ca_fingerprint).decode('ascii'),
            'algorithm': self.algorithm.to_dict(),
            'uif': self.uif,
            'private_key_data': base64.b64encode(self.private_key_data).decode('ascii') if self.private_key_data else '',
            'public_key_data': base64.b64encode(self.public_key_data).decode('ascii') if self.public_key_data else ''
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeySlot':
        """Create from dictionary."""
        fingerprint = data.get('fingerprint', '')
        ca_fingerprint = data.get('ca_fingerprint', '')
        private_key_data = data.get('private_key_data', '')
        public_key_data = data.get('public_key_data', '')
        return cls(
            fingerprint=base64.b64decode(fingerprint) if fingerprint else b'\x00' * 20,
            generation_time=data.get('generation_time', 0),
            ca_fingerprint=base64.b64decode(ca_fingerprint) if ca_fingerprint else b'\x00' * 20,
            algorithm=AlgorithmAttributes.from_dict(data.get('algorithm', {})),
            uif=data.get('uif', 0),
            private_key_data=base64.b64decode(private_key_data) if private_key_data else b'',
            public_key_data=base64.b64decode(public_key_data) if public_key_data else b''
        )


@dataclass
class PINData:
    """PIN-related data."""
    # PW1 (User PIN) - default "123456"
    pw1_hash: bytes = b''
    pw1_length: int = 6  # Current PIN length
    pw1_min_length: int = 6
    pw1_max_length: int = 127
    pw1_retry_counter: int = 3
    pw1_max_retries: int = 3
    
    # PW1 mode 81 behavior: True = valid for multiple signatures
    pw1_valid_multiple: bool = True
    
    # PW3 (Admin PIN) - default "12345678"
    pw3_hash: bytes = b''
    pw3_length: int = 8
    pw3_min_length: int = 8
    pw3_max_length: int = 127
    pw3_retry_counter: int = 3
    pw3_max_retries: int = 3
    
    # Reset Code
    rc_hash: bytes = b''
    rc_length: int = 0  # 0 = not set
    rc_min_length: int = 8
    rc_max_length: int = 127
    rc_retry_counter: int = 0  # 0 = not set/blocked
    rc_max_retries: int = 3
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'pw1_hash': base64.b64encode(self.pw1_hash).decode('ascii') if self.pw1_hash else '',
            'pw1_length': self.pw1_length,
            'pw1_min_length': self.pw1_min_length,
            'pw1_max_length': self.pw1_max_length,
            'pw1_retry_counter': self.pw1_retry_counter,
            'pw1_max_retries': self.pw1_max_retries,
            'pw1_valid_multiple': self.pw1_valid_multiple,
            'pw3_hash': base64.b64encode(self.pw3_hash).decode('ascii') if self.pw3_hash else '',
            'pw3_length': self.pw3_length,
            'pw3_min_length': self.pw3_min_length,
            'pw3_max_length': self.pw3_max_length,
            'pw3_retry_counter': self.pw3_retry_counter,
            'pw3_max_retries': self.pw3_max_retries,
            'rc_hash': base64.b64encode(self.rc_hash).decode('ascii') if self.rc_hash else '',
            'rc_length': self.rc_length,
            'rc_min_length': self.rc_min_length,
            'rc_max_length': self.rc_max_length,
            'rc_retry_counter': self.rc_retry_counter,
            'rc_max_retries': self.rc_max_retries
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PINData':
        """Create from dictionary."""
        instance = cls()
        pw1_hash = data.get('pw1_hash', '')
        instance.pw1_hash = base64.b64decode(pw1_hash) if pw1_hash else b''
        instance.pw1_length = data.get('pw1_length', 6)
        instance.pw1_min_length = data.get('pw1_min_length', 6)
        instance.pw1_max_length = data.get('pw1_max_length', 127)
        instance.pw1_retry_counter = data.get('pw1_retry_counter', 3)
        instance.pw1_max_retries = data.get('pw1_max_retries', 3)
        instance.pw1_valid_multiple = data.get('pw1_valid_multiple', True)
        pw3_hash = data.get('pw3_hash', '')
        instance.pw3_hash = base64.b64decode(pw3_hash) if pw3_hash else b''
        instance.pw3_length = data.get('pw3_length', 8)
        instance.pw3_min_length = data.get('pw3_min_length', 8)
        instance.pw3_max_length = data.get('pw3_max_length', 127)
        instance.pw3_retry_counter = data.get('pw3_retry_counter', 3)
        instance.pw3_max_retries = data.get('pw3_max_retries', 3)
        rc_hash = data.get('rc_hash', '')
        instance.rc_hash = base64.b64decode(rc_hash) if rc_hash else b''
        instance.rc_length = data.get('rc_length', 0)
        instance.rc_min_length = data.get('rc_min_length', 8)
        instance.rc_max_length = data.get('rc_max_length', 127)
        instance.rc_retry_counter = data.get('rc_retry_counter', 0)
        instance.rc_max_retries = data.get('rc_max_retries', 3)
        return instance


@dataclass 
class CardholderData:
    """Cardholder-related data."""
    # Name (ISO 8859-1 encoded, surname<<given_name format)
    name: str = ""
    
    # Language preference (ISO 639-1, up to 4 languages)
    # Default to "en" since some clients (johnnycanencrypt) expect non-empty language
    language: str = "en"
    
    # Sex (ISO 5218: 0=unknown, 1=male, 2=female, 9=not applicable)
    sex: int = 0
    
    # Login data (UTF-8)
    login: str = ""
    
    # URL for public key retrieval
    url: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'language': self.language,
            'sex': self.sex,
            'login': self.login,
            'url': self.url
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CardholderData':
        """Create from dictionary."""
        return cls(
            name=data.get('name', ''),
            language=data.get('language', ''),
            sex=data.get('sex', 0),
            login=data.get('login', ''),
            url=data.get('url', '')
        )


@dataclass
class CardState:
    """Complete card state."""
    # Card identification
    manufacturer_id: int = 0x0000  # 2 bytes
    serial_number: int = 0x00000001  # 4 bytes
    
    # OpenPGP version
    version_major: int = 3
    version_minor: int = 4
    
    # PIN data
    pin_data: PINData = field(default_factory=PINData)
    
    # Cardholder data
    cardholder: CardholderData = field(default_factory=CardholderData)
    
    # Key slots
    key_sig: KeySlot = field(default_factory=KeySlot)  # Signature key
    key_dec: KeySlot = field(default_factory=KeySlot)  # Decryption key
    key_aut: KeySlot = field(default_factory=KeySlot)  # Authentication key
    
    # Digital signature counter
    signature_counter: int = 0
    
    # Private use data objects
    private_do_1: bytes = b''  # 0101
    private_do_2: bytes = b''  # 0102
    private_do_3: bytes = b''  # 0103 (requires PW1)
    private_do_4: bytes = b''  # 0104 (requires PW3)
    
    # Cardholder certificate
    certificate: bytes = b''
    
    # Card capabilities (Extended Capabilities DO)
    supports_sm: bool = False  # Secure Messaging
    supports_get_challenge: bool = True
    supports_key_import: bool = True
    supports_pw_status_change: bool = True
    supports_private_dos: bool = True
    supports_algo_attr_change: bool = True
    supports_aes: bool = False
    supports_kdf: bool = False
    
    # Maximum lengths
    max_challenge_length: int = 255
    max_cardholder_cert_length: int = 2048
    max_special_do_length: int = 255
    max_pin_block_2_format: bool = False
    max_mse_command: bool = False
    
    # Card lifecycle
    terminated: bool = False
    
    def get_aid(self) -> bytes:
        """
        Get the Application Identifier (AID).
        
        Format:
        - D2 76 00 01 24 01: RID + OpenPGP application
        - XX XX: Version (e.g., 03 04 for v3.4)
        - XX XX: Manufacturer ID
        - XX XX XX XX: Serial number
        - 00 00: RFU
        """
        return bytes([
            0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,  # RID + PIX
            self.version_major, self.version_minor,
            (self.manufacturer_id >> 8) & 0xFF,
            self.manufacturer_id & 0xFF,
            (self.serial_number >> 24) & 0xFF,
            (self.serial_number >> 16) & 0xFF,
            (self.serial_number >> 8) & 0xFF,
            self.serial_number & 0xFF,
            0x00, 0x00  # RFU
        ])
    
    def get_historical_bytes(self) -> bytes:
        """
        Get the historical bytes for ATR and 5F52 DO.
        
        Yubikey returns: 00 73 00 00 E0 05 90 00
        - 0x00: Category indicator
        - 0x73: Card service data (supports SELECT by full DF name)
        - 0x00: Card capabilities byte 1
        - 0x00: Card capabilities byte 2
        - 0xE0: Status indicator present + data following
        - 0x05: Life cycle status (operational, TERMINATE allowed)
        - 0x90 0x00: Status word (success)
        
        The life cycle status 0x05 indicates:
        - Card is in operational state
        - TERMINATE DF command is supported
        """
        # Match Yubikey format exactly
        lifecycle_status = 0x07 if self.terminated else 0x05
        
        return bytes([
            0x00,  # Category indicator
            0x73,  # Card service data
            0x00,  # Card capabilities byte 1
            0x00,  # Card capabilities byte 2
            0xE0,  # Status indicator (life cycle present + status)
            lifecycle_status,  # Life cycle: 0x05 = operational, 0x07 = terminated
            0x90, 0x00  # Status word
        ])
    
    def get_general_feature_management(self) -> bytes:
        """
        Get the General Feature Management DO (7F74).
        
        This DO indicates which optional features the card supports.
        GPG uses this to determine if factory-reset is available.
        
        Yubikey returns: 81 01 20
        - Tag 81 (Button/Feature byte)
        - Length 01
        - Value 0x20 (bit 5 set = TERMINATE DF command supported)
        
        The 0x20 value indicates:
        - Bit 5 (0x20): Card supports TERMINATE DF command (factory reset)
        """
        # Yubikey format: 81 01 20
        # Tag 81 = Button/feature byte, value 0x20 = TERMINATE DF supported
        return bytes([0x81, 0x01, 0x20])
    
    def get_extended_capabilities(self) -> bytes:
        """Get the Extended Capabilities DO (C0)."""
        flags = 0
        if self.supports_sm:
            flags |= 0x80
        if self.supports_get_challenge:
            flags |= 0x40
        if self.supports_key_import:
            flags |= 0x20
        if self.supports_pw_status_change:
            flags |= 0x10
        if self.supports_private_dos:
            flags |= 0x08
        if self.supports_algo_attr_change:
            flags |= 0x04
        if self.supports_aes:
            flags |= 0x02
        if self.supports_kdf:
            flags |= 0x01
        
        return bytes([
            flags,
            0x00,  # SM algorithm (0 = none)
            (self.max_challenge_length >> 8) & 0xFF,
            self.max_challenge_length & 0xFF,
            (self.max_cardholder_cert_length >> 8) & 0xFF,
            self.max_cardholder_cert_length & 0xFF,
            (self.max_special_do_length >> 8) & 0xFF,
            self.max_special_do_length & 0xFF,
            0x01 if self.max_pin_block_2_format else 0x00,
            0x01 if self.max_mse_command else 0x00
        ])
    
    def get_pw_status_bytes(self) -> bytes:
        """
        Get the PW Status Bytes (C4).
        
        Format:
        - Byte 1: PW1 status (0x00 = single use, 0x01 = valid for multiple)
        - Byte 2: Max length PW1 (UTF-8)
        - Byte 3: Max length Reset Code
        - Byte 4: Max length PW3
        - Byte 5: PW1 retry counter
        - Byte 6: Reset Code retry counter (0 = not set)
        - Byte 7: PW3 retry counter
        """
        return bytes([
            0x01 if self.pin_data.pw1_valid_multiple else 0x00,
            self.pin_data.pw1_max_length,
            self.pin_data.rc_max_length,
            self.pin_data.pw3_max_length,
            self.pin_data.pw1_retry_counter,
            self.pin_data.rc_retry_counter,
            self.pin_data.pw3_retry_counter
        ])
    
    def get_fingerprints(self) -> bytes:
        """Get all key fingerprints (C5) - 60 bytes total."""
        return (
            self.key_sig.fingerprint.ljust(20, b'\x00') +
            self.key_dec.fingerprint.ljust(20, b'\x00') +
            self.key_aut.fingerprint.ljust(20, b'\x00')
        )
    
    def get_ca_fingerprints(self) -> bytes:
        """Get all CA fingerprints (C6) - 60 bytes total."""
        return (
            self.key_sig.ca_fingerprint.ljust(20, b'\x00') +
            self.key_dec.ca_fingerprint.ljust(20, b'\x00') +
            self.key_aut.ca_fingerprint.ljust(20, b'\x00')
        )
    
    def get_key_timestamps(self) -> bytes:
        """Get key generation timestamps (CD) - 12 bytes total."""
        result = b''
        for key in [self.key_sig, self.key_dec, self.key_aut]:
            ts = key.generation_time
            result += bytes([
                (ts >> 24) & 0xFF,
                (ts >> 16) & 0xFF,
                (ts >> 8) & 0xFF,
                ts & 0xFF
            ])
        return result
    
    def get_signature_counter_bytes(self) -> bytes:
        """Get digital signature counter (93) - 3 bytes."""
        return bytes([
            (self.signature_counter >> 16) & 0xFF,
            (self.signature_counter >> 8) & 0xFF,
            self.signature_counter & 0xFF
        ])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'manufacturer_id': self.manufacturer_id,
            'serial_number': self.serial_number,
            'version_major': self.version_major,
            'version_minor': self.version_minor,
            'pin_data': self.pin_data.to_dict(),
            'cardholder': self.cardholder.to_dict(),
            'key_sig': self.key_sig.to_dict(),
            'key_dec': self.key_dec.to_dict(),
            'key_aut': self.key_aut.to_dict(),
            'signature_counter': self.signature_counter,
            'private_do_1': base64.b64encode(self.private_do_1).decode('ascii') if self.private_do_1 else '',
            'private_do_2': base64.b64encode(self.private_do_2).decode('ascii') if self.private_do_2 else '',
            'private_do_3': base64.b64encode(self.private_do_3).decode('ascii') if self.private_do_3 else '',
            'private_do_4': base64.b64encode(self.private_do_4).decode('ascii') if self.private_do_4 else '',
            'certificate': base64.b64encode(self.certificate).decode('ascii') if self.certificate else '',
            'terminated': self.terminated
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CardState':
        """Create from dictionary."""
        state = cls()
        state.manufacturer_id = data.get('manufacturer_id', 0)
        state.serial_number = data.get('serial_number', 1)
        state.version_major = data.get('version_major', 3)
        state.version_minor = data.get('version_minor', 4)
        state.pin_data = PINData.from_dict(data.get('pin_data', {}))
        state.cardholder = CardholderData.from_dict(data.get('cardholder', {}))
        state.key_sig = KeySlot.from_dict(data.get('key_sig', {}))
        state.key_dec = KeySlot.from_dict(data.get('key_dec', {}))
        state.key_aut = KeySlot.from_dict(data.get('key_aut', {}))
        state.signature_counter = data.get('signature_counter', 0)
        private_do_1 = data.get('private_do_1', '')
        state.private_do_1 = base64.b64decode(private_do_1) if private_do_1 else b''
        private_do_2 = data.get('private_do_2', '')
        state.private_do_2 = base64.b64decode(private_do_2) if private_do_2 else b''
        private_do_3 = data.get('private_do_3', '')
        state.private_do_3 = base64.b64decode(private_do_3) if private_do_3 else b''
        private_do_4 = data.get('private_do_4', '')
        state.private_do_4 = base64.b64decode(private_do_4) if private_do_4 else b''
        certificate = data.get('certificate', '')
        state.certificate = base64.b64decode(certificate) if certificate else b''
        state.terminated = data.get('terminated', False)
        return state


class CardDataStore:
    """
    Handles persistent storage of card state.
    
    The storage location can be configured via the JCECARD_STORAGE_DIR
    environment variable. If not set, defaults to /var/lib/jcecard which is
    accessible by both the pcscd daemon (running as root) and user processes.
    """
    
    DEFAULT_STATE_FILE = 'card_state.json'
    
    @staticmethod
    def _get_default_storage_dir() -> Path:
        """Get the default storage directory, checking environment variable first."""
        env_path = os.environ.get('JCECARD_STORAGE_DIR')
        if env_path:
            return Path(env_path)
        # Use /var/lib/jcecard for cross-user accessibility
        # This allows both pcscd (root) and user processes to access
        return Path('/var/lib/jcecard')
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize the card data store.
        
        Args:
            storage_path: Path to store card data. If None, uses default location.
        """
        if storage_path is None:
            self.storage_dir = self._get_default_storage_dir()
        else:
            self.storage_dir = storage_path
        
        self.state_file = self.storage_dir / self.DEFAULT_STATE_FILE
        self.state: CardState = CardState()
    
    def _ensure_storage_dir(self) -> None:
        """Create storage directory if it doesn't exist."""
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        # Set permissions to allow other users to read (for tests)
        try:
            os.chmod(self.storage_dir, 0o755)
        except OSError:
            pass
    
    def load(self) -> bool:
        """
        Load card state from storage.
        
        Returns:
            True if state was loaded, False if new state was created
        """
        if not self.state_file.exists():
            logger.info("No existing card state, creating new")
            self.state = CardState()
            self._initialize_default_pins()
            return False
        
        try:
            with open(self.state_file, 'r') as f:
                data = json.load(f)
            self.state = CardState.from_dict(data)
            logger.info(f"Loaded card state from {self.state_file}")
            return True
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load card state: {e}")
            self.state = CardState()
            self._initialize_default_pins()
            return False
    
    def save(self) -> bool:
        """
        Save card state to storage.
        
        Returns:
            True if save successful, False otherwise
        """
        self._ensure_storage_dir()
        
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.state.to_dict(), f, indent=2)
            # Set permissions to allow other users to read (for tests)
            try:
                os.chmod(self.state_file, 0o644)
            except OSError:
                pass
            logger.debug(f"Saved card state to {self.state_file}")
            return True
        except IOError as e:
            logger.error(f"Failed to save card state: {e}")
            return False
    
    def _initialize_default_pins(self) -> None:
        """Initialize default PIN hashes."""
        # Default PW1: "123456"
        self.state.pin_data.pw1_hash = self._hash_pin("123456")
        self.state.pin_data.pw1_length = 6
        
        # Default PW3: "12345678"
        self.state.pin_data.pw3_hash = self._hash_pin("12345678")
        self.state.pin_data.pw3_length = 8
    
    @staticmethod
    def _hash_pin(pin: str) -> bytes:
        """
        Hash a PIN for storage.
        
        Note: In a real implementation, you'd use a proper KDF like
        Argon2 or PBKDF2 with a salt. For this simulation, we use
        SHA-256 for simplicity.
        """
        return hashlib.sha256(pin.encode('utf-8')).digest()
    
    def reset_to_factory(self) -> None:
        """Reset card to factory defaults."""
        self.state = CardState()
        self._initialize_default_pins()
        self.save()
        logger.info("Card reset to factory defaults")
    
    def get_state(self) -> CardState:
        """Get the current card state."""
        return self.state
    
    def update_state(self, **kwargs: Any) -> None:
        """Update card state fields and save."""
        for key, value in kwargs.items():
            if hasattr(self.state, key):
                setattr(self.state, key, value)
        self.save()

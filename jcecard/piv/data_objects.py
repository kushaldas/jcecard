"""
PIV Data Objects and Constants

Defines PIV key slots, algorithm identifiers, and data objects per NIST SP 800-73-4.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class PIVSlot(IntEnum):
    """PIV key slot identifiers (P2 values for key operations)."""
    AUTHENTICATION = 0x9A      # PIV Authentication (slot 1)
    SIGNATURE = 0x9C           # Digital Signature (slot 2)
    KEY_MANAGEMENT = 0x9D      # Key Management/encryption (slot 3)
    CARD_AUTH = 0x9E           # Card Authentication (no PIN required, slot 4)
    
    # Retired Key Management slots (82-95)
    RETIRED_1 = 0x82
    RETIRED_2 = 0x83
    RETIRED_3 = 0x84
    RETIRED_4 = 0x85
    RETIRED_5 = 0x86
    RETIRED_6 = 0x87
    RETIRED_7 = 0x88
    RETIRED_8 = 0x89
    RETIRED_9 = 0x8A
    RETIRED_10 = 0x8B
    RETIRED_11 = 0x8C
    RETIRED_12 = 0x8D
    RETIRED_13 = 0x8E
    RETIRED_14 = 0x8F
    RETIRED_15 = 0x90
    RETIRED_16 = 0x91
    RETIRED_17 = 0x92
    RETIRED_18 = 0x93
    RETIRED_19 = 0x94
    RETIRED_20 = 0x95
    
    # Special slots
    ATTESTATION = 0xF9         # Attestation key/certificate
    MANAGEMENT_KEY = 0x9B      # Management key (3DES/AES)


class PIVAlgorithm(IntEnum):
    """PIV algorithm identifiers for key generation."""
    RSA_1024 = 0x06
    RSA_2048 = 0x07
    ECC_P256 = 0x11           # NIST prime256v1 (secp256r1)
    ECC_P384 = 0x14           # NIST secp384r1
    
    # Management key algorithms
    TDES = 0x03               # Triple DES (default for management key)
    AES_128 = 0x08
    AES_192 = 0x0A
    AES_256 = 0x0C


class PIVKeyRef(IntEnum):
    """PIV key references for VERIFY command."""
    PIV_PIN = 0x80            # PIV Card Application PIN
    PIV_PUK = 0x81            # PIN Unblocking Key
    GLOBAL_PIN = 0x00         # Global PIN (if supported)


class PIVDataObjectID:
    """PIV Data Object identifiers (3-byte tags)."""
    # Core data objects
    CHUID = bytes([0x5F, 0xC1, 0x02])           # Card Holder Unique Identifier
    CCC = bytes([0x5F, 0xC1, 0x07])             # Card Capability Container
    DISCOVERY = bytes([0x7E])                   # Discovery Object
    KEY_HISTORY = bytes([0x5F, 0xC1, 0x0C])     # Key History Object
    PRINTED_INFO = bytes([0x5F, 0xC1, 0x09])    # Printed Information
    SECURITY_OBJECT = bytes([0x5F, 0xC1, 0x06]) # Security Object
    
    # Certificate objects
    CERT_PIV_AUTH = bytes([0x5F, 0xC1, 0x05])   # X.509 Cert for PIV Auth (9A)
    CERT_CARD_AUTH = bytes([0x5F, 0xC1, 0x08])  # X.509 Cert for Card Auth (9E)
    CERT_SIGNATURE = bytes([0x5F, 0xC1, 0x0A])  # X.509 Cert for Digital Sig (9C)
    CERT_KEY_MGMT = bytes([0x5F, 0xC1, 0x0B])   # X.509 Cert for Key Mgmt (9D)
    
    # Retired key management certificates
    CERT_RETIRED_1 = bytes([0x5F, 0xC1, 0x0D])
    CERT_RETIRED_2 = bytes([0x5F, 0xC1, 0x0E])
    CERT_RETIRED_3 = bytes([0x5F, 0xC1, 0x0F])
    CERT_RETIRED_4 = bytes([0x5F, 0xC1, 0x10])
    CERT_RETIRED_5 = bytes([0x5F, 0xC1, 0x11])
    # ... up to RETIRED_20
    
    # Biometric objects
    FINGERPRINTS = bytes([0x5F, 0xC1, 0x03])
    FACIAL_IMAGE = bytes([0x5F, 0xC1, 0x08])
    
    # Attestation
    ATTESTATION_CERT = bytes([0x5F, 0xFF, 0x01])
    
    @classmethod
    def get_cert_object_id(cls, slot: PIVSlot) -> Optional[bytes]:
        """Get the certificate data object ID for a key slot."""
        mapping = {
            PIVSlot.AUTHENTICATION: cls.CERT_PIV_AUTH,
            PIVSlot.CARD_AUTH: cls.CERT_CARD_AUTH,
            PIVSlot.SIGNATURE: cls.CERT_SIGNATURE,
            PIVSlot.KEY_MANAGEMENT: cls.CERT_KEY_MGMT,
        }
        return mapping.get(slot)


@dataclass
class PIVKeyData:
    """Stores key material for a PIV key slot."""
    algorithm: PIVAlgorithm
    private_key: bytes          # Private key material (DER or raw)
    public_key: bytes           # Public key in PIV format (7F49 template)
    certificate: Optional[bytes] = None  # X.509 certificate (DER)
    pin_policy: int = 0x01      # 0=Default, 1=Never, 2=Once, 3=Always
    touch_policy: int = 0x01    # 0=Default, 1=Never, 2=Always, 3=Cached
    
    def is_rsa(self) -> bool:
        """Check if this is an RSA key."""
        return self.algorithm in (PIVAlgorithm.RSA_1024, PIVAlgorithm.RSA_2048)
    
    def is_ecc(self) -> bool:
        """Check if this is an ECC key."""
        return self.algorithm in (PIVAlgorithm.ECC_P256, PIVAlgorithm.ECC_P384)
    
    def key_size_bits(self) -> int:
        """Get key size in bits."""
        sizes = {
            PIVAlgorithm.RSA_1024: 1024,
            PIVAlgorithm.RSA_2048: 2048,
            PIVAlgorithm.ECC_P256: 256,
            PIVAlgorithm.ECC_P384: 384,
        }
        return sizes.get(self.algorithm, 0)


@dataclass
class PIVDataObjects:
    """Container for all PIV data objects."""
    
    # Core objects
    chuid: Optional[bytes] = None
    ccc: Optional[bytes] = None
    discovery: Optional[bytes] = None
    key_history: Optional[bytes] = None
    printed_info: Optional[bytes] = None
    security_object: Optional[bytes] = None
    
    # Key slots (slot ID -> PIVKeyData)
    keys: dict = field(default_factory=dict)
    
    # Certificates by object ID
    certificates: dict = field(default_factory=dict)
    
    def get_data_object(self, object_id: bytes) -> Optional[bytes]:
        """Get a data object by its ID."""
        # Check core objects
        id_tuple = tuple(object_id)
        
        if id_tuple == tuple(PIVDataObjectID.CHUID):
            return self.chuid
        elif id_tuple == tuple(PIVDataObjectID.CCC):
            return self.ccc
        elif id_tuple == tuple(PIVDataObjectID.DISCOVERY):
            return self.discovery
        elif id_tuple == tuple(PIVDataObjectID.KEY_HISTORY):
            return self.key_history
        elif id_tuple == tuple(PIVDataObjectID.PRINTED_INFO):
            return self.printed_info
        elif id_tuple == tuple(PIVDataObjectID.SECURITY_OBJECT):
            return self.security_object
        
        # Check certificates
        return self.certificates.get(id_tuple)
    
    def put_data_object(self, object_id: bytes, data: bytes) -> bool:
        """Store a data object."""
        id_tuple = tuple(object_id)
        
        if id_tuple == tuple(PIVDataObjectID.CHUID):
            self.chuid = data
        elif id_tuple == tuple(PIVDataObjectID.CCC):
            self.ccc = data
        elif id_tuple == tuple(PIVDataObjectID.DISCOVERY):
            self.discovery = data
        elif id_tuple == tuple(PIVDataObjectID.KEY_HISTORY):
            self.key_history = data
        elif id_tuple == tuple(PIVDataObjectID.PRINTED_INFO):
            self.printed_info = data
        elif id_tuple == tuple(PIVDataObjectID.SECURITY_OBJECT):
            self.security_object = data
        else:
            # Assume it's a certificate
            self.certificates[id_tuple] = data
        
        return True
    
    def get_key(self, slot: PIVSlot) -> Optional[PIVKeyData]:
        """Get key data for a slot."""
        return self.keys.get(slot)
    
    def put_key(self, slot: PIVSlot, key_data: PIVKeyData) -> None:
        """Store key data for a slot."""
        self.keys[slot] = key_data
        
        # Also store certificate if present
        if key_data.certificate:
            cert_obj_id = PIVDataObjectID.get_cert_object_id(slot)
            if cert_obj_id:
                self.certificates[tuple(cert_obj_id)] = key_data.certificate
    
    def delete_key(self, slot: PIVSlot) -> bool:
        """Delete key from a slot."""
        if slot in self.keys:
            del self.keys[slot]
            
            # Also remove certificate
            cert_obj_id = PIVDataObjectID.get_cert_object_id(slot)
            if cert_obj_id:
                id_tuple = tuple(cert_obj_id)
                if id_tuple in self.certificates:
                    del self.certificates[id_tuple]
            
            return True
        return False
    
    @staticmethod
    def create_default_chuid() -> bytes:
        """
        Create a default CHUID (Card Holder Unique Identifier).
        
        Structure per NIST SP 800-73-4:
        - 30: FASC-N (Federal Agency Smart Credential Number) - not used for non-federal
        - 34: Card UUID (16 bytes) - required
        - 35: Expiration Date
        - 3E: Signature (not used)
        - FE: Error Detection Code (LRC)
        """
        import os
        
        # Generate random UUID
        uuid_bytes = os.urandom(16)
        
        # Expiration date: 2099-12-31 (YYYYMMDD in BCD would be complex, use placeholder)
        expiry = bytes([0x32, 0x30, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31])  # "20991231"
        
        # Build CHUID TLV
        chuid = bytes([
            0x30, 0x19,  # FASC-N tag + length (25 bytes placeholder)
        ]) + bytes(25) + bytes([
            0x34, 0x10,  # Card UUID tag + length (16 bytes)
        ]) + uuid_bytes + bytes([
            0x35, 0x08,  # Expiration date tag + length
        ]) + expiry + bytes([
            0xFE, 0x00,  # Error Detection Code (empty)
        ])
        
        return chuid
    
    @staticmethod
    def create_default_ccc() -> bytes:
        """
        Create a default CCC (Card Capability Container).
        
        Structure per NIST SP 800-73-4:
        - F0: Card Identifier
        - F1: Capability Container version number
        - F2: Capability Grammar version number
        - F3: Applications CardURL
        - F4: PKCS#15
        - F5: Registered Data Model number
        - F6: Access Control Rule Table
        - F7: Card APDUs (TRUE if all data elements can be accessed through contact interface)
        - FA: Redirection Tag (not used)
        - FB: Capability Tuples (CTs)
        - FC: Status Tuples (STs)
        - FD: Next CCC (not used)
        - FE: Error Detection Code
        """
        import os
        
        # Card identifier: application ID + serial number
        card_id = bytes([0xA0, 0x00, 0x00, 0x03, 0x08]) + os.urandom(9)  # 14 bytes total
        
        ccc = bytes([
            0xF0, 0x15,  # Card Identifier (21 bytes)
        ]) + bytes([0x00]) + card_id + bytes(6) + bytes([
            0xF1, 0x01, 0x21,  # Capability Container version (0x21)
            0xF2, 0x01, 0x21,  # Capability Grammar version (0x21)
            0xF3, 0x00,        # Applications CardURL (empty)
            0xF4, 0x01, 0x00,  # PKCS#15 (not used)
            0xF5, 0x01, 0x10,  # Registered Data Model (16)
            0xF6, 0x00,        # Access Control Rule Table (empty)
            0xF7, 0x00,        # Card APDUs (empty - can be accessed)
            0xFA, 0x00,        # Redirection Tag (not used)
            0xFB, 0x00,        # Capability Tuples (empty)
            0xFC, 0x00,        # Status Tuples (empty)
            0xFD, 0x00,        # Next CCC (not used)
            0xFE, 0x00,        # Error Detection Code (empty)
        ])
        
        return ccc

"""
PIV Applet Implementation

Main PIV card applet class that handles all PIV commands.
Implements NIST SP 800-73-4 PIV card specification.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional, Tuple

from ..apdu import APDUCommand, APDUResponse, SW
from ..tlv import TLVEncoder
from .data_objects import (
    PIVAlgorithm,
    PIVDataObjects,
    PIVKeyData,
    PIVKeyRef,
    PIVSlot,
)

logger = logging.getLogger(__name__)


# PIV Application ID
PIV_AID = bytes([0xA0, 0x00, 0x00, 0x03, 0x08])

# Default credentials
DEFAULT_PIN = b"123456"
DEFAULT_PUK = b"12345678"
DEFAULT_MGMT_KEY = bytes.fromhex("010203040506070801020304050607080102030405060708")

# Retry limits
DEFAULT_PIN_RETRIES = 3
DEFAULT_PUK_RETRIES = 3


# PIV-specific status words (not in base SW enum)
class PIVSW:
    """PIV-specific status words."""
    # Base for retry counter (63CX where X is retries remaining)
    VERIFY_FAIL_BASE = 0x63C0
    # Base for more data available (61XX where XX is remaining bytes)
    MORE_DATA_BASE = 0x6100


def make_response(sw: int, data: bytes = b"") -> APDUResponse:
    """Create an APDUResponse from a status word and optional data."""
    return APDUResponse(data=data, sw1=(sw >> 8) & 0xFF, sw2=sw & 0xFF)


@dataclass
class PIVSecurityState:
    """Security state for PIV applet."""
    
    # PIN state
    pin: bytes = field(default_factory=lambda: DEFAULT_PIN)
    pin_retries: int = DEFAULT_PIN_RETRIES
    pin_retries_remaining: int = DEFAULT_PIN_RETRIES
    pin_verified: bool = False
    
    # PUK state
    puk: bytes = field(default_factory=lambda: DEFAULT_PUK)
    puk_retries: int = DEFAULT_PUK_RETRIES
    puk_retries_remaining: int = DEFAULT_PUK_RETRIES
    
    # Management key state
    mgmt_key: bytes = field(default_factory=lambda: DEFAULT_MGMT_KEY)
    mgmt_key_algorithm: PIVAlgorithm = PIVAlgorithm.TDES
    mgmt_authenticated: bool = False
    
    # Challenge for GENERAL AUTHENTICATE
    current_challenge: Optional[bytes] = None
    
    def reset_pin_verification(self) -> None:
        """Reset PIN verification state (called on card reset)."""
        self.pin_verified = False
        self.mgmt_authenticated = False
        self.current_challenge = None
    
    def verify_pin(self, pin: bytes) -> Tuple[bool, int]:
        """
        Verify PIN.
        
        Returns:
            (success, retries_remaining)
        """
        # Strip FF padding
        pin = pin.rstrip(b'\xFF')
        
        if self.pin_retries_remaining <= 0:
            return False, 0
        
        if pin == self.pin:
            self.pin_verified = True
            self.pin_retries_remaining = self.pin_retries
            return True, self.pin_retries_remaining
        else:
            self.pin_retries_remaining -= 1
            self.pin_verified = False
            return False, self.pin_retries_remaining
    
    def verify_puk(self, puk: bytes) -> Tuple[bool, int]:
        """
        Verify PUK.
        
        Returns:
            (success, retries_remaining)
        """
        if self.puk_retries_remaining <= 0:
            return False, 0
        
        if puk == self.puk:
            self.puk_retries_remaining = self.puk_retries
            return True, self.puk_retries_remaining
        else:
            self.puk_retries_remaining -= 1
            return False, self.puk_retries_remaining
    
    def change_pin(self, old_pin: bytes, new_pin: bytes) -> Tuple[bool, int]:
        """
        Change PIN.
        
        Returns:
            (success, retries_remaining)
        """
        old_pin = old_pin.rstrip(b'\xFF')
        new_pin = new_pin.rstrip(b'\xFF')
        
        if self.pin_retries_remaining <= 0:
            return False, 0
        
        if old_pin == self.pin:
            self.pin = new_pin
            self.pin_retries_remaining = self.pin_retries
            return True, self.pin_retries_remaining
        else:
            self.pin_retries_remaining -= 1
            return False, self.pin_retries_remaining
    
    def reset_pin_with_puk(self, puk: bytes, new_pin: bytes) -> Tuple[bool, int]:
        """
        Reset PIN using PUK.
        
        Returns:
            (success, remaining_retries) - remaining_retries for PUK if failed
        """
        new_pin = new_pin.rstrip(b'\xFF')
        
        success, retries = self.verify_puk(puk)
        if success:
            self.pin = new_pin
            self.pin_retries_remaining = self.pin_retries
            return True, self.pin_retries_remaining
        return False, retries


class PIVApplet:
    """
    PIV Card Applet Implementation.
    
    Implements NIST SP 800-73-4 PIV card commands:
    - SELECT (A4)
    - VERIFY (20)
    - CHANGE REFERENCE DATA (24)
    - RESET RETRY COUNTER (2C)
    - GET DATA (CB)
    - PUT DATA (DB)
    - GENERATE ASYMMETRIC KEY PAIR (47)
    - GENERAL AUTHENTICATE (87)
    
    Plus Yubico extensions:
    - GET VERSION (FD)
    - GET SERIAL (F8)
    """
    
    def __init__(self):
        """Initialize PIV applet."""
        self.selected = False
        self.security = PIVSecurityState()
        self.data_objects = PIVDataObjects()
        
        # Version and serial
        self.version = (1, 0, 0)  # Virtual card version 1.0.0
        self.serial = int.from_bytes(os.urandom(4), 'big')
        
        # Response chaining buffer
        self._response_buffer: bytes = b""
        
        # Command handlers
        self._handlers = {
            0xA4: self._handle_select,
            0x20: self._handle_verify,
            0x24: self._handle_change_reference_data,
            0x2C: self._handle_reset_retry_counter,
            0xCB: self._handle_get_data,
            0xDB: self._handle_put_data,
            0x47: self._handle_generate_key,
            0x87: self._handle_general_authenticate,
            0xFD: self._handle_get_version,
            0xF8: self._handle_get_serial,
            0xC0: self._handle_get_response,
        }
    
    def reset(self) -> None:
        """Reset applet state (called on card reset/power cycle)."""
        self.selected = False
        self.security.reset_pin_verification()
        self._response_buffer = b""
    
    def process_apdu(self, apdu: APDUCommand) -> APDUResponse:
        """
        Process an APDU command.
        
        Args:
            apdu: The APDU command to process
            
        Returns:
            APDUResponse with status word and optional data
        """
        logger.debug(f"PIV APDU: INS={apdu.ins:02X} P1={apdu.p1:02X} P2={apdu.p2:02X}")
        
        # Check if we have a handler for this instruction
        handler = self._handlers.get(apdu.ins)
        
        if handler is None:
            logger.warning(f"Unknown PIV instruction: {apdu.ins:02X}")
            return make_response(SW.INS_NOT_SUPPORTED)
        
        try:
            return handler(apdu)
        except Exception as e:
            logger.exception(f"Error processing PIV APDU: {e}")
            return make_response(SW.UNKNOWN_ERROR)
    
    def _handle_select(self, apdu: APDUCommand) -> APDUResponse:
        """
        Handle SELECT command (INS A4).
        
        Select PIV application by AID.
        """
        if apdu.p1 != 0x04:  # Select by DF name
            return make_response(SW.INCORRECT_P1_P2)
        
        # Check AID
        if apdu.data != PIV_AID:
            return make_response(SW.FILE_NOT_FOUND)
        
        self.selected = True
        self.security.reset_pin_verification()
        
        # Build response: Application Property Template
        # 4F: AID, 79: Coexistent Tag Allocation Authority
        response_data = bytes([
            0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,  # Application identifier
            0x79, 0x07,  # Coexistent tag allocation authority
            0x4F, 0x05,  # AID tag
        ]) + PIV_AID
        
        logger.info("PIV application selected")
        return make_response(SW.SUCCESS, response_data)
    
    def _handle_verify(self, apdu: APDUCommand) -> APDUResponse:
        """
        Handle VERIFY command (INS 20).
        
        P2 = 80: PIV PIN
        P2 = 81: PUK
        
        Empty data = check retry counter
        """
        key_ref = apdu.p2
        
        if key_ref == PIVKeyRef.PIV_PIN:
            # PIN verification
            if not apdu.data:
                # Return retry counter
                return make_response(PIVSW.VERIFY_FAIL_BASE + self.security.pin_retries_remaining)
            
            success, retries = self.security.verify_pin(apdu.data)
            if success:
                logger.info("PIV PIN verified successfully")
                return make_response(SW.SUCCESS)
            else:
                logger.warning(f"PIV PIN verification failed, {retries} retries remaining")
                if retries == 0:
                    return make_response(SW.AUTH_METHOD_BLOCKED)
                return make_response(PIVSW.VERIFY_FAIL_BASE + retries)
        
        elif key_ref == PIVKeyRef.PIV_PUK:
            # PUK verification (mainly for checking retry counter)
            if not apdu.data:
                return make_response(PIVSW.VERIFY_FAIL_BASE + self.security.puk_retries_remaining)
            
            success, retries = self.security.verify_puk(apdu.data)
            if success:
                return make_response(SW.SUCCESS)
            else:
                if retries == 0:
                    return make_response(SW.AUTH_METHOD_BLOCKED)
                return make_response(PIVSW.VERIFY_FAIL_BASE + retries)
        
        else:
            return make_response(SW.INCORRECT_P1_P2)
    
    def _handle_change_reference_data(self, apdu: APDUCommand) -> APDUResponse:
        """
        Handle CHANGE REFERENCE DATA command (INS 24).
        
        Change PIN or PUK.
        Data format: old_value (8 bytes padded) + new_value (8 bytes padded)
        """
        key_ref = apdu.p2
        
        if len(apdu.data) != 16:
            return make_response(SW.WRONG_LENGTH)
        
        old_value = apdu.data[:8]
        new_value = apdu.data[8:]
        
        if key_ref == PIVKeyRef.PIV_PIN:
            success, retries = self.security.change_pin(old_value, new_value)
            if success:
                logger.info("PIV PIN changed successfully")
                return make_response(SW.SUCCESS)
            else:
                if retries == 0:
                    return make_response(SW.AUTH_METHOD_BLOCKED)
                return make_response(PIVSW.VERIFY_FAIL_BASE + retries)
        
        elif key_ref == PIVKeyRef.PIV_PUK:
            # Change PUK - verify old, set new
            if self.security.puk_retries_remaining <= 0:
                return make_response(SW.AUTH_METHOD_BLOCKED)
            
            if old_value.rstrip(b'\xFF') == self.security.puk:
                self.security.puk = new_value.rstrip(b'\xFF')
                self.security.puk_retries_remaining = self.security.puk_retries
                logger.info("PIV PUK changed successfully")
                return make_response(SW.SUCCESS)
            else:
                self.security.puk_retries_remaining -= 1
                if self.security.puk_retries_remaining == 0:
                    return make_response(SW.AUTH_METHOD_BLOCKED)
                return make_response(PIVSW.VERIFY_FAIL_BASE + self.security.puk_retries_remaining)
        
        else:
            return make_response(SW.INCORRECT_P1_P2)
    
    def _handle_reset_retry_counter(self, apdu: APDUCommand) -> APDUResponse:
        """
        Handle RESET RETRY COUNTER command (INS 2C).
        
        Reset PIN using PUK.
        Data format: PUK (8 bytes) + new_PIN (8 bytes padded)
        """
        if apdu.p2 != PIVKeyRef.PIV_PIN:
            return make_response(SW.INCORRECT_P1_P2)
        
        if len(apdu.data) != 16:
            return make_response(SW.WRONG_LENGTH)
        
        puk = apdu.data[:8]
        new_pin = apdu.data[8:]
        
        success, retries = self.security.reset_pin_with_puk(puk, new_pin)
        if success:
            logger.info("PIV PIN reset with PUK successfully")
            return make_response(SW.SUCCESS)
        else:
            if retries == 0:
                return make_response(SW.AUTH_METHOD_BLOCKED)
            return make_response(PIVSW.VERIFY_FAIL_BASE + retries)
    
    def _handle_get_data(self, apdu: APDUCommand) -> APDUResponse:
        """
        Handle GET DATA command (INS CB).
        
        Read data objects from the card.
        P1P2 = 3FFF (file identifier)
        Data = 5C tag + object ID
        """
        if apdu.p1 != 0x3F or apdu.p2 != 0xFF:
            return make_response(SW.INCORRECT_P1_P2)
        
        # Parse TLV to get object ID
        if len(apdu.data) < 2 or apdu.data[0] != 0x5C:
            return make_response(SW.WRONG_DATA)
        
        tag_len = apdu.data[1]
        object_id = apdu.data[2:2 + tag_len]
        
        # Get the data object
        data = self.data_objects.get_data_object(object_id)
        if data is None:
            return make_response(SW.FILE_NOT_FOUND)
        
        # Wrap in 53 tag
        response = TLVEncoder.encode(0x53, data)
        
        logger.debug(f"GET DATA for object {object_id.hex()}: {len(response)} bytes")
        return make_response(SW.SUCCESS, response)
    
    def _handle_put_data(self, apdu: APDUCommand) -> APDUResponse:
        """
        Handle PUT DATA command (INS DB).
        
        Write data objects to the card.
        Requires management key authentication.
        """
        if not self.security.mgmt_authenticated:
            return make_response(SW.SECURITY_STATUS_NOT_SATISFIED)
        
        if apdu.p1 != 0x3F or apdu.p2 != 0xFF:
            return make_response(SW.INCORRECT_P1_P2)
        
        # Parse TLV to get object ID and data
        if len(apdu.data) < 2 or apdu.data[0] != 0x5C:
            return make_response(SW.WRONG_DATA)
        
        tag_len = apdu.data[1]
        object_id = apdu.data[2:2 + tag_len]
        
        # Find the data (53 tag)
        remaining = apdu.data[2 + tag_len:]
        if len(remaining) < 2 or remaining[0] != 0x53:
            return make_response(SW.WRONG_DATA)
        
        data_len = remaining[1]
        if remaining[1] == 0x82:
            data_len = (remaining[2] << 8) | remaining[3]
            data = remaining[4:4 + data_len]
        elif remaining[1] == 0x81:
            data_len = remaining[2]
            data = remaining[3:3 + data_len]
        else:
            data = remaining[2:2 + data_len]
        
        # Store the data
        self.data_objects.put_data_object(object_id, data)
        logger.info(f"PUT DATA for object {object_id.hex()}: {len(data)} bytes")
        
        return make_response(SW.SUCCESS)
    
    def _handle_generate_key(self, apdu: APDUCommand) -> APDUResponse:
        """
        Handle GENERATE ASYMMETRIC KEY PAIR command (INS 47).
        
        Generate a key pair in the specified slot.
        P2 = slot ID (9A, 9C, 9D, 9E, etc.)
        Data = AC tag with algorithm specification
        """
        if not self.security.mgmt_authenticated:
            return make_response(SW.SECURITY_STATUS_NOT_SATISFIED)
        
        # Get slot from P2
        try:
            slot = PIVSlot(apdu.p2)
        except ValueError:
            # Check if it's a valid retired slot
            if 0x82 <= apdu.p2 <= 0x95:
                slot = PIVSlot(apdu.p2)
            else:
                return make_response(SW.INCORRECT_P1_P2)
        
        # Parse algorithm from data (AC 03 80 01 XX)
        if len(apdu.data) < 5:
            return make_response(SW.WRONG_LENGTH)
        
        if apdu.data[0] != 0xAC:
            return make_response(SW.WRONG_DATA)
        
        # Find 80 tag for algorithm
        idx = 2
        algorithm = None
        while idx < len(apdu.data):
            tag = apdu.data[idx]
            length = apdu.data[idx + 1]
            if tag == 0x80 and length == 1:
                algorithm = apdu.data[idx + 2]
                break
            idx += 2 + length
        
        if algorithm is None:
            return make_response(SW.WRONG_DATA)
        
        try:
            algo = PIVAlgorithm(algorithm)
        except ValueError:
            return make_response(SW.INCORRECT_P1_P2)
        
        logger.info(f"Generating {algo.name} key in slot {slot.name}")
        
        # Generate key based on algorithm
        if algo == PIVAlgorithm.RSA_2048:
            return self._generate_rsa_key(slot, 2048)
        elif algo == PIVAlgorithm.RSA_1024:
            return self._generate_rsa_key(slot, 1024)
        elif algo == PIVAlgorithm.ECC_P256:
            return self._generate_ecc_key(slot, PIVAlgorithm.ECC_P256)
        elif algo == PIVAlgorithm.ECC_P384:
            return self._generate_ecc_key(slot, PIVAlgorithm.ECC_P384)
        else:
            return make_response(SW.INCORRECT_P1_P2)
    
    def _generate_rsa_key(self, slot: PIVSlot, bits: int) -> APDUResponse:
        """Generate RSA key pair."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        try:
            # Generate RSA key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=bits,
                backend=default_backend()
            )
            
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()
            
            # Encode modulus and exponent
            n_bytes = public_numbers.n.to_bytes((bits + 7) // 8, 'big')
            e_bytes = public_numbers.e.to_bytes(3, 'big')  # 65537 = 0x010001
            
            # Build public key response (7F49 template)
            # 81 = modulus, 82 = exponent
            pub_content = TLVEncoder.encode(0x81, n_bytes) + TLVEncoder.encode(0x82, e_bytes)
            pub_data = TLVEncoder.encode(0x7F49, pub_content)
            
            # Serialize private key
            priv_data = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Store key
            algo = PIVAlgorithm.RSA_2048 if bits == 2048 else PIVAlgorithm.RSA_1024
            key_data = PIVKeyData(
                algorithm=algo,
                private_key=priv_data,
                public_key=pub_data
            )
            self.data_objects.put_key(slot, key_data)
            
            logger.info(f"Generated RSA-{bits} key in slot {slot.name}, modulus {len(n_bytes)} bytes")
            return make_response(SW.SUCCESS, pub_data)
            
        except Exception as e:
            logger.exception(f"Failed to generate RSA key: {e}")
            return make_response(SW.UNKNOWN_ERROR)
    
    def _generate_ecc_key(self, slot: PIVSlot, algorithm: PIVAlgorithm) -> APDUResponse:
        """Generate ECC key pair (P-256 or P-384)."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        try:
            # Determine curve
            if algorithm == PIVAlgorithm.ECC_P256:
                curve = ec.SECP256R1()
                coord_size = 32
            elif algorithm == PIVAlgorithm.ECC_P384:
                curve = ec.SECP384R1()
                coord_size = 48
            else:
                return make_response(SW.INCORRECT_P1_P2)
            
            # Generate ECC key
            private_key = ec.generate_private_key(curve, default_backend())
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()
            
            # Encode as uncompressed point (04 + X + Y)
            x_bytes = public_numbers.x.to_bytes(coord_size, 'big')
            y_bytes = public_numbers.y.to_bytes(coord_size, 'big')
            point = bytes([0x04]) + x_bytes + y_bytes
            
            # Build public key response (7F49 template with 86 tag for EC point)
            pub_data = TLVEncoder.encode(0x7F49, TLVEncoder.encode(0x86, point))
            
            # Serialize private key
            priv_data = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Store key
            key_data = PIVKeyData(
                algorithm=algorithm,
                private_key=priv_data,
                public_key=pub_data
            )
            self.data_objects.put_key(slot, key_data)
            
            logger.info(f"Generated ECC {algorithm.name} key in slot {slot.name}")
            return make_response(SW.SUCCESS, pub_data)
            
        except Exception as e:
            logger.exception(f"Failed to generate ECC key: {e}")
            return make_response(SW.UNKNOWN_ERROR)
    
    def _handle_general_authenticate(self, apdu: APDUCommand) -> APDUResponse:
        """
        Handle GENERAL AUTHENTICATE command (INS 87).
        
        Used for:
        - Management key authentication (P2=9B)
        - Signing operations (P2=9A, 9C)
        - Decryption/ECDH (P2=9D)
        - Card authentication (P2=9E)
        
        Data format: 7C template with:
        - 80: Witness (for challenge-response)
        - 81: Challenge
        - 82: Response
        """
        algo = apdu.p1
        key_ref = apdu.p2
        
        # Parse 7C template
        if not apdu.data or apdu.data[0] != 0x7C:
            return make_response(SW.WRONG_DATA)
        
        # Parse contents
        contents = apdu.data[2:]  # Skip 7C and length
        tags = {}
        idx = 0
        while idx < len(contents):
            tag = contents[idx]
            length = contents[idx + 1]
            value = contents[idx + 2:idx + 2 + length] if length > 0 else b""
            tags[tag] = value
            idx += 2 + length
        
        # Management key authentication
        if key_ref == PIVSlot.MANAGEMENT_KEY:
            return self._authenticate_mgmt_key(algo, tags)
        
        # Key operations (signing, decryption)
        try:
            slot = PIVSlot(key_ref)
        except ValueError:
            return make_response(SW.INCORRECT_P1_P2)
        
        # Check PIN for slots that require it
        if slot != PIVSlot.CARD_AUTH and not self.security.pin_verified:
            return make_response(SW.SECURITY_STATUS_NOT_SATISFIED)
        
        # Get key for this slot
        key_data = self.data_objects.get_key(slot)
        if key_data is None:
            return make_response(SW.REFERENCED_DATA_NOT_FOUND)
        
        # Handle signing (82 tag with empty value = request signature)
        if 0x82 in tags and not tags[0x82]:
            # Sign the challenge (81 tag)
            if 0x81 not in tags:
                return make_response(SW.WRONG_DATA)
            
            challenge = tags[0x81]
            return self._sign_data(key_data, challenge)
        
        # Handle decryption/ECDH (85 tag for cipher text)
        if 0x85 in tags:
            cipher_text = tags[0x85]
            return self._decrypt_data(key_data, cipher_text)
        
        return make_response(SW.WRONG_DATA)
    
    def _authenticate_mgmt_key(self, algo: int, tags: dict) -> APDUResponse:
        """
        Authenticate management key using challenge-response.
        
        Steps:
        1. Host sends empty 80 tag to get challenge (witness)
        2. Card returns witness (unencrypted challenge)
        3. Host sends 80 (encrypted challenge) + 81 (host challenge)
        4. Card decrypts host's response, verifies it matches original challenge
        5. Card encrypts host challenge and returns in 82 tag
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        # Create cipher
        cipher = Cipher(
            algorithms.TripleDES(self.security.mgmt_key),
            modes.ECB(),
            backend=default_backend()
        )
        
        # Step 1: Request challenge (empty 80 tag)
        if 0x80 in tags and not tags[0x80] and 0x81 not in tags:
            # Generate random witness (challenge)
            witness = os.urandom(8)
            self.security.current_challenge = witness
            
            # Encrypt the witness with management key and send in tag 80
            encryptor = cipher.encryptor()
            encrypted_witness = encryptor.update(witness) + encryptor.finalize()
            
            response = bytes([0x7C, 0x0A, 0x80, 0x08]) + encrypted_witness
            logger.debug(f"Management key auth: witness {witness.hex()}, encrypted {encrypted_witness.hex()}")
            return make_response(SW.SUCCESS, response)
        
        # Step 2: Verify response and host challenge
        if 0x80 in tags and 0x81 in tags:
            if self.security.current_challenge is None:
                return make_response(SW.CONDITIONS_NOT_SATISFIED)
            
            host_witness = tags[0x80]  # Host's decrypted witness (should match our original)
            host_challenge = tags[0x81]  # Host's challenge for us to encrypt
            
            logger.debug(f"Original witness: {self.security.current_challenge.hex()}")
            logger.debug(f"Host witness (plaintext): {host_witness.hex()}")
            
            # Host should have decrypted our encrypted witness to get the original witness
            # They send it back in plaintext - we just compare directly
            if host_witness != self.security.current_challenge:
                logger.warning("Management key authentication failed")
                self.security.current_challenge = None
                return make_response(SW.SECURITY_STATUS_NOT_SATISFIED)
            
            # Encrypt host challenge and return in 82 tag
            encryptor = cipher.encryptor()
            our_response = encryptor.update(host_challenge) + encryptor.finalize()
            
            self.security.mgmt_authenticated = True
            self.security.current_challenge = None
            
            response = bytes([0x7C, 0x0A, 0x82, 0x08]) + our_response
            logger.info("Management key authenticated successfully")
            return make_response(SW.SUCCESS, response)
        
        return make_response(SW.WRONG_DATA)
    
    def _sign_data(self, key_data: PIVKeyData, data: bytes) -> APDUResponse:
        """Sign data with the private key."""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, ec
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
        from cryptography.hazmat.backends import default_backend
        
        try:
            # Load private key
            private_key = serialization.load_der_private_key(
                key_data.private_key,
                password=None,
                backend=default_backend()
            )
            
            if key_data.is_rsa() and isinstance(private_key, RSAPrivateKey):
                # RSA signature (PKCS#1 v1.5)
                # Data should be DigestInfo (hash OID + hash value)
                signature = private_key.sign(
                    data,
                    padding.PKCS1v15(),
                    Prehashed(hashes.SHA256())  # Assume SHA256
                )
            elif isinstance(private_key, EllipticCurvePrivateKey):
                # ECDSA signature
                # Data is the hash to sign
                signature = private_key.sign(
                    data,
                    ec.ECDSA(Prehashed(hashes.SHA256()))
                )
            else:
                logger.error(f"Unsupported key type for signing: {type(private_key)}")
                return make_response(SW.WRONG_DATA)
            
            # Return signature in 7C template with 82 tag
            response = bytes([0x7C, len(signature) + 2, 0x82, len(signature)]) + signature
            
            logger.debug(f"Signed {len(data)} bytes, signature {len(signature)} bytes")
            return make_response(SW.SUCCESS, response)
            
        except Exception as e:
            logger.exception(f"Signing failed: {e}")
            return make_response(SW.UNKNOWN_ERROR)
    
    def _decrypt_data(self, key_data: PIVKeyData, cipher_text: bytes) -> APDUResponse:
        """Decrypt data or perform ECDH."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding, ec
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
        from cryptography.hazmat.backends import default_backend
        
        try:
            # Load private key
            private_key = serialization.load_der_private_key(
                key_data.private_key,
                password=None,
                backend=default_backend()
            )
            
            if key_data.is_rsa() and isinstance(private_key, RSAPrivateKey):
                # RSA decryption (PKCS#1 v1.5)
                plaintext = private_key.decrypt(
                    cipher_text,
                    padding.PKCS1v15()
                )
            elif isinstance(private_key, EllipticCurvePrivateKey):
                # ECDH: cipher_text is the peer's public point
                # Load peer public key from point
                if cipher_text[0] != 0x04:
                    return make_response(SW.WRONG_DATA)
                
                coord_size = 32 if key_data.algorithm == PIVAlgorithm.ECC_P256 else 48
                curve = ec.SECP256R1() if key_data.algorithm == PIVAlgorithm.ECC_P256 else ec.SECP384R1()
                
                x = int.from_bytes(cipher_text[1:1 + coord_size], 'big')
                y = int.from_bytes(cipher_text[1 + coord_size:1 + 2*coord_size], 'big')
                
                peer_public = ec.EllipticCurvePublicNumbers(x, y, curve).public_key(default_backend())
                
                # Perform ECDH
                shared_key = private_key.exchange(ec.ECDH(), peer_public)
                plaintext = shared_key
            else:
                logger.error(f"Unsupported key type for decrypt: {type(private_key)}")
                return make_response(SW.WRONG_DATA)
            
            # Return result in 7C template with 82 tag
            if len(plaintext) <= 127:
                response = bytes([0x7C, len(plaintext) + 2, 0x82, len(plaintext)]) + plaintext
            else:
                # Use 81 length encoding
                response = bytes([0x7C, 0x81, len(plaintext) + 3, 0x82, 0x81, len(plaintext)]) + plaintext
            
            logger.debug(f"Decrypted/ECDH result: {len(plaintext)} bytes")
            return make_response(SW.SUCCESS, response)
            
        except Exception as e:
            logger.exception(f"Decryption/ECDH failed: {e}")
            return make_response(SW.UNKNOWN_ERROR)
    
    def _handle_get_version(self, apdu: APDUCommand) -> APDUResponse:
        """
        Handle GET VERSION command (INS FD) - Yubico extension.
        
        Returns firmware version as 3 bytes (major, minor, patch).
        """
        response = bytes(self.version)
        return make_response(SW.SUCCESS, response)
    
    def _handle_get_serial(self, apdu: APDUCommand) -> APDUResponse:
        """
        Handle GET SERIAL command (INS F8) - Yubico extension.
        
        Returns serial number as 4 bytes (big-endian).
        """
        response = self.serial.to_bytes(4, 'big')
        return make_response(SW.SUCCESS, response)
    
    def _handle_get_response(self, apdu: APDUCommand) -> APDUResponse:
        """
        Handle GET RESPONSE command (INS C0).
        
        Returns remaining data from previous command.
        """
        if not self._response_buffer:
            return make_response(SW.CONDITIONS_NOT_SATISFIED)
        
        le = apdu.le if apdu.le else 256
        data = self._response_buffer[:le]
        self._response_buffer = self._response_buffer[le:]
        
        if self._response_buffer:
            # More data available
            remaining = min(len(self._response_buffer), 255)
            return make_response(PIVSW.MORE_DATA_BASE + remaining, data)
        
        return make_response(SW.SUCCESS, data)

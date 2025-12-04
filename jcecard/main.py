"""
Main Entry Point for jcecard Virtual Smart Card

This module provides the main entry point for running the virtual
OpenPGP smart card. It connects to vpcd and handles all APDU commands.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Callable, Optional

from .vpcd_connection import VPCDConnection
from .apdu import APDUParser, APDUResponse, APDUCommand, SW, OpenPGPIns, APDUError
from .atr import DEFAULT_ATR
from .tlv import TLV, TLVEncoder, TLVParser, OpenPGPTag
from .card_data import CardState, CardDataStore, CardholderData, AlgorithmID
from .pin_manager import PINManager, PINRef, PINResult
from .security_state import SecurityState, AccessCondition, OperationAccess
from .crypto_backend import (
    CryptoBackend, SimpleCryptoBackend, get_crypto_backend,
    KeyType, GeneratedKey, SignatureResult, DecryptionResult
)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class OpenPGPCard:
    """
    Virtual OpenPGP Smart Card implementation.
    
    This class handles the card logic, processing APDU commands
    and maintaining card state.
    """
    
    def __init__(self, atr: bytes = DEFAULT_ATR, storage_path: Optional[Path] = None):
        """
        Initialize the OpenPGP card.
        
        Args:
            atr: The ATR to use for this card
            storage_path: Path for persistent card data storage
        """
        self.atr = atr
        self.selected = False
        self.powered = False
        
        # Response chaining buffer
        self._response_buffer: bytes = b''
        
        # Command chaining buffer
        self._command_buffer: bytes = b''
        self._chaining_ins: Optional[int] = None
        
        # Initialize card data store
        self._data_store = CardDataStore(storage_path)
        self._data_store.load()
        
        # Initialize PIN manager
        self._pin_manager = PINManager(self._data_store.state)
        
        # Initialize security state
        self._security = SecurityState()
        self._security.set_card_state(self._data_store.state)
        self._security.set_pin_manager(self._pin_manager)
        
        # Initialize crypto backend
        self._crypto = get_crypto_backend()
        
        # Load existing keys if any
        self._load_stored_keys()
        
        logger.info("OpenPGP card initialized")
    
    @property
    def card_state(self) -> CardState:
        """Get the current card state."""
        return self._data_store.state
    
    def _load_stored_keys(self) -> None:
        """Load stored keys into the crypto backend."""
        state = self.card_state
        
        # Load signature key
        if state.key_sig.private_key_data:
            self._crypto.load_key(
                KeyType.SIGNATURE,
                state.key_sig.private_key_data,
                state.key_sig.algorithm
            )
        
        # Load decryption key
        if state.key_dec.private_key_data:
            self._crypto.load_key(
                KeyType.DECRYPTION,
                state.key_dec.private_key_data,
                state.key_dec.algorithm
            )
        
        # Load authentication key
        if state.key_aut.private_key_data:
            self._crypto.load_key(
                KeyType.AUTHENTICATION,
                state.key_aut.private_key_data,
                state.key_aut.algorithm
            )
    
    def save_state(self) -> None:
        """Save card state to persistent storage."""
        self._data_store.save()
    
    def power_on(self) -> None:
        """Handle card power on."""
        self.powered = True
        self.selected = False
        self._response_buffer = b''
        self._command_buffer = b''
        self._chaining_ins = None
        self._security.reset()
        logger.info("Card powered on")
    
    def power_off(self) -> None:
        """Handle card power off."""
        self.powered = False
        self.selected = False
        self._response_buffer = b''
        self._command_buffer = b''
        self._chaining_ins = None
        self._security.reset()
        self.save_state()
        logger.info("Card powered off")
    
    def reset(self) -> bytes:
        """
        Handle card reset.
        
        Returns:
            The ATR to send
        """
        self.selected = False
        self._response_buffer = b''
        self._command_buffer = b''
        self._chaining_ins = None
        self._security.reset()
        logger.info("Card reset")
        return self.atr
    
    def get_atr(self) -> bytes:
        """
        Get the ATR.
        
        Returns:
            The ATR bytes
        """
        return self.atr
    
    def process_apdu(self, raw_apdu: bytes) -> bytes:
        """
        Process an incoming APDU command.
        
        Args:
            raw_apdu: The raw APDU bytes
            
        Returns:
            The response bytes (data + SW)
        """
        try:
            cmd = APDUParser.parse(raw_apdu)
            logger.debug(f"Processing: {cmd}")
            
            # Handle command chaining
            if cmd.chained:
                return self._handle_chained_command(cmd)
            elif self._command_buffer:
                # Last command in chain
                self._command_buffer += cmd.data
                cmd.data = self._command_buffer
                self._command_buffer = b''
                self._chaining_ins = None
            
            # Route to appropriate handler
            response = self._route_command(cmd)
            
            logger.debug(f"Response: {response}")
            return response.to_bytes()
            
        except APDUError as e:
            logger.warning(f"APDU parse error: {e}")
            return APDUResponse.error(SW.WRONG_LENGTH).to_bytes()
        except Exception as e:
            logger.exception(f"Error processing APDU: {e}")
            return APDUResponse.error(SW.UNKNOWN_ERROR).to_bytes()
    
    def _handle_chained_command(self, cmd: APDUCommand) -> bytes:
        """
        Handle a chained command (not the last in the chain).
        
        Args:
            cmd: The APDU command
            
        Returns:
            Response bytes
        """
        if self._chaining_ins is None:
            self._chaining_ins = cmd.ins
            self._command_buffer = cmd.data
        elif self._chaining_ins != cmd.ins:
            # INS changed mid-chain, error
            self._command_buffer = b''
            self._chaining_ins = None
            return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED).to_bytes()
        else:
            self._command_buffer += cmd.data
        
        # Acknowledge the chain
        return APDUResponse.success().to_bytes()
    
    def _route_command(self, cmd: APDUCommand) -> APDUResponse:
        """
        Route a command to the appropriate handler.
        
        Args:
            cmd: The parsed APDU command
            
        Returns:
            The APDU response
        """
        # Check class byte (0x00 or 0x0C for OpenPGP)
        if cmd.cla not in (0x00, 0x0C, 0x10):  # 0x10 for chaining
            return APDUResponse.error(SW.CLA_NOT_SUPPORTED)
        
        # Handle GET RESPONSE for chained responses
        if cmd.ins == OpenPGPIns.GET_RESPONSE:
            return self._handle_get_response(cmd)
        
        # Route based on instruction
        handlers: dict[int, Callable[[APDUCommand], APDUResponse]] = {
            OpenPGPIns.SELECT: self._handle_select,
            OpenPGPIns.GET_DATA: self._handle_get_data,
            OpenPGPIns.VERIFY: self._handle_verify,
            OpenPGPIns.CHANGE_REFERENCE_DATA: self._handle_change_reference_data,
            OpenPGPIns.RESET_RETRY_COUNTER: self._handle_reset_retry_counter,
            OpenPGPIns.PUT_DATA: self._handle_put_data,
            OpenPGPIns.PUT_DATA_ODD: self._handle_put_data_odd,
            OpenPGPIns.GENERATE_ASYMMETRIC_KEY_PAIR: self._handle_generate_key,
            OpenPGPIns.PSO: self._handle_pso,
            OpenPGPIns.INTERNAL_AUTHENTICATE: self._handle_internal_authenticate,
            OpenPGPIns.GET_CHALLENGE: self._handle_get_challenge,
            OpenPGPIns.TERMINATE_DF: self._handle_terminate,
            OpenPGPIns.ACTIVATE_FILE: self._handle_activate,
        }
        
        handler = handlers.get(cmd.ins)
        if handler is not None:
            return handler(cmd)
        
        logger.warning(f"Unsupported instruction: {cmd.ins:02X}")
        return APDUResponse.error(SW.INS_NOT_SUPPORTED)
    
    def _handle_get_response(self, cmd: APDUCommand) -> APDUResponse:
        """Handle GET RESPONSE command for response chaining."""
        if not self._response_buffer:
            return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
        
        le = cmd.le or 256
        chunk = self._response_buffer[:le]
        self._response_buffer = self._response_buffer[le:]
        
        if self._response_buffer:
            remaining = min(len(self._response_buffer), 255)
            return APDUResponse.more_data(chunk, remaining)
        else:
            return APDUResponse.success(chunk)
    
    def _handle_select(self, cmd: APDUCommand) -> APDUResponse:
        """Handle SELECT command."""
        # P1=0x04 means select by DF name (AID)
        if cmd.p1 == 0x04:
            # Check if selecting OpenPGP application
            # Compare the RID + PIX prefix (first 6 bytes)
            card_aid = self.card_state.get_aid()
            if cmd.data[:6] == card_aid[:6]:
                self.selected = True
                logger.info("OpenPGP application selected")
                
                # Return FCI (File Control Information) or just success
                # For now, return success with AID
                return APDUResponse.success()
            else:
                return APDUResponse.error(SW.FILE_NOT_FOUND)
        
        return APDUResponse.error(SW.INCORRECT_P1_P2)
    
    def _handle_get_data(self, cmd: APDUCommand) -> APDUResponse:
        """Handle GET DATA command."""
        if not self.selected:
            return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
        
        # Tag is encoded in P1-P2
        tag = (cmd.p1 << 8) | cmd.p2
        
        logger.info(f"GET DATA for tag {tag:04X}")
        
        # Check access condition
        access = OperationAccess.get_data_access(tag)
        if not self._security.check_access(access):
            return APDUResponse.error(SW.SECURITY_STATUS_NOT_SATISFIED)
        
        # Handle various data objects
        state = self.card_state
        
        if tag == 0x004F:  # AID
            return APDUResponse.success(state.get_aid())
        
        elif tag == 0x005E:  # Login data
            return APDUResponse.success(state.cardholder.login.encode('utf-8'))
        
        elif tag == 0x0065:  # Cardholder Related Data
            data = self._build_cardholder_data()
            return APDUResponse.success(data)
        
        elif tag == 0x006E:  # Application Related Data
            data = self._build_application_related_data()
            return APDUResponse.success(data)
        
        elif tag == 0x007A:  # Security Support Template
            data = self._build_security_support_template()
            return APDUResponse.success(data)
        
        elif tag == 0x00C4:  # PW Status Bytes
            return APDUResponse.success(state.get_pw_status_bytes())
        
        elif tag == 0x0101:  # Private DO 1
            return APDUResponse.success(state.private_do_1)
        
        elif tag == 0x0102:  # Private DO 2
            return APDUResponse.success(state.private_do_2)
        
        elif tag == 0x0103:  # Private DO 3 (requires PW1)
            return APDUResponse.success(state.private_do_3)
        
        elif tag == 0x0104:  # Private DO 4 (requires PW3)
            return APDUResponse.success(state.private_do_4)
        
        elif tag == 0x7F21:  # Cardholder Certificate
            return APDUResponse.success(state.certificate)
        
        elif tag == 0x00C0:  # Extended Capabilities
            return APDUResponse.success(state.get_extended_capabilities())
        
        elif tag == 0x00C1:  # Algorithm Attributes - Signature
            return APDUResponse.success(state.key_sig.algorithm.to_bytes())
        
        elif tag == 0x00C2:  # Algorithm Attributes - Decryption
            return APDUResponse.success(state.key_dec.algorithm.to_bytes())
        
        elif tag == 0x00C3:  # Algorithm Attributes - Authentication
            return APDUResponse.success(state.key_aut.algorithm.to_bytes())
        
        elif tag == 0x00C5:  # Fingerprints
            return APDUResponse.success(state.get_fingerprints())
        
        elif tag == 0x00C6:  # CA Fingerprints
            return APDUResponse.success(state.get_ca_fingerprints())
        
        elif tag == 0x00CD:  # Key Generation Timestamps
            return APDUResponse.success(state.get_key_timestamps())
        
        elif tag == 0x0093:  # Digital Signature Counter
            return APDUResponse.success(state.get_signature_counter_bytes())
        
        elif tag == 0x5F50:  # URL
            return APDUResponse.success(state.cardholder.url.encode('utf-8'))
        
        else:
            logger.warning(f"Unknown GET DATA tag: {tag:04X}")
            return APDUResponse.error(SW.REFERENCED_DATA_NOT_FOUND)
    
    def _build_cardholder_data(self) -> bytes:
        """Build Cardholder Related Data (tag 65)."""
        state = self.card_state
        
        # Build sub-DOs
        result = b''
        
        # 5B - Name
        name_bytes = state.cardholder.name.encode('latin-1', errors='replace')
        result += TLVEncoder.encode(0x5B, name_bytes)
        
        # 5F2D - Language preference
        lang_bytes = state.cardholder.language.encode('ascii', errors='replace')
        result += TLVEncoder.encode(0x5F2D, lang_bytes)
        
        # 5F35 - Sex
        result += TLVEncoder.encode(0x5F35, bytes([state.cardholder.sex]))
        
        return result
    
    def _build_application_related_data(self) -> bytes:
        """Build Application Related Data (tag 6E)."""
        state = self.card_state
        
        result = b''
        
        # 4F - AID
        result += TLVEncoder.encode(0x4F, state.get_aid())
        
        # 5F52 - Historical bytes
        result += TLVEncoder.encode(0x5F52, state.get_historical_bytes())
        
        # 73 - Discretionary DOs (contains C0-C6, CD, etc.)
        discretionary = b''
        discretionary += TLVEncoder.encode(0xC0, state.get_extended_capabilities())
        discretionary += TLVEncoder.encode(0xC1, state.key_sig.algorithm.to_bytes())
        discretionary += TLVEncoder.encode(0xC2, state.key_dec.algorithm.to_bytes())
        discretionary += TLVEncoder.encode(0xC3, state.key_aut.algorithm.to_bytes())
        discretionary += TLVEncoder.encode(0xC4, state.get_pw_status_bytes())
        discretionary += TLVEncoder.encode(0xC5, state.get_fingerprints())
        discretionary += TLVEncoder.encode(0xC6, state.get_ca_fingerprints())
        discretionary += TLVEncoder.encode(0xCD, state.get_key_timestamps())
        
        result += TLVEncoder.encode(0x73, discretionary)
        
        return result
    
    def _build_security_support_template(self) -> bytes:
        """Build Security Support Template (tag 7A)."""
        state = self.card_state
        
        # 93 - Digital Signature Counter
        return TLVEncoder.encode(0x93, state.get_signature_counter_bytes())
    
    def _handle_verify(self, cmd: APDUCommand) -> APDUResponse:
        """Handle VERIFY command."""
        if not self.selected:
            return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
        
        # P2 indicates which PIN: 0x81=PW1(sign), 0x82=PW1(decrypt), 0x83=PW3
        pin_ref = cmd.p2
        
        logger.info(f"VERIFY for PIN reference {pin_ref:02X}")
        
        # Check if it's a valid PIN reference
        if pin_ref not in (PINRef.PW1_SIGN, PINRef.PW1_DECRYPT, PINRef.PW3):
            return APDUResponse.error(SW.INCORRECT_P1_P2)
        
        if not cmd.data:
            # Empty data = check if PIN is verified
            is_verified, retries = self._security.check_pin_status(pin_ref)
            if is_verified:
                return APDUResponse.success()
            else:
                # Return retry counter in SW
                return APDUResponse.error(SW.counter_warning(retries))
        
        # Verify the PIN
        pin = cmd.data.decode('utf-8', errors='replace')
        result = self._security.verify_pin(pin_ref, pin)
        
        if result.is_success:
            self.save_state()
            return APDUResponse.success()
        elif result.is_blocked:
            self.save_state()
            return APDUResponse.error(SW.AUTH_METHOD_BLOCKED)
        else:
            self.save_state()
            return APDUResponse.error(SW.counter_warning(result.retries_remaining))
    
    def _handle_change_reference_data(self, cmd: APDUCommand) -> APDUResponse:
        """Handle CHANGE REFERENCE DATA command."""
        if not self.selected:
            return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
        
        pin_ref = cmd.p2
        logger.info(f"CHANGE REFERENCE DATA for {pin_ref:02X}")
        
        if pin_ref not in (PINRef.PW1_SIGN, PINRef.PW3):
            return APDUResponse.error(SW.INCORRECT_P1_P2)
        
        # Data format: old PIN || new PIN
        # Need to determine the split point
        data = cmd.data
        
        if pin_ref == PINRef.PW1_SIGN:
            # Change PW1
            # Old PIN length is current PW1 length
            old_len = self.card_state.pin_data.pw1_length
            if len(data) < old_len + self.card_state.pin_data.pw1_min_length:
                return APDUResponse.error(SW.WRONG_LENGTH)
            
            old_pin = data[:old_len].decode('utf-8', errors='replace')
            new_pin = data[old_len:].decode('utf-8', errors='replace')
            
            result = self._pin_manager.change_pw1(old_pin, new_pin)
        
        elif pin_ref == PINRef.PW3:
            # Change PW3
            old_len = self.card_state.pin_data.pw3_length
            if len(data) < old_len + self.card_state.pin_data.pw3_min_length:
                return APDUResponse.error(SW.WRONG_LENGTH)
            
            old_pin = data[:old_len].decode('utf-8', errors='replace')
            new_pin = data[old_len:].decode('utf-8', errors='replace')
            
            result = self._pin_manager.change_pw3(old_pin, new_pin)
        else:
            return APDUResponse.error(SW.INCORRECT_P1_P2)
        
        self.save_state()
        
        if result.is_success:
            return APDUResponse.success()
        elif result.is_blocked:
            return APDUResponse.error(SW.AUTH_METHOD_BLOCKED)
        elif result.result == PINResult.INVALID_LENGTH:
            return APDUResponse.error(SW.WRONG_LENGTH)
        else:
            return APDUResponse.error(SW.counter_warning(result.retries_remaining))
    
    def _handle_reset_retry_counter(self, cmd: APDUCommand) -> APDUResponse:
        """Handle RESET RETRY COUNTER command."""
        if not self.selected:
            return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
        
        logger.info(f"RESET RETRY COUNTER P1={cmd.p1:02X}")
        
        # P2 must be 0x81 (reset PW1)
        if cmd.p2 != 0x81:
            return APDUResponse.error(SW.INCORRECT_P1_P2)
        
        data = cmd.data
        
        if cmd.p1 == 0x00:
            # Reset using Reset Code
            # Data format: Reset Code || new PW1
            rc_len = self.card_state.pin_data.rc_length
            if rc_len == 0:
                return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
            
            if len(data) < rc_len + self.card_state.pin_data.pw1_min_length:
                return APDUResponse.error(SW.WRONG_LENGTH)
            
            reset_code = data[:rc_len].decode('utf-8', errors='replace')
            new_pin = data[rc_len:].decode('utf-8', errors='replace')
            
            result = self._pin_manager.reset_pw1_with_reset_code(reset_code, new_pin)
        
        elif cmd.p1 == 0x02:
            # Reset using Admin PIN (must already be verified)
            if not self._security.is_pw3_verified():
                return APDUResponse.error(SW.SECURITY_STATUS_NOT_SATISFIED)
            
            # Data is just the new PW1
            if len(data) < self.card_state.pin_data.pw1_min_length:
                return APDUResponse.error(SW.WRONG_LENGTH)
            
            new_pin = data.decode('utf-8', errors='replace')
            result = self._pin_manager.reset_pw1_with_admin(new_pin, admin_verified=True)
        
        else:
            return APDUResponse.error(SW.INCORRECT_P1_P2)
        
        self.save_state()
        
        if result.is_success:
            return APDUResponse.success()
        elif result.is_blocked:
            return APDUResponse.error(SW.AUTH_METHOD_BLOCKED)
        else:
            return APDUResponse.error(SW.counter_warning(result.retries_remaining))
    
    def _handle_put_data(self, cmd: APDUCommand) -> APDUResponse:
        """Handle PUT DATA command (even instruction)."""
        if not self.selected:
            return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
        
        tag = (cmd.p1 << 8) | cmd.p2
        logger.info(f"PUT DATA for tag {tag:04X}")
        
        # Check access condition
        access = OperationAccess.put_data_access(tag)
        if not self._security.check_access(access):
            return APDUResponse.error(SW.SECURITY_STATUS_NOT_SATISFIED)
        
        state = self.card_state
        data = cmd.data
        
        try:
            if tag == 0x005B:  # Name
                state.cardholder.name = data.decode('latin-1')
            
            elif tag == 0x005E:  # Login data
                state.cardholder.login = data.decode('utf-8')
            
            elif tag == 0x5F2D:  # Language preference
                state.cardholder.language = data.decode('ascii')
            
            elif tag == 0x5F35:  # Sex
                if len(data) >= 1:
                    state.cardholder.sex = data[0]
            
            elif tag == 0x5F50:  # URL
                state.cardholder.url = data.decode('utf-8')
            
            elif tag == 0x0101:  # Private DO 1
                state.private_do_1 = data
            
            elif tag == 0x0102:  # Private DO 2
                state.private_do_2 = data
            
            elif tag == 0x0103:  # Private DO 3
                state.private_do_3 = data
            
            elif tag == 0x0104:  # Private DO 4
                state.private_do_4 = data
            
            elif tag == 0x7F21:  # Cardholder Certificate
                state.certificate = data
            
            elif tag == 0x00D3:  # Reset Code
                rc = data.decode('utf-8') if data else ''
                result = self._pin_manager.set_reset_code(rc, admin_verified=self._security.is_pw3_verified())
                if not result.is_success:
                    return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
            
            elif tag == 0x00C4:  # PW Status Bytes (only byte 0 can be changed)
                if len(data) >= 1:
                    state.pin_data.pw1_valid_multiple = (data[0] != 0x00)
            
            else:
                logger.warning(f"Unknown PUT DATA tag: {tag:04X}")
                return APDUResponse.error(SW.REFERENCED_DATA_NOT_FOUND)
            
            self.save_state()
            return APDUResponse.success()
            
        except (UnicodeDecodeError, ValueError) as e:
            logger.warning(f"PUT DATA decode error: {e}")
            return APDUResponse.error(SW.WRONG_DATA)
    
    def _handle_put_data_odd(self, cmd: APDUCommand) -> APDUResponse:
        """Handle PUT DATA command (odd instruction, for key import)."""
        if not self.selected:
            return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
        
        logger.info("PUT DATA (key import)")
        
        # TODO: Implement key import in Phase 3
        return APDUResponse.error(SW.SECURITY_STATUS_NOT_SATISFIED)
    
    def _handle_generate_key(self, cmd: APDUCommand) -> APDUResponse:
        """
        Handle GENERATE ASYMMETRIC KEY PAIR command (INS 0x47).
        
        P1: 0x80 = Generation of key pair
            0x81 = Reading of public key template
        
        Data: Control Reference Template (CRT)
            B6 = Signature key
            B8 = Decryption key
            A4 = Authentication key
        """
        if not self.selected:
            return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
        
        logger.info(f"GENERATE KEY P1={cmd.p1:02X}")
        
        # Check admin PIN for key generation
        if cmd.p1 == 0x80:  # Generate new key pair
            if not self._security.is_pw3_verified():
                return APDUResponse.error(SW.SECURITY_STATUS_NOT_SATISFIED)
        
        # Parse the CRT to determine which key slot
        if not cmd.data:
            return APDUResponse.error(SW.WRONG_LENGTH)
        
        try:
            tlvs = TLVParser.parse(cmd.data)
            if not tlvs:
                return APDUResponse.error(SW.WRONG_DATA)
            
            crt_tag = tlvs[0].tag
        except Exception as e:
            logger.warning(f"Failed to parse CRT: {e}")
            return APDUResponse.error(SW.WRONG_DATA)
        
        # Map CRT tag to key type
        key_type_map = {
            0xB6: KeyType.SIGNATURE,
            0xB8: KeyType.DECRYPTION,
            0xA4: KeyType.AUTHENTICATION,
        }
        
        key_type = key_type_map.get(crt_tag)
        if key_type is None:
            return APDUResponse.error(SW.INCORRECT_P1_P2)
        
        # Get the key slot from card state
        key_slot_map = {
            KeyType.SIGNATURE: self.card_state.key_sig,
            KeyType.DECRYPTION: self.card_state.key_dec,
            KeyType.AUTHENTICATION: self.card_state.key_aut,
        }
        key_slot = key_slot_map[key_type]
        
        if cmd.p1 == 0x81:
            # Read existing public key
            if not key_slot.public_key_data:
                return APDUResponse.error(SW.REFERENCED_DATA_NOT_FOUND)
            
            # Return public key in 7F49 template
            return APDUResponse.success(key_slot.public_key_data)
        
        elif cmd.p1 == 0x80:
            # Generate new key pair
            algorithm = key_slot.algorithm
            
            logger.info(f"Generating algorithm {algorithm.algorithm_id:02X} key for {key_type.name}")
            
            # Generate based on algorithm
            if algorithm.algorithm_id == AlgorithmID.RSA_2048:
                bits = algorithm.param1 if algorithm.param1 else 2048
                result = self._crypto.generate_rsa_key(key_type, bits)
            elif algorithm.algorithm_id in (AlgorithmID.ECDSA_P256, AlgorithmID.EDDSA, AlgorithmID.ECDH_X25519):
                result = self._crypto.generate_curve25519_key(key_type)
            else:
                logger.warning(f"Unsupported algorithm: {algorithm.algorithm_id:02X}")
                return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
            
            if result is None:
                logger.error("Key generation failed")
                return APDUResponse.error(SW.UNKNOWN_ERROR)
            
            # Store key data
            key_slot.public_key_data = result.public_key_data
            key_slot.private_key_data = result.private_key_data
            key_slot.fingerprint = result.fingerprint
            key_slot.generation_time = result.generation_time
            
            self.save_state()
            
            logger.info(f"Generated key with fingerprint {result.fingerprint.hex()}")
            
            # Return public key template
            return APDUResponse.success(result.public_key_data)
        
        else:
            return APDUResponse.error(SW.INCORRECT_P1_P2)
    
    def _handle_pso(self, cmd: APDUCommand) -> APDUResponse:
        """
        Handle PSO (Perform Security Operation) command (INS 0x2A).
        
        P1-P2: 0x9E9A = Compute Digital Signature
               0x8086 = Decipher
        """
        if not self.selected:
            return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
        
        p1p2 = (cmd.p1 << 8) | cmd.p2
        
        if p1p2 == 0x9E9A:  # Compute Digital Signature
            return self._handle_pso_sign(cmd)
        
        elif p1p2 == 0x8086:  # Decipher
            return self._handle_pso_decipher(cmd)
        
        else:
            return APDUResponse.error(SW.INCORRECT_P1_P2)
    
    def _handle_pso_sign(self, cmd: APDUCommand) -> APDUResponse:
        """
        Handle PSO:COMPUTE DIGITAL SIGNATURE.
        
        The data contains the digest to be signed.
        For RSA, data includes DigestInfo (algorithm OID + hash).
        For EdDSA/ECDSA, data is just the hash.
        """
        logger.info("PSO: COMPUTE DIGITAL SIGNATURE")
        
        # Check PW1 verification for signing (mode 81)
        if not self._security.is_pw1_sign_verified():
            return APDUResponse.error(SW.SECURITY_STATUS_NOT_SATISFIED)
        
        # Check that signature key exists
        if not self._crypto.has_key(KeyType.SIGNATURE):
            logger.warning("No signature key available")
            return APDUResponse.error(SW.REFERENCED_DATA_NOT_FOUND)
        
        # Get data to sign
        data = cmd.data
        if not data:
            return APDUResponse.error(SW.WRONG_LENGTH)
        
        logger.debug(f"Signing {len(data)} bytes of data")
        
        # Perform signature
        result = self._crypto.sign(data, KeyType.SIGNATURE)
        
        if not result.success:
            logger.error(f"Signing failed: {result.error}")
            return APDUResponse.error(SW.UNKNOWN_ERROR)
        
        # Increment signature counter
        self.card_state.signature_counter += 1
        self.save_state()
        
        # Clear PW1 if single-use mode
        if not self.card_state.pin_data.pw1_valid_multiple:
            self._security.clear_pw1_sign()
        
        logger.info(f"Signature computed, {len(result.signature)} bytes")
        
        # Check if response needs chaining
        if cmd.le and len(result.signature) > cmd.le:
            self._response_buffer = result.signature[cmd.le:]
            remaining = min(len(self._response_buffer), 255)
            return APDUResponse.more_data(result.signature[:cmd.le], remaining)
        
        return APDUResponse.success(result.signature)
    
    def _handle_pso_decipher(self, cmd: APDUCommand) -> APDUResponse:
        """
        Handle PSO:DECIPHER.
        
        The data contains the ciphertext to decrypt.
        First byte indicates padding:
            0x00 = PKCS#1 v1.5 padding (RSA)
            0x02 = ECDH cipher
            0xA6 = Wrapped in DO for AES key
        """
        logger.info("PSO: DECIPHER")
        
        # Check PW1 verification for decryption (mode 82)
        if not self._security.is_pw1_decrypt_verified():
            return APDUResponse.error(SW.SECURITY_STATUS_NOT_SATISFIED)
        
        # Check that decryption key exists
        if not self._crypto.has_key(KeyType.DECRYPTION):
            logger.warning("No decryption key available")
            return APDUResponse.error(SW.REFERENCED_DATA_NOT_FOUND)
        
        data = cmd.data
        if not data:
            return APDUResponse.error(SW.WRONG_LENGTH)
        
        # Check padding indicator
        padding_indicator = data[0]
        ciphertext = data[1:]
        
        logger.debug(f"Deciphering {len(ciphertext)} bytes, padding={padding_indicator:02X}")
        
        # Perform decryption
        result = self._crypto.decrypt(ciphertext, KeyType.DECRYPTION)
        
        if not result.success:
            logger.error(f"Decryption failed: {result.error}")
            return APDUResponse.error(SW.UNKNOWN_ERROR)
        
        logger.info(f"Decrypted to {len(result.plaintext)} bytes")
        
        # Check if response needs chaining
        if cmd.le and len(result.plaintext) > cmd.le:
            self._response_buffer = result.plaintext[cmd.le:]
            remaining = min(len(self._response_buffer), 255)
            return APDUResponse.more_data(result.plaintext[:cmd.le], remaining)
        
        return APDUResponse.success(result.plaintext)
    
    def _handle_internal_authenticate(self, cmd: APDUCommand) -> APDUResponse:
        """
        Handle INTERNAL AUTHENTICATE command (INS 0x88).
        
        Used for client authentication (e.g., SSH authentication).
        Signs the challenge/authentication data with the authentication key.
        
        P1-P2: Algorithm reference (usually 0x0000)
        Data: Authentication data/challenge to sign
        """
        if not self.selected:
            return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
        
        logger.info("INTERNAL AUTHENTICATE")
        
        # Check PW1 verification for authentication (mode 82)
        if not self._security.is_pw1_decrypt_verified():
            return APDUResponse.error(SW.SECURITY_STATUS_NOT_SATISFIED)
        
        # Check that authentication key exists
        if not self._crypto.has_key(KeyType.AUTHENTICATION):
            logger.warning("No authentication key available")
            return APDUResponse.error(SW.REFERENCED_DATA_NOT_FOUND)
        
        # Get challenge data
        data = cmd.data
        if not data:
            return APDUResponse.error(SW.WRONG_LENGTH)
        
        logger.debug(f"Authenticating {len(data)} bytes of challenge data")
        
        # Sign the challenge with authentication key
        result = self._crypto.authenticate(data)
        
        if not result.success:
            logger.error(f"Authentication failed: {result.error}")
            return APDUResponse.error(SW.UNKNOWN_ERROR)
        
        logger.info(f"Authentication signature: {len(result.signature)} bytes")
        
        # Check if response needs chaining
        if cmd.le and len(result.signature) > cmd.le:
            self._response_buffer = result.signature[cmd.le:]
            remaining = min(len(self._response_buffer), 255)
            return APDUResponse.more_data(result.signature[:cmd.le], remaining)
        
        return APDUResponse.success(result.signature)
    
    def _handle_get_challenge(self, cmd: APDUCommand) -> APDUResponse:
        """Handle GET CHALLENGE command."""
        if not self.selected:
            return APDUResponse.error(SW.CONDITIONS_NOT_SATISFIED)
        
        import os
        length = cmd.le or 8
        challenge = os.urandom(length)
        logger.info(f"GET CHALLENGE: {length} bytes")
        return APDUResponse.success(challenge)
    
    def _handle_terminate(self, cmd: APDUCommand) -> APDUResponse:
        """Handle TERMINATE DF command."""
        logger.info("TERMINATE DF")
        # TODO: Implement card termination
        return APDUResponse.error(SW.SECURITY_STATUS_NOT_SATISFIED)
    
    def _handle_activate(self, cmd: APDUCommand) -> APDUResponse:
        """Handle ACTIVATE FILE command."""
        logger.info("ACTIVATE FILE")
        # TODO: Implement card activation
        return APDUResponse.success()


def run_card(host: str = 'localhost', port: int = 35963) -> None:
    """
    Run the virtual OpenPGP card.
    
    Args:
        host: vpcd host address
        port: vpcd port number
    """
    card = OpenPGPCard()
    connection = VPCDConnection(host=host, port=port)
    
    # Set up callbacks
    connection.set_callbacks(
        on_power_on=card.power_on,
        on_power_off=card.power_off,
        on_reset=card.reset,
        on_atr_request=card.get_atr,
        on_apdu=card.process_apdu
    )
    
    logger.info(f"Starting virtual OpenPGP card, connecting to vpcd at {host}:{port}")
    
    try:
        connection.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except ConnectionError as e:
        logger.error(f"Connection error: {e}")
        logger.info("Make sure vpcd is running. Install with: sudo apt install vsmartcard-vpcd")
    finally:
        connection.disconnect()


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description='jcecard - Virtual OpenPGP Smart Card',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Connect to vpcd on localhost:35963
  %(prog)s --port 35964       # Use different port
  %(prog)s -v                 # Verbose output
  %(prog)s -vv                # Debug output

Prerequisites:
  1. Install vpcd: sudo apt install vsmartcard-vpcd
  2. Restart pcscd: sudo systemctl restart pcscd
  3. Run this virtual card
  4. Use gpg --card-status to interact with the card
        """
    )
    
    parser.add_argument(
        '--host',
        default='localhost',
        help='vpcd host address (default: localhost)'
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=35963,
        help='vpcd port number (default: 35963)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='count',
        default=0,
        help='Increase verbosity (use -vv for debug)'
    )
    
    args = parser.parse_args()
    
    # Set log level based on verbosity
    if args.verbose >= 2:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose >= 1:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.WARNING)
    
    run_card(host=args.host, port=args.port)


if __name__ == '__main__':
    main()

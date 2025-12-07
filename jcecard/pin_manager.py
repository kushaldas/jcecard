"""
PIN Manager Module

Handles PIN verification, change, and reset operations for the OpenPGP card.

PIN Types:
- PW1 (User PIN): Used for signing (mode 81) and decryption/auth (mode 82)
- PW3 (Admin PIN): Used for administrative operations
- RC (Reset Code): Used to reset PW1 when blocked

Default PINs:
- PW1: "123456"
- PW3: "12345678"
"""

import hashlib
import logging
from enum import IntEnum
from typing import Tuple
from dataclasses import dataclass

from .card_data import CardState, PINData


logger = logging.getLogger(__name__)


class PINRef(IntEnum):
    """PIN reference values for VERIFY command."""
    PW1_SIGN = 0x81     # PW1 for signing
    PW1_DECRYPT = 0x82  # PW1 for decryption/authentication
    PW3 = 0x83          # Admin PIN


class PINResult(IntEnum):
    """Result codes for PIN operations."""
    SUCCESS = 0
    WRONG_PIN = 1
    BLOCKED = 2
    INVALID_LENGTH = 3
    NOT_SET = 4
    ALREADY_VERIFIED = 5


@dataclass
class PINVerifyResult:
    """Result of a PIN verification attempt."""
    result: PINResult
    retries_remaining: int = 0
    
    @property
    def is_success(self) -> bool:
        return self.result == PINResult.SUCCESS
    
    @property
    def is_blocked(self) -> bool:
        return self.result == PINResult.BLOCKED


class PINManager:
    """
    Manages PIN operations for the OpenPGP card.
    
    Handles:
    - PIN verification
    - PIN change
    - PIN reset (using Reset Code or Admin PIN)
    - Retry counter management
    """
    
    def __init__(self, card_state: CardState):
        """
        Initialize PIN manager.
        
        Args:
            card_state: The card state containing PIN data
        """
        self.state = card_state
    
    @property
    def pin_data(self) -> PINData:
        """Get PIN data from card state."""
        return self.state.pin_data
    
    @staticmethod
    def hash_pin(pin: str) -> bytes:
        """
        Hash a PIN for comparison/storage.
        
        Args:
            pin: The PIN string
            
        Returns:
            Hashed PIN bytes
        """
        return hashlib.sha256(pin.encode('utf-8')).digest()
    
    def verify_pw1(self, pin: str, mode: int = PINRef.PW1_SIGN) -> PINVerifyResult:
        """
        Verify PW1 (User PIN).
        
        Args:
            pin: The PIN to verify
            mode: 0x81 for signing, 0x82 for decryption
            
        Returns:
            PINVerifyResult with status and remaining retries
        """
        # Check if blocked
        if self.pin_data.pw1_retry_counter == 0:
            logger.warning("PW1 is blocked")
            return PINVerifyResult(PINResult.BLOCKED, 0)
        
        # Validate PIN length
        if len(pin) < self.pin_data.pw1_min_length or len(pin) > self.pin_data.pw1_max_length:
            logger.debug(f"PW1 length {len(pin)} out of range")
            # Still decrement counter for wrong length
            self.pin_data.pw1_retry_counter -= 1
            return PINVerifyResult(PINResult.INVALID_LENGTH, self.pin_data.pw1_retry_counter)
        
        # Verify PIN
        pin_hash = self.hash_pin(pin)
        if pin_hash == self.pin_data.pw1_hash:
            # Success - reset retry counter
            self.pin_data.pw1_retry_counter = self.pin_data.pw1_max_retries
            logger.info(f"PW1 verified successfully (mode {mode:02X})")
            return PINVerifyResult(PINResult.SUCCESS, self.pin_data.pw1_retry_counter)
        else:
            # Wrong PIN - decrement counter
            self.pin_data.pw1_retry_counter -= 1
            logger.warning(f"PW1 verification failed, {self.pin_data.pw1_retry_counter} retries remaining")
            
            if self.pin_data.pw1_retry_counter == 0:
                return PINVerifyResult(PINResult.BLOCKED, 0)
            return PINVerifyResult(PINResult.WRONG_PIN, self.pin_data.pw1_retry_counter)
    
    def verify_pw3(self, pin: str) -> PINVerifyResult:
        """
        Verify PW3 (Admin PIN).
        
        Args:
            pin: The PIN to verify
            
        Returns:
            PINVerifyResult with status and remaining retries
        """
        # Check if blocked
        if self.pin_data.pw3_retry_counter == 0:
            logger.warning("PW3 is blocked")
            return PINVerifyResult(PINResult.BLOCKED, 0)
        
        # Validate PIN length
        if len(pin) < self.pin_data.pw3_min_length or len(pin) > self.pin_data.pw3_max_length:
            logger.debug(f"PW3 length {len(pin)} out of range")
            self.pin_data.pw3_retry_counter -= 1
            return PINVerifyResult(PINResult.INVALID_LENGTH, self.pin_data.pw3_retry_counter)
        
        # Verify PIN
        pin_hash = self.hash_pin(pin)
        if pin_hash == self.pin_data.pw3_hash:
            # Success - reset retry counter
            self.pin_data.pw3_retry_counter = self.pin_data.pw3_max_retries
            logger.info("PW3 verified successfully")
            return PINVerifyResult(PINResult.SUCCESS, self.pin_data.pw3_retry_counter)
        else:
            # Wrong PIN - decrement counter
            self.pin_data.pw3_retry_counter -= 1
            logger.warning(f"PW3 verification failed, {self.pin_data.pw3_retry_counter} retries remaining")
            
            if self.pin_data.pw3_retry_counter == 0:
                return PINVerifyResult(PINResult.BLOCKED, 0)
            return PINVerifyResult(PINResult.WRONG_PIN, self.pin_data.pw3_retry_counter)
    
    def verify_reset_code(self, reset_code: str) -> PINVerifyResult:
        """
        Verify Reset Code.
        
        Args:
            reset_code: The reset code to verify
            
        Returns:
            PINVerifyResult with status and remaining retries
        """
        # Check if Reset Code is set
        if self.pin_data.rc_retry_counter == 0 or not self.pin_data.rc_hash:
            logger.warning("Reset Code is not set or blocked")
            return PINVerifyResult(PINResult.NOT_SET, 0)
        
        # Validate length
        if len(reset_code) < self.pin_data.rc_min_length or len(reset_code) > self.pin_data.rc_max_length:
            self.pin_data.rc_retry_counter -= 1
            return PINVerifyResult(PINResult.INVALID_LENGTH, self.pin_data.rc_retry_counter)
        
        # Verify Reset Code
        rc_hash = self.hash_pin(reset_code)
        if rc_hash == self.pin_data.rc_hash:
            self.pin_data.rc_retry_counter = self.pin_data.rc_max_retries
            logger.info("Reset Code verified successfully")
            return PINVerifyResult(PINResult.SUCCESS, self.pin_data.rc_retry_counter)
        else:
            self.pin_data.rc_retry_counter -= 1
            logger.warning(f"Reset Code verification failed, {self.pin_data.rc_retry_counter} retries remaining")
            
            if self.pin_data.rc_retry_counter == 0:
                return PINVerifyResult(PINResult.BLOCKED, 0)
            return PINVerifyResult(PINResult.WRONG_PIN, self.pin_data.rc_retry_counter)
    
    def change_pw1(self, old_pin: str, new_pin: str) -> PINVerifyResult:
        """
        Change PW1 (User PIN).
        
        Args:
            old_pin: Current PIN
            new_pin: New PIN to set
            
        Returns:
            PINVerifyResult with status
        """
        # First verify old PIN
        result = self.verify_pw1(old_pin)
        if not result.is_success:
            return result
        
        # Validate new PIN length
        if len(new_pin) < self.pin_data.pw1_min_length or len(new_pin) > self.pin_data.pw1_max_length:
            logger.debug(f"New PW1 length {len(new_pin)} out of range")
            return PINVerifyResult(PINResult.INVALID_LENGTH, self.pin_data.pw1_retry_counter)
        
        # Set new PIN
        self.pin_data.pw1_hash = self.hash_pin(new_pin)
        self.pin_data.pw1_length = len(new_pin)
        logger.info("PW1 changed successfully")
        return PINVerifyResult(PINResult.SUCCESS, self.pin_data.pw1_retry_counter)
    
    def change_pw3(self, old_pin: str, new_pin: str) -> PINVerifyResult:
        """
        Change PW3 (Admin PIN).
        
        Args:
            old_pin: Current PIN
            new_pin: New PIN to set
            
        Returns:
            PINVerifyResult with status
        """
        # First verify old PIN
        result = self.verify_pw3(old_pin)
        if not result.is_success:
            return result
        
        # Validate new PIN length
        if len(new_pin) < self.pin_data.pw3_min_length or len(new_pin) > self.pin_data.pw3_max_length:
            logger.debug(f"New PW3 length {len(new_pin)} out of range")
            return PINVerifyResult(PINResult.INVALID_LENGTH, self.pin_data.pw3_retry_counter)
        
        # Set new PIN
        self.pin_data.pw3_hash = self.hash_pin(new_pin)
        self.pin_data.pw3_length = len(new_pin)
        logger.info("PW3 changed successfully")
        return PINVerifyResult(PINResult.SUCCESS, self.pin_data.pw3_retry_counter)
    
    def reset_pw1_with_reset_code(self, reset_code: str, new_pin: str) -> PINVerifyResult:
        """
        Reset PW1 using Reset Code.
        
        Args:
            reset_code: The reset code
            new_pin: New PW1 to set
            
        Returns:
            PINVerifyResult with status
        """
        # Verify Reset Code
        result = self.verify_reset_code(reset_code)
        if not result.is_success:
            return result
        
        # Validate new PIN length
        if len(new_pin) < self.pin_data.pw1_min_length or len(new_pin) > self.pin_data.pw1_max_length:
            return PINVerifyResult(PINResult.INVALID_LENGTH, self.pin_data.rc_retry_counter)
        
        # Reset PW1
        self.pin_data.pw1_hash = self.hash_pin(new_pin)
        self.pin_data.pw1_length = len(new_pin)
        self.pin_data.pw1_retry_counter = self.pin_data.pw1_max_retries
        logger.info("PW1 reset with Reset Code")
        return PINVerifyResult(PINResult.SUCCESS, self.pin_data.pw1_retry_counter)
    
    def reset_pw1_with_admin(self, new_pin: str, admin_verified: bool = False) -> PINVerifyResult:
        """
        Reset PW1 using Admin PIN (must already be verified).
        
        Args:
            new_pin: New PW1 to set
            admin_verified: Whether PW3 has been verified
            
        Returns:
            PINVerifyResult with status
        """
        if not admin_verified:
            logger.warning("Admin PIN not verified for PW1 reset")
            return PINVerifyResult(PINResult.WRONG_PIN, 0)
        
        # Validate new PIN length
        if len(new_pin) < self.pin_data.pw1_min_length or len(new_pin) > self.pin_data.pw1_max_length:
            return PINVerifyResult(PINResult.INVALID_LENGTH, self.pin_data.pw1_retry_counter)
        
        # Reset PW1
        self.pin_data.pw1_hash = self.hash_pin(new_pin)
        self.pin_data.pw1_length = len(new_pin)
        self.pin_data.pw1_retry_counter = self.pin_data.pw1_max_retries
        logger.info("PW1 reset with Admin PIN")
        return PINVerifyResult(PINResult.SUCCESS, self.pin_data.pw1_retry_counter)
    
    def set_reset_code(self, reset_code: str, admin_verified: bool = False) -> PINVerifyResult:
        """
        Set the Reset Code (requires Admin PIN verification).
        
        Args:
            reset_code: The reset code to set (empty string to clear)
            admin_verified: Whether PW3 has been verified
            
        Returns:
            PINVerifyResult with status
        """
        if not admin_verified:
            logger.warning("Admin PIN not verified for Reset Code change")
            return PINVerifyResult(PINResult.WRONG_PIN, 0)
        
        if not reset_code:
            # Clear Reset Code
            self.pin_data.rc_hash = b''
            self.pin_data.rc_length = 0
            self.pin_data.rc_retry_counter = 0
            logger.info("Reset Code cleared")
            return PINVerifyResult(PINResult.SUCCESS, 0)
        
        # Validate length
        if len(reset_code) < self.pin_data.rc_min_length or len(reset_code) > self.pin_data.rc_max_length:
            return PINVerifyResult(PINResult.INVALID_LENGTH, 0)
        
        # Set Reset Code
        self.pin_data.rc_hash = self.hash_pin(reset_code)
        self.pin_data.rc_length = len(reset_code)
        self.pin_data.rc_retry_counter = self.pin_data.rc_max_retries
        logger.info("Reset Code set")
        return PINVerifyResult(PINResult.SUCCESS, self.pin_data.rc_retry_counter)
    
    def get_retry_counters(self) -> Tuple[int, int, int]:
        """
        Get current retry counters.
        
        Returns:
            Tuple of (PW1 retries, RC retries, PW3 retries)
        """
        return (
            self.pin_data.pw1_retry_counter,
            self.pin_data.rc_retry_counter,
            self.pin_data.pw3_retry_counter
        )
    
    def is_pw1_blocked(self) -> bool:
        """Check if PW1 is blocked."""
        return self.pin_data.pw1_retry_counter == 0
    
    def is_pw3_blocked(self) -> bool:
        """Check if PW3 is blocked."""
        return self.pin_data.pw3_retry_counter == 0
    
    def is_rc_available(self) -> bool:
        """Check if Reset Code is set and not blocked."""
        return bool(self.pin_data.rc_hash) and self.pin_data.rc_retry_counter > 0

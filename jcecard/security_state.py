"""
Security State Module

Manages the authentication/security state of the OpenPGP card.

The security state tracks:
- Which PINs have been verified in the current session
- Access control for various operations
- PIN verification modes (81 vs 82 for PW1)

The security state is reset on:
- Card reset
- Card power off
- Explicit security state reset
"""

import logging
from enum import IntEnum, auto
from typing import Set, Optional
from dataclasses import dataclass, field

from .card_data import CardState
from .pin_manager import PINManager, PINRef, PINVerifyResult, PINResult


logger = logging.getLogger(__name__)


class AccessCondition(IntEnum):
    """Access conditions for operations."""
    ALWAYS = auto()       # No authentication required
    PW1_81 = auto()       # PW1 mode 81 (signing)
    PW1_82 = auto()       # PW1 mode 82 (decryption/authentication)
    PW1_ANY = auto()      # Either PW1 mode
    PW3 = auto()          # Admin PIN required
    NEVER = auto()        # Operation not allowed


@dataclass
class SecurityState:
    """
    Tracks the current security/authentication state.
    
    This is session state that gets reset when the card is reset or powered off.
    """
    # Set of verified PIN references
    _verified_pins: Set[int] = field(default_factory=set)
    
    # Whether PW1 mode 81 has been used for signing (for single-use mode)
    _pw1_81_used: bool = False
    
    # Reference to card state for checking PW1 multiple use setting
    _card_state: Optional[CardState] = None
    
    # Reference to PIN manager
    _pin_manager: Optional[PINManager] = None
    
    def __post_init__(self):
        """Initialize after dataclass creation."""
        self._verified_pins = set()
    
    def set_card_state(self, state: CardState) -> None:
        """Set reference to card state."""
        self._card_state = state
    
    def set_pin_manager(self, manager: PINManager) -> None:
        """Set reference to PIN manager."""
        self._pin_manager = manager
    
    def reset(self) -> None:
        """Reset security state (e.g., on card reset)."""
        self._verified_pins.clear()
        self._pw1_81_used = False
        logger.info("Security state reset")
    
    def verify_pin(self, pin_ref: int, pin: str) -> PINVerifyResult:
        """
        Verify a PIN and update security state.
        
        Args:
            pin_ref: PIN reference (0x81, 0x82, or 0x83)
            pin: The PIN string to verify
            
        Returns:
            PINVerifyResult with verification status
        """
        if self._pin_manager is None:
            logger.error("PIN manager not set")
            return PINVerifyResult(PINResult.WRONG_PIN, 0)
        
        if pin_ref == PINRef.PW1_SIGN:
            result = self._pin_manager.verify_pw1(pin, PINRef.PW1_SIGN)
            if result.is_success:
                self._verified_pins.add(PINRef.PW1_SIGN)
                self._pw1_81_used = False  # Reset usage flag
                logger.info("PW1 (sign mode) verified and added to security state")
        
        elif pin_ref == PINRef.PW1_DECRYPT:
            result = self._pin_manager.verify_pw1(pin, PINRef.PW1_DECRYPT)
            if result.is_success:
                self._verified_pins.add(PINRef.PW1_DECRYPT)
                logger.info("PW1 (decrypt mode) verified and added to security state")
        
        elif pin_ref == PINRef.PW3:
            result = self._pin_manager.verify_pw3(pin)
            if result.is_success:
                self._verified_pins.add(PINRef.PW3)
                logger.info("PW3 verified and added to security state")
        
        else:
            logger.warning(f"Unknown PIN reference: {pin_ref:02X}")
            return PINVerifyResult(PINResult.WRONG_PIN, 0)
        
        return result
    
    def check_pin_status(self, pin_ref: int) -> tuple[bool, int]:
        """
        Check if a PIN is verified (empty VERIFY command).
        
        Args:
            pin_ref: PIN reference to check
            
        Returns:
            Tuple of (is_verified, retry_counter)
        """
        if self._pin_manager is None:
            return (False, 0)
        
        retries = 0
        if pin_ref in (PINRef.PW1_SIGN, PINRef.PW1_DECRYPT):
            retries = self._pin_manager.pin_data.pw1_retry_counter
        elif pin_ref == PINRef.PW3:
            retries = self._pin_manager.pin_data.pw3_retry_counter
        
        is_verified = self.is_verified(pin_ref)
        return (is_verified, retries)
    
    def is_verified(self, pin_ref: int) -> bool:
        """
        Check if a specific PIN has been verified.
        
        Args:
            pin_ref: PIN reference to check
            
        Returns:
            True if PIN is verified in current session
        """
        return pin_ref in self._verified_pins
    
    def is_pw1_sign_verified(self) -> bool:
        """Check if PW1 mode 81 (signing) is verified."""
        if PINRef.PW1_SIGN not in self._verified_pins:
            return False
        
        # Check single-use mode
        if self._card_state and not self._card_state.pin_data.pw1_valid_multiple:
            # Single use mode - check if already used
            if self._pw1_81_used:
                return False
        
        return True
    
    def is_pw1_decrypt_verified(self) -> bool:
        """Check if PW1 mode 82 (decryption/auth) is verified."""
        return PINRef.PW1_DECRYPT in self._verified_pins
    
    def is_pw3_verified(self) -> bool:
        """Check if PW3 (admin) is verified."""
        return PINRef.PW3 in self._verified_pins
    
    def consume_pw1_sign(self) -> bool:
        """
        Consume PW1 sign verification (for single-use mode).
        
        Call this after a successful signing operation.
        
        Returns:
            True if verification was consumed/available
        """
        if not self.is_pw1_sign_verified():
            return False
        
        self._pw1_81_used = True
        
        # In single-use mode, also clear from verified set
        if self._card_state and not self._card_state.pin_data.pw1_valid_multiple:
            self._verified_pins.discard(PINRef.PW1_SIGN)
            logger.info("PW1 sign verification consumed (single-use mode)")
        
        return True
    
    def clear_verification(self, pin_ref: int) -> None:
        """
        Clear verification status for a PIN.
        
        Args:
            pin_ref: PIN reference to clear
        """
        self._verified_pins.discard(pin_ref)
        if pin_ref == PINRef.PW1_SIGN:
            self._pw1_81_used = False
        logger.debug(f"Cleared verification for PIN ref {pin_ref:02X}")
    
    def clear_pw1_sign(self) -> None:
        """Clear PW1 sign verification (for single-use mode after signing)."""
        self.clear_verification(PINRef.PW1_SIGN)
    
    def check_access(self, condition: AccessCondition) -> bool:
        """
        Check if an access condition is satisfied.
        
        Args:
            condition: The access condition to check
            
        Returns:
            True if access is granted
        """
        if condition == AccessCondition.ALWAYS:
            return True
        
        elif condition == AccessCondition.NEVER:
            return False
        
        elif condition == AccessCondition.PW1_81:
            return self.is_pw1_sign_verified()
        
        elif condition == AccessCondition.PW1_82:
            return self.is_pw1_decrypt_verified()
        
        elif condition == AccessCondition.PW1_ANY:
            return self.is_pw1_sign_verified() or self.is_pw1_decrypt_verified()
        
        elif condition == AccessCondition.PW3:
            return self.is_pw3_verified()
        
        return False


# Access conditions for various OpenPGP card operations
class OperationAccess:
    """Defines access conditions for card operations."""
    
    # GET DATA operations
    GET_DATA = {
        0x004F: AccessCondition.ALWAYS,  # AID
        0x005E: AccessCondition.ALWAYS,  # Login data
        0x0065: AccessCondition.ALWAYS,  # Cardholder Related Data
        0x006E: AccessCondition.ALWAYS,  # Application Related Data
        0x007A: AccessCondition.ALWAYS,  # Security Support Template
        0x00C4: AccessCondition.ALWAYS,  # PW Status Bytes
        0x0101: AccessCondition.ALWAYS,  # Private DO 1
        0x0102: AccessCondition.ALWAYS,  # Private DO 2
        0x0103: AccessCondition.PW1_ANY, # Private DO 3 (requires PW1)
        0x0104: AccessCondition.PW3,     # Private DO 4 (requires PW3)
        0x7F21: AccessCondition.ALWAYS,  # Cardholder Certificate
    }
    
    # PUT DATA operations
    PUT_DATA = {
        0x005B: AccessCondition.PW3,     # Name
        0x005E: AccessCondition.PW3,     # Login data
        0x5F2D: AccessCondition.PW3,     # Language preference
        0x5F35: AccessCondition.PW3,     # Sex
        0x5F50: AccessCondition.PW3,     # URL
        0x00C4: AccessCondition.PW3,     # PW Status Bytes
        0x00C1: AccessCondition.PW3,     # Algorithm attributes SIG
        0x00C2: AccessCondition.PW3,     # Algorithm attributes DEC
        0x00C3: AccessCondition.PW3,     # Algorithm attributes AUT
        0x0101: AccessCondition.PW1_ANY, # Private DO 1
        0x0102: AccessCondition.PW1_ANY, # Private DO 2
        0x0103: AccessCondition.PW3,     # Private DO 3
        0x0104: AccessCondition.PW3,     # Private DO 4
        0x7F21: AccessCondition.PW3,     # Cardholder Certificate
        0x00D3: AccessCondition.PW3,     # Reset Code
    }
    
    # Cryptographic operations
    CRYPTO = {
        'sign': AccessCondition.PW1_81,
        'decrypt': AccessCondition.PW1_82,
        'authenticate': AccessCondition.PW1_82,
    }
    
    # Key management
    KEY_MANAGEMENT = {
        'generate': AccessCondition.PW3,
        'import': AccessCondition.PW3,
        'read_public': AccessCondition.ALWAYS,
    }
    
    @classmethod
    def get_data_access(cls, tag: int) -> AccessCondition:
        """Get access condition for GET DATA operation."""
        return cls.GET_DATA.get(tag, AccessCondition.ALWAYS)
    
    @classmethod
    def put_data_access(cls, tag: int) -> AccessCondition:
        """Get access condition for PUT DATA operation."""
        return cls.PUT_DATA.get(tag, AccessCondition.PW3)
    
    @classmethod
    def crypto_access(cls, operation: str) -> AccessCondition:
        """Get access condition for cryptographic operation."""
        return cls.CRYPTO.get(operation, AccessCondition.NEVER)
    
    @classmethod
    def key_access(cls, operation: str) -> AccessCondition:
        """Get access condition for key management operation."""
        return cls.KEY_MANAGEMENT.get(operation, AccessCondition.PW3)

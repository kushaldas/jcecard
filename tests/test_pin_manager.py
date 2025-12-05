"""
Tests for PIN Manager operations.

Tests cover:
- PW1 (User PIN) verification and change
- PW3 (Admin PIN) verification and change
- Reset Code operations
- Retry counter management
- PIN blocking and unblocking
"""

import pytest
import hashlib
from jcecard.card_data import CardState, PINData
from jcecard.pin_manager import (
    PINManager,
    PINRef,
    PINResult,
    PINVerifyResult,
)


class TestPINVerification:
    """Tests for PIN verification operations."""
    
    def test_verify_pw1_correct_pin(self, pin_manager):
        """Test successful PW1 verification."""
        result = pin_manager.verify_pw1("123456")
        assert result.is_success
        assert result.result == PINResult.SUCCESS
    
    def test_verify_pw1_wrong_pin(self, pin_manager):
        """Test PW1 verification with wrong PIN."""
        result = pin_manager.verify_pw1("wrong_pin")
        assert not result.is_success
        assert result.result == PINResult.WRONG_PIN
        assert result.retries_remaining == 2  # One retry consumed
    
    def test_verify_pw1_decrements_counter(self, pin_manager, card_state):
        """Test that wrong PIN decrements retry counter."""
        initial_retries = card_state.pin_data.pw1_retry_counter
        
        pin_manager.verify_pw1("wrong_pin")
        assert card_state.pin_data.pw1_retry_counter == initial_retries - 1
    
    def test_verify_pw1_resets_counter_on_success(self, pin_manager, card_state):
        """Test that correct PIN resets retry counter."""
        # First, decrement counter with wrong PIN
        pin_manager.verify_pw1("wrong")
        assert card_state.pin_data.pw1_retry_counter == 2
        
        # Correct PIN should reset to max
        pin_manager.verify_pw1("123456")
        assert card_state.pin_data.pw1_retry_counter == 3
    
    def test_verify_pw1_blocked(self, pin_manager, card_state):
        """Test blocked PW1 handling."""
        card_state.pin_data.pw1_retry_counter = 0
        
        result = pin_manager.verify_pw1("123456")
        assert result.is_blocked
        assert result.result == PINResult.BLOCKED
    
    def test_verify_pw1_too_short(self, pin_manager):
        """Test PW1 verification with too short PIN."""
        result = pin_manager.verify_pw1("123")  # Min is 6
        assert result.result == PINResult.INVALID_LENGTH
    
    def test_verify_pw1_signing_mode(self, pin_manager):
        """Test PW1 verification for signing mode."""
        result = pin_manager.verify_pw1("123456", mode=PINRef.PW1_SIGN)
        assert result.is_success
    
    def test_verify_pw1_decrypt_mode(self, pin_manager):
        """Test PW1 verification for decrypt mode."""
        result = pin_manager.verify_pw1("123456", mode=PINRef.PW1_DECRYPT)
        assert result.is_success
    
    def test_verify_pw3_correct_pin(self, pin_manager):
        """Test successful PW3 verification."""
        result = pin_manager.verify_pw3("12345678")
        assert result.is_success
        assert result.result == PINResult.SUCCESS
    
    def test_verify_pw3_wrong_pin(self, pin_manager):
        """Test PW3 verification with wrong PIN."""
        result = pin_manager.verify_pw3("wrong_admin_pin")
        assert not result.is_success
        assert result.result == PINResult.WRONG_PIN
    
    def test_verify_pw3_blocked(self, pin_manager, card_state):
        """Test blocked PW3 handling."""
        card_state.pin_data.pw3_retry_counter = 0
        
        result = pin_manager.verify_pw3("12345678")
        assert result.is_blocked


class TestPINChange:
    """Tests for PIN change operations."""
    
    def test_change_pw1_success(self, pin_manager, card_state):
        """Test successful PW1 change."""
        result = pin_manager.change_pw1("123456", "654321")
        assert result.is_success
        
        # Verify new PIN works
        result = pin_manager.verify_pw1("654321")
        assert result.is_success
        
        # Old PIN should fail
        result = pin_manager.verify_pw1("123456")
        assert not result.is_success
    
    def test_change_pw1_wrong_old_pin(self, pin_manager):
        """Test PW1 change with wrong old PIN."""
        result = pin_manager.change_pw1("wrongpin", "654321")  # Use longer PIN
        assert not result.is_success
        # Could be WRONG_PIN or INVALID_LENGTH depending on implementation
        assert result.result in (PINResult.WRONG_PIN, PINResult.INVALID_LENGTH)
    
    def test_change_pw1_invalid_new_pin_length(self, pin_manager):
        """Test PW1 change with invalid new PIN length."""
        result = pin_manager.change_pw1("123456", "123")  # Too short
        assert result.result == PINResult.INVALID_LENGTH
    
    def test_change_pw3_success(self, pin_manager):
        """Test successful PW3 change."""
        result = pin_manager.change_pw3("12345678", "87654321")
        assert result.is_success
        
        # Verify new PIN works
        result = pin_manager.verify_pw3("87654321")
        assert result.is_success
    
    def test_change_pw3_wrong_old_pin(self, pin_manager):
        """Test PW3 change with wrong old PIN."""
        result = pin_manager.change_pw3("wrong_pin", "87654321")
        assert not result.is_success


class TestPINReset:
    """Tests for PIN reset operations."""
    
    def test_reset_pw1_with_admin(self, pin_manager, card_state):
        """Test resetting PW1 with Admin PIN."""
        # Block PW1
        card_state.pin_data.pw1_retry_counter = 0
        
        # Reset with admin (requires prior verification - simulated by admin_verified=True)
        result = pin_manager.reset_pw1_with_admin("999999", admin_verified=True)
        assert result.is_success
        
        # PW1 should be unblocked and new PIN should work
        assert not pin_manager.is_pw1_blocked()
        result = pin_manager.verify_pw1("999999")
        assert result.is_success
    
    def test_reset_pw1_with_admin_not_verified(self, pin_manager):
        """Test PW1 reset without admin verification."""
        result = pin_manager.reset_pw1_with_admin("999999", admin_verified=False)
        assert not result.is_success
    
    def test_reset_pw1_with_reset_code(self, pin_manager, card_state):
        """Test resetting PW1 with Reset Code."""
        # Set up reset code
        rc_hash = hashlib.sha256(b"resetcode").digest()
        card_state.pin_data.rc_hash = rc_hash
        card_state.pin_data.rc_length = 9
        card_state.pin_data.rc_retry_counter = 3
        
        # Block PW1
        card_state.pin_data.pw1_retry_counter = 0
        
        # Reset with reset code
        result = pin_manager.reset_pw1_with_reset_code("resetcode", "999999")
        assert result.is_success
        
        # PW1 should work with new PIN
        result = pin_manager.verify_pw1("999999")
        assert result.is_success
    
    def test_reset_pw1_with_wrong_reset_code(self, pin_manager, card_state):
        """Test PW1 reset with wrong Reset Code."""
        # Set up reset code
        rc_hash = hashlib.sha256(b"resetcode").digest()
        card_state.pin_data.rc_hash = rc_hash
        card_state.pin_data.rc_length = 9
        card_state.pin_data.rc_retry_counter = 3
        
        result = pin_manager.reset_pw1_with_reset_code("wrongcode", "999999")
        assert not result.is_success


class TestResetCode:
    """Tests for Reset Code operations."""
    
    def test_set_reset_code(self, pin_manager, card_state):
        """Test setting Reset Code."""
        result = pin_manager.set_reset_code("myresetcode", admin_verified=True)
        assert result.is_success
        
        # Verify RC is set
        assert card_state.pin_data.rc_hash != b''
        assert card_state.pin_data.rc_length == 11
    
    def test_set_reset_code_without_admin(self, pin_manager):
        """Test setting Reset Code without admin verification."""
        result = pin_manager.set_reset_code("myresetcode", admin_verified=False)
        assert not result.is_success
    
    def test_clear_reset_code(self, pin_manager, card_state):
        """Test clearing Reset Code."""
        # First set it
        pin_manager.set_reset_code("myresetcode", admin_verified=True)
        assert card_state.pin_data.rc_hash != b''
        
        # Clear it
        result = pin_manager.set_reset_code("", admin_verified=True)
        assert result.is_success
        assert card_state.pin_data.rc_hash == b''
    
    def test_verify_reset_code_success(self, pin_manager, card_state):
        """Test successful Reset Code verification."""
        # Set up reset code
        pin_manager.set_reset_code("myresetcode", admin_verified=True)
        
        result = pin_manager.verify_reset_code("myresetcode")
        assert result.is_success
    
    def test_verify_reset_code_wrong(self, pin_manager, card_state):
        """Test Reset Code verification with wrong code."""
        pin_manager.set_reset_code("myresetcode", admin_verified=True)
        
        result = pin_manager.verify_reset_code("wrongcode")
        assert not result.is_success
        assert result.result == PINResult.WRONG_PIN
    
    def test_verify_reset_code_not_set(self, pin_manager):
        """Test Reset Code verification when not set."""
        result = pin_manager.verify_reset_code("anycode")
        assert result.result == PINResult.NOT_SET


class TestRetryCounters:
    """Tests for retry counter management."""
    
    def test_get_retry_counters(self, pin_manager, card_state):
        """Test getting retry counters."""
        pw1, rc, pw3 = pin_manager.get_retry_counters()
        assert pw1 == 3
        assert pw3 == 3
        assert rc == 0  # Reset code not set
    
    def test_is_pw1_blocked(self, pin_manager, card_state):
        """Test PW1 blocked check."""
        assert not pin_manager.is_pw1_blocked()
        
        card_state.pin_data.pw1_retry_counter = 0
        assert pin_manager.is_pw1_blocked()
    
    def test_is_pw3_blocked(self, pin_manager, card_state):
        """Test PW3 blocked check."""
        assert not pin_manager.is_pw3_blocked()
        
        card_state.pin_data.pw3_retry_counter = 0
        assert pin_manager.is_pw3_blocked()
    
    def test_is_rc_available(self, pin_manager, card_state):
        """Test Reset Code availability check."""
        assert not pin_manager.is_rc_available()
        
        # Set reset code
        pin_manager.set_reset_code("resetcode", admin_verified=True)
        assert pin_manager.is_rc_available()
        
        # Block it
        card_state.pin_data.rc_retry_counter = 0
        assert not pin_manager.is_rc_available()


class TestPINBlocking:
    """Tests for PIN blocking behavior."""
    
    def test_pw1_blocks_after_max_retries(self, pin_manager, card_state):
        """Test PW1 blocks after max failed attempts."""
        # Use PIN that's valid length but wrong value
        for _ in range(3):
            result = pin_manager.verify_pw1("654321")  # Wrong but valid length
        
        assert pin_manager.is_pw1_blocked()
        assert result.is_blocked
    
    def test_pw3_blocks_after_max_retries(self, pin_manager, card_state):
        """Test PW3 blocks after max failed attempts."""
        # Use PIN that's valid length but wrong value
        for _ in range(3):
            result = pin_manager.verify_pw3("87654321")  # Wrong but valid length (8 chars)
        
        assert pin_manager.is_pw3_blocked()
        assert result.is_blocked
    
    def test_rc_blocks_after_max_retries(self, pin_manager, card_state):
        """Test Reset Code blocks after max failed attempts."""
        # Set up reset code
        pin_manager.set_reset_code("myresetcode", admin_verified=True)
        
        # Use all retries with wrong but valid length reset code
        for _ in range(3):
            result = pin_manager.verify_reset_code("wrongcode1")
        
        assert not pin_manager.is_rc_available()


class TestPINHash:
    """Tests for PIN hashing."""
    
    def test_hash_pin_consistency(self):
        """Test that same PIN produces same hash."""
        hash1 = PINManager.hash_pin("123456")
        hash2 = PINManager.hash_pin("123456")
        assert hash1 == hash2
    
    def test_hash_pin_different_pins(self):
        """Test that different PINs produce different hashes."""
        hash1 = PINManager.hash_pin("123456")
        hash2 = PINManager.hash_pin("654321")
        assert hash1 != hash2
    
    def test_hash_pin_length(self):
        """Test that hash is SHA-256 (32 bytes)."""
        hash_val = PINManager.hash_pin("123456")
        assert len(hash_val) == 32


class TestPINRef:
    """Tests for PIN reference values."""
    
    def test_pin_ref_values(self):
        """Test PIN reference enum values."""
        assert PINRef.PW1_SIGN == 0x81
        assert PINRef.PW1_DECRYPT == 0x82
        assert PINRef.PW3 == 0x83


class TestPINVerifyResult:
    """Tests for PINVerifyResult dataclass."""
    
    def test_is_success_property(self):
        """Test is_success property."""
        result = PINVerifyResult(PINResult.SUCCESS, 3)
        assert result.is_success
        
        result = PINVerifyResult(PINResult.WRONG_PIN, 2)
        assert not result.is_success
    
    def test_is_blocked_property(self):
        """Test is_blocked property."""
        result = PINVerifyResult(PINResult.BLOCKED, 0)
        assert result.is_blocked
        
        result = PINVerifyResult(PINResult.WRONG_PIN, 1)
        assert not result.is_blocked

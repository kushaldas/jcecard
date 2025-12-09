"""
Tests for PIV Applet Implementation

Tests the PIV card emulation functionality including:
- PIV application selection
- PIN verification
- Key generation (RSA, ECC)
- Signing and ECDH operations
- Data object storage
"""

import pytest
import hashlib
import os
from dataclasses import dataclass

from jcecard.apdu import APDUCommand, APDUResponse, SW
from jcecard.piv import PIVApplet, PIVDataObjects, PIVSlot, PIVAlgorithm
from jcecard.piv.applet import PIV_AID, PIVSW, PIVSecurityState, PIVKeyRef
from jcecard.piv.data_objects import PIVKeyData


# Test fixtures

@pytest.fixture
def piv_applet():
    """Create a fresh PIV applet for testing."""
    return PIVApplet()


@pytest.fixture
def selected_applet(piv_applet):
    """Create a PIV applet that has been selected."""
    select_cmd = APDUCommand(
        cla=0x00,
        ins=0xA4,
        p1=0x04,
        p2=0x00,
        data=PIV_AID
    )
    response = piv_applet.process_apdu(select_cmd)
    assert response.sw == SW.SUCCESS
    return piv_applet


@pytest.fixture
def authenticated_applet(selected_applet):
    """
    Create a PIV applet with management key authenticated.
    
    Note: For simplicity, we directly set the management key authenticated flag.
    In a real scenario, you'd use GENERAL AUTHENTICATE command.
    """
    selected_applet.security.mgmt_authenticated = True
    return selected_applet


@pytest.fixture
def pin_verified_applet(selected_applet):
    """Create a PIV applet with PIN verified."""
    # Verify PIN
    pin_cmd = APDUCommand(
        cla=0x00,
        ins=0x20,
        p1=0x00,
        p2=0x80,
        data=b"123456\xFF\xFF"  # Default PIN padded to 8 bytes
    )
    response = selected_applet.process_apdu(pin_cmd)
    assert response.sw == SW.SUCCESS
    return selected_applet


# Selection tests

class TestPIVSelect:
    """Tests for PIV application selection."""
    
    def test_select_piv_application(self, piv_applet):
        """Test selecting PIV application with correct AID."""
        select_cmd = APDUCommand(
            cla=0x00,
            ins=0xA4,
            p1=0x04,
            p2=0x00,
            data=PIV_AID
        )
        response = piv_applet.process_apdu(select_cmd)
        
        assert response.sw == SW.SUCCESS
        assert piv_applet.selected is True
        assert len(response.data) > 0
    
    def test_select_wrong_aid(self, piv_applet):
        """Test selecting with wrong AID fails."""
        wrong_aid = bytes([0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])  # OpenPGP AID
        select_cmd = APDUCommand(
            cla=0x00,
            ins=0xA4,
            p1=0x04,
            p2=0x00,
            data=wrong_aid
        )
        response = piv_applet.process_apdu(select_cmd)
        
        assert response.sw == SW.FILE_NOT_FOUND
        assert piv_applet.selected is False
    
    def test_select_wrong_p1(self, piv_applet):
        """Test select with wrong P1 fails."""
        select_cmd = APDUCommand(
            cla=0x00,
            ins=0xA4,
            p1=0x00,  # Wrong P1
            p2=0x00,
            data=PIV_AID
        )
        response = piv_applet.process_apdu(select_cmd)
        
        assert response.sw == SW.INCORRECT_P1_P2


# PIN verification tests

class TestPIVVerify:
    """Tests for PIN verification."""
    
    def test_check_pin_retries(self, selected_applet):
        """Test checking PIN retry counter."""
        verify_cmd = APDUCommand(
            cla=0x00,
            ins=0x20,
            p1=0x00,
            p2=0x80,
            data=b""  # Empty data = check retries
        )
        response = selected_applet.process_apdu(verify_cmd)
        
        # Should return 63CX where X is retry count (default 3)
        assert response.sw == PIVSW.VERIFY_FAIL_BASE + 3
    
    def test_verify_correct_pin(self, selected_applet):
        """Test verifying correct PIN."""
        verify_cmd = APDUCommand(
            cla=0x00,
            ins=0x20,
            p1=0x00,
            p2=0x80,
            data=b"123456\xFF\xFF"  # Default PIN padded to 8 bytes
        )
        response = selected_applet.process_apdu(verify_cmd)
        
        assert response.sw == SW.SUCCESS
        assert selected_applet.security.pin_verified is True
    
    def test_verify_wrong_pin(self, selected_applet):
        """Test verifying wrong PIN decrements retry counter."""
        verify_cmd = APDUCommand(
            cla=0x00,
            ins=0x20,
            p1=0x00,
            p2=0x80,
            data=b"654321\xFF\xFF"  # Wrong PIN
        )
        response = selected_applet.process_apdu(verify_cmd)
        
        # Should fail with 2 retries remaining
        assert response.sw == PIVSW.VERIFY_FAIL_BASE + 2
        assert selected_applet.security.pin_verified is False
        assert selected_applet.security.pin_retries_remaining == 2
    
    def test_pin_blocked_after_max_attempts(self, selected_applet):
        """Test PIN gets blocked after max failed attempts."""
        wrong_pin = b"000000\xFF\xFF"
        
        # Attempt 3 wrong PINs
        for i in range(3):
            verify_cmd = APDUCommand(
                cla=0x00,
                ins=0x20,
                p1=0x00,
                p2=0x80,
                data=wrong_pin
            )
            response = selected_applet.process_apdu(verify_cmd)
        
        # Final response should be blocked
        assert response.sw == SW.AUTH_METHOD_BLOCKED
        
        # Further attempts should also return blocked
        verify_cmd = APDUCommand(
            cla=0x00,
            ins=0x20,
            p1=0x00,
            p2=0x80,
            data=wrong_pin
        )
        response = selected_applet.process_apdu(verify_cmd)
        assert response.sw == SW.AUTH_METHOD_BLOCKED
    
    def test_verify_puk(self, selected_applet):
        """Test verifying PUK."""
        verify_cmd = APDUCommand(
            cla=0x00,
            ins=0x20,
            p1=0x00,
            p2=0x81,  # PUK key reference
            data=b"12345678"  # Default PUK
        )
        response = selected_applet.process_apdu(verify_cmd)
        
        assert response.sw == SW.SUCCESS


# Change PIN tests

class TestPIVChangePin:
    """Tests for changing PIN."""
    
    def test_change_pin(self, selected_applet):
        """Test changing PIN with correct old PIN."""
        change_cmd = APDUCommand(
            cla=0x00,
            ins=0x24,
            p1=0x00,
            p2=0x80,
            data=b"123456\xFF\xFF" + b"654321\xFF\xFF"  # old + new
        )
        response = selected_applet.process_apdu(change_cmd)
        
        assert response.sw == SW.SUCCESS
        
        # Verify new PIN works
        verify_cmd = APDUCommand(
            cla=0x00,
            ins=0x20,
            p1=0x00,
            p2=0x80,
            data=b"654321\xFF\xFF"
        )
        response = selected_applet.process_apdu(verify_cmd)
        assert response.sw == SW.SUCCESS
    
    def test_change_pin_wrong_old(self, selected_applet):
        """Test changing PIN with wrong old PIN fails."""
        change_cmd = APDUCommand(
            cla=0x00,
            ins=0x24,
            p1=0x00,
            p2=0x80,
            data=b"000000\xFF\xFF" + b"654321\xFF\xFF"  # wrong old + new
        )
        response = selected_applet.process_apdu(change_cmd)
        
        # Should fail with retry count
        assert (response.sw & 0xFFF0) == PIVSW.VERIFY_FAIL_BASE


# Reset retry counter tests

class TestPIVResetRetry:
    """Tests for resetting retry counter with PUK."""
    
    def test_reset_pin_with_puk(self, selected_applet):
        """Test resetting blocked PIN with PUK."""
        # First, block the PIN
        wrong_pin = b"000000\xFF\xFF"
        for _ in range(3):
            verify_cmd = APDUCommand(
                cla=0x00,
                ins=0x20,
                p1=0x00,
                p2=0x80,
                data=wrong_pin
            )
            selected_applet.process_apdu(verify_cmd)
        
        # Now reset with PUK
        reset_cmd = APDUCommand(
            cla=0x00,
            ins=0x2C,
            p1=0x00,
            p2=0x80,
            data=b"12345678" + b"111111\xFF\xFF"  # PUK + new PIN
        )
        response = selected_applet.process_apdu(reset_cmd)
        
        assert response.sw == SW.SUCCESS
        
        # Verify new PIN works
        verify_cmd = APDUCommand(
            cla=0x00,
            ins=0x20,
            p1=0x00,
            p2=0x80,
            data=b"111111\xFF\xFF"
        )
        response = selected_applet.process_apdu(verify_cmd)
        assert response.sw == SW.SUCCESS


# Key generation tests

class TestPIVKeyGeneration:
    """Tests for key generation."""
    
    def test_generate_rsa2048_key_without_auth(self, selected_applet):
        """Test key generation fails without management key authentication."""
        generate_cmd = APDUCommand(
            cla=0x00,
            ins=0x47,
            p1=0x00,
            p2=0x9A,  # Authentication slot
            data=bytes([0xAC, 0x03, 0x80, 0x01, 0x07])  # RSA 2048
        )
        response = selected_applet.process_apdu(generate_cmd)
        
        assert response.sw == SW.SECURITY_STATUS_NOT_SATISFIED
    
    def test_generate_rsa2048_key(self, authenticated_applet):
        """Test generating RSA 2048 key."""
        generate_cmd = APDUCommand(
            cla=0x00,
            ins=0x47,
            p1=0x00,
            p2=0x9A,  # Authentication slot
            data=bytes([0xAC, 0x03, 0x80, 0x01, 0x07])  # RSA 2048
        )
        response = authenticated_applet.process_apdu(generate_cmd)
        
        assert response.sw == SW.SUCCESS
        assert len(response.data) > 0
        
        # Check TLV structure: should start with 7F49
        assert response.data[0] == 0x7F
        assert response.data[1] == 0x49
        
        # Verify key was stored
        key = authenticated_applet.data_objects.get_key(PIVSlot.AUTHENTICATION)
        assert key is not None
        assert key.algorithm == PIVAlgorithm.RSA_2048
    
    def test_generate_ecc_p256_key(self, authenticated_applet):
        """Test generating ECC P-256 key."""
        generate_cmd = APDUCommand(
            cla=0x00,
            ins=0x47,
            p1=0x00,
            p2=0x9C,  # Signature slot
            data=bytes([0xAC, 0x03, 0x80, 0x01, 0x11])  # ECC P-256
        )
        response = authenticated_applet.process_apdu(generate_cmd)
        
        assert response.sw == SW.SUCCESS
        assert len(response.data) > 0
        
        # Check TLV structure: should start with 7F49
        assert response.data[0] == 0x7F
        assert response.data[1] == 0x49
        
        # Verify key was stored
        key = authenticated_applet.data_objects.get_key(PIVSlot.SIGNATURE)
        assert key is not None
        assert key.algorithm == PIVAlgorithm.ECC_P256
    
    def test_generate_ecc_p384_key(self, authenticated_applet):
        """Test generating ECC P-384 key."""
        generate_cmd = APDUCommand(
            cla=0x00,
            ins=0x47,
            p1=0x00,
            p2=0x9D,  # Key Management slot
            data=bytes([0xAC, 0x03, 0x80, 0x01, 0x14])  # ECC P-384
        )
        response = authenticated_applet.process_apdu(generate_cmd)
        
        assert response.sw == SW.SUCCESS
        
        # Verify key was stored
        key = authenticated_applet.data_objects.get_key(PIVSlot.KEY_MANAGEMENT)
        assert key is not None
        assert key.algorithm == PIVAlgorithm.ECC_P384
    
    def test_generate_key_invalid_slot(self, authenticated_applet):
        """Test generating key in invalid slot fails."""
        generate_cmd = APDUCommand(
            cla=0x00,
            ins=0x47,
            p1=0x00,
            p2=0x01,  # Invalid slot
            data=bytes([0xAC, 0x03, 0x80, 0x01, 0x07])
        )
        response = authenticated_applet.process_apdu(generate_cmd)
        
        assert response.sw == SW.INCORRECT_P1_P2


# Version and serial tests

class TestPIVVersionSerial:
    """Tests for version and serial number commands."""
    
    def test_get_version(self, selected_applet):
        """Test getting firmware version."""
        version_cmd = APDUCommand(
            cla=0x00,
            ins=0xFD,
            p1=0x00,
            p2=0x00
        )
        response = selected_applet.process_apdu(version_cmd)
        
        assert response.sw == SW.SUCCESS
        assert len(response.data) == 3  # major, minor, patch
    
    def test_get_serial(self, selected_applet):
        """Test getting serial number."""
        serial_cmd = APDUCommand(
            cla=0x00,
            ins=0xF8,
            p1=0x00,
            p2=0x00
        )
        response = selected_applet.process_apdu(serial_cmd)
        
        assert response.sw == SW.SUCCESS
        assert len(response.data) == 4  # 4-byte serial


# Data object tests

class TestPIVDataObjects:
    """Tests for data object operations."""
    
    def test_get_nonexistent_data_object(self, selected_applet):
        """Test reading non-existent data object."""
        # Try to read CHUID (doesn't exist by default)
        get_data_cmd = APDUCommand(
            cla=0x00,
            ins=0xCB,
            p1=0x3F,
            p2=0xFF,
            data=bytes([0x5C, 0x03, 0x5F, 0xC1, 0x02])  # CHUID object ID
        )
        response = selected_applet.process_apdu(get_data_cmd)
        
        assert response.sw == SW.FILE_NOT_FOUND
    
    def test_put_and_get_data_object(self, authenticated_applet):
        """Test storing and retrieving data object."""
        # Create CHUID
        chuid_data = PIVDataObjects.create_default_chuid()
        
        # PUT DATA
        put_data_cmd = APDUCommand(
            cla=0x00,
            ins=0xDB,
            p1=0x3F,
            p2=0xFF,
            data=bytes([0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x53, len(chuid_data)]) + chuid_data
        )
        response = authenticated_applet.process_apdu(put_data_cmd)
        
        assert response.sw == SW.SUCCESS
        
        # GET DATA
        get_data_cmd = APDUCommand(
            cla=0x00,
            ins=0xCB,
            p1=0x3F,
            p2=0xFF,
            data=bytes([0x5C, 0x03, 0x5F, 0xC1, 0x02])
        )
        response = authenticated_applet.process_apdu(get_data_cmd)
        
        assert response.sw == SW.SUCCESS
        assert len(response.data) > 0
    
    def test_put_data_without_auth(self, selected_applet):
        """Test PUT DATA fails without management key authentication."""
        put_data_cmd = APDUCommand(
            cla=0x00,
            ins=0xDB,
            p1=0x3F,
            p2=0xFF,
            data=bytes([0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x53, 0x01, 0x00])
        )
        response = selected_applet.process_apdu(put_data_cmd)
        
        assert response.sw == SW.SECURITY_STATUS_NOT_SATISFIED


# General authenticate tests

class TestPIVGeneralAuthenticate:
    """Tests for GENERAL AUTHENTICATE command."""
    
    def test_ecdsa_signature_without_pin(self, authenticated_applet):
        """Test signing without PIN fails (except for Card Auth slot)."""
        # First generate a key
        generate_cmd = APDUCommand(
            cla=0x00,
            ins=0x47,
            p1=0x00,
            p2=0x9C,  # Signature slot
            data=bytes([0xAC, 0x03, 0x80, 0x01, 0x11])  # ECC P-256
        )
        authenticated_applet.process_apdu(generate_cmd)
        
        # Try to sign without PIN
        test_hash = hashlib.sha256(b"test data").digest()
        sign_cmd = APDUCommand(
            cla=0x00,
            ins=0x87,
            p1=0x11,  # ECC P-256
            p2=0x9C,  # Signature slot
            data=bytes([0x7C, len(test_hash) + 4, 0x82, 0x00, 0x81, len(test_hash)]) + test_hash
        )
        response = authenticated_applet.process_apdu(sign_cmd)
        
        assert response.sw == SW.SECURITY_STATUS_NOT_SATISFIED
    
    def test_ecdsa_signature_with_pin(self, authenticated_applet):
        """Test ECDSA signing with PIN verified."""
        # Generate a key
        generate_cmd = APDUCommand(
            cla=0x00,
            ins=0x47,
            p1=0x00,
            p2=0x9C,  # Signature slot
            data=bytes([0xAC, 0x03, 0x80, 0x01, 0x11])  # ECC P-256
        )
        authenticated_applet.process_apdu(generate_cmd)
        
        # Verify PIN
        verify_cmd = APDUCommand(
            cla=0x00,
            ins=0x20,
            p1=0x00,
            p2=0x80,
            data=b"123456\xFF\xFF"
        )
        authenticated_applet.process_apdu(verify_cmd)
        
        # Sign
        test_hash = hashlib.sha256(b"test data").digest()
        sign_cmd = APDUCommand(
            cla=0x00,
            ins=0x87,
            p1=0x11,  # ECC P-256
            p2=0x9C,  # Signature slot
            data=bytes([0x7C, len(test_hash) + 4, 0x82, 0x00, 0x81, len(test_hash)]) + test_hash
        )
        response = authenticated_applet.process_apdu(sign_cmd)
        
        assert response.sw == SW.SUCCESS
        assert len(response.data) > 0
        # Response should be 7C template with 82 tag containing signature
        assert response.data[0] == 0x7C


# Security state tests

class TestPIVSecurityState:
    """Tests for PIV security state management."""
    
    def test_security_state_reset(self, pin_verified_applet):
        """Test that security state resets on card reset."""
        assert pin_verified_applet.security.pin_verified is True
        
        pin_verified_applet.reset()
        
        assert pin_verified_applet.security.pin_verified is False
        assert pin_verified_applet.security.mgmt_authenticated is False
        assert pin_verified_applet.selected is False
    
    def test_pin_verification_resets_on_select(self, pin_verified_applet):
        """Test that PIN verification resets when reselecting."""
        assert pin_verified_applet.security.pin_verified is True
        
        # Reselect the application
        select_cmd = APDUCommand(
            cla=0x00,
            ins=0xA4,
            p1=0x04,
            p2=0x00,
            data=PIV_AID
        )
        pin_verified_applet.process_apdu(select_cmd)
        
        assert pin_verified_applet.security.pin_verified is False


# PIVKeyData tests

class TestPIVKeyData:
    """Tests for PIVKeyData dataclass."""
    
    def test_is_rsa(self):
        """Test is_rsa() method."""
        rsa_key = PIVKeyData(
            algorithm=PIVAlgorithm.RSA_2048,
            private_key=b"",
            public_key=b""
        )
        assert rsa_key.is_rsa() is True
        assert rsa_key.is_ecc() is False
        
        ecc_key = PIVKeyData(
            algorithm=PIVAlgorithm.ECC_P256,
            private_key=b"",
            public_key=b""
        )
        assert ecc_key.is_rsa() is False
        assert ecc_key.is_ecc() is True
    
    def test_key_size_bits(self):
        """Test key_size_bits() method."""
        rsa2048 = PIVKeyData(algorithm=PIVAlgorithm.RSA_2048, private_key=b"", public_key=b"")
        assert rsa2048.key_size_bits() == 2048
        
        ecc256 = PIVKeyData(algorithm=PIVAlgorithm.ECC_P256, private_key=b"", public_key=b"")
        assert ecc256.key_size_bits() == 256
        
        ecc384 = PIVKeyData(algorithm=PIVAlgorithm.ECC_P384, private_key=b"", public_key=b"")
        assert ecc384.key_size_bits() == 384


# PIVDataObjects tests

class TestPIVDataObjectsClass:
    """Tests for PIVDataObjects class."""
    
    def test_put_and_get_key(self):
        """Test storing and retrieving keys."""
        data_objects = PIVDataObjects()
        
        key_data = PIVKeyData(
            algorithm=PIVAlgorithm.ECC_P256,
            private_key=b"private",
            public_key=b"public"
        )
        data_objects.put_key(PIVSlot.AUTHENTICATION, key_data)
        
        retrieved = data_objects.get_key(PIVSlot.AUTHENTICATION)
        assert retrieved is not None
        assert retrieved.algorithm == PIVAlgorithm.ECC_P256
        assert retrieved.private_key == b"private"
    
    def test_delete_key(self):
        """Test deleting a key."""
        data_objects = PIVDataObjects()
        
        key_data = PIVKeyData(
            algorithm=PIVAlgorithm.ECC_P256,
            private_key=b"private",
            public_key=b"public"
        )
        data_objects.put_key(PIVSlot.AUTHENTICATION, key_data)
        
        assert data_objects.delete_key(PIVSlot.AUTHENTICATION) is True
        assert data_objects.get_key(PIVSlot.AUTHENTICATION) is None
        
        # Delete non-existent key returns False
        assert data_objects.delete_key(PIVSlot.AUTHENTICATION) is False
    
    def test_create_default_chuid(self):
        """Test creating default CHUID."""
        chuid = PIVDataObjects.create_default_chuid()
        
        assert len(chuid) > 0
        assert chuid[0] == 0x30  # FASC-N tag
    
    def test_create_default_ccc(self):
        """Test creating default CCC."""
        ccc = PIVDataObjects.create_default_ccc()
        
        assert len(ccc) > 0
        assert ccc[0] == 0xF0  # Card Identifier tag

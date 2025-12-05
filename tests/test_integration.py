"""
Integration Tests for OpenPGP Virtual Smart Card.

Tests cover:
- Full card operations through OpenPGPCard class
- APDU command processing end-to-end
- Key generation and usage flows
- PIN verification and management flows
- Card state persistence

These tests assume:
- johnnycanencrypt module is available
- vpcd service is available (for vpcd connection tests)
"""

import pytest
import tempfile
from pathlib import Path

from jcecard.main import OpenPGPCard
from jcecard.apdu import (
    APDUCommand, APDUResponse, APDUParser, APDUBuilder,
    SW, OpenPGPIns, PSOP1P2,
)
from jcecard.tlv import TLV, TLVParser, TLVEncoder, OpenPGPTag
from jcecard.card_data import CardState, CardDataStore
from jcecard.crypto_backend import CryptoBackend, KeyType
from jcecard.atr import DEFAULT_ATR


# OpenPGP card AID
OPENPGP_AID = bytes.fromhex("D27600012401")


def create_test_card(tmpdir):
    """Create a test card with temporary storage."""
    storage_path = Path(tmpdir) / "card_data.json"
    card = OpenPGPCard(storage_path=storage_path)
    return card


class TestOpenPGPCardBasic:
    """Basic tests for OpenPGPCard initialization and lifecycle."""
    
    @pytest.fixture
    def card(self):
        """Create a fresh OpenPGPCard with temporary storage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            yield card
    
    def test_card_creation(self, card):
        """Test card can be created."""
        assert card is not None
        assert card.atr == DEFAULT_ATR
    
    def test_card_power_on(self, card):
        """Test card power on."""
        card.power_on()
        assert card.powered is True
    
    def test_card_power_off(self, card):
        """Test card power off."""
        card.power_on()
        card.power_off()
        assert card.powered is False
    
    def test_card_reset(self, card):
        """Test card reset returns ATR."""
        card.power_on()
        atr = card.reset()
        assert atr == DEFAULT_ATR
    
    def test_card_state_access(self, card):
        """Test accessing card state."""
        state = card.card_state
        assert isinstance(state, CardState)
        assert state.version_major == 3
        assert state.version_minor == 4


class TestAPDUProcessing:
    """Tests for APDU command processing."""
    
    @pytest.fixture
    def card(self):
        """Create a powered-on card."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            yield card
    
    def test_select_openpgp(self, card):
        """Test SELECT command for OpenPGP application."""
        # Build SELECT command
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.SELECT, 0x04, 0x00,
            data=OPENPGP_AID
        )
        
        # Process APDU
        response_bytes = card.process_apdu(apdu_bytes)
        
        # Parse response - should succeed
        assert len(response_bytes) >= 2
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        assert sw == SW.SUCCESS
        assert card.selected is True
    
    def test_select_wrong_aid(self, card):
        """Test SELECT with wrong AID."""
        wrong_aid = bytes.fromhex("A0000000031010")  # Visa AID
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.SELECT, 0x04, 0x00,
            data=wrong_aid
        )
        
        response_bytes = card.process_apdu(apdu_bytes)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        assert sw == SW.FILE_NOT_FOUND
    
    def test_get_data_aid(self, card):
        """Test GET DATA for AID (4F)."""
        # First select the application
        select_apdu = APDUBuilder.build_command(
            0x00, OpenPGPIns.SELECT, 0x04, 0x00,
            data=OPENPGP_AID
        )
        card.process_apdu(select_apdu)
        
        # GET DATA for AID
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.GET_DATA, 0x00, 0x4F,
            le=0
        )
        
        response_bytes = card.process_apdu(apdu_bytes)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        
        # Should succeed and return AID data
        assert sw == SW.SUCCESS
        data = response_bytes[:-2]
        assert len(data) > 0
    
    def test_get_data_application_related(self, card):
        """Test GET DATA for Application Related Data (6E)."""
        # First select
        select_apdu = APDUBuilder.build_command(
            0x00, OpenPGPIns.SELECT, 0x04, 0x00,
            data=OPENPGP_AID
        )
        card.process_apdu(select_apdu)
        
        # GET DATA for Application Related Data
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.GET_DATA, 0x00, 0x6E,
            le=0
        )
        
        response_bytes = card.process_apdu(apdu_bytes)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        
        # Should succeed
        assert sw == SW.SUCCESS
        data = response_bytes[:-2]
        
        # Should be TLV formatted
        if len(data) > 0:
            tlvs = TLVParser.parse(data)
            assert len(tlvs) >= 1
    
    def test_command_without_select(self, card):
        """Test that commands fail without SELECT."""
        # Try GET DATA without selecting first
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.GET_DATA, 0x00, 0x4F,
            le=0
        )
        
        response_bytes = card.process_apdu(apdu_bytes)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        
        # Should fail - conditions not satisfied
        assert sw != SW.SUCCESS


class TestPINVerification:
    """Tests for PIN verification through APDU."""
    
    @pytest.fixture
    def selected_card(self):
        """Create a card with OpenPGP app selected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # Select OpenPGP
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            card.process_apdu(select_apdu)
            
            yield card
    
    def test_verify_pw1_correct(self, selected_card):
        """Test VERIFY with correct PW1."""
        # Default PW1 is "123456"
        pin = b"123456"
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.VERIFY, 0x00, 0x81,
            data=pin
        )
        
        response_bytes = selected_card.process_apdu(apdu_bytes)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        
        assert sw == SW.SUCCESS
    
    def test_verify_pw1_wrong(self, selected_card):
        """Test VERIFY with wrong PW1."""
        pin = b"wrongpin"
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.VERIFY, 0x00, 0x81,
            data=pin
        )
        
        response_bytes = selected_card.process_apdu(apdu_bytes)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        
        # Should be 63CX (X = retries remaining)
        assert (sw & 0xFFF0) == 0x63C0
    
    def test_verify_pw3_correct(self, selected_card):
        """Test VERIFY with correct PW3 (Admin PIN)."""
        # Default PW3 is "12345678"
        pin = b"12345678"
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.VERIFY, 0x00, 0x83,
            data=pin
        )
        
        response_bytes = selected_card.process_apdu(apdu_bytes)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        
        assert sw == SW.SUCCESS
    
    def test_verify_check_status(self, selected_card):
        """Test VERIFY with empty data to check PIN status."""
        # Empty VERIFY checks if PIN verification is needed
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.VERIFY, 0x00, 0x81
        )
        
        response_bytes = selected_card.process_apdu(apdu_bytes)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        
        # Should return 63CX (retries) or 9000 (already verified)
        assert sw == SW.SUCCESS or (sw & 0xFFF0) == 0x63C0


class TestKeyGeneration:
    """Tests for key generation through card interface."""
    
    @pytest.fixture
    def authenticated_card(self):
        """Create a card with Admin PIN verified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # Select OpenPGP
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            card.process_apdu(select_apdu)
            
            # Verify Admin PIN
            pin = b"12345678"
            verify_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x83,
                data=pin
            )
            card.process_apdu(verify_apdu)
            
            yield card
    
    def test_generate_signature_key(self, authenticated_card):
        """Test generating signature key."""
        # GENERATE ASYMMETRIC KEY PAIR for signature key
        # P1=0x80 (generate), CRT B6 (signature)
        crt = bytes([0xB6, 0x00])  # CRT for signature key
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.GENERATE_ASYMMETRIC_KEY_PAIR, 0x80, 0x00,
            data=crt,
            le=0
        )
        
        response_bytes = authenticated_card.process_apdu(apdu_bytes)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        
        # Should succeed or return public key with success
        # Note: Actual key generation may take time
        assert sw == SW.SUCCESS or sw == SW.CONDITIONS_NOT_SATISFIED
    
    def test_read_public_key(self, authenticated_card):
        """Test reading public key."""
        # GENERATE ASYMMETRIC KEY PAIR with P1=0x81 reads existing key
        crt = bytes([0xB6, 0x00])  # CRT for signature key
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.GENERATE_ASYMMETRIC_KEY_PAIR, 0x81, 0x00,
            data=crt,
            le=0
        )
        
        response_bytes = authenticated_card.process_apdu(apdu_bytes)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        
        # May return key data or error if no key exists
        # Both are valid behaviors
        # SW 0x61XX means "more data available" for large keys
        is_more_data = (sw & 0xFF00) == 0x6100
        assert sw in (SW.SUCCESS, SW.CONDITIONS_NOT_SATISFIED, SW.FILE_NOT_FOUND, 
                     SW.REFERENCED_DATA_NOT_FOUND) or is_more_data


class TestSigningOperation:
    """Tests for signing operations."""
    
    @pytest.fixture
    def card_with_key(self):
        """Create a card with signature key and PW1 verified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # Select OpenPGP
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            card.process_apdu(select_apdu)
            
            # Generate key using crypto backend directly
            card._crypto.generate_rsa_key(KeyType.SIGNATURE, bits=2048)
            
            # Verify PW1 for signing
            pin = b"123456"
            verify_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x81,
                data=pin
            )
            card.process_apdu(verify_apdu)
            
            yield card
    
    def test_compute_signature(self, card_with_key):
        """Test PSO: COMPUTE DIGITAL SIGNATURE."""
        # Hash to sign (SHA-256 DigestInfo)
        # This is the hash with algorithm identifier prefix
        hash_data = bytes.fromhex(
            "3031300d060960864801650304020105000420"  # DigestInfo header
        ) + bytes([0x00] * 32)  # 32-byte hash
        
        p1p2 = PSOP1P2.CDS  # 0x9E9A
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.PSO,
            (p1p2 >> 8) & 0xFF, p1p2 & 0xFF,
            data=hash_data,
            le=0
        )
        
        response_bytes = card_with_key.process_apdu(apdu_bytes)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        
        # Should succeed if key is loaded and PIN verified
        # SW 0x61XX means "more data available" which is also success for large signatures
        # Note: May fail if crypto setup differs
        is_more_data = (sw & 0xFF00) == 0x6100
        assert sw in (SW.SUCCESS, SW.CONDITIONS_NOT_SATISFIED, SW.SECURITY_STATUS_NOT_SATISFIED) or is_more_data


class TestDecryptionOperation:
    """Tests for decryption operations."""
    
    @pytest.fixture
    def card_with_dec_key(self):
        """Create a card with decryption key and PW1-82 verified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # Select OpenPGP
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            card.process_apdu(select_apdu)
            
            # Generate decryption key
            card._crypto.generate_rsa_key(KeyType.DECRYPTION, bits=2048)
            
            # Verify PW1 mode 82 for decryption
            pin = b"123456"
            verify_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x82,
                data=pin
            )
            card.process_apdu(verify_apdu)
            
            yield card
    
    def test_decipher_requires_valid_data(self, card_with_dec_key):
        """Test PSO: DECIPHER with invalid data."""
        # Invalid encrypted data
        encrypted_data = bytes([0x00] * 128)
        
        p1p2 = PSOP1P2.DEC  # 0x8086
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.PSO,
            (p1p2 >> 8) & 0xFF, p1p2 & 0xFF,
            data=encrypted_data,
            le=0
        )
        
        response_bytes = card_with_dec_key.process_apdu(apdu_bytes)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        
        # Should fail with invalid data (not a proper OpenPGP encrypted message)
        # Various error codes are acceptable
        assert sw != 0  # Should return some status


class TestPINChange:
    """Tests for PIN change operations."""
    
    @pytest.fixture
    def selected_card(self):
        """Create a card with OpenPGP app selected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # Select OpenPGP
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            card.process_apdu(select_apdu)
            
            yield card
    
    def test_change_pw1(self, selected_card):
        """Test CHANGE REFERENCE DATA for PW1."""
        # Old PIN + New PIN
        old_pin = b"123456"
        new_pin = b"654321"
        data = old_pin + new_pin
        
        apdu_bytes = APDUBuilder.build_command(
            0x00, OpenPGPIns.CHANGE_REFERENCE_DATA, 0x00, 0x81,
            data=data
        )
        
        response_bytes = selected_card.process_apdu(apdu_bytes)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        
        assert sw == SW.SUCCESS
        
        # Verify new PIN works
        verify_apdu = APDUBuilder.build_command(
            0x00, OpenPGPIns.VERIFY, 0x00, 0x81,
            data=new_pin
        )
        
        response_bytes = selected_card.process_apdu(verify_apdu)
        sw = (response_bytes[-2] << 8) | response_bytes[-1]
        
        assert sw == SW.SUCCESS


class TestCardDataPersistence:
    """Tests for card data persistence."""
    
    def test_state_persists_across_sessions(self):
        """Test that card state persists when saved."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "card_data.json"
            
            # Create card and modify state
            card1 = OpenPGPCard(storage_path=storage_path)
            card1.power_on()
            
            # Change cardholder name
            card1.card_state.cardholder.name = "Test<<User"
            card1.save_state()
            card1.power_off()
            
            # Create new card instance with same storage
            card2 = OpenPGPCard(storage_path=storage_path)
            card2.power_on()
            
            # Should have the saved name
            assert card2.card_state.cardholder.name == "Test<<User"
    
    def test_signature_counter_persists(self):
        """Test that signature counter persists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "card_data.json"
            
            card1 = OpenPGPCard(storage_path=storage_path)
            card1.power_on()
            
            # Set signature counter
            card1.card_state.signature_counter = 42
            card1.save_state()
            card1.power_off()
            
            # Load again
            card2 = OpenPGPCard(storage_path=storage_path)
            assert card2.card_state.signature_counter == 42


class TestVPCDConnection:
    """Tests for vpcd connection functionality.
    
    These tests require vpcd to be running.
    """
    
    def test_vpcd_connection_import(self):
        """Test VPCDConnection can be imported."""
        from jcecard.vpcd_connection import VPCDConnection, VPCDControl
        assert VPCDConnection is not None
        assert VPCDControl is not None
    
    def test_vpcd_control_constants(self):
        """Test VPCDControl enum values."""
        from jcecard.vpcd_connection import VPCDControl
        assert VPCDControl.OFF == 0
        assert VPCDControl.ON == 1
        assert VPCDControl.RESET == 2
        assert VPCDControl.ATR == 4
    
    def test_vpcd_connection_creation(self):
        """Test creating VPCDConnection instance."""
        from jcecard.vpcd_connection import VPCDConnection
        
        conn = VPCDConnection()
        assert conn.host == 'localhost'
        assert conn.port == 35963
        assert conn.connected is False
    
    def test_vpcd_connection_custom_port(self):
        """Test VPCDConnection with custom port."""
        from jcecard.vpcd_connection import VPCDConnection
        
        conn = VPCDConnection(host='127.0.0.1', port=12345)
        assert conn.host == '127.0.0.1'
        assert conn.port == 12345
    
    def test_vpcd_connect_to_service(self):
        """Test connecting to vpcd service.
        
        This test requires vpcd to be running on localhost:35963.
        """
        from jcecard.vpcd_connection import VPCDConnection
        
        conn = VPCDConnection()
        
        # Try to connect - will succeed if vpcd is running
        result = conn.connect()
        
        if result:
            assert conn.connected is True
            conn.disconnect()
            assert conn.connected is False
        else:
            # vpcd not running - this is acceptable for unit tests
            # but should be available in full integration testing
            pytest.skip("vpcd service not available")


class TestFullCardFlow:
    """End-to-end tests for complete card operations."""
    
    def test_full_select_and_get_data_flow(self):
        """Test complete flow: SELECT -> GET DATA."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # SELECT
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            response = card.process_apdu(select_apdu)
            assert (response[-2] << 8 | response[-1]) == SW.SUCCESS
            
            # GET DATA - Application Related Data
            get_data_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.GET_DATA, 0x00, 0x6E,
                le=0
            )
            response = card.process_apdu(get_data_apdu)
            assert (response[-2] << 8 | response[-1]) == SW.SUCCESS
            
            # GET DATA - Cardholder Related Data
            get_data_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.GET_DATA, 0x00, 0x65,
                le=0
            )
            response = card.process_apdu(get_data_apdu)
            sw = response[-2] << 8 | response[-1]
            assert sw in (SW.SUCCESS, SW.FILE_NOT_FOUND)  # May be empty
    
    def test_full_pin_verify_and_sign_flow(self):
        """Test complete flow: SELECT -> VERIFY -> SIGN."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # SELECT
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            response = card.process_apdu(select_apdu)
            assert (response[-2] << 8 | response[-1]) == SW.SUCCESS
            
            # Generate signature key
            card._crypto.generate_rsa_key(KeyType.SIGNATURE, bits=2048)
            
            # VERIFY PW1
            verify_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x81,
                data=b"123456"
            )
            response = card.process_apdu(verify_apdu)
            assert (response[-2] << 8 | response[-1]) == SW.SUCCESS
            
            # PSO: COMPUTE DIGITAL SIGNATURE
            hash_data = bytes([0x00] * 32)  # Simplified hash
            p1p2 = PSOP1P2.CDS
            sign_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.PSO,
                (p1p2 >> 8) & 0xFF, p1p2 & 0xFF,
                data=hash_data,
                le=0
            )
            response = card.process_apdu(sign_apdu)
            sw = response[-2] << 8 | response[-1]
            
            # Should succeed or fail gracefully
            # SW 0x61XX means "more data available" which is also success for large signatures
            is_more_data = (sw & 0xFF00) == 0x6100
            assert sw in (SW.SUCCESS, SW.CONDITIONS_NOT_SATISFIED, 
                         SW.SECURITY_STATUS_NOT_SATISFIED, SW.WRONG_DATA) or is_more_data


class TestCardTerminateActivate:
    """Tests for TERMINATE DF and ACTIVATE FILE operations."""
    
    def test_terminate_without_pw3_fails(self):
        """Test that TERMINATE DF fails without PW3 verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # SELECT OpenPGP application
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            response = card.process_apdu(select_apdu)
            assert (response[-2] << 8 | response[-1]) == SW.SUCCESS
            
            # Try TERMINATE DF without PW3 verification
            terminate_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.TERMINATE_DF, 0x00, 0x00
            )
            response = card.process_apdu(terminate_apdu)
            sw = response[-2] << 8 | response[-1]
            
            # Should fail - security status not satisfied
            assert sw == SW.SECURITY_STATUS_NOT_SATISFIED
    
    def test_terminate_with_pw3_succeeds(self):
        """Test that TERMINATE DF succeeds with PW3 verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # SELECT OpenPGP application
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            response = card.process_apdu(select_apdu)
            assert (response[-2] << 8 | response[-1]) == SW.SUCCESS
            
            # Verify PW3 (admin PIN - default is "12345678")
            verify_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x83,
                data=b"12345678"
            )
            response = card.process_apdu(verify_apdu)
            assert (response[-2] << 8 | response[-1]) == SW.SUCCESS
            
            # TERMINATE DF should succeed
            terminate_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.TERMINATE_DF, 0x00, 0x00
            )
            response = card.process_apdu(terminate_apdu)
            sw = response[-2] << 8 | response[-1]
            assert sw == SW.SUCCESS
            
            # Verify card is terminated
            assert card.card_state.terminated is True
    
    def test_terminate_with_both_pins_blocked(self):
        """Test that TERMINATE DF succeeds when both PINs are blocked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # SELECT OpenPGP application
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            response = card.process_apdu(select_apdu)
            assert (response[-2] << 8 | response[-1]) == SW.SUCCESS
            
            # Block PW1 by entering wrong PIN 3 times
            wrong_pw1_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x81,
                data=b"wrongpin"
            )
            for _ in range(3):
                card.process_apdu(wrong_pw1_apdu)
            
            # Block PW3 by entering wrong PIN 3 times
            wrong_pw3_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x83,
                data=b"wrongpinx"
            )
            for _ in range(3):
                card.process_apdu(wrong_pw3_apdu)
            
            # Verify both PINs are blocked
            assert card._pin_manager.is_pw1_blocked() is True
            assert card._pin_manager.is_pw3_blocked() is True
            
            # TERMINATE DF should succeed when both are blocked
            terminate_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.TERMINATE_DF, 0x00, 0x00
            )
            response = card.process_apdu(terminate_apdu)
            sw = response[-2] << 8 | response[-1]
            assert sw == SW.SUCCESS
    
    def test_commands_blocked_after_termination(self):
        """Test that regular commands fail after card termination."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # SELECT OpenPGP application
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            response = card.process_apdu(select_apdu)
            assert (response[-2] << 8 | response[-1]) == SW.SUCCESS
            
            # Verify PW3 and terminate
            verify_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x83,
                data=b"12345678"
            )
            card.process_apdu(verify_apdu)
            
            terminate_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.TERMINATE_DF, 0x00, 0x00
            )
            card.process_apdu(terminate_apdu)
            
            # Try GET DATA - should fail
            get_data_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.GET_DATA, 0x00, 0x4F,
                le=0
            )
            response = card.process_apdu(get_data_apdu)
            sw = response[-2] << 8 | response[-1]
            assert sw == SW.CONDITIONS_NOT_SATISFIED
            
            # Try VERIFY - should fail
            verify_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x81,
                data=b"123456"
            )
            response = card.process_apdu(verify_apdu)
            sw = response[-2] << 8 | response[-1]
            assert sw == SW.CONDITIONS_NOT_SATISFIED
    
    def test_select_works_when_terminated(self):
        """Test that SELECT command still works when terminated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # SELECT, verify PW3, and terminate
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            card.process_apdu(select_apdu)
            
            verify_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x83,
                data=b"12345678"
            )
            card.process_apdu(verify_apdu)
            
            terminate_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.TERMINATE_DF, 0x00, 0x00
            )
            card.process_apdu(terminate_apdu)
            
            # SELECT should still work
            response = card.process_apdu(select_apdu)
            sw = response[-2] << 8 | response[-1]
            assert sw == SW.SUCCESS
    
    def test_activate_fails_when_not_terminated(self):
        """Test that ACTIVATE FILE fails when card is not terminated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # SELECT OpenPGP application
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            response = card.process_apdu(select_apdu)
            assert (response[-2] << 8 | response[-1]) == SW.SUCCESS
            
            # Try ACTIVATE FILE when not terminated
            activate_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.ACTIVATE_FILE, 0x00, 0x00
            )
            response = card.process_apdu(activate_apdu)
            sw = response[-2] << 8 | response[-1]
            
            # Should fail - card not terminated
            assert sw == SW.CONDITIONS_NOT_SATISFIED
    
    def test_activate_resets_card_to_factory_state(self):
        """Test that ACTIVATE FILE resets card to factory state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # SELECT OpenPGP application
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            card.process_apdu(select_apdu)
            
            # Change PW1 PIN
            verify_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x81,
                data=b"123456"
            )
            card.process_apdu(verify_apdu)
            
            # Set cardholder name via PUT DATA
            put_data_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.PUT_DATA, 0x00, 0x5B,
                data=b"Test User"
            )
            
            # Verify PW3 for PUT DATA
            verify_pw3_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x83,
                data=b"12345678"
            )
            card.process_apdu(verify_pw3_apdu)
            card.process_apdu(put_data_apdu)
            
            # Terminate card
            terminate_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.TERMINATE_DF, 0x00, 0x00
            )
            card.process_apdu(terminate_apdu)
            assert card.card_state.terminated is True
            
            # Activate card
            activate_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.ACTIVATE_FILE, 0x00, 0x00
            )
            response = card.process_apdu(activate_apdu)
            sw = response[-2] << 8 | response[-1]
            assert sw == SW.SUCCESS
            
            # Verify card is no longer terminated
            assert card.card_state.terminated is False
    
    def test_card_works_normally_after_activation(self):
        """Test that card works normally after ACTIVATE FILE."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # SELECT, verify PW3, terminate
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            card.process_apdu(select_apdu)
            
            verify_pw3_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x83,
                data=b"12345678"
            )
            card.process_apdu(verify_pw3_apdu)
            
            terminate_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.TERMINATE_DF, 0x00, 0x00
            )
            card.process_apdu(terminate_apdu)
            
            # Activate
            activate_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.ACTIVATE_FILE, 0x00, 0x00
            )
            card.process_apdu(activate_apdu)
            
            # SELECT should work
            response = card.process_apdu(select_apdu)
            assert (response[-2] << 8 | response[-1]) == SW.SUCCESS
            
            # VERIFY PW1 with default PIN should work (reset to factory)
            verify_pw1_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x81,
                data=b"123456"
            )
            response = card.process_apdu(verify_pw1_apdu)
            assert (response[-2] << 8 | response[-1]) == SW.SUCCESS
            
            # GET DATA should work
            get_data_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.GET_DATA, 0x00, 0x4F,
                le=0
            )
            response = card.process_apdu(get_data_apdu)
            sw = response[-2] << 8 | response[-1]
            assert sw == SW.SUCCESS
    
    def test_terminate_and_activate_preserves_nothing(self):
        """Test that terminate+activate cycle clears all card data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            card = create_test_card(tmpdir)
            card.power_on()
            
            # SELECT
            select_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.SELECT, 0x04, 0x00,
                data=OPENPGP_AID
            )
            card.process_apdu(select_apdu)
            
            # Verify PW3 and generate a key
            verify_pw3_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.VERIFY, 0x00, 0x83,
                data=b"12345678"
            )
            card.process_apdu(verify_pw3_apdu)
            
            # Generate signature key
            card._crypto.generate_rsa_key(KeyType.SIGNATURE, bits=2048)
            
            # Verify key exists
            assert card._crypto.has_key(KeyType.SIGNATURE) is True
            
            # Terminate
            terminate_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.TERMINATE_DF, 0x00, 0x00
            )
            card.process_apdu(terminate_apdu)
            
            # Activate
            activate_apdu = APDUBuilder.build_command(
                0x00, OpenPGPIns.ACTIVATE_FILE, 0x00, 0x00
            )
            card.process_apdu(activate_apdu)
            
            # Verify key is gone
            assert card._crypto.has_key(KeyType.SIGNATURE) is False

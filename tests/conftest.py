"""
Pytest configuration and fixtures for OpenPGP card tests.
"""

import pytest
import pexpect
import time
from dataclasses import dataclass, field
from typing import Optional
import hashlib


# Import modules to test
from jcecard.card_data import CardState, PINData, CardholderData, KeySlot, AlgorithmAttributes
from jcecard.pin_manager import PINManager


@pytest.fixture
def jcecard_process():
    """
    Fixture that starts jcecard as a child process using pexpect.
    
    Yields the pexpect child process and cleans up on exit.
    Skips the test if vpcd is not available or jcecard fails to connect.
    
    Note: vpcd may stop listening if no card has connected recently.
    Restarting pcscd (sudo systemctl restart pcscd) will restart vpcd.
    """
    # Start jcecard as a child process using python -c to call run_card
    child = pexpect.spawn(
        'python', ['-c', 'from jcecard.main import run_card; run_card()'],
        encoding='utf-8',
        timeout=30
    )
    
    # Wait for the card to connect to vpcd
    try:
        child.expect('Connected to vpcd', timeout=5)
    except pexpect.TIMEOUT:
        child.terminate(force=True)
        pytest.skip("jcecard failed to connect to vpcd - vpcd may not be running. Try: sudo systemctl restart pcscd")
    except pexpect.EOF:
        output = child.before or ""
        if "Connection refused" in output or "Failed to connect" in output:
            pytest.skip("vpcd service not available - try: sudo systemctl restart pcscd")
        pytest.fail(f"jcecard terminated unexpectedly: {output}")
    
    # Give pcscd time to detect the card
    time.sleep(1)
    
    yield child
    
    # Cleanup: terminate the child process
    if child.isalive():
        child.terminate(force=True)
        child.wait()


@pytest.fixture
def default_pin_data():
    """Create PINData with default PINs (123456 / 12345678)."""
    pin_data = PINData()
    pin_data.pw1_hash = hashlib.sha256(b"123456").digest()
    pin_data.pw1_length = 6
    pin_data.pw3_hash = hashlib.sha256(b"12345678").digest()
    pin_data.pw3_length = 8
    return pin_data


@pytest.fixture
def card_state(default_pin_data):
    """Create a CardState with default PINs configured."""
    state = CardState()
    state.pin_data = default_pin_data
    return state


@pytest.fixture
def pin_manager(card_state):
    """Create a PINManager with default card state."""
    return PINManager(card_state)


@pytest.fixture
def sample_tlv_data():
    """Sample TLV data for testing."""
    return {
        # Simple TLV: tag=0x5F50 (URL), length=10, value="example.com"
        "simple": bytes.fromhex("5F500A6578616D706C652E636F6D"),  # URL DO
        # Constructed TLV: Application Related Data (6E)
        "constructed": bytes.fromhex("6E0A5F500762696E617279"),
        # Nested TLV structure
        "nested": bytes.fromhex(
            "6E"  # Application Related Data
            "12"  # Length = 18
            "4F07"  # AID tag, length 7
            "D276000124010304"  # AID value
            "5F500B"  # URL tag, length 11
            "6578616D706C652E636F6D"  # URL value
        ),
    }


@pytest.fixture
def sample_apdu_commands():
    """Sample APDU command bytes for testing."""
    return {
        # SELECT by AID
        "select": bytes.fromhex("00A4040006D27600012401"),
        # VERIFY PW1 (mode 81) with PIN "123456"
        "verify_pw1": bytes.fromhex("00200081063132333435360000"),
        # GET DATA (Application Related Data)
        "get_data": bytes.fromhex("00CA006E00"),
        # Case 1: No data in, no data expected
        "case1": bytes.fromhex("00C00000"),
        # Case 2: No data in, Le bytes expected
        "case2": bytes.fromhex("00CA006E00"),
        # Case 3: Data in, no response data expected
        "case3": bytes.fromhex("00DA005E04DEADBEEF"),
        # Case 4: Data in, response expected
        "case4": bytes.fromhex("002A9E9A0B48656C6C6F576F726C6400"),
    }


@pytest.fixture
def sample_apdu_responses():
    """Sample APDU response bytes for testing."""
    return {
        # Success
        "success": bytes.fromhex("9000"),
        # Success with data
        "success_with_data": bytes.fromhex("DEADBEEF9000"),
        # Wrong PIN (2 tries remaining)
        "wrong_pin_2": bytes.fromhex("63C2"),
        # PIN blocked
        "pin_blocked": bytes.fromhex("6983"),
        # File not found
        "not_found": bytes.fromhex("6A82"),
        # Wrong length
        "wrong_length": bytes.fromhex("6700"),
        # More data available
        "more_data": bytes.fromhex("6110"),
    }

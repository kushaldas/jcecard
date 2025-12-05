"""
Tests for reset_yubikey() functionality with the virtual card.

These tests verify that johnnycanencrypt's reset_yubikey() function
works correctly with our virtual OpenPGP card implementation.

Prerequisites:
- vpcd service must be running (sudo apt install vsmartcard-vpcd)
- pcscd must be restarted after vpcd install (sudo systemctl restart pcscd)
"""

import pytest


class TestResetYubikey:
    """Tests for reset_yubikey() functionality."""

    def test_reset_yubikey_and_set_name(self, jcecard_process):
        """
        Test that reset_yubikey() works and the card functions after reset.

        This test:
        1. Uses the jcecard_process fixture to start the virtual card
        2. Calls reset_yubikey() which terminates and activates the card
        3. Sets the cardholder name on the card (verifies admin PIN works)
        """
        from johnnycanencrypt import johnnycanencrypt as rjce

        # Reset the card using johnnycanencrypt
        # This sends: SELECT -> 3 wrong PW1 -> 3 wrong PW3 -> TERMINATE -> ACTIVATE
        rjce.reset_yubikey()

        # After reset, the card process should still be running, and in the output we can see "Card activated - reset to factory defaults"
        jcecard_process.expect("Card activated - reset to factory defaults", timeout=5)

        # Now set the cardholder name using the admin PIN
        # Default admin PIN after reset is "12345678"
        # If this succeeds, it proves:
        # 1. reset_yubikey() worked (card is in factory state)
        # 2. Admin PIN verification works
        # 3. PUT DATA command works
        test_name = b"Test User"
        rjce.set_name(test_name, b"12345678")

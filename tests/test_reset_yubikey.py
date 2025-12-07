"""
Tests for reset_yubikey() functionality with the virtual card.

These tests verify that johnnycanencrypt's reset_yubikey() function
works correctly with our virtual OpenPGP card implementation.

Prerequisites:
- jcecard TCP server must be running (python -m jcecard.tcp_server --debug)
- pcscd must be running with the IFD handler installed
"""



class TestResetYubikey:
    """Tests for reset_yubikey() functionality."""

    def test_reset_yubikey_and_set_name(self, jcecard_process):
        """
        Test that reset_yubikey() works and the card functions after reset.

        This test:
        1. Uses the jcecard_process fixture to verify the virtual card is available
        2. Calls reset_yubikey() which terminates and activates the card
        3. Sets the cardholder name on the card (verifies admin PIN works)
        4. Verifies the name was set by reading card details
        """
        from johnnycanencrypt import johnnycanencrypt as rjce

        # Reset the card using johnnycanencrypt
        # This sends: SELECT -> 3 wrong PW1 -> 3 wrong PW3 -> TERMINATE -> ACTIVATE
        rjce.reset_yubikey()

        # Now set the cardholder name using the admin PIN
        # Default admin PIN after reset is "12345678"
        # If this succeeds, it proves:
        # 1. reset_yubikey() worked (card is in factory state)
        # 2. Admin PIN verification works
        # 3. PUT DATA command works
        test_name = b"Test User"
        rjce.set_name(test_name, b"12345678")
        
        # Verify the name was actually set by reading card details
        details = rjce.get_card_details()
        assert details.get("name") == "Test User", f"Name not set correctly: {details.get('name')}"

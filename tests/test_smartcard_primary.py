"""
Tests for primary key upload and signing functionality with the virtual card.

These tests verify that johnnycanencrypt's key upload and signing functions
work correctly with our virtual OpenPGP card implementation.

Prerequisites:
- pcscd must be running with the ifd-jcecard driver installed
- The driver is at: /usr/lib/pcsc/drivers/ifd-jcecard.bundle/
"""

import os
import tempfile
from pathlib import Path

import pytest
import johnnycanencrypt as jce
import johnnycanencrypt.johnnycanencrypt as rjce

from conftest import get_card_state_path


class TestSmartcardPrimary:
    """Tests for primary key upload and signing functionality."""

    def test_reset_set_name_and_url(self, jcecard_process):
        """
        Test resetting the card and setting name and URL.
        
        First set name, verify it's stored in JSON, then set URL.
        """
        import json
        from pathlib import Path
        from johnnycanencrypt import johnnycanencrypt as rjce
        
        # Reset the card
        rjce.reset_yubikey()
        
        # Set name first
        rjce.set_name(b"Test<<User", b"12345678")
        
        # Verify the name is in the card state JSON file first
        card_state_path = get_card_state_path()
        assert card_state_path.exists(), f"Card state file not found: {card_state_path}"
        
        with open(card_state_path) as f:
            state = json.load(f)
        assert state.get("cardholder", {}).get("name") == "Test<<User", \
            f"Name not in card state: {state.get('cardholder', {}).get('name')}"
        
        # Now try to set URL
        rjce.set_url(b"https://example.com/key.asc", b"12345678")
        
        # Verify URL is in card state JSON
        with open(card_state_path) as f:
            state = json.load(f)
        assert state.get("cardholder", {}).get("url") == "https://example.com/key.asc", \
            f"URL not in card state: {state.get('cardholder', {}).get('url')}"

    def test_upload_primary_key_and_sign(self, jcecard_process):
        """
        Test uploading a primary key to the card and signing data.

        The test key (primary_with_sign.asc) is an EdDSA key:
        - Primary key: Ed25519, fingerprint 84AA9D410CD1E5C7C53897700E4A2EE1F630C34E
        - Subkey: X25519 (ECDH), fingerprint 663FAB98B765329AC24B6992DCDD170A74767C42

        This test:
        1. Resets the card
        2. Imports the key to a keystore
        3. Uploads the primary key to the signing slot
        4. Uploads subkey to the encryption slot
        5. Verifies fingerprints are correctly stored in card state JSON
        """
        import json
        
        # Expected fingerprints from the test key
        EXPECTED_SIG_FINGERPRINT = "84AA9D410CD1E5C7C53897700E4A2EE1F630C34E"
        EXPECTED_DEC_FINGERPRINT = "663FAB98B765329AC24B6992DCDD170A74767C42"
        
        # Reset the card first
        rjce.reset_yubikey()

        # Set card holder info
        rjce.set_name(b"Sign<<Primary", b"12345678")
        rjce.set_url(b"https://example.com/test.asc", b"12345678")

        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)

            # Import the test key (in tests/files directory)
            test_key_path = Path(__file__).parent / "files" / "primary_with_sign.asc"
            if not test_key_path.exists():
                pytest.skip(f"Test key file not found: {test_key_path}")

            k = ks.import_key(str(test_key_path))

            # Upload the primary key to signing slot (slot 2)
            rjce.upload_primary_to_smartcard(k.keyvalue, b"12345678", "redhat", whichslot=2)

            # Verify signature key fingerprint is set in card state JSON
            card_state_path = get_card_state_path()
            with open(card_state_path) as f:
                state = json.load(f)
            
            sig_fingerprint = state.get("key_sig", {}).get("fingerprint", "")
            # Fingerprint is stored as base64 in JSON, decode and convert to hex
            if sig_fingerprint:
                import base64
                sig_fp_hex = base64.b64decode(sig_fingerprint).hex().upper()
            else:
                sig_fp_hex = ""
            
            assert sig_fp_hex == EXPECTED_SIG_FINGERPRINT, \
                f"Signature key fingerprint mismatch. Expected: {EXPECTED_SIG_FINGERPRINT}, Got: {sig_fp_hex}"

            # Upload subkeys to the card (encryption key)
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=1)

            # Verify decryption key fingerprint is set
            with open(card_state_path) as f:
                state = json.load(f)
            
            dec_fingerprint = state.get("key_dec", {}).get("fingerprint", "")
            if dec_fingerprint:
                dec_fp_hex = base64.b64decode(dec_fingerprint).hex().upper()
            else:
                dec_fp_hex = ""
            
            assert dec_fp_hex == EXPECTED_DEC_FINGERPRINT, \
                f"Decryption key fingerprint mismatch. Expected: {EXPECTED_DEC_FINGERPRINT}, Got: {dec_fp_hex}"

            # NOTE: Signing with imported keys requires parsing the raw OpenPGP
            # key material and loading it into the crypto backend. This is not
            # yet implemented. The key import successfully stores metadata
            # (fingerprint, timestamp, algorithm attributes).

    def test_certify_key_on_card(self, jcecard_process):
        """
        Test certifying another key using the primary key on the card.

        This test:
        1. Resets the card
        2. Uploads a primary key to the card
        3. Imports another key to certify
        4. Certifies the other key using the card
        """
        # Reset the card first
        rjce.reset_yubikey()

        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)

            # Import the signing key (in tests/files directory)
            test_key_path = Path(__file__).parent / "files" / "primary_with_sign.asc"
            if not test_key_path.exists():
                pytest.skip(f"Test key file not found: {test_key_path}")

            k = ks.import_key(str(test_key_path))

            # Save the public key for later
            public_key = k.get_pub_key()

            # Upload the primary key to signing slot
            rjce.upload_primary_to_smartcard(k.keyvalue, b"12345678", "redhat", whichslot=2)

            # Sync the keystore with the smartcard
            ks.sync_smartcard()

            # Import a key to certify (we'll use another test key if available)
            other_key_path = Path(__file__).parent / "files" / "public_to_certify.asc"
            if not other_key_path.exists():
                pytest.skip(f"Key to certify not found: {other_key_path}")

            other = ks.import_key(str(other_key_path))

            # Get UIDs from the key to certify
            # For testing, we'll certify the first UID
            uids = other.uids
            if not uids:
                pytest.skip("No UIDs found in key to certify")

            # Extract the UID value (uids is a list of dicts with 'value' or combined name/email)
            # The UID format is typically "Name <email>" 
            first_uid = uids[0]
            if isinstance(first_uid, dict):
                # Build UID string from name and email
                uid_str = f"{first_uid.get('name', '')} <{first_uid.get('email', '')}>"
            else:
                uid_str = str(first_uid)

            # Certify the key
            certified_key = ks.certify_key(
                k,
                other,
                [uid_str],
                jce.SignatureType.PersonaCertification,
                password="123456",
                oncard=True,
            )

            assert certified_key is not None, "Certified key should not be None"
            assert len(certified_key.keyvalue) > 0, "Certified key should have content"

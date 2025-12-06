"""
Tests for signing functionality with the virtual card.

These tests verify that johnnycanencrypt's signing functions
work correctly with our virtual OpenPGP card implementation.
"""

import json
import tempfile
from pathlib import Path

import pytest
import johnnycanencrypt as jce
import johnnycanencrypt.johnnycanencrypt as rjce

from conftest import get_card_state_path


class TestSmartcardSign:
    """Tests for signing operations."""

    def test_sign_with_uploaded_cv25519_key(self, jcecard_process):
        """
        Test signing data with an uploaded Cv25519 key.
        
        Steps:
        1. Reset card
        2. Upload Cv25519 key (signature + encryption + auth subkeys)
        3. Sign test data using card
        4. Verify signature using public key
        """
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            # Import Cv25519 test key
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.sec"
            if not test_key_path.exists():
                pytest.skip(f"Test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            # Reset and upload keys
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            # New keystore with public key only
            with tempfile.TemporaryDirectory() as tempdir2:
                ks2 = jce.KeyStore(tempdir2)
                pub_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.pub"
                k2 = ks2.import_key(str(pub_key_path))
                
                # Test data to sign
                msg = b"Test message for signing on virtual card"
                
                # Sign on card
                signature = rjce.sign_bytes_detached_on_card(k2.keyvalue, msg, b"123456")
                
                assert signature is not None
                assert len(signature) > 0
                
                # Verify signature
                result = ks2.verify(k2, msg, signature)
                assert result is True, "Signature verification failed"

    def test_sign_increments_counter(self, jcecard_process):
        """
        Test that signing increments the signature counter.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            # Import test key
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.sec"
            if not test_key_path.exists():
                pytest.skip(f"Test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            # Reset and upload keys
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            # Get initial counter from card state
            card_state_path = get_card_state_path()
            with open(card_state_path) as f:
                state = json.load(f)
            initial_count = state.get("signature_counter", 0)
            
            # New keystore with public key only
            with tempfile.TemporaryDirectory() as tempdir2:
                ks2 = jce.KeyStore(tempdir2)
                pub_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.pub"
                k2 = ks2.import_key(str(pub_key_path))
                
                # Sign data
                msg = b"Counter test message"
                rjce.sign_bytes_detached_on_card(k2.keyvalue, msg, b"123456")
            
            # Check counter incremented
            with open(card_state_path) as f:
                state = json.load(f)
            assert state.get("signature_counter", 0) == initial_count + 1

    def test_sign_multiple_messages(self, jcecard_process):
        """
        Test signing multiple messages in sequence.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            # Import test key
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.sec"
            if not test_key_path.exists():
                pytest.skip(f"Test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            # Reset and upload keys
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            # New keystore with public key
            with tempfile.TemporaryDirectory() as tempdir2:
                ks2 = jce.KeyStore(tempdir2)
                pub_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.pub"
                k2 = ks2.import_key(str(pub_key_path))
                
                messages = [
                    b"First message",
                    b"Second message with more content",
                    b"Third message",
                ]
                
                for msg in messages:
                    signature = rjce.sign_bytes_detached_on_card(k2.keyvalue, msg, b"123456")
                    assert signature is not None
                    assert len(signature) > 0
                    assert ks2.verify(k2, msg, signature), f"Verification failed for: {msg}"

    def test_fingerprints_after_upload(self, jcecard_process):
        """
        Test that fingerprints are correctly stored after key upload.
        """
        import base64
        
        # Expected fingerprints for Cv25519 test key
        EXPECTED_SIG_FP = "30A697C27F90EAED0B78C8235E0BDC772A2CF037"
        EXPECTED_ENC_FP = "5D22EC7757DF42ED9C21AC9E7020C6D7B564D455"
        EXPECTED_AUTH_FP = "50BAC98D4ADFD5D4485A1B04DEECB8B1546ED530"
        
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.sec"
            if not test_key_path.exists():
                pytest.skip(f"Test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            # Reset and upload all keys
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            # Verify fingerprints in card state
            card_state_path = get_card_state_path()
            with open(card_state_path) as f:
                state = json.load(f)
            
            sig_fp = base64.b64decode(state["key_sig"]["fingerprint"]).hex().upper()
            enc_fp = base64.b64decode(state["key_dec"]["fingerprint"]).hex().upper()
            auth_fp = base64.b64decode(state["key_aut"]["fingerprint"]).hex().upper()
            
            assert sig_fp == EXPECTED_SIG_FP, f"Sig fingerprint mismatch: {sig_fp}"
            assert enc_fp == EXPECTED_ENC_FP, f"Enc fingerprint mismatch: {enc_fp}"
            assert auth_fp == EXPECTED_AUTH_FP, f"Auth fingerprint mismatch: {auth_fp}"

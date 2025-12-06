"""
Tests for encryption and decryption functionality with the virtual card.

These tests verify that johnnycanencrypt's encryption/decryption functions
work correctly with our virtual OpenPGP card implementation.
"""

import json
import tempfile
from pathlib import Path

import pytest
import johnnycanencrypt as jce
import johnnycanencrypt.johnnycanencrypt as rjce

from conftest import get_card_state_path


class TestSmartcardEncryptDecrypt:
    """Tests for encryption and decryption operations."""

    def test_encrypt_and_decrypt_cv25519(self, jcecard_process):
        """
        Test encrypting data with public key and decrypting on card.
        
        Steps:
        1. Reset card
        2. Upload Cv25519 keys to card
        3. Encrypt data using public key (in software)
        4. Decrypt on card using private key
        5. Verify decrypted data matches original
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
            
            # New keystore with public key only for encryption
            with tempfile.TemporaryDirectory() as tempdir2:
                ks2 = jce.KeyStore(tempdir2)
                pub_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.pub"
                k2 = ks2.import_key(str(pub_key_path))
                
                # Original message
                msg = b"Secret message for decryption test"
                
                # Encrypt with public key
                encrypted: bytes = ks2.encrypt([k2], msg)  # type: ignore[assignment]
                assert encrypted is not None
                assert b"BEGIN PGP MESSAGE" in encrypted
                
                # Decrypt on card
                decrypted = rjce.decrypt_bytes_on_card(k2.keyvalue, encrypted, b"123456")  # type: ignore[arg-type]
                
                assert decrypted == msg, f"Decryption mismatch: {decrypted} != {msg}"

    def test_decrypt_multiple_messages(self, jcecard_process):
        """
        Test decrypting multiple messages in sequence.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.sec"
            if not test_key_path.exists():
                pytest.skip(f"Test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            with tempfile.TemporaryDirectory() as tempdir2:
                ks2 = jce.KeyStore(tempdir2)
                pub_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.pub"
                k2 = ks2.import_key(str(pub_key_path))
                
                messages = [
                    b"First secret message",
                    b"Second secret message with more content",
                    b"Third secret",
                ]
                
                for msg in messages:
                    encrypted = ks2.encrypt([k2], msg)  # type: ignore[assignment]
                    decrypted = rjce.decrypt_bytes_on_card(k2.keyvalue, encrypted, b"123456")  # type: ignore[arg-type]
                    assert decrypted == msg, f"Decryption mismatch for: {msg}"

    def test_encrypt_decrypt_large_message(self, jcecard_process):
        """
        Test encrypting and decrypting a larger message.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.sec"
            if not test_key_path.exists():
                pytest.skip(f"Test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            with tempfile.TemporaryDirectory() as tempdir2:
                ks2 = jce.KeyStore(tempdir2)
                pub_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.pub"
                k2 = ks2.import_key(str(pub_key_path))
                
                # Create a larger message (1KB)
                msg = b"A" * 1024
                
                encrypted = ks2.encrypt([k2], msg)  # type: ignore[assignment]
                decrypted = rjce.decrypt_bytes_on_card(k2.keyvalue, encrypted, b"123456")  # type: ignore[arg-type]
                
                assert decrypted == msg, "Large message decryption failed"


class TestSmartcardSignAndEncrypt:
    """Tests for combined sign and encrypt operations."""

    def test_sign_and_encrypt_roundtrip(self, jcecard_process):
        """
        Test signing and encrypting in sequence.
        
        This tests that the card can handle multiple operations in sequence.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.sec"
            if not test_key_path.exists():
                pytest.skip(f"Test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            with tempfile.TemporaryDirectory() as tempdir2:
                ks2 = jce.KeyStore(tempdir2)
                pub_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.pub"
                k2 = ks2.import_key(str(pub_key_path))
                
                msg = b"Message for sign and encrypt test"
                
                # First sign
                signature = rjce.sign_bytes_detached_on_card(k2.keyvalue, msg, b"123456")
                assert signature is not None
                assert ks2.verify(k2, msg, signature)
                
                # Then encrypt and decrypt
                encrypted = ks2.encrypt([k2], msg)  # type: ignore[assignment]
                decrypted = rjce.decrypt_bytes_on_card(k2.keyvalue, encrypted, b"123456")  # type: ignore[arg-type]
                assert decrypted == msg
                
                # Sign again to confirm card still works
                signature2 = rjce.sign_bytes_detached_on_card(k2.keyvalue, msg, b"123456")
                assert signature2 is not None
                assert ks2.verify(k2, msg, signature2)


class TestSmartcardKeySlotState:
    """Tests for key slot state after operations."""
    
    def test_algorithm_attributes_stored(self, jcecard_process):
        """
        Verify that algorithm attributes are stored for uploaded keys.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.sec"
            if not test_key_path.exists():
                pytest.skip(f"Test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            card_state_path = get_card_state_path()
            with open(card_state_path) as f:
                state = json.load(f)
            
            # EdDSA signing key should have algorithm_id 0x16 (22)
            sig_algo = state["key_sig"]["algorithm"]
            assert sig_algo["algorithm_id"] == 0x16, f"Expected EdDSA (0x16), got {sig_algo['algorithm_id']:#x}"
            
            # X25519 decryption key should have algorithm_id 0x12 (18)
            dec_algo = state["key_dec"]["algorithm"]
            assert dec_algo["algorithm_id"] == 0x12, f"Expected ECDH (0x12), got {dec_algo['algorithm_id']:#x}"
            
            # Authentication key should also be EdDSA
            auth_algo = state["key_aut"]["algorithm"]
            assert auth_algo["algorithm_id"] == 0x16, f"Expected EdDSA (0x16), got {auth_algo['algorithm_id']:#x}"

    def test_private_key_data_stored(self, jcecard_process):
        """
        Verify that private key data is stored after key upload.
        """
        import base64
        
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / "5286C32E7C71E14C4C82F9AE0B207108925CB162.sec"
            if not test_key_path.exists():
                pytest.skip(f"Test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            card_state_path = get_card_state_path()
            with open(card_state_path) as f:
                state = json.load(f)
            
            # All key slots should have private key data
            sig_key_data = state["key_sig"]["private_key_data"]
            dec_key_data = state["key_dec"]["private_key_data"]
            auth_key_data = state["key_aut"]["private_key_data"]
            
            assert sig_key_data, "Signature key data should not be empty"
            assert dec_key_data, "Decryption key data should not be empty"
            assert auth_key_data, "Authentication key data should not be empty"
            
            # Verify they decode to 32 bytes (Ed25519/X25519 private keys)
            sig_raw = base64.b64decode(sig_key_data)
            dec_raw = base64.b64decode(dec_key_data)
            auth_raw = base64.b64decode(auth_key_data)
            
            assert len(sig_raw) == 32, f"Sig key should be 32 bytes, got {len(sig_raw)}"
            assert len(dec_raw) == 32, f"Dec key should be 32 bytes, got {len(dec_raw)}"
            assert len(auth_raw) == 32, f"Auth key should be 32 bytes, got {len(auth_raw)}"


class TestSmartcardRSAOperations:
    """Tests for RSA key operations with the virtual card."""

    # RSA4096 test key fingerprints
    RSA_KEY_FINGERPRINT = "2184DF8AF2CAFEB16357FE43E6F848F1DDC66C12"
    RSA_SIG_FP = "E89EF5363C6F3E47A2067199067DC0B8054D00B1"
    RSA_ENC_FP = "2366949147F5DA0306657B76C6F6EC57D4DFB9EC"
    RSA_AUTH_FP = "B5871E65B9F6E5CF02C43E49B85DB676BEF37B03"

    def test_upload_rsa_keys(self, jcecard_process):
        """
        Test uploading RSA4096 keys to the card.
        
        Verifies that fingerprints are correctly stored.
        """
        import base64
        
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / f"{self.RSA_KEY_FINGERPRINT}.sec"
            if not test_key_path.exists():
                pytest.skip(f"RSA test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            # Verify fingerprints
            data = rjce.get_card_details()
            
            sig_fp = jce.utils.convert_fingerprint(data["sig_f"])
            enc_fp = jce.utils.convert_fingerprint(data["enc_f"])
            auth_fp = jce.utils.convert_fingerprint(data["auth_f"])
            
            assert sig_fp == self.RSA_SIG_FP, f"Sig fingerprint mismatch: {sig_fp}"
            assert enc_fp == self.RSA_ENC_FP, f"Enc fingerprint mismatch: {enc_fp}"
            assert auth_fp == self.RSA_AUTH_FP, f"Auth fingerprint mismatch: {auth_fp}"

    def test_rsa_encrypt_and_decrypt(self, jcecard_process):
        """
        Test encrypting data with RSA public key and decrypting on card.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / f"{self.RSA_KEY_FINGERPRINT}.sec"
            if not test_key_path.exists():
                pytest.skip(f"RSA test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            # New keystore with public key only
            with tempfile.TemporaryDirectory() as tempdir2:
                ks2 = jce.KeyStore(tempdir2)
                pub_key_path = Path(__file__).parent.parent / "smartcardtests" / f"{self.RSA_KEY_FINGERPRINT}.pub"
                k2 = ks2.import_key(str(pub_key_path))
                
                msg = b"OpenPGP on smartcard with RSA."
                
                # Encrypt with public key
                encrypted: bytes = ks2.encrypt([k2], msg)  # type: ignore[assignment]
                assert encrypted is not None
                assert b"BEGIN PGP MESSAGE" in encrypted
                
                # Decrypt on card
                decrypted = rjce.decrypt_bytes_on_card(k2.keyvalue, encrypted, b"123456")  # type: ignore[arg-type]
                
                assert decrypted == msg, f"RSA decryption mismatch: {decrypted} != {msg}"

    def test_rsa_sign_and_verify(self, jcecard_process):
        """
        Test signing data with RSA key on card and verifying.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / f"{self.RSA_KEY_FINGERPRINT}.sec"
            if not test_key_path.exists():
                pytest.skip(f"RSA test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            # New keystore with public key
            with tempfile.TemporaryDirectory() as tempdir2:
                ks2 = jce.KeyStore(tempdir2)
                pub_key_path = Path(__file__).parent.parent / "smartcardtests" / f"{self.RSA_KEY_FINGERPRINT}.pub"
                k2 = ks2.import_key(str(pub_key_path))
                
                msg = b"OpenPGP RSA signing test message."
                
                # Sign on card
                signature = rjce.sign_bytes_detached_on_card(k2.keyvalue, msg, b"123456")
                
                assert signature is not None
                assert len(signature) > 0
                
                # Verify signature
                result = ks2.verify(k2, msg, signature)
                assert result is True, "RSA signature verification failed"

    def test_rsa_sign_multiple_messages(self, jcecard_process):
        """
        Test signing multiple messages with RSA key in sequence.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / f"{self.RSA_KEY_FINGERPRINT}.sec"
            if not test_key_path.exists():
                pytest.skip(f"RSA test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            with tempfile.TemporaryDirectory() as tempdir2:
                ks2 = jce.KeyStore(tempdir2)
                pub_key_path = Path(__file__).parent.parent / "smartcardtests" / f"{self.RSA_KEY_FINGERPRINT}.pub"
                k2 = ks2.import_key(str(pub_key_path))
                
                messages = [
                    b"First RSA signed message",
                    b"Second RSA message with more content",
                    b"Third RSA message",
                ]
                
                for msg in messages:
                    signature = rjce.sign_bytes_detached_on_card(k2.keyvalue, msg, b"123456")
                    assert signature is not None
                    assert len(signature) > 0
                    assert ks2.verify(k2, msg, signature), f"RSA verification failed for: {msg}"

    def test_rsa_decrypt_multiple_messages(self, jcecard_process):
        """
        Test decrypting multiple RSA-encrypted messages in sequence.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            ks = jce.KeyStore(tempdir)
            
            test_key_path = Path(__file__).parent.parent / "smartcardtests" / f"{self.RSA_KEY_FINGERPRINT}.sec"
            if not test_key_path.exists():
                pytest.skip(f"RSA test key not found: {test_key_path}")
            
            k = ks.import_key(str(test_key_path))
            
            rjce.reset_yubikey()
            rjce.upload_to_smartcard(k.keyvalue, b"12345678", "redhat", whichkeys=7)
            
            with tempfile.TemporaryDirectory() as tempdir2:
                ks2 = jce.KeyStore(tempdir2)
                pub_key_path = Path(__file__).parent.parent / "smartcardtests" / f"{self.RSA_KEY_FINGERPRINT}.pub"
                k2 = ks2.import_key(str(pub_key_path))
                
                messages = [
                    b"First RSA encrypted secret",
                    b"Second RSA secret message",
                    b"Third RSA secret",
                ]
                
                for msg in messages:
                    encrypted = ks2.encrypt([k2], msg)  # type: ignore[assignment]
                    decrypted = rjce.decrypt_bytes_on_card(k2.keyvalue, encrypted, b"123456")  # type: ignore[arg-type]
                    assert decrypted == msg, f"RSA decryption mismatch for: {msg}"

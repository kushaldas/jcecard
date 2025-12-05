"""
Tests for Cryptographic Backend operations.

Tests cover:
- Key generation (RSA, Curve25519)
- Digital signatures
- Decryption
- Key loading
- CryptoBackend and SimpleCryptoBackend classes

Note: johnnycanencrypt module is assumed to always be available.
"""

import pytest
import time
from jcecard.crypto_backend import (
    CryptoBackend,
    KeyType,
    GeneratedKey,
    SignatureResult,
    DecryptionResult,
)


class TestKeyType:
    """Tests for KeyType enum."""
    
    def test_key_type_values(self):
        """Test KeyType enum values match OpenPGP card CRT tags."""
        assert KeyType.SIGNATURE == 0xB6
        assert KeyType.DECRYPTION == 0xB8
        assert KeyType.AUTHENTICATION == 0xA4
    
    def test_key_type_names(self):
        """Test KeyType enum names."""
        assert KeyType.SIGNATURE.name == "SIGNATURE"
        assert KeyType.DECRYPTION.name == "DECRYPTION"
        assert KeyType.AUTHENTICATION.name == "AUTHENTICATION"


class TestGeneratedKey:
    """Tests for GeneratedKey dataclass."""
    
    def test_generated_key_creation(self):
        """Test creating GeneratedKey."""
        key = GeneratedKey(
            public_key_data=b"public",
            private_key_data=b"private",
            fingerprint=b"\x00" * 20,
            generation_time=1234567890
        )
        assert key.public_key_data == b"public"
        assert key.private_key_data == b"private"
        assert len(key.fingerprint) == 20
        assert key.generation_time == 1234567890


class TestSignatureResult:
    """Tests for SignatureResult dataclass."""
    
    def test_successful_signature(self):
        """Test successful signature result."""
        result = SignatureResult(
            signature=b"signature_data",
            success=True
        )
        assert result.success
        assert result.signature == b"signature_data"
        assert result.error is None
    
    def test_failed_signature(self):
        """Test failed signature result."""
        result = SignatureResult(
            signature=b"",
            success=False,
            error="Key not loaded"
        )
        assert not result.success
        assert result.error == "Key not loaded"


class TestDecryptionResult:
    """Tests for DecryptionResult dataclass."""
    
    def test_successful_decryption(self):
        """Test successful decryption result."""
        result = DecryptionResult(
            plaintext=b"decrypted data",
            success=True
        )
        assert result.success
        assert result.plaintext == b"decrypted data"
        assert result.error is None
    
    def test_failed_decryption(self):
        """Test failed decryption result."""
        result = DecryptionResult(
            plaintext=b"",
            success=False,
            error="Decryption failed"
        )
        assert not result.success
        assert result.error == "Decryption failed"


class TestCryptoBackendAvailability:
    """Tests for CryptoBackend availability check."""
    
    def test_is_available(self):
        """Test is_available static method - should always be True."""
        result = CryptoBackend.is_available()
        assert result is True


class TestCryptoBackendBasic:
    """Basic tests for CryptoBackend."""
    
    def test_backend_creation(self):
        """Test creating CryptoBackend instance."""
        backend = CryptoBackend()
        assert backend is not None
    
    def test_default_password(self):
        """Test default password is set."""
        assert CryptoBackend.DEFAULT_PASSWORD == "virtual-openpgp-card"
    
    def test_sign_without_key(self):
        """Test signing without loaded key."""
        backend = CryptoBackend()
        result = backend.sign(b"test data")
        assert not result.success
        assert result.error is not None and "Key not loaded" in result.error
    
    def test_decrypt_without_key(self):
        """Test decryption without loaded key."""
        backend = CryptoBackend()
        result = backend.decrypt(b"test data")
        assert not result.success
        assert result.error is not None and "Key not loaded" in result.error



class TestRSAKeyGeneration:
    """Tests for RSA key generation (requires johnnycanencrypt)."""
    
    def test_generate_rsa_2048(self):
        """Test generating RSA-2048 key."""
        backend = CryptoBackend()
        result = backend.generate_rsa_key(KeyType.SIGNATURE, bits=2048)
        
        assert result is not None
        assert isinstance(result, GeneratedKey)
        assert len(result.fingerprint) == 20  # v4 fingerprint
        assert result.generation_time > 0
        assert len(result.public_key_data) > 0
        assert len(result.private_key_data) > 0
    
    def test_generate_rsa_4096(self):
        """Test generating RSA-4096 key."""
        backend = CryptoBackend()
        result = backend.generate_rsa_key(KeyType.SIGNATURE, bits=4096)
        
        assert result is not None
        assert len(result.fingerprint) == 20
    
    def test_generate_rsa_for_different_key_types(self):
        """Test generating RSA keys for different purposes."""
        backend = CryptoBackend()
        
        for key_type in [KeyType.SIGNATURE, KeyType.DECRYPTION, KeyType.AUTHENTICATION]:
            result = backend.generate_rsa_key(key_type)
            assert result is not None, f"Failed for {key_type.name}"
    
    def test_generate_rsa_timestamps(self):
        """Test that generated key has valid timestamp."""
        backend = CryptoBackend()
        before = int(time.time())
        result = backend.generate_rsa_key(KeyType.SIGNATURE)
        after = int(time.time())
        
        assert result is not None
        assert before <= result.generation_time <= after



class TestCurve25519KeyGeneration:
    """Tests for Curve25519 key generation (requires johnnycanencrypt)."""
    
    def test_generate_curve25519(self):
        """Test generating Curve25519 key."""
        backend = CryptoBackend()
        result = backend.generate_curve25519_key(KeyType.SIGNATURE)
        
        assert result is not None
        assert isinstance(result, GeneratedKey)
        assert len(result.fingerprint) == 20
        assert result.generation_time > 0
    
    def test_generate_curve25519_for_encryption(self):
        """Test generating Curve25519 key for encryption."""
        backend = CryptoBackend()
        result = backend.generate_curve25519_key(KeyType.DECRYPTION)
        
        assert result is not None
        assert len(result.public_key_data) > 0



class TestSigning:
    """Tests for signing operations (requires johnnycanencrypt)."""
    
    @pytest.fixture
    def backend_with_sig_key(self):
        """Create backend with signature key loaded."""
        backend = CryptoBackend()
        result = backend.generate_rsa_key(KeyType.SIGNATURE)
        assert result is not None
        return backend
    
    def test_sign_data(self, backend_with_sig_key):
        """Test signing data."""
        data = b"Hello, World!"
        result = backend_with_sig_key.sign(data)
        
        assert result.success
        assert len(result.signature) > 0
        assert result.error is None
    
    def test_sign_hash(self, backend_with_sig_key):
        """Test signing a hash (typical smart card usage)."""
        import hashlib
        hash_data = hashlib.sha256(b"test message").digest()
        
        result = backend_with_sig_key.sign(hash_data)
        assert result.success
    
    def test_sign_empty_data(self, backend_with_sig_key):
        """Test signing empty data."""
        result = backend_with_sig_key.sign(b"")
        # Implementation may accept or reject empty data
        # Just verify it doesn't crash
        assert isinstance(result, SignatureResult)



class TestAuthentication:
    """Tests for authentication operations (requires johnnycanencrypt)."""
    
    @pytest.fixture
    def backend_with_auth_key(self):
        """Create backend with authentication key loaded."""
        backend = CryptoBackend()
        result = backend.generate_rsa_key(KeyType.AUTHENTICATION)
        assert result is not None
        return backend
    
    def test_authenticate_challenge(self, backend_with_auth_key):
        """Test authenticating a challenge."""
        challenge = b"random_challenge_data_12345"
        result = backend_with_auth_key.authenticate(challenge)
        
        assert result.success
        assert len(result.signature) > 0



class TestKeyLoading:
    """Tests for key loading operations (requires johnnycanencrypt)."""
    
    def test_load_generated_key(self):
        """Test loading a previously generated key."""
        from jcecard.card_data import AlgorithmAttributes
        
        backend = CryptoBackend()
        
        # Generate a key first
        generated = backend.generate_rsa_key(KeyType.SIGNATURE)
        assert generated is not None
        
        # Create new backend and load the key
        backend2 = CryptoBackend()
        algo = AlgorithmAttributes.rsa(2048)
        
        success = backend2.load_key(
            KeyType.SIGNATURE,
            generated.private_key_data,
            algo
        )
        assert success
        
        # Verify the loaded key can sign
        result = backend2.sign(b"test data")
        assert result.success
    
    def test_load_empty_key_data(self):
        """Test loading empty key data fails gracefully."""
        from jcecard.card_data import AlgorithmAttributes
        
        backend = CryptoBackend()
        algo = AlgorithmAttributes.rsa(2048)
        
        success = backend.load_key(KeyType.SIGNATURE, b"", algo)
        assert not success
    
    def test_load_invalid_key_data(self):
        """Test loading invalid key data fails gracefully."""
        from jcecard.card_data import AlgorithmAttributes
        
        backend = CryptoBackend()
        algo = AlgorithmAttributes.rsa(2048)
        
        success = backend.load_key(KeyType.SIGNATURE, b"invalid key data", algo)
        assert not success


  
class TestEncryptionDecryption:
    """Tests for encryption/decryption operations (requires johnnycanencrypt)."""
    
    @pytest.fixture
    def backend_with_enc_key(self):
        """Create backend with encryption key loaded."""
        backend = CryptoBackend()
        result = backend.generate_rsa_key(KeyType.DECRYPTION)
        assert result is not None
        return backend
    
    def test_decrypt_requires_encrypted_data(self, backend_with_enc_key):
        """Test that decrypt expects properly encrypted data."""
        # Raw data won't decrypt properly
        result = backend_with_enc_key.decrypt(b"not encrypted data")
        # Should fail because the data isn't in OpenPGP encrypted format
        assert not result.success


class TestCryptoBackendMultipleKeys:
    """Tests for managing multiple keys."""
    
    
    def test_different_keys_per_slot(self):
        """Test generating different keys for each slot."""
        backend = CryptoBackend()
        
        sig_key = backend.generate_rsa_key(KeyType.SIGNATURE)
        dec_key = backend.generate_rsa_key(KeyType.DECRYPTION)
        auth_key = backend.generate_rsa_key(KeyType.AUTHENTICATION)
        
        assert sig_key is not None
        assert dec_key is not None
        assert auth_key is not None
        
        # Fingerprints should all be different
        assert sig_key.fingerprint != dec_key.fingerprint
        assert dec_key.fingerprint != auth_key.fingerprint
        assert sig_key.fingerprint != auth_key.fingerprint
    
    
    def test_sign_with_correct_key(self):
        """Test that signing uses the signature key."""
        backend = CryptoBackend()
        
        # Generate signature key
        sig_key = backend.generate_rsa_key(KeyType.SIGNATURE)
        assert sig_key is not None
        
        # Sign should use signature key
        result = backend.sign(b"test data", KeyType.SIGNATURE)
        assert result.success
        
        # Signing with decryption key type should fail (no key loaded)
        result = backend.sign(b"test data", KeyType.DECRYPTION)
        assert not result.success


class TestFingerprintCalculation:
    """Tests for key fingerprint handling."""
    
    
    def test_fingerprint_is_20_bytes(self):
        """Test v4 fingerprint is 20 bytes (SHA-1)."""
        backend = CryptoBackend()
        result = backend.generate_rsa_key(KeyType.SIGNATURE)
        
        assert result is not None
        assert len(result.fingerprint) == 20
    
    
    def test_fingerprint_is_hex_decodable(self):
        """Test fingerprint can be encoded to hex."""
        backend = CryptoBackend()
        result = backend.generate_rsa_key(KeyType.SIGNATURE)
        
        assert result is not None
        fingerprint_hex = result.fingerprint.hex()
        assert len(fingerprint_hex) == 40  # 20 bytes = 40 hex chars
    
    
    def test_different_keys_have_different_fingerprints(self):
        """Test that different keys have unique fingerprints."""
        backend = CryptoBackend()
        
        key1 = backend.generate_rsa_key(KeyType.SIGNATURE)
        
        # Create new backend for fresh key
        backend2 = CryptoBackend()
        key2 = backend2.generate_rsa_key(KeyType.SIGNATURE)
        
        assert key1 is not None and key2 is not None
        assert key1.fingerprint != key2.fingerprint

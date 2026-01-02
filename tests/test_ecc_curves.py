#!/usr/bin/env python3
"""
ECC Curve Tests: Test key generation and operations for NIST P-384.

This test:
1. Uses gpg --edit-card via pexpect to generate P-384 keys on the card
2. Tests signing and encryption with the generated keys

Prerequisites:
- pcscd running with jcecard IFD handler
- Virtual jcecard connected
"""

import pytest
import pexpect
import tempfile
import os
import subprocess
import sys


# Default PINs for virtual card
DEFAULT_USER_PIN = "123456"
DEFAULT_ADMIN_PIN = "12345678"


class GPGCardHelper:
    """Helper class to interact with GPG card operations via pexpect."""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.env = os.environ.copy()
        self.gnupg_home = os.environ.get('GNUPGHOME', os.path.expanduser('~/.gnupg'))

    def delete_keys_by_email(self, email: str) -> bool:
        """Delete all GPG keys matching the given email."""
        try:
            result = subprocess.run(
                ['gpg', '--list-keys', '--with-colons', email],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return True

            fingerprints = []
            for line in result.stdout.split('\n'):
                if line.startswith('fpr:'):
                    parts = line.split(':')
                    if len(parts) >= 10:
                        fingerprints.append(parts[9])

            for fpr in fingerprints:
                subprocess.run(
                    ['gpg', '--batch', '--yes', '--delete-secret-keys', fpr],
                    env=self.env,
                    capture_output=True,
                    timeout=30
                )
                subprocess.run(
                    ['gpg', '--batch', '--yes', '--delete-keys', fpr],
                    env=self.env,
                    capture_output=True,
                    timeout=30
                )

            return True

        except Exception as e:
            print(f"Error during key cleanup: {e}")
            return False

    def factory_reset(self) -> bool:
        """Factory reset the card."""
        print("\n=== Factory Reset Card ===")

        child = pexpect.spawn(
            'gpg --pinentry-mode loopback --edit-card',
            env=self.env,
            encoding='utf-8',
            timeout=self.timeout
        )

        try:
            child.expect('gpg/card>', timeout=30)
            child.sendline('admin')
            child.expect('gpg/card>')
            child.sendline('factory-reset')

            idx = child.expect(['Continue\\?', 'y/N', 'gpg/card>'], timeout=10)
            if idx in [0, 1]:
                child.sendline('y')
                try:
                    idx2 = child.expect(['Really', 'y/N', 'gpg/card>'], timeout=10)
                    if idx2 in [0, 1]:
                        child.sendline('yes')
                except pexpect.TIMEOUT:
                    pass

            child.expect('gpg/card>', timeout=30)
            child.sendline('quit')
            child.expect(pexpect.EOF, timeout=10)

            print("Factory reset complete")
            return True

        except Exception as e:
            print(f"Reset failed: {e}")
            return False
        finally:
            child.close()

    def generate_p384_keys(self, user_name: str = "Test User",
                           user_email: str = "test@example.com") -> bool:
        """
        Generate NIST P-384 keys on card using gpg --edit-card.

        Args:
            user_name: Name for the key
            user_email: Email for the key

        Returns:
            True if successful
        """
        print("\n=== Generate NIST P-384 Keys on Card ===")

        child = pexpect.spawn(
            'gpg --pinentry-mode loopback --command-fd=0 --status-fd=1 --edit-card',
            env=self.env,
            encoding='utf-8',
            timeout=self.timeout
        )
        child.logfile = sys.stdout

        prompt_pattern = r'GET_LINE cardedit.prompt|gpg/card>'
        algo_pattern = r'GET_LINE cardedit.genkeys.algo|Your selection|selection'
        curve_pattern = r'GET_LINE keygen.curve|Your selection|curve'
        pin_pattern = r'GET_HIDDEN passphrase.enter'

        try:
            child.expect(prompt_pattern, timeout=30)

            # Enter admin mode
            child.sendline('admin')
            child.expect(prompt_pattern)

            # Set key algorithm to ECC P-384 for all slots
            child.sendline('key-attr')

            # Signature key - select ECC then P-384 (option 4)
            child.expect(algo_pattern, timeout=10)
            child.sendline('2')  # ECC
            child.expect(curve_pattern, timeout=10)
            child.sendline('4')  # NIST P-384
            child.expect(pin_pattern, timeout=10)
            child.sendline(DEFAULT_ADMIN_PIN)

            # Encryption key - select ECC then P-384
            child.expect(algo_pattern, timeout=10)
            child.sendline('2')  # ECC
            child.expect(curve_pattern, timeout=10)
            child.sendline('4')  # NIST P-384
            child.expect(pin_pattern, timeout=10)
            child.sendline(DEFAULT_ADMIN_PIN)

            # Authentication key - select ECC then P-384
            child.expect(algo_pattern, timeout=10)
            child.sendline('2')  # ECC
            child.expect(curve_pattern, timeout=10)
            child.sendline('4')  # NIST P-384
            child.expect(pin_pattern, timeout=10)
            child.sendline(DEFAULT_ADMIN_PIN)

            child.expect(prompt_pattern, timeout=30)
            print("Key attributes set to P-384")

            # Now generate the keys
            child.sendline('generate')

            # Backup question - no backup
            child.expect(['GET_LINE cardedit.genkeys.backup_enc', 'backup', 'y/N'], timeout=15)
            child.sendline('n')

            # User PIN may be required first
            child.expect(pin_pattern, timeout=15)
            child.sendline(DEFAULT_USER_PIN)

            # Key expiration
            child.expect(['GET_LINE keygen.valid', 'Key is valid for', 'expire', '0 ='], timeout=15)
            child.sendline('0')  # No expiration

            # Real name
            child.expect(['GET_LINE keygen.name', 'Real name'], timeout=10)
            child.sendline(user_name)

            # Email
            child.expect(['GET_LINE keygen.email', 'Email address'], timeout=10)
            child.sendline(user_email)

            # Comment
            child.expect(['GET_LINE keygen.comment', 'Comment'], timeout=10)
            child.sendline('')

            # Admin PIN for key generation
            child.expect(pin_pattern, timeout=15)
            child.sendline(DEFAULT_ADMIN_PIN)

            # Handle multiple PIN prompts for key generation
            for _ in range(6):
                try:
                    idx = child.expect([r'NEED_PASSPHRASE', pin_pattern, r'KEY_CREATED', prompt_pattern], timeout=60)
                    if idx == 0:
                        # NEED_PASSPHRASE means signing operation - use User PIN
                        child.expect(pin_pattern, timeout=10)
                        child.sendline(DEFAULT_USER_PIN)
                    elif idx == 1:
                        # Generic PIN prompt - try Admin PIN
                        child.sendline(DEFAULT_ADMIN_PIN)
                    elif idx == 2:
                        # KEY_CREATED - success!
                        print("Key created successfully!")
                        child.expect(prompt_pattern, timeout=30)
                        break
                    else:
                        break
                except pexpect.TIMEOUT:
                    break

            # Quit
            child.sendline('quit')
            child.expect(pexpect.EOF, timeout=10)

            print("P-384 key generation complete")
            return True

        except pexpect.TIMEOUT as e:
            print(f"Timeout: {e}")
            print(f"Before: {child.before}")
            return False
        except pexpect.EOF as e:
            print(f"EOF: {e}")
            return False
        finally:
            child.close()

    def test_sign_and_verify(self, email: str) -> bool:
        """Test signing and verification with the generated key."""
        print(f"\n=== Test Sign/Verify with {email} ===")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Test message for signing\n")
            test_file = f.name

        sig_file = test_file + '.sig'

        try:
            # Sign
            result = subprocess.run(
                ['gpg', '--pinentry-mode', 'loopback', '--passphrase', DEFAULT_USER_PIN,
                 '-u', email, '--detach-sign', test_file],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                print(f"Signing failed: {result.stderr}")
                return False

            # Verify
            result = subprocess.run(
                ['gpg', '--verify', sig_file, test_file],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(f"Verification failed: {result.stderr}")
                return False

            print("Sign/Verify test passed")
            return True

        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)
            if os.path.exists(sig_file):
                os.unlink(sig_file)

    def test_encrypt_and_decrypt(self, email: str) -> bool:
        """Test encryption and decryption with the generated key."""
        print(f"\n=== Test Encrypt/Decrypt with {email} ===")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            test_message = "Secret test message for encryption\n"
            f.write(test_message)
            test_file = f.name

        enc_file = test_file + '.gpg'
        dec_file = test_file + '.dec'

        try:
            # Encrypt
            result = subprocess.run(
                ['gpg', '--encrypt', '-r', email, '-o', enc_file, test_file],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(f"Encryption failed: {result.stderr}")
                return False

            # Decrypt
            result = subprocess.run(
                ['gpg', '--pinentry-mode', 'loopback', '--passphrase', DEFAULT_USER_PIN,
                 '-o', dec_file, '--decrypt', enc_file],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                print(f"Decryption failed: {result.stderr}")
                return False

            # Verify content
            with open(dec_file, 'r') as f:
                decrypted = f.read()

            if decrypted != test_message:
                print(f"Content mismatch: expected '{test_message}', got '{decrypted}'")
                return False

            print("Encrypt/Decrypt test passed")
            return True

        finally:
            for f in [test_file, enc_file, dec_file]:
                if os.path.exists(f):
                    os.unlink(f)


@pytest.fixture
def gpg_helper():
    """Provide a GPG card helper instance."""
    helper = GPGCardHelper(timeout=120)
    yield helper


class TestNISTP384:
    """Test NIST P-384 curve key generation and operations."""

    EMAIL = "p384test@example.com"

    def test_generate_p384_keys(self, gpg_helper):
        """Generate NIST P-384 keys on card."""
        gpg_helper.delete_keys_by_email(self.EMAIL)
        gpg_helper.factory_reset()

        success = gpg_helper.generate_p384_keys(user_email=self.EMAIL)
        assert success, "Failed to generate NIST P-384 keys"

    def test_p384_sign_verify(self, gpg_helper):
        """Test signing with NIST P-384 key."""
        success = gpg_helper.test_sign_and_verify(self.EMAIL)
        assert success, "NIST P-384 sign/verify failed"

    def test_p384_encrypt_decrypt(self, gpg_helper):
        """Test encryption with NIST P-384 key."""
        success = gpg_helper.test_encrypt_and_decrypt(self.EMAIL)
        assert success, "NIST P-384 encrypt/decrypt failed"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])

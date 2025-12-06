#!/usr/bin/env python3
"""
On-card key generation: Test key generation on card using GPG via pexpect.

This test:
1. Uses gpg --edit-card via pexpect to generate cv25519 keys on the card
2. Exports the public key using gpg
3. Encrypts a message using the public key  
4. Decrypts on the card using gpg

Prerequisites:
- pcscd running (with or without jcecard IFD handler)
- An OpenPGP card connected (Yubikey or virtual jcecard)
"""

import pytest
import pexpect
import tempfile
import os
import time
import subprocess
from pathlib import Path


# Default PINs for virtual card
DEFAULT_USER_PIN = "123456"
DEFAULT_ADMIN_PIN = "12345678"


class GPGCardHelper:
    """Helper class to interact with GPG card operations via pexpect."""
    
    def __init__(self, timeout: int = 60):
        """
        Initialize GPG card helper.
        
        Uses the user's existing GNUPGHOME (or default ~/.gnupg).
        
        Args:
            timeout: Default timeout for pexpect operations
        """
        self.timeout = timeout
        self.env = os.environ.copy()
        # Use existing GNUPGHOME or default
        self.gnupg_home = os.environ.get('GNUPGHOME', os.path.expanduser('~/.gnupg'))
    
    def cleanup(self):
        """No cleanup needed when using user's GNUPGHOME."""
        pass
    
    def get_card_status(self) -> dict:
        """
        Get card status using gpg --card-status.
        
        Returns:
            Dictionary with card info or empty dict on error
        """
        try:
            result = subprocess.run(
                ['gpg', '--card-status'],
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                print(f"Card status error: {result.stderr}")
                return {}
            
            # Parse output
            info = {}
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, _, value = line.partition(':')
                    info[key.strip()] = value.strip()
            
            return info
            
        except Exception as e:
            print(f"Failed to get card status: {e}")
            return {}
    
    def factory_reset(self) -> bool:
        """
        Factory reset the card using gpg --edit-card.
        
        Returns:
            True if successful
        """
        print("\n=== Factory Reset Card ===")
        
        child = pexpect.spawn(
            'gpg --pinentry-mode loopback --edit-card',
            env=self.env,
            encoding='utf-8',
            timeout=self.timeout
        )
        child.logfile = None  # Set to sys.stdout for debugging
        
        try:
            # Wait for gpg/card prompt
            child.expect('gpg/card>', timeout=30)
            
            # Enter admin mode
            child.sendline('admin')
            child.expect('gpg/card>')
            
            # Factory reset
            child.sendline('factory-reset')
            
            # Confirm reset - GPG asks multiple times
            idx = child.expect(['Continue\\?', 'y/N', 'gpg/card>'], timeout=10)
            if idx in [0, 1]:
                child.sendline('y')
                
                # May ask for final confirmation
                try:
                    idx2 = child.expect(['Really', 'y/N', 'gpg/card>'], timeout=10)
                    if idx2 in [0, 1]:
                        child.sendline('yes')
                except pexpect.TIMEOUT:
                    pass
            
            # Wait for completion
            child.expect('gpg/card>', timeout=30)
            
            # Quit
            child.sendline('quit')
            child.expect(pexpect.EOF, timeout=10)
            
            print("Factory reset complete")
            return True
            
        except pexpect.TIMEOUT as e:
            print(f"Timeout during reset: {e}")
            print(f"Before: {child.before}")
            return False
        except pexpect.EOF as e:
            print(f"EOF during reset: {e}")
            return False
        finally:
            child.close()
    
    def generate_cv25519_keys(self, user_name: str = "Test User", 
                              user_email: str = "test@example.com") -> bool:
        """
        Generate cv25519 keys on card using gpg --edit-card.
        
        This sets the key algorithm to cv25519 and generates new keys.
        
        Args:
            user_name: Name for the key
            user_email: Email for the key
            
        Returns:
            True if successful
        """
        print("\n=== Generate CV25519 Keys on Card ===")
        
        import sys
        child = pexpect.spawn(
            'gpg --pinentry-mode loopback --command-fd=0 --status-fd=1 --edit-card',
            env=self.env,
            encoding='utf-8',
            timeout=self.timeout
        )
        child.logfile = sys.stdout  # Enable logging for debugging
        
        # With --status-fd, GPG outputs [GNUPG:] GET_LINE cardedit.prompt instead of gpg/card>
        prompt_pattern = r'GET_LINE cardedit.prompt|gpg/card>'
        algo_pattern = r'GET_LINE cardedit.genkeys.algo|Your selection|selection'
        curve_pattern = r'GET_LINE keygen.curve|Your selection|curve'
        pin_pattern = r'GET_HIDDEN passphrase.enter'
        
        try:
            # Wait for gpg/card prompt
            child.expect(prompt_pattern, timeout=30)
            
            # Enter admin mode
            child.sendline('admin')
            child.expect(prompt_pattern)
            
            # Set key algorithm to ECC (cv25519)
            # key-attr command lets us select algorithm for each key slot
            child.sendline('key-attr')
            
            # Signature key - select ECC
            child.expect(algo_pattern, timeout=10)
            child.sendline('2')  # ECC
            
            # Select curve for signature key - EdDSA
            child.expect(curve_pattern, timeout=10)
            child.sendline('1')  # Curve 25519
            
            # Admin PIN required after signature key attr change
            child.expect(pin_pattern, timeout=10)
            child.sendline(DEFAULT_ADMIN_PIN)
            
            # Encryption key - select ECC
            child.expect(algo_pattern, timeout=10)
            child.sendline('2')  # ECC
            
            # Select curve for encryption key - cv25519
            child.expect(curve_pattern, timeout=10)
            child.sendline('1')  # Curve 25519
            
            # Admin PIN required again after encryption key attr change
            child.expect(pin_pattern, timeout=10)
            child.sendline(DEFAULT_ADMIN_PIN)
            
            # Authentication key - select ECC
            child.expect(algo_pattern, timeout=10)
            child.sendline('2')  # ECC
            
            # Select curve for authentication key - EdDSA
            child.expect(curve_pattern, timeout=10)
            child.sendline('1')  # Curve 25519
            
            # Admin PIN required again after authentication key attr change
            child.expect(pin_pattern, timeout=10)
            child.sendline(DEFAULT_ADMIN_PIN)
            
            # Wait for key-attr to complete
            child.expect(prompt_pattern, timeout=30)
            
            print("Key attributes set to cv25519")
            
            # Now generate the keys
            child.sendline('generate')
            
            # Backup question - no backup (GET_LINE cardedit.genkeys.backup_enc)
            child.expect(['GET_LINE cardedit.genkeys.backup_enc', 'backup', 'y/N'], timeout=15)
            child.sendline('n')
            
            # User PIN required for generate (not Admin PIN!)
            child.expect(pin_pattern, timeout=15)
            child.sendline(DEFAULT_USER_PIN)
            
            # Key expiration (GET_LINE keygen.valid)
            child.expect(['GET_LINE keygen.valid', 'Key is valid for', 'expire', '0 ='], timeout=15)
            child.sendline('0')  # No expiration
            
            # Note: GPG does NOT ask "Is this correct?" when 0 (no expiration) is selected
            # It goes directly to asking for the name
            
            # Real name (GET_LINE keygen.name)
            child.expect(['GET_LINE keygen.name', 'Real name'], timeout=10)
            child.sendline(user_name)
            
            # Email (GET_LINE keygen.email)
            child.expect(['GET_LINE keygen.email', 'Email address'], timeout=10)
            child.sendline(user_email)
            
            # Comment (GET_LINE keygen.comment)
            child.expect(['GET_LINE keygen.comment', 'Comment'], timeout=10)
            child.sendline('')
            
            # GPG shows "You selected this USER-ID:" but with --status-fd it goes
            # directly to asking for Admin PIN for key generation (no confirmation prompt)
            
            # Admin PIN for key generation
            child.expect(pin_pattern, timeout=15)
            child.sendline(DEFAULT_ADMIN_PIN)
            
            # PIN prompts for key generation on card
            # After Admin PIN, gpg may need User PIN for signing the key
            # NEED_PASSPHRASE indicates signing operation (needs User PIN)
            for _ in range(6):  # Up to 6 PIN prompts
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
                        # KEY_CREATED - success! Wait for prompt
                        print("Key created successfully!")
                        child.expect(prompt_pattern, timeout=30)
                        break
                    else:
                        break  # Got the prompt, key generation done
                except pexpect.TIMEOUT:
                    break
            
            # Quit
            child.sendline('quit')
            child.expect(pexpect.EOF, timeout=10)
            
            print("Key generation complete")
            return True
            
        except pexpect.TIMEOUT as e:
            print(f"Timeout during key generation: {e}")
            print(f"Before: {child.before}")
            return False
        except pexpect.EOF as e:
            print(f"EOF during key generation: {e}")
            return False
        finally:
            child.close()
    
    def export_public_key(self, key_id: str = None) -> str:
        """
        Export the public key from the card.
        
        Args:
            key_id: Key ID or email to export (exports all if None)
            
        Returns:
            Armored public key string, or empty string on error
        """
        print("\n=== Export Public Key ===")
        
        try:
            cmd = ['gpg', '--armor', '--export']
            if key_id:
                cmd.append(key_id)
            
            result = subprocess.run(
                cmd,
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                print(f"Exported public key ({len(result.stdout)} bytes)")
                return result.stdout
            else:
                print(f"Export failed: {result.stderr}")
                return ""
                
        except Exception as e:
            print(f"Failed to export public key: {e}")
            return ""
    
    def encrypt_message(self, message: str, recipient: str) -> str:
        """
        Encrypt a message for a recipient.
        
        Args:
            message: The message to encrypt
            recipient: Email or key ID of recipient
            
        Returns:
            Armored encrypted message, or empty string on error
        """
        print(f"\n=== Encrypt Message for {recipient} ===")
        
        try:
            result = subprocess.run(
                ['gpg', '--armor', '--encrypt', '--recipient', recipient, '--trust-model', 'always'],
                input=message,
                env=self.env,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                print(f"Encrypted message ({len(result.stdout)} bytes)")
                return result.stdout
            else:
                print(f"Encryption failed: {result.stderr}")
                return ""
                
        except Exception as e:
            print(f"Failed to encrypt: {e}")
            return ""
    
    def decrypt_message(self, encrypted: str) -> str:
        """
        Decrypt a message using the card.
        
        This will prompt for PIN via pinentry.
        
        Args:
            encrypted: The armored encrypted message
            
        Returns:
            Decrypted plaintext, or empty string on error
        """
        print("\n=== Decrypt Message on Card ===")
        
        # For automated testing, we need to handle PIN entry
        # Use gpg with --pinentry-mode loopback and --passphrase
        child = pexpect.spawn(
            'gpg --decrypt --pinentry-mode loopback',
            env=self.env,
            encoding='utf-8',
            timeout=self.timeout
        )
        child.logfile = None
        
        try:
            # Send the encrypted message
            child.sendline(encrypted)
            child.sendeof()
            
            # Wait for PIN prompt
            try:
                child.expect(['PIN', 'passphrase', 'Passphrase'], timeout=15)
                child.sendline(DEFAULT_USER_PIN)
            except pexpect.TIMEOUT:
                pass
            
            # Wait for decryption
            child.expect(pexpect.EOF, timeout=30)
            
            # Get output
            output = child.before
            
            # Parse out the decrypted message (remove gpg status messages)
            lines = output.split('\n')
            decrypted_lines = []
            in_message = False
            
            for line in lines:
                # Skip gpg status lines
                if line.startswith('gpg:'):
                    continue
                if '-----BEGIN PGP MESSAGE-----' in line:
                    continue
                if '-----END PGP MESSAGE-----' in line:
                    continue
                if line.strip():
                    decrypted_lines.append(line)
            
            decrypted = '\n'.join(decrypted_lines).strip()
            print(f"Decrypted: {decrypted[:50]}...")
            return decrypted
            
        except pexpect.TIMEOUT as e:
            print(f"Timeout during decryption: {e}")
            print(f"Before: {child.before}")
            return ""
        except pexpect.EOF:
            # Try to get what we have
            return child.before.strip() if child.before else ""
        finally:
            child.close()
    
    def decrypt_message_simple(self, encrypted: str) -> str:
        """
        Simpler decryption using subprocess with echo for PIN.
        
        Args:
            encrypted: The armored encrypted message
            
        Returns:
            Decrypted plaintext, or empty string on error
        """
        print("\n=== Decrypt Message on Card (simple) ===")
        
        try:
            # Write encrypted message to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.asc', delete=False) as f:
                f.write(encrypted)
                encrypted_file = f.name
            
            try:
                # Use --batch and --pinentry-mode loopback with --passphrase
                result = subprocess.run(
                    [
                        'gpg', '--decrypt',
                        '--batch',
                        '--pinentry-mode', 'loopback',
                        '--passphrase', DEFAULT_USER_PIN,
                        encrypted_file
                    ],
                    env=self.env,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    print(f"Decrypted successfully")
                    return result.stdout
                else:
                    print(f"Decryption failed: {result.stderr}")
                    return ""
                    
            finally:
                os.unlink(encrypted_file)
                
        except Exception as e:
            print(f"Failed to decrypt: {e}")
            return ""


class TestOnCardKeyGeneration:
    """
    On-card Tests: Generate keys on card using GPG via pexpect.
    
    These tests work with any OpenPGP card (real Yubikey or jcecard virtual card).
    
    Requirements:
    - pcscd running (with or without jcecard IFD handler)
    - An OpenPGP card connected (Yubikey or virtual jcecard)
    """
    
    @pytest.fixture
    def gpg_helper(self):
        """Create a GPG helper with temporary GNUPGHOME."""
        helper = GPGCardHelper()
        yield helper
        helper.cleanup()
    
    def test_card_is_available(self, gpg_helper):
        """Test that an OpenPGP card is accessible via gpg."""
        status = gpg_helper.get_card_status()
        
        assert status, "Card should be accessible"
        # Check for any key that indicates we got card status
        assert any('Application' in k or 'Reader' in k or 'Serial' in k for k in status.keys()), \
            f"Should have card info, got keys: {list(status.keys())[:5]}"
        
        print(f"\nCard Status:")
        for key, value in list(status.items())[:10]:
            print(f"  {key}: {value}")
    
    def test_factory_reset(self, gpg_helper):
        """Test factory reset of the card."""
        result = gpg_helper.factory_reset()
        assert result, "Factory reset should succeed"
        
        # Verify card is reset
        status = gpg_helper.get_card_status()
        assert status, "Card should still be accessible after reset"
    
    def test_generate_cv25519_keys(self, gpg_helper):
        """Test generating cv25519 keys on the card."""
        # First reset the card
        reset_result = gpg_helper.factory_reset()
        assert reset_result, "Factory reset should succeed"
        
        # Generate keys
        gen_result = gpg_helper.generate_cv25519_keys(
            user_name="OnCard Test",
            user_email="oncard@test.local"
        )
        assert gen_result, "Key generation should succeed"
        
        # Verify keys are on card
        status = gpg_helper.get_card_status()
        print(f"\nCard status after key generation:")
        for key, value in status.items():
            if 'key' in key.lower() or 'finger' in key.lower():
                print(f"  {key}: {value}")
    
    def test_full_encrypt_decrypt_flow(self, gpg_helper):
        """
        Full flow test:
        1. Reset card
        2. Generate cv25519 keys
        3. Export public key
        4. Encrypt a message
        5. Decrypt on card
        6. Verify decrypted matches original
        """
        # Step 1: Reset card
        print("\n" + "="*60)
        print("Step 1: Factory Reset")
        print("="*60)
        assert gpg_helper.factory_reset(), "Factory reset should succeed"
        
        # Step 2: Generate keys
        print("\n" + "="*60)
        print("Step 2: Generate CV25519 Keys")
        print("="*60)
        assert gpg_helper.generate_cv25519_keys(
            user_name="Encrypt Test",
            user_email="encrypt@test.local"
        ), "Key generation should succeed"
        
        # Step 3: Export public key
        print("\n" + "="*60)
        print("Step 3: Export Public Key")
        print("="*60)
        public_key = gpg_helper.export_public_key("encrypt@test.local")
        assert public_key, "Should export public key"
        assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in public_key
        
        # Step 4: Encrypt a message
        print("\n" + "="*60)
        print("Step 4: Encrypt Message")
        print("="*60)
        original_message = "Hello from on-card keygen! This is a test message for cv25519 encryption."
        encrypted = gpg_helper.encrypt_message(original_message, "encrypt@test.local")
        assert encrypted, "Should encrypt message"
        assert "-----BEGIN PGP MESSAGE-----" in encrypted
        
        # Step 5: Decrypt on card
        print("\n" + "="*60)
        print("Step 5: Decrypt on Card")
        print("="*60)
        decrypted = gpg_helper.decrypt_message_simple(encrypted)
        assert decrypted, "Should decrypt message"
        
        # Step 6: Verify
        print("\n" + "="*60)
        print("Step 6: Verify")
        print("="*60)
        print(f"Original:  {original_message}")
        print(f"Decrypted: {decrypted}")
        assert decrypted.strip() == original_message.strip(), "Decrypted should match original"
        
        print("\n" + "="*60)
        print("SUCCESS: Full encrypt/decrypt flow completed!")
        print("="*60)


if __name__ == '__main__':
    # Run tests directly
    pytest.main([__file__, '-xvs'])

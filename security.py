#!/usr/bin/env python3
"""
Security Module for Seed Phrase Tool
Handles password protection, encryption, and secure memory clearing
"""

import os
import hashlib
import secrets
import ctypes
import getpass
from typing import Optional, Tuple

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class SecurityManager:
    """Manages security operations for seed phrase storage"""

    PBKDF2_ITERATIONS = 480000

    def __init__(self):
        self._keys = []  # Track allocated key buffers for clearing

    def generate_salt(self) -> bytes:
        """Generate a cryptographically secure random salt"""
        return secrets.token_bytes(32)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive an encryption key from a password using PBKDF2

        Args:
            password: User password
            salt: Random salt bytes

        Returns:
            Derived key bytes (32 bytes)
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library not available")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))

    def get_fernet(self, password: str, salt: bytes) -> 'Fernet':
        """
        Get a Fernet cipher instance from password and salt

        Args:
            password: User password
            salt: Salt bytes

        Returns:
            Fernet cipher instance
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library not available")

        key = self.derive_key(password, salt)
        fernet_key = base64.urlsafe_b64encode(key)
        return Fernet(fernet_key)

    def encrypt(self, data: str, password: str) -> Tuple[bytes, bytes]:
        """
        Encrypt data with a password

        Args:
            data: Plaintext data string
            password: Encryption password

        Returns:
            Tuple of (encrypted_bytes, salt)
        """
        salt = self.generate_salt()
        fernet = self.get_fernet(password, salt)
        encrypted = fernet.encrypt(data.encode('utf-8'))
        return encrypted, salt

    def decrypt(self, encrypted: bytes, password: str, salt: bytes) -> str:
        """
        Decrypt data with a password

        Args:
            encrypted: Encrypted bytes
            password: Decryption password
            salt: Salt used during encryption

        Returns:
            Decrypted plaintext string
        """
        fernet = self.get_fernet(password, salt)
        return fernet.decrypt(encrypted).decode('utf-8')

    def secure_clear(self, data: bytearray) -> None:
        """
        Securely clear sensitive data from memory

        Args:
            data: Bytearray to clear (modified in-place)
        """
        try:
            # Overwrite with zeros using ctypes for best-effort secure clearing
            buf = (ctypes.c_char * len(data)).from_buffer(data)
            ctypes.memset(buf, 0, len(data))
        except Exception:
            # Fallback: zero out manually
            for i in range(len(data)):
                data[i] = 0

    def hash_password(self, password: str, salt: bytes) -> str:
        """
        Hash a password for storage comparison

        Args:
            password: Plaintext password
            salt: Salt bytes

        Returns:
            Hex digest of hashed password
        """
        dk = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            self.PBKDF2_ITERATIONS
        )
        return dk.hex()

    def prompt_password(self, prompt: str = "Enter password: ",
                        confirm: bool = False) -> str:
        """
        Securely prompt for a password

        Args:
            prompt: Prompt string to display
            confirm: Whether to ask for confirmation

        Returns:
            Password string
        """
        while True:
            password = getpass.getpass(prompt)
            if not confirm:
                return password
            confirm_pw = getpass.getpass("Confirm password: ")
            if password == confirm_pw:
                return password
            print("Passwords do not match. Try again.")

    def mask_phrase(self, phrase: str, visible_words: int = 2) -> str:
        """
        Mask a seed phrase showing only the first N words

        Args:
            phrase: Seed phrase string
            visible_words: Number of words to show unmasked

        Returns:
            Masked phrase string
        """
        words = phrase.split()
        masked = []
        for i, word in enumerate(words):
            if i < visible_words:
                masked.append(word)
            else:
                masked.append('*' * len(word))
        return ' '.join(masked)

    @staticmethod
    def print_security_warning() -> None:
        """Print a security warning for sensitive operations"""
        print("\n" + "=" * 60)
        print("⚠️  SECURITY WARNING")
        print("=" * 60)
        print("• Seed phrases grant FULL access to your crypto assets")
        print("• Never share seed phrases with anyone")
        print("• Store backups in a secure, offline location")
        print("• Clear clipboard after pasting seed phrases")
        print("• Ensure no one can see your screen")
        print("=" * 60 + "\n")

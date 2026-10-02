"""
AY Vault - Cryptographic Engine
Implements authenticated symmetric encryption (AES-256-GCM), key management,
and PBKDF2/Argon2 key derivation routines.
"""

import os
from pathlib import Path
from typing import Optional, Tuple
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from config.settings import (
    AES_GCM_NONCE_BYTES,
    AES_KEY_SIZE_BYTES,
    MASTER_KEY_FILE,
    PBKDF2_ITERATIONS,
)
from security.security_utils import calculate_sha256_bytes


class CryptoError(Exception):
    """Base exception for cryptographic failures."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption or integrity verification fails."""
    pass


class EncryptionManager:
    """
    Manages vault encryption keys and executes AES-256-GCM authenticated
    encryption and decryption with authenticated tag validation.
    """

    def __init__(self, key_path: Optional[Path] = None):
        self._key_path = key_path or MASTER_KEY_FILE
        self._master_key: bytes = self._load_or_generate_master_key()

    def _load_or_generate_master_key(self) -> bytes:
        """Loads master key from protected file, or generates a fresh 256-bit key."""
        if self._key_path.exists():
            with open(self._key_path, "rb") as f:
                key = f.read()
                if len(key) == AES_KEY_SIZE_BYTES:
                    return key

        # Generate fresh 256-bit cryptographic key
        new_key = AESGCM.generate_key(bit_length=256)
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._key_path, "wb") as f:
            f.write(new_key)
        # Attempt to restrict permissions on POSIX systems if applicable
        try:
            os.chmod(self._key_path, 0o600)
        except Exception:
            pass
        return new_key

    def encrypt_bytes(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypts plaintext using AES-256-GCM.
        Returns: 12-byte Nonce + Ciphertext (with appended 16-byte GCM Auth Tag).
        """
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        aesgcm = AESGCM(self._master_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext

    def decrypt_bytes(self, payload: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypts an encrypted payload using AES-256-GCM and verifies authenticity.
        Raises DecryptionError if payload is tampered or corrupt.
        """
        if len(payload) < AES_GCM_NONCE_BYTES + 16:
            raise DecryptionError("Payload is too short to be valid ciphertext.")

        nonce = payload[:AES_GCM_NONCE_BYTES]
        ciphertext = payload[AES_GCM_NONCE_BYTES:]

        aesgcm = AESGCM(self._master_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag as e:
            raise DecryptionError(
                "Cryptographic Integrity Check Failed: Authentication tag mismatch or corrupted ciphertext."
            ) from e
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {str(e)}") from e

    def encrypt_file(
        self, source_path: Path, dest_path: Path
    ) -> Tuple[str, str, int]:
        """
        Encrypts a file from source to dest in vault.
        Returns (plaintext_sha256, ciphertext_sha256, ciphertext_size_bytes).
        """
        with open(source_path, "rb") as f:
            plaintext = f.read()

        plaintext_sha256 = calculate_sha256_bytes(plaintext)
        ciphertext_payload = self.encrypt_bytes(
            plaintext, associated_data=dest_path.name.encode("utf-8")
        )
        ciphertext_sha256 = calculate_sha256_bytes(ciphertext_payload)

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(dest_path, "wb") as f:
            f.write(ciphertext_payload)

        return plaintext_sha256, ciphertext_sha256, len(ciphertext_payload)

    def decrypt_file(
        self,
        encrypted_path: Path,
        dest_path: Path,
        expected_plaintext_sha256: Optional[str] = None,
    ) -> str:
        """
        Decrypts a vault file and writes the plaintext to dest_path.
        Verifies both AES-GCM authentication tag and SHA-256 plaintext integrity.
        """
        with open(encrypted_path, "rb") as f:
            ciphertext_payload = f.read()

        plaintext = self.decrypt_bytes(
            ciphertext_payload, associated_data=encrypted_path.name.encode("utf-8")
        )
        actual_sha256 = calculate_sha256_bytes(plaintext)

        if expected_plaintext_sha256 and actual_sha256 != expected_plaintext_sha256:
            raise DecryptionError(
                f"Integrity Mismatch: expected {expected_plaintext_sha256}, got {actual_sha256}"
            )

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(dest_path, "wb") as f:
            f.write(plaintext)

        return actual_sha256

    @staticmethod
    def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
        """Derives a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE_BYTES,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(passphrase.encode("utf-8"))

    @staticmethod
    def encrypt_with_passphrase(plaintext: bytes, passphrase: str) -> bytes:
        """
        Encrypts bytes using a user-supplied passphrase (used for encrypted backups).
        Format: [16 bytes SALT] + [12 bytes NONCE] + [CIPHERTEXT + 16 bytes TAG]
        """
        salt = os.urandom(16)
        key = EncryptionManager.derive_key_from_passphrase(passphrase, salt)
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return salt + nonce + ciphertext

    @staticmethod
    def decrypt_with_passphrase(payload: bytes, passphrase: str) -> bytes:
        """
        Decrypts bytes encrypted with a user-supplied passphrase.
        """
        if len(payload) < 16 + AES_GCM_NONCE_BYTES + 16:
            raise DecryptionError("Backup archive payload is invalid or truncated.")

        salt = payload[:16]
        nonce = payload[16 : 16 + AES_GCM_NONCE_BYTES]
        ciphertext = payload[16 + AES_GCM_NONCE_BYTES :]

        key = EncryptionManager.derive_key_from_passphrase(passphrase, salt)
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as e:
            raise DecryptionError("Incorrect backup passphrase or corrupted archive.") from e


_global_encryption_manager = EncryptionManager()


def get_encryption_manager() -> EncryptionManager:
    """Returns the singleton EncryptionManager."""
    return _global_encryption_manager

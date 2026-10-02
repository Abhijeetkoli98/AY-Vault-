"""
AY Vault - Encrypted Document Storage
Handles physical storage, reading, and deletion of encrypted file payloads in the vault.
"""

import os
from pathlib import Path
from typing import Optional, Tuple
from config.settings import VAULT_DIR
from security.encryption import get_encryption_manager
from security.security_utils import calculate_sha256_bytes


class DocumentStorage:
    """Manages raw encrypted file blobs on disk."""

    def __init__(self, vault_dir: Optional[Path] = None):
        self.vault_dir = vault_dir or VAULT_DIR
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.crypto = get_encryption_manager()

    def get_storage_path(self, stored_filename: str) -> Path:
        """Resolves internal storage path."""
        return self.vault_dir / stored_filename

    def store_encrypted_bytes(
        self, doc_id: str, version: int, plaintext_bytes: bytes
    ) -> Tuple[str, str, str, int]:
        """
        Encrypts plaintext bytes with AES-256-GCM and writes to vault.
        Returns: (stored_filename, plaintext_sha256, ciphertext_sha256, ciphertext_size_bytes)
        """
        stored_filename = f"{doc_id}_v{version}.enc"
        dest_path = self.get_storage_path(stored_filename)

        plaintext_sha256 = calculate_sha256_bytes(plaintext_bytes)
        ciphertext = self.crypto.encrypt_bytes(
            plaintext_bytes, associated_data=stored_filename.encode("utf-8")
        )
        ciphertext_sha256 = calculate_sha256_bytes(ciphertext)

        with open(dest_path, "wb") as f:
            f.write(ciphertext)

        return stored_filename, plaintext_sha256, ciphertext_sha256, len(ciphertext)

    def retrieve_and_decrypt(
        self, stored_filename: str, expected_plaintext_sha256: Optional[str] = None
    ) -> bytes:
        """
        Reads encrypted blob, validates AES-GCM tag, decrypts, and checks SHA-256.
        """
        file_path = self.get_storage_path(stored_filename)
        if not file_path.exists():
            raise FileNotFoundError(f"Vault storage file '{stored_filename}' does not exist.")

        with open(file_path, "rb") as f:
            ciphertext = f.read()

        plaintext = self.crypto.decrypt_bytes(
            ciphertext, associated_data=stored_filename.encode("utf-8")
        )

        if expected_plaintext_sha256:
            actual_sha = calculate_sha256_bytes(plaintext)
            if actual_sha != expected_plaintext_sha256:
                raise ValueError("Plaintext integrity hash mismatch after decryption.")

        return plaintext

    def delete_encrypted_file(self, stored_filename: str) -> bool:
        """Securely deletes an encrypted vault file."""
        file_path = self.get_storage_path(stored_filename)
        if file_path.exists():
            try:
                # Overwrite bytes with zeros before unlink (secure file sanitization)
                size = file_path.stat().st_size
                with open(file_path, "wb") as f:
                    f.write(b"\x00" * size)
                file_path.unlink()
                return True
            except Exception:
                file_path.unlink(missing_ok=True)
                return True
        return False

    def get_vault_stats(self) -> dict:
        """Returns statistics about encrypted storage in the vault."""
        total_files = 0
        total_bytes = 0
        for f in self.vault_dir.glob("*.enc"):
            if f.is_file():
                total_files += 1
                total_bytes += f.stat().st_size
        return {
            "total_files": total_files,
            "total_bytes": total_bytes,
            "vault_path": str(self.vault_dir),
        }


_global_doc_storage = DocumentStorage()


def get_doc_storage() -> DocumentStorage:
    """Returns singleton DocumentStorage."""
    return _global_doc_storage

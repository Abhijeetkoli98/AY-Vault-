"""
AY Vault - Security Utilities
Cryptographic helpers, secure comparison, input sanitization, and hashing routines.
"""

import hashlib
import hmac
import os
import re
import secrets
import uuid
from pathlib import Path
from typing import Union


def secure_random_token(length_bytes: int = 32) -> str:
    """Generates a cryptographically strong URL-safe random token."""
    return secrets.token_urlsafe(length_bytes)


def secure_uuid() -> str:
    """Generates a secure UUIDv4 string for document and resource IDs."""
    return str(uuid.uuid4())


def constant_time_compare(val1: Union[str, bytes], val2: Union[str, bytes]) -> bool:
    """Performs constant-time comparison to prevent timing attacks."""
    if isinstance(val1, str):
        val1 = val1.encode("utf-8")
    if isinstance(val2, str):
        val2 = val2.encode("utf-8")
    return hmac.compare_digest(val1, val2)


def calculate_sha256_bytes(data: bytes) -> str:
    """Calculates hex SHA-256 digest of raw byte content."""
    return hashlib.sha256(data).hexdigest()


def calculate_sha256_file(file_path: Union[str, Path]) -> str:
    """Calculates hex SHA-256 digest of a disk file chunk by chunk."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes filenames to prevent path traversal, hidden files, or illegal characters.
    Strips directory separators and non-standard characters.
    """
    # Remove directory paths
    base_name = os.path.basename(filename)
    # Strip null bytes and control chars
    clean_name = re.sub(r"[\x00-\x1f\x7f]", "", base_name)
    # Keep only alphanumeric, hyphens, underscores, dots, and spaces
    clean_name = re.sub(r"[^a-zA-Z0-9_\-\. ]", "_", clean_name).strip()
    if not clean_name or clean_name.startswith("."):
        clean_name = f"vault_doc_{secrets.token_hex(4)}.dat"
    return clean_name


def format_file_size(size_in_bytes: int) -> str:
    """Formats bytes into human-readable representation."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.1f} {unit}"
        size_in_bytes /= 1024.0
    return f"{size_in_bytes:.1f} TB"

"""
AY Vault - Password Manager
Implements RFC 9106 Argon2id password hashing, complexity validation, and verification.
"""

import re
from typing import Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from config.settings import (
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_HASH_LEN,
    ARGON2_SALT_LEN,
    PASSWORD_MIN_LENGTH,
)


class PasswordManager:
    """Manages password hashing and security policies using Argon2id."""

    def __init__(self):
        self._hasher = PasswordHasher(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            salt_len=ARGON2_SALT_LEN,
        )

    def hash_password(self, password: str) -> str:
        """Hashes a plaintext password using Argon2id with unique cryptographic salt."""
        return self._hasher.hash(password)

    def verify_password(self, password_hash: str, candidate_password: str) -> bool:
        """Verifies a plaintext candidate against an Argon2id hash in constant time."""
        try:
            return self._hasher.verify(password_hash, candidate_password)
        except (VerifyMismatchError, VerificationError, Exception):
            return False

    def check_needs_rehash(self, password_hash: str) -> bool:
        """Determines if the hash parameters need to be updated to match current policy."""
        try:
            return self._hasher.check_needs_rehash(password_hash)
        except Exception:
            return False

    @staticmethod
    def validate_password_complexity(password: str) -> Tuple[bool, str]:
        """
        Validates password against enterprise complexity requirements:
        - Minimum length
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special symbol
        """
        if len(password) < PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter (A-Z)."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter (a-z)."
        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one numerical digit (0-9)."
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\",.<>?/\\|`~]", password):
            return False, "Password must contain at least one special character."
        return True, "Password meets all complexity requirements."


_global_password_manager = PasswordManager()


def get_password_manager() -> PasswordManager:
    """Returns the singleton PasswordManager instance."""
    return _global_password_manager

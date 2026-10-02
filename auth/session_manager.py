"""
AY Vault - Session Management
Maintains active user sessions, token tracking, and inactivity timeouts.
"""

import datetime
from dataclasses import dataclass
from typing import Optional
from config.settings import SESSION_TIMEOUT_MINUTES
from security.security_utils import secure_random_token


@dataclass
class UserSession:
    """Represents an authenticated user security context."""
    user_id: int
    username: str
    full_name: str
    role: str
    department: str
    clearance_level: str
    token: str
    created_at: datetime.datetime
    last_activity: datetime.datetime
    ip_address: str = "127.0.0.1 (Localhost)"

    def is_expired(self) -> bool:
        """Checks if session has expired due to inactivity."""
        now = datetime.datetime.now(datetime.timezone.utc)
        elapsed_seconds = (now - self.last_activity).total_seconds()
        return elapsed_seconds > (SESSION_TIMEOUT_MINUTES * 60)

    def touch(self) -> None:
        """Updates last activity timestamp to prevent timeout during active usage."""
        self.last_activity = datetime.datetime.now(datetime.timezone.utc)


class SessionManager:
    """Manages active application session lifecycle."""

    def __init__(self):
        self._current_session: Optional[UserSession] = None

    def create_session(
        self, user_record: dict, ip_address: str = "127.0.0.1 (Localhost)"
    ) -> UserSession:
        """Creates and stores an authenticated user session."""
        now = datetime.datetime.now(datetime.timezone.utc)
        session = UserSession(
            user_id=user_record["id"],
            username=user_record["username"],
            full_name=user_record["full_name"],
            role=user_record["role"],
            department=user_record["department"],
            clearance_level=user_record["clearance_level"],
            token=secure_random_token(32),
            created_at=now,
            last_activity=now,
            ip_address=ip_address,
        )
        self._current_session = session
        return session

    def get_current_session(self) -> Optional[UserSession]:
        """Returns the current active session, or None if expired/not logged in."""
        if self._current_session is None:
            return None
        if self._current_session.is_expired():
            self._current_session = None
            return None
        self._current_session.touch()
        return self._current_session

    def terminate_session(self) -> None:
        """Terminates active session (logout)."""
        self._current_session = None

    def is_authenticated(self) -> bool:
        """Returns True if a valid unexpired session exists."""
        return self.get_current_session() is not None


_global_session_manager = SessionManager()


def get_session_manager() -> SessionManager:
    """Returns the singleton SessionManager."""
    return _global_session_manager

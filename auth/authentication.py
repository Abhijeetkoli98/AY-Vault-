"""
AY Vault - Authentication Service
Handles login, password verification, account lockouts (exactly 5 failed attempts),
session initiation, and audit tracking.
"""

import datetime
from dataclasses import dataclass
from typing import Optional
from auth.password_manager import get_password_manager
from auth.session_manager import UserSession, get_session_manager
from audit.audit_logger import get_audit_logger
from config.settings import MAX_FAILED_LOGINS
from database.database import get_db


@dataclass
class AuthResult:
    """Encapsulates the result of an authentication operation."""
    success: bool
    session: Optional[UserSession] = None
    error_message: Optional[str] = None
    is_locked: bool = False
    remaining_attempts: int = MAX_FAILED_LOGINS


class AuthenticationService:
    """Manages user authentication, lockout enforcement, and credential verification."""

    def __init__(self):
        self.db = get_db()
        self.password_manager = get_password_manager()
        self.session_manager = get_session_manager()
        self.audit_logger = get_audit_logger()

    def login(
        self,
        username: str,
        password: str,
        ip_address: str = "127.0.0.1 (Localhost)",
    ) -> AuthResult:
        """
        Authenticates user with username and password.
        Enforces strict account lockout on 5 consecutive failures.
        All attempts are logged to the tamper-evident audit ledger.
        """
        username = username.strip()
        if not username or not password:
            return AuthResult(
                success=False,
                error_message="Username and password are required.",
                remaining_attempts=MAX_FAILED_LOGINS,
            )

        user = self.db.fetch_one(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE;", (username,)
        )

        if not user:
            # Timing-attack mitigation: perform a dummy verify to equalize response time
            self.password_manager.verify_password(
                "$argon2id$v=19$m=65536,t=3,p=4$dummy_salt$dummy_hash", "invalid"
            )
            self.audit_logger.log_event(
                event_type="AUTH_FAILED",
                action="USER_LOGIN_UNKNOWN_ACCOUNT",
                status="FAILURE",
                username=username,
                resource_type="USER",
                resource_id=None,
                ip_address=ip_address,
                details={"reason": "User not found in system directory."},
            )
            return AuthResult(
                success=False,
                error_message="Invalid username or password.",
                remaining_attempts=MAX_FAILED_LOGINS,
            )

        user_id = user["id"]
        canonical_username = user["username"]

        # Check if already locked
        if user["is_locked"]:
            self.audit_logger.log_event(
                event_type="AUTH_BLOCKED",
                action="USER_LOGIN_LOCKED_ACCOUNT",
                status="DENIED",
                user_id=user_id,
                username=canonical_username,
                resource_type="USER",
                resource_id=str(user_id),
                ip_address=ip_address,
                details={
                    "reason": "Account is locked due to security policy violations.",
                    "locked_at": user["locked_at"],
                },
            )
            return AuthResult(
                success=False,
                is_locked=True,
                remaining_attempts=0,
                error_message=(
                    f"Account '{canonical_username}' is LOCKED due to {MAX_FAILED_LOGINS} consecutive failed login attempts. "
                    "An Administrator must unlock your account."
                ),
            )

        # Verify password
        is_valid = self.password_manager.verify_password(user["password_hash"], password)

        if not is_valid:
            new_failed_count = user["failed_login_attempts"] + 1

            if new_failed_count >= MAX_FAILED_LOGINS:
                # Trigger Account Lockout
                now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
                self.db.execute(
                    "UPDATE users SET failed_login_attempts = ?, is_locked = 1, locked_at = ? WHERE id = ?;",
                    (new_failed_count, now_str, user_id),
                )
                self.audit_logger.log_event(
                    event_type="AUTH_LOCKOUT",
                    action="ACCOUNT_LOCKED_EXCESSIVE_FAILURES",
                    status="DENIED",
                    user_id=user_id,
                    username=canonical_username,
                    resource_type="USER",
                    resource_id=str(user_id),
                    ip_address=ip_address,
                    details={
                        "failed_attempts": new_failed_count,
                        "lockout_threshold": MAX_FAILED_LOGINS,
                        "locked_at": now_str,
                    },
                )
                return AuthResult(
                    success=False,
                    is_locked=True,
                    remaining_attempts=0,
                    error_message=(
                        f"Account '{canonical_username}' has been LOCKED. "
                        f"Failed {MAX_FAILED_LOGINS} consecutive login attempts. Contact an Administrator."
                    ),
                )
            else:
                self.db.execute(
                    "UPDATE users SET failed_login_attempts = ? WHERE id = ?;",
                    (new_failed_count, user_id),
                )
                remaining = MAX_FAILED_LOGINS - new_failed_count
                self.audit_logger.log_event(
                    event_type="AUTH_FAILED",
                    action="USER_LOGIN_BAD_CREDENTIALS",
                    status="FAILURE",
                    user_id=user_id,
                    username=canonical_username,
                    resource_type="USER",
                    resource_id=str(user_id),
                    ip_address=ip_address,
                    details={
                        "failed_attempt_number": new_failed_count,
                        "remaining_attempts": remaining,
                    },
                )
                return AuthResult(
                    success=False,
                    is_locked=False,
                    remaining_attempts=remaining,
                    error_message=f"Invalid credentials. {remaining} attempt(s) remaining before account lockout.",
                )

        # Successful Login: Reset failed attempts & update last_login
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.db.execute(
            "UPDATE users SET failed_login_attempts = 0, last_login = ? WHERE id = ?;",
            (now_str, user_id),
        )

        session = self.session_manager.create_session(user, ip_address=ip_address)

        self.audit_logger.log_event(
            event_type="AUTH_LOGIN",
            action="USER_LOGIN_SUCCESS",
            status="SUCCESS",
            user_id=user_id,
            username=canonical_username,
            resource_type="SESSION",
            resource_id=session.token[:8] + "...",
            ip_address=ip_address,
            details={
                "role": user["role"],
                "clearance": user["clearance_level"],
                "department": user["department"],
            },
        )

        return AuthResult(success=True, session=session, remaining_attempts=MAX_FAILED_LOGINS)

    def logout(self) -> None:
        """Terminates session and writes audit event."""
        session = self.session_manager.get_current_session()
        if session:
            self.audit_logger.log_event(
                event_type="AUTH_LOGOUT",
                action="USER_LOGOUT",
                status="SUCCESS",
                user_id=session.user_id,
                username=session.username,
                resource_type="SESSION",
                resource_id=session.token[:8] + "...",
                ip_address=session.ip_address,
                details={"duration_seconds": (datetime.datetime.now(datetime.timezone.utc) - session.created_at).total_seconds()},
            )
            self.session_manager.terminate_session()

    def unlock_user_account(self, target_user_id: int, admin_session: UserSession) -> bool:
        """Unlocks a locked account. Requires Admin privilege."""
        if admin_session.role != "Admin":
            return False

        user = self.db.fetch_one("SELECT * FROM users WHERE id = ?;", (target_user_id,))
        if not user:
            return False

        self.db.execute(
            "UPDATE users SET is_locked = 0, failed_login_attempts = 0, locked_at = NULL WHERE id = ?;",
            (target_user_id,),
        )

        self.audit_logger.log_event(
            event_type="USER_UNLOCK",
            action="ADMIN_UNLOCKED_USER",
            status="SUCCESS",
            user_id=admin_session.user_id,
            username=admin_session.username,
            resource_type="USER",
            resource_id=str(target_user_id),
            details={"unlocked_user": user["username"], "unlocked_by": admin_session.username},
        )
        return True


_global_auth_service = AuthenticationService()


def get_auth_service() -> AuthenticationService:
    """Returns singleton AuthenticationService."""
    return _global_auth_service

"""
AY Vault - User Administration & Identity Management
Handles user creation, role assignment, password resets, and account unlocking.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from auth.password_manager import get_password_manager
from auth.session_manager import UserSession
from audit.audit_logger import get_audit_logger
from database.database import get_db
from security.access_control import VaultAction
from security.policy_engine import PolicyDecision, get_policy_engine


class UserManager:
    """Manages identity lifecycle and user attributes."""

    def __init__(self):
        self.db = get_db()
        self.policy = get_policy_engine()
        self.audit = get_audit_logger()
        self.pwd = get_password_manager()

    def list_users(self, session: UserSession) -> Tuple[List[Dict[str, Any]], PolicyDecision]:
        """Lists all system users. Requires USER_MANAGE authorization."""
        decision = self.policy.evaluate(session, VaultAction.USER_MANAGE)
        if not decision.is_permitted:
            return [], decision

        users = self.db.fetch_all(
            """
            SELECT id, username, full_name, role, department,
                   clearance_level, failed_login_attempts, is_locked,
                   locked_at, created_at, last_login
            FROM users
            ORDER BY id ASC;
            """
        )
        return users, decision

    def create_user(
        self,
        username: str,
        password: str,
        full_name: str,
        role: str,
        department: str,
        clearance_level: str,
        session: UserSession,
    ) -> Tuple[bool, PolicyDecision, str]:
        """Creates a new user record. Requires USER_MANAGE authorization."""
        decision = self.policy.evaluate(session, VaultAction.USER_MANAGE)
        if not decision.is_permitted:
            return False, decision, decision.reason

        username = username.strip()
        full_name = full_name.strip()

        if not username or not password or not full_name:
            return False, decision, "Username, password, and full name are required."

        # Validate password complexity
        is_valid_pwd, msg = self.pwd.validate_password_complexity(password)
        if not is_valid_pwd:
            return False, decision, msg

        existing = self.db.fetch_one(
            "SELECT id FROM users WHERE username = ? COLLATE NOCASE;", (username,)
        )
        if existing:
            return False, decision, f"Username '{username}' already exists."

        pwd_hash = self.pwd.hash_password(password)
        now_str = datetime.now(timezone.utc).isoformat()

        user_id = self.db.execute(
            """
            INSERT INTO users (
                username, password_hash, full_name, role, department,
                clearance_level, failed_login_attempts, is_locked,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?);
            """,
            (username, pwd_hash, full_name, role, department, clearance_level, now_str),
        )

        self.audit.log_event(
            event_type="USER_CREATE",
            action="CREATE_NEW_USER",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="USER",
            resource_id=str(user_id),
            details={
                "created_username": username,
                "role": role,
                "clearance": clearance_level,
                "department": department,
            },
        )
        return True, decision, "User created successfully."

    def update_user_attributes(
        self,
        target_user_id: int,
        role: str,
        department: str,
        clearance_level: str,
        session: UserSession,
    ) -> Tuple[bool, PolicyDecision, str]:
        """Updates user role, department, or clearance. Requires USER_MANAGE authorization."""
        decision = self.policy.evaluate(session, VaultAction.USER_MANAGE)
        if not decision.is_permitted:
            return False, decision, decision.reason

        user = self.db.fetch_one("SELECT * FROM users WHERE id = ?;", (target_user_id,))
        if not user:
            return False, decision, "User not found."

        self.db.execute(
            "UPDATE users SET role = ?, department = ?, clearance_level = ? WHERE id = ?;",
            (role, department, clearance_level, target_user_id),
        )

        self.audit.log_event(
            event_type="USER_UPDATE",
            action="MODIFY_USER_ATTRIBUTES",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="USER",
            resource_id=str(target_user_id),
            details={
                "target_username": user["username"],
                "new_role": role,
                "new_clearance": clearance_level,
                "new_department": department,
            },
        )
        return True, decision, "User attributes updated successfully."

    def reset_user_password(
        self,
        target_user_id: int,
        new_password: str,
        session: UserSession,
    ) -> Tuple[bool, PolicyDecision, str]:
        """Admin password reset for a target user. Requires USER_MANAGE authorization."""
        decision = self.policy.evaluate(session, VaultAction.USER_MANAGE)
        if not decision.is_permitted:
            return False, decision, decision.reason

        is_valid_pwd, msg = self.pwd.validate_password_complexity(new_password)
        if not is_valid_pwd:
            return False, decision, msg

        user = self.db.fetch_one("SELECT * FROM users WHERE id = ?;", (target_user_id,))
        if not user:
            return False, decision, "User not found."

        new_hash = self.pwd.hash_password(new_password)
        self.db.execute(
            "UPDATE users SET password_hash = ?, failed_login_attempts = 0 WHERE id = ?;",
            (new_hash, target_user_id),
        )

        self.audit.log_event(
            event_type="USER_PWD_RESET",
            action="ADMIN_PASSWORD_RESET",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="USER",
            resource_id=str(target_user_id),
            details={"target_username": user["username"]},
        )
        return True, decision, "Password reset successfully."

    def unlock_user(
        self,
        target_user_id: int,
        session: UserSession,
    ) -> Tuple[bool, PolicyDecision, str]:
        """Unlocks a locked account. Requires USER_MANAGE authorization."""
        decision = self.policy.evaluate(session, VaultAction.USER_MANAGE)
        if not decision.is_permitted:
            return False, decision, decision.reason

        user = self.db.fetch_one("SELECT * FROM users WHERE id = ?;", (target_user_id,))
        if not user:
            return False, decision, "User not found."

        self.db.execute(
            "UPDATE users SET is_locked = 0, failed_login_attempts = 0, locked_at = NULL WHERE id = ?;",
            (target_user_id,),
        )

        self.audit.log_event(
            event_type="USER_UNLOCK",
            action="ADMIN_MANUAL_UNLOCK",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="USER",
            resource_id=str(target_user_id),
            details={"target_username": user["username"]},
        )
        return True, decision, f"Account '{user['username']}' unlocked successfully."


_global_user_manager = UserManager()


def get_user_manager() -> UserManager:
    """Returns singleton UserManager."""
    return _global_user_manager

"""
AY Vault - Access Control & RBAC Matrix
Defines system actions, role hierarchies, and clearance evaluations.
"""

from enum import Enum
from typing import Dict, List
from config.settings import (
    CLASSIFICATION_RANK,
    PERM_AUDIT_VERIFY,
    PERM_AUDIT_VIEW,
    PERM_BACKUP_CREATE,
    PERM_BACKUP_RESTORE,
    PERM_DOC_CHANGE_PERM,
    PERM_DOC_DELETE,
    PERM_DOC_DOWNLOAD,
    PERM_DOC_READ,
    PERM_DOC_WRITE,
    PERM_SECURITY_ADMIN,
    PERM_USER_MANAGE,
    ROLE_ADMIN,
    ROLE_MANAGER,
    ROLE_PERMISSIONS,
    ROLE_VIEWER,
)


class VaultAction(str, Enum):
    """Actions subject to policy enforcement."""
    DOC_READ = PERM_DOC_READ
    DOC_WRITE = PERM_DOC_WRITE
    DOC_DOWNLOAD = PERM_DOC_DOWNLOAD
    DOC_DELETE = PERM_DOC_DELETE
    DOC_CHANGE_PERM = PERM_DOC_CHANGE_PERM
    AUDIT_VIEW = PERM_AUDIT_VIEW
    AUDIT_VERIFY = PERM_AUDIT_VERIFY
    USER_MANAGE = PERM_USER_MANAGE
    BACKUP_CREATE = PERM_BACKUP_CREATE
    BACKUP_RESTORE = PERM_BACKUP_RESTORE
    SECURITY_ADMIN = PERM_SECURITY_ADMIN


def has_role_permission(role: str, action: VaultAction) -> bool:
    """Checks if role possesses baseline permission for an action."""
    allowed_perms = ROLE_PERMISSIONS.get(role, [])
    return action.value in allowed_perms


def is_clearance_sufficient(user_clearance: str, resource_classification: str) -> bool:
    """
    Evaluates Bell-LaPadula simple security property (No Read Up).
    User clearance rank must be >= resource classification rank.
    """
    user_rank = CLASSIFICATION_RANK.get(user_clearance, 0)
    resource_rank = CLASSIFICATION_RANK.get(resource_classification, 999)
    return user_rank >= resource_rank

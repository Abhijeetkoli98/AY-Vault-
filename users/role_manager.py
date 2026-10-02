"""
AY Vault - Role & Permission Definitions
Central definitions for system roles, permissions, and security clearance hierarchies.
"""

from typing import Dict, List
from config.settings import (
    CLASSIFICATION_LEVELS,
    CLASSIFICATION_RANK,
    DEPARTMENTS,
    ROLE_ADMIN,
    ROLE_MANAGER,
    ROLE_PERMISSIONS,
    ROLE_VIEWER,
    SYSTEM_ROLES,
)


class RoleManager:
    """Provides role metadata, permission definitions, and clearance mappings."""

    @staticmethod
    def get_all_roles() -> List[str]:
        return list(SYSTEM_ROLES)

    @staticmethod
    def get_role_permissions(role: str) -> List[str]:
        return list(ROLE_PERMISSIONS.get(role, []))

    @staticmethod
    def get_all_departments() -> List[str]:
        return list(DEPARTMENTS)

    @staticmethod
    def get_all_clearance_levels() -> List[str]:
        return list(CLASSIFICATION_LEVELS)

    @staticmethod
    def get_role_description(role: str) -> str:
        descriptions = {
            ROLE_ADMIN: "Full system administration, key management, user administration, backup/restore, and audit verification.",
            ROLE_MANAGER: "Document creation, editing, departmental administration, and standard audit log review.",
            ROLE_VIEWER: "Read-only document access within authorized clearance levels and assigned departmental compartment.",
        }
        return descriptions.get(role, "Standard authenticated user role.")


_global_role_manager = RoleManager()


def get_role_manager() -> RoleManager:
    """Returns singleton RoleManager."""
    return _global_role_manager

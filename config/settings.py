"""
AY Vault - Configuration & Security Settings
Centralized configuration management for paths, crypto parameters, RBAC, and UI styling.
"""

from pathlib import Path
from typing import Dict, List

# Base Directory Paths
BASE_DIR: Path = Path(__file__).resolve().parent.parent
DATA_DIR: Path = BASE_DIR / "data"
VAULT_DIR: Path = DATA_DIR / "vault"
BACKUP_DIR: Path = DATA_DIR / "backups"
ASSETS_DIR: Path = BASE_DIR / "assets"
DB_PATH: Path = DATA_DIR / "ayvault.db"
MASTER_KEY_FILE: Path = DATA_DIR / ".master.key"

# Ensure runtime directories exist
for path in [DATA_DIR, VAULT_DIR, BACKUP_DIR, ASSETS_DIR]:
    path.mkdir(parents=True, exist_ok=True)

# Authentication & Account Security
MAX_FAILED_LOGINS: int = 5  # Lock account after exactly 5 consecutive failed attempts
SESSION_TIMEOUT_MINUTES: int = 30
PASSWORD_MIN_LENGTH: int = 8

# Cryptographic Specifications
# Argon2id Parameters (RFC 9106 recommended defaults)
ARGON2_TIME_COST: int = 3
ARGON2_MEMORY_COST: int = 65536  # 64 MB
ARGON2_PARALLELISM: int = 4
ARGON2_HASH_LEN: int = 32
ARGON2_SALT_LEN: int = 16

# Symmetric Encryption: AES-256-GCM
AES_KEY_SIZE_BYTES: int = 32  # 256 bits
AES_GCM_NONCE_BYTES: int = 12  # 96 bits standard nonce
PBKDF2_ITERATIONS: int = 200000

# Document Security Classifications & Hierarchies
CLASSIFICATION_LEVELS: List[str] = [
    "UNRESTRICTED",
    "CONFIDENTIAL",
    "RESTRICTED",
    "TOP_SECRET",
]

CLASSIFICATION_RANK: Dict[str, int] = {
    "UNRESTRICTED": 1,
    "CONFIDENTIAL": 2,
    "RESTRICTED": 3,
    "TOP_SECRET": 4,
}

DEPARTMENTS: List[str] = [
    "Security",
    "Engineering",
    "Finance",
    "Operations",
    "Executive",
]

# Standard System Roles
ROLE_ADMIN: str = "Admin"
ROLE_MANAGER: str = "Manager"
ROLE_VIEWER: str = "Viewer"

SYSTEM_ROLES: List[str] = [ROLE_ADMIN, ROLE_MANAGER, ROLE_VIEWER]

# Permissions
PERM_DOC_READ: str = "doc:read"
PERM_DOC_WRITE: str = "doc:write"
PERM_DOC_DOWNLOAD: str = "doc:download"
PERM_DOC_DELETE: str = "doc:delete"
PERM_DOC_CHANGE_PERM: str = "doc:change_perm"
PERM_AUDIT_VIEW: str = "audit:view"
PERM_AUDIT_VERIFY: str = "audit:verify"
PERM_USER_MANAGE: str = "user:manage"
PERM_BACKUP_CREATE: str = "backup:create"
PERM_BACKUP_RESTORE: str = "backup:restore"
PERM_SECURITY_ADMIN: str = "security:admin"

ROLE_PERMISSIONS: Dict[str, List[str]] = {
    ROLE_ADMIN: [
        PERM_DOC_READ,
        PERM_DOC_WRITE,
        PERM_DOC_DOWNLOAD,
        PERM_DOC_DELETE,
        PERM_DOC_CHANGE_PERM,
        PERM_AUDIT_VIEW,
        PERM_AUDIT_VERIFY,
        PERM_USER_MANAGE,
        PERM_BACKUP_CREATE,
        PERM_BACKUP_RESTORE,
        PERM_SECURITY_ADMIN,
    ],
    ROLE_MANAGER: [
        PERM_DOC_READ,
        PERM_DOC_WRITE,
        PERM_DOC_DOWNLOAD,
        PERM_AUDIT_VIEW,
    ],
    ROLE_VIEWER: [
        PERM_DOC_READ,
    ],
}

# UI Theme - High-Contrast Dark Slate Cybersecurity Aesthetic
THEME = {
    "bg_dark": "#090d16",          # Deepest background
    "bg_card": "#131b2e",          # Card / Surface background
    "bg_surface": "#1e293b",       # Intermediate surface
    "bg_input": "#0f172a",         # Entry inputs
    "border": "#2c3e55",           # Borders & grid lines
    "border_focus": "#38bdf8",     # Focused border
    "primary": "#3b82f6",          # Primary action blue
    "primary_hover": "#2563eb",    # Hover blue
    "accent_cyan": "#06b6d4",      # Highlighting / Key stats
    "accent_indigo": "#6366f1",    # Secondary accent
    "success": "#10b981",          # Audit verified / safe green
    "success_bg": "#064e3b",       # Green badge background
    "warning": "#f59e0b",          # Alerts / Warnings
    "warning_bg": "#78350f",       # Warning badge background
    "danger": "#ef4444",           # Locks / Violations / Tampering
    "danger_bg": "#7f1d1d",        # Danger badge background
    "text_primary": "#f8fafc",     # High contrast foreground
    "text_secondary": "#94a3b8",   # Soft subheadings
    "text_muted": "#64748b",       # Footers and inactive labels
    "sidebar_bg": "#0d1322",       # Distinct sidebar
    "sidebar_active": "#1d283a",   # Active menu item
}

# Application Metadata
APP_NAME: str = "AY Vault"
APP_SUBTITLE: str = "Secure Offline Document Management System"
APP_VERSION: str = "1.0.0-SEC"

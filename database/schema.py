"""
AY Vault - Database Schema Definitions
Defines tables for users, encrypted documents, version tracking, hash-chained audit logs,
and policy configurations.
"""

SCHEMA_SQL = """
-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL,
    department TEXT NOT NULL,
    clearance_level TEXT NOT NULL DEFAULT 'UNRESTRICTED',
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    is_locked INTEGER NOT NULL DEFAULT 0,
    locked_at TEXT,
    created_at TEXT NOT NULL,
    last_login TEXT
);

-- Documents Table
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    classification_level TEXT NOT NULL,
    department TEXT NOT NULL,
    owner_id INTEGER NOT NULL,
    owner_username TEXT NOT NULL,
    plaintext_sha256 TEXT NOT NULL,
    ciphertext_sha256 TEXT NOT NULL,
    encryption_algo TEXT NOT NULL DEFAULT 'AES-256-GCM',
    version INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(owner_id) REFERENCES users(id)
);

-- Document Versions Table
CREATE TABLE IF NOT EXISTS document_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id TEXT NOT NULL,
    version_number INTEGER NOT NULL,
    stored_filename TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    plaintext_sha256 TEXT NOT NULL,
    ciphertext_sha256 TEXT NOT NULL,
    modified_by INTEGER NOT NULL,
    modified_by_username TEXT NOT NULL,
    change_summary TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(document_id) REFERENCES documents(id)
);

-- Hash-Chained Tamper-Evident Audit Ledger
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user_id INTEGER,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    status TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '127.0.0.1 (Localhost)',
    details TEXT NOT NULL DEFAULT '{}',
    previous_hash TEXT NOT NULL,
    current_hash TEXT NOT NULL
);

-- Security Policies Table
CREATE TABLE IF NOT EXISTS security_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_name TEXT UNIQUE NOT NULL,
    description TEXT,
    min_clearance TEXT NOT NULL,
    department_enforced INTEGER NOT NULL DEFAULT 1,
    require_admin_override INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1
);

-- System Key-Value Configuration / Metadata
CREATE TABLE IF NOT EXISTS system_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Indexes for Fast Querying and Forensics
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_docs_classification ON documents(classification_level);
CREATE INDEX IF NOT EXISTS idx_docs_department ON documents(department);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username);
"""

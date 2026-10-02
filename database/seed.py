"""
AY Vault - Database Seeding & Mock Enterprise Data Ingestion
Initializes schema, creates default enterprise roles, users (including pre-locked account),
encrypts realistic sample documents into data/vault/, and creates an initial valid audit chain.
"""

from datetime import datetime, timezone
from pathlib import Path
from auth.password_manager import get_password_manager
from audit.audit_logger import get_audit_logger
from audit.audit_verifier import get_audit_verifier
from config.settings import VAULT_DIR
from database.database import get_db
from documents.document_storage import get_doc_storage
from security.security_utils import calculate_sha256_bytes, secure_uuid


SAMPLE_DOCS = [
    {
        "title": "AY-SEC-2026 Incident Response & Breach Containment Plan",
        "filename": "AY-SEC-2026-Incident-Response-Plan.md",
        "classification": "TOP_SECRET",
        "department": "Security",
        "owner_username": "admin",
        "description": "Standard Operating Procedure for handling zero-day exploits, containment isolation, and forensic triage.",
        "content": (
            "# AY Vault - Cyber Incident Response & Breach Containment SOP\n\n"
            "**Classification: TOP SECRET // NOFORN**\n"
            "**Effective Date: October 2026**\n"
            "**Document Control ID: AY-SOP-IR-0994**\n\n"
            "## 1. Executive Summary\n"
            "This protocol establishes the mandatory response procedures for containment, eradication,\n"
            "and cryptographic chain-of-custody in the event of an adversary breach or hardware compromise.\n\n"
            "## 2. Immediate Containment Checklist\n"
            "1. Sever all network and air-gap bridge connections.\n"
            "2. Execute cryptographic key revocation for all active session tokens.\n"
            "3. Export immutable audit ledger snapshot to write-once optical media.\n"
            "4. Take live volatility memory dumps prior to system power cycling.\n\n"
            "## 3. Cryptographic Re-Anchoring\n"
            "If database tampering is suspected, run forensic audit verification via `AuditVerifier`.\n"
            "Cross-reference current head hash with offsite cryptographic witness."
        ),
    },
    {
        "title": "Q3 Financial Audit & Capital Reserves Ledger",
        "filename": "Q3-Financial-Audit-Report.txt",
        "classification": "RESTRICTED",
        "department": "Finance",
        "owner_username": "bob_viewer",
        "description": "Quarterly audit evaluation of liquid operating reserves, capital expenditure, and risk insurance.",
        "content": (
            "AY ENTERPRISE - Q3 FINANCIAL AUDIT & CAPITAL RESERVES\n"
            "Classification: RESTRICTED - FINANCE INTERNAL ONLY\n"
            "Auditor: Bob Martinez, Senior Financial Analyst\n\n"
            "--- SUMMARY OF ASSETS & RESERVES ---\n"
            "Operating Liquidity:       $14,250,000 USD\n"
            "Cryptographic Vault Reserves: $8,700,000 USD\n"
            "Cyber Insurance Hedge:      $25,000,000 Policy Coverage\n\n"
            "--- COMPLIANCE AFFIRMATION ---\n"
            "All balance sheets have been reconciled against internal ledgers.\n"
            "Offline records match physical custody certificates."
        ),
    },
    {
        "title": "Zero-Trust Cloud Infrastructure Architecture Blueprint",
        "filename": "Cloud-Infrastructure-Architecture-Blueprint.md",
        "classification": "CONFIDENTIAL",
        "department": "Engineering",
        "owner_username": "sarah_mgr",
        "description": "Microsegmentation guidelines, mutual TLS parameters, and KMS envelope encryption topologies.",
        "content": (
            "# Zero-Trust Cloud Infrastructure Architecture Blueprint\n\n"
            "**Classification: CONFIDENTIAL**\n"
            "**Author: Sarah Chen, Lead Infrastructure Architect**\n\n"
            "## 1. Architectural Pillars\n"
            "- **Mutual TLS (mTLS):** Enforced across all service-to-service communication.\n"
            "- **Ephemeral Identities:** Short-lived tokens with 15-minute validity windows.\n"
            "- **Envelope Encryption:** Local AES-256-GCM keys wrapped by Hardware Security Modules (HSMs).\n"
            "- **Immutable Forensics:** Append-only SHA-256 audit chaining."
        ),
    },
    {
        "title": "AY Enterprise Acceptable Use & Offline Data Handling Policy",
        "filename": "Company-Acceptable-Use-Policy-v4.txt",
        "classification": "UNRESTRICTED",
        "department": "Operations",
        "owner_username": "admin",
        "description": "Mandatory hygiene practices for all personnel operating within air-gapped environments.",
        "content": (
            "AY ENTERPRISE ACCEPTABLE USE POLICY (AUP-V4)\n"
            "Classification: UNRESTRICTED - ALL PERSONNEL\n\n"
            "1. Universal Security Obligations:\n"
            "   - Personnel must use unique passphrases meeting enterprise complexity standards.\n"
            "   - Accounts are locked after 5 consecutive failed attempts.\n"
            "   - Removable media must be scanned in quarantine stations before connecting.\n"
            "   - Plaintext storage of sensitive documents is strictly forbidden."
        ),
    },
]


def seed_database(force_reseed: bool = False) -> None:
    """Initializes schema and injects baseline demo records if empty."""
    db = get_db()
    db.initialize_schema()
    pwd_mgr = get_password_manager()
    audit = get_audit_logger()
    storage = get_doc_storage()

    # Check if database already has users
    user_count_row = db.fetch_one("SELECT COUNT(*) as cnt FROM users;")
    user_count = user_count_row["cnt"] if user_count_row else 0

    if user_count > 0 and not force_reseed:
        return

    now_iso = datetime.now(timezone.utc).isoformat()

    # Clear existing data if reseeding
    if force_reseed:
        db.execute("DELETE FROM document_versions;")
        db.execute("DELETE FROM documents;")
        db.execute("DELETE FROM users;")
        db.execute("DELETE FROM audit_log;")
        db.execute("DELETE FROM security_policies;")
        try:
            db.execute("DELETE FROM sqlite_sequence;")
        except Exception:
            pass

    # 1. System Genesis Audit Log
    audit.log_event(
        event_type="SYSTEM_INIT",
        action="INITIALIZE_VAULT_GENESIS",
        status="SUCCESS",
        username="SYSTEM",
        resource_type="SYSTEM",
        resource_id="GENESIS",
        details={"version": "1.0.0-SEC", "engine": "AES-256-GCM / Argon2id"},
    )

    # 2. Seed Users
    # Admin
    admin_hash = pwd_mgr.hash_password("Admin@AYVault2026!")
    admin_id = db.execute(
        """
        INSERT INTO users (
            username, password_hash, full_name, role, department,
            clearance_level, failed_login_attempts, is_locked, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?);
        """,
        ("admin", admin_hash, "Dr. Alex Vance", "Admin", "Security", "TOP_SECRET", now_iso),
    )
    audit.log_event(
        event_type="USER_CREATE",
        action="SEED_USER",
        status="SUCCESS",
        user_id=admin_id,
        username="admin",
        resource_type="USER",
        resource_id=str(admin_id),
        details={"role": "Admin", "clearance": "TOP_SECRET", "department": "Security"},
    )

    # Manager
    mgr_hash = pwd_mgr.hash_password("Manager@AYVault2026!")
    mgr_id = db.execute(
        """
        INSERT INTO users (
            username, password_hash, full_name, role, department,
            clearance_level, failed_login_attempts, is_locked, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?);
        """,
        ("sarah_mgr", mgr_hash, "Sarah Chen", "Manager", "Engineering", "RESTRICTED", now_iso),
    )
    audit.log_event(
        event_type="USER_CREATE",
        action="SEED_USER",
        status="SUCCESS",
        user_id=mgr_id,
        username="sarah_mgr",
        resource_type="USER",
        resource_id=str(mgr_id),
        details={"role": "Manager", "clearance": "RESTRICTED", "department": "Engineering"},
    )

    # Viewer
    viewer_hash = pwd_mgr.hash_password("Viewer@AYVault2026!")
    viewer_id = db.execute(
        """
        INSERT INTO users (
            username, password_hash, full_name, role, department,
            clearance_level, failed_login_attempts, is_locked, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?);
        """,
        ("bob_viewer", viewer_hash, "Bob Martinez", "Viewer", "Finance", "CONFIDENTIAL", now_iso),
    )
    audit.log_event(
        event_type="USER_CREATE",
        action="SEED_USER",
        status="SUCCESS",
        user_id=viewer_id,
        username="bob_viewer",
        resource_type="USER",
        resource_id=str(viewer_id),
        details={"role": "Viewer", "clearance": "CONFIDENTIAL", "department": "Finance"},
    )

    # Pre-Locked User (to demonstrate lockout status & admin unlock)
    locked_hash = pwd_mgr.hash_password("Locked@AYVault2026!")
    locked_id = db.execute(
        """
        INSERT INTO users (
            username, password_hash, full_name, role, department,
            clearance_level, failed_login_attempts, is_locked, locked_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 5, 1, ?, ?);
        """,
        (
            "dave_locked",
            locked_hash,
            "Dave Miller",
            "Viewer",
            "Operations",
            "UNRESTRICTED",
            now_iso,
            now_iso,
        ),
    )
    audit.log_event(
        event_type="AUTH_LOCKOUT",
        action="PRE_SEEDED_LOCKOUT",
        status="DENIED",
        user_id=locked_id,
        username="dave_locked",
        resource_type="USER",
        resource_id=str(locked_id),
        details={"reason": "Seeded pre-locked user demonstrating 5-attempt security lockout."},
    )

    # Map username to user ID
    user_map = {
        "admin": admin_id,
        "sarah_mgr": mgr_id,
        "bob_viewer": viewer_id,
        "dave_locked": locked_id,
    }

    # 3. Seed Realistic Encrypted Documents
    for item in SAMPLE_DOCS:
        doc_id = secure_uuid()
        raw_bytes = item["content"].encode("utf-8")
        owner_id = user_map.get(item["owner_username"], admin_id)
        owner_name = item["owner_username"]

        stored_filename, plain_sha, cipher_sha, cipher_size = storage.store_encrypted_bytes(
            doc_id=doc_id, version=1, plaintext_bytes=raw_bytes
        )

        db.execute(
            """
            INSERT INTO documents (
                id, title, original_filename, stored_filename, file_size_bytes,
                mime_type, classification_level, department, owner_id,
                owner_username, plaintext_sha256, ciphertext_sha256,
                encryption_algo, version, description, created_at,
                updated_at, is_deleted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0);
            """,
            (
                doc_id,
                item["title"],
                item["filename"],
                stored_filename,
                len(raw_bytes),
                "text/markdown" if item["filename"].endswith(".md") else "text/plain",
                item["classification"],
                item["department"],
                owner_id,
                owner_name,
                plain_sha,
                cipher_sha,
                "AES-256-GCM",
                1,
                item["description"],
                now_iso,
                now_iso,
            ),
        )

        # Version snapshot
        db.execute(
            """
            INSERT INTO document_versions (
                document_id, version_number, stored_filename, file_size_bytes,
                plaintext_sha256, ciphertext_sha256, modified_by,
                modified_by_username, change_summary, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                doc_id,
                1,
                stored_filename,
                len(raw_bytes),
                plain_sha,
                cipher_sha,
                owner_id,
                owner_name,
                "Initial encrypted baseline ingestion.",
                now_iso,
            ),
        )

        audit.log_event(
            event_type="DOC_UPLOAD",
            action="SEED_ENCRYPTED_DOCUMENT",
            status="SUCCESS",
            user_id=owner_id,
            username=owner_name,
            resource_type="DOCUMENT",
            resource_id=doc_id,
            details={
                "title": item["title"],
                "classification": item["classification"],
                "department": item["department"],
                "plaintext_sha256": plain_sha,
            },
        )

    # 4. Verify the newly generated audit chain immediately
    report = get_audit_verifier().verify_integrity()
    if not report.is_valid:
        raise RuntimeError(f"Seed audit chain integrity verification failed: {report.error_message}")

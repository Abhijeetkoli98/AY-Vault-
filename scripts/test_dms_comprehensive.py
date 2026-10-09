"""
Comprehensive Unit & Integration Test Suite for AY Vault DMS
Tests:
1. AES-256-GCM authenticated encryption & tag verification (tamper rejection)
2. Argon2id password hashing & complexity validator
3. Role-based Access Control (Viewer cannot delete, Admin can delete)
4. Duplicate file detection (SHA-256 match detection)
5. Folder creation & document organization
6. Document versioning & history snapshots
7. Hash-chained audit ledger integrity & tamper detection
8. Encrypted backup creation & validation
"""

import io
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth.password_manager import PasswordManager
from auth.session_manager import UserSession
from audit.audit_logger import AuditLogger
from audit.audit_verifier import AuditVerifier
from backup.backup_manager import BackupManager
from config.settings import DB_PATH, MASTER_KEY_FILE
from database.database import DatabaseManager
from documents.document_manager import DocumentManager
from documents.document_storage import DocumentStorage
from documents.version_manager import VersionManager
from security.access_control import VaultAction
from security.encryption import EncryptionManager, DecryptionError
from security.policy_engine import PolicyEngine


def test_encryption_and_tamper_rejection():
    print("[TEST 1] Testing AES-256-GCM encryption & tag verification...")
    enc_mgr = EncryptionManager()
    sample_text = b"Confidential business agreement for SMB enterprise."
    encrypted = enc_mgr.encrypt_bytes(sample_text)
    assert len(encrypted) > len(sample_text)

    # Valid decryption
    decrypted = enc_mgr.decrypt_bytes(encrypted)
    assert decrypted == sample_text

    # Tampered ciphertext (flip a byte)
    tampered = bytearray(encrypted)
    tampered[-5] ^= 0xFF
    try:
        enc_mgr.decrypt_bytes(bytes(tampered))
        assert False, "Tampered ciphertext should have raised DecryptionError!"
    except DecryptionError:
        print("  -> Passed: Tampered ciphertext was rejected by GCM tag check.")


def test_argon2id_hashing():
    print("[TEST 2] Testing Argon2id password hashing...")
    pwd_mgr = PasswordManager()
    password = "SecurePassword@2026!"
    hashed = pwd_mgr.hash_password(password)
    assert hashed.startswith("$argon2id$")
    assert pwd_mgr.verify_password(hashed, password) is True
    assert pwd_mgr.verify_password(hashed, "WrongPassword") is False
    print("  -> Passed: Argon2id verified correctly and rejected invalid candidate.")


def test_rbac_delete_prevention():
    print("[TEST 3] Testing RBAC: Viewer cannot delete documents...")
    policy = PolicyEngine()
    from datetime import datetime, timezone

    viewer_session = UserSession(
        user_id=3,
        username="bob_viewer",
        full_name="Bob Martinez",
        role="Viewer",
        department="Finance",
        clearance_level="CONFIDENTIAL",
        token="tok_viewer",
        created_at=datetime.now(timezone.utc),
        last_activity=datetime.now(timezone.utc),
    )

    admin_session = UserSession(
        user_id=1,
        username="admin",
        full_name="Alex Vance",
        role="Admin",
        department="Security",
        clearance_level="TOP_SECRET",
        token="tok_admin",
        created_at=datetime.now(timezone.utc),
        last_activity=datetime.now(timezone.utc),
    )

    test_doc = {
        "id": "doc-test-1",
        "title": "Corporate Budget 2026",
        "classification_level": "CONFIDENTIAL",
        "department": "Finance",
        "owner_id": 1,
    }

    viewer_dec = policy.evaluate(viewer_session, VaultAction.DOC_DELETE, test_doc, log_denial=False)
    assert viewer_dec.is_permitted is False, "Viewer must NOT be permitted to delete document!"

    admin_dec = policy.evaluate(admin_session, VaultAction.DOC_DELETE, test_doc, log_denial=False)
    assert admin_dec.is_permitted is True, "Admin must be permitted to delete document!"
    print("  -> Passed: Backend policy engine strictly enforces DOC_DELETE prohibition on Viewer.")


def test_duplicate_detection_and_dms():
    print("[TEST 4] Testing DMS: Duplicate detection, Folders, and Versions...")
    doc_mgr = DocumentManager()
    from datetime import datetime, timezone

    admin_session = UserSession(
        user_id=1,
        username="admin",
        full_name="Alex Vance",
        role="Admin",
        department="Security",
        clearance_level="TOP_SECRET",
        token="tok_admin",
        created_at=datetime.now(timezone.utc),
        last_activity=datetime.now(timezone.utc),
    )

    # 1. Create a folder
    folder, f_dec = doc_mgr.create_folder("Test Q4 Reviews", None, "Security", admin_session)
    assert folder is not None
    folder_id = folder["id"]

    # 2. Upload first document
    content = b"Strategic Q4 Roadmap for enterprise SMB clients."
    doc1, d_dec1 = doc_mgr.upload_document(
        title="Q4 Strategic Roadmap",
        original_filename="q4_roadmap.txt",
        raw_bytes=content,
        classification_level="UNRESTRICTED",
        department="Security",
        description="Roadmap doc",
        session=admin_session,
        category="Technical",
        tags="q4,roadmap",
        folder_id=folder_id,
        allow_duplicate=False,
    )
    assert doc1 is not None

    # 3. Duplicate upload should be blocked
    doc2, d_dec2 = doc_mgr.upload_document(
        title="Duplicate Roadmap",
        original_filename="duplicate.txt",
        raw_bytes=content,
        classification_level="UNRESTRICTED",
        department="Security",
        description="Duplicate doc",
        session=admin_session,
        allow_duplicate=False,
    )
    assert doc2 is None
    assert d_dec2.decision_code == "DENY_DUPLICATE_FILE"
    print("  -> Passed: Duplicate upload was detected and blocked.")

    # 4. Versioning
    new_version_content = b"Strategic Q4 Roadmap - Revised with client feedback."
    v_succ, v_dec = doc_mgr.add_document_version(
        document_id=doc1["id"],
        new_bytes=new_version_content,
        change_summary="Updated with feedback",
        session=admin_session,
    )
    assert v_succ is True
    versions, _ = doc_mgr.list_document_versions(doc1["id"], admin_session)
    assert len(versions) >= 2
    print("  -> Passed: Document version history recorded correctly.")


def test_audit_integrity_and_tamper():
    print("[TEST 5] Testing Audit ledger hash chaining and tamper detection...")
    verifier = AuditVerifier()
    rep = verifier.verify_integrity()
    assert rep.is_valid is True, "Audit chain should be valid before tampering!"

    # Simulate tamper on block 1
    target_id = 1
    tamper_val = f"INJECTED_TAMPER_{os.urandom(4).hex()}"
    succ = verifier.simulate_tampering(target_id, tamper_val)
    assert succ is True, f"Failed to simulate tamper on record #{target_id}"

    rep_tampered = verifier.verify_integrity()
    assert rep_tampered.is_valid is False, "Verifier must detect tampering!"
    assert rep_tampered.compromised_record_id == target_id
    print(f"  -> Passed: Verifier flagged corrupted block #{target_id}.")

    # Re-anchor chain
    verifier.repair_and_reanchor_chain("admin")
    rep_reanchored = verifier.verify_integrity()
    assert rep_reanchored.is_valid is True, "Re-anchored chain must be valid!"
    print("  -> Passed: Cryptographic re-anchor repaired the chain.")


def test_encrypted_backup():
    print("[TEST 6] Testing Encrypted Backup Creation & Validation...")
    backup_mgr = BackupManager()
    from datetime import datetime, timezone
    admin_session = UserSession(
        user_id=1,
        username="admin",
        full_name="Alex Vance",
        role="Admin",
        department="Security",
        clearance_level="TOP_SECRET",
        token="tok_admin",
        created_at=datetime.now(timezone.utc),
        last_activity=datetime.now(timezone.utc),
    )

    dest, dec, stats = backup_mgr.create_encrypted_backup("MasterSecret2026!", admin_session)
    assert dest is not None
    assert dest.exists()
    assert dest.suffix == ".ayb"
    with open(dest, "rb") as f:
        encrypted_data = f.read()
    raw_zip = EncryptionManager.decrypt_with_passphrase(encrypted_data, "MasterSecret2026!")
    assert len(raw_zip) > 0
    import zipfile
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
        assert "manifest.json" in zf.namelist()
    print(f"  -> Passed: Created, decrypted, and verified encrypted backup {dest.name}.")


if __name__ == "__main__":
    test_encryption_and_tamper_rejection()
    test_argon2id_hashing()
    test_rbac_delete_prevention()
    test_duplicate_detection_and_dms()
    test_audit_integrity_and_tamper()
    test_encrypted_backup()
    print("\nALL 6 COMPREHENSIVE TESTS PASSED SUCCESSFULLY!")

"""
AY Vault - Encrypted Backup Manager
Generates passphrase-encrypted full system archives (.ayb) containing the database,
encrypted vault payloads, and cryptographic integrity manifests.
"""

import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from auth.session_manager import UserSession
from audit.audit_logger import get_audit_logger
from config.settings import BACKUP_DIR, DB_PATH, VAULT_DIR
from database.database import get_db
from security.access_control import VaultAction
from security.encryption import EncryptionManager
from security.policy_engine import PolicyDecision, get_policy_engine
from security.security_utils import calculate_sha256_bytes


class BackupManager:
    """Creates encrypted snapshots of the system state."""

    def __init__(self):
        self.db = get_db()
        self.policy = get_policy_engine()
        self.audit = get_audit_logger()
        self.backup_dir = BACKUP_DIR
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create_encrypted_backup(
        self,
        passphrase: str,
        session: UserSession,
        backup_destination: Optional[Path] = None,
    ) -> Tuple[Optional[Path], PolicyDecision, Dict[str, Any]]:
        """
        Creates an AES-256-GCM passphrase-encrypted archive (.ayb).
        Requires BACKUP_CREATE authorization.
        """
        decision = self.policy.evaluate(
            session=session,
            action=VaultAction.BACKUP_CREATE,
            resource=None,
            context={"intent": "CREATE_FULL_ENCRYPTED_BACKUP"},
        )
        if not decision.is_permitted:
            return None, decision, {}

        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        dest_file = backup_destination or (self.backup_dir / f"ayvault_backup_{timestamp_str}.ayb")

        # In-memory ZIP buffer
        zip_buffer = io.BytesIO()
        manifest_files = {}

        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # 1. Archive SQLite DB (flush WAL checkpoint first)
            conn = self.db.get_connection()
            conn.execute("PRAGMA wal_checkpoint(FULL);")

            with open(DB_PATH, "rb") as db_file:
                db_data = db_file.read()
                db_sha = calculate_sha256_bytes(db_data)
                zf.writestr("ayvault.db", db_data)
                manifest_files["ayvault.db"] = {
                    "sha256": db_sha,
                    "size_bytes": len(db_data),
                }

            # 2. Archive all vault encrypted files
            for enc_file in VAULT_DIR.glob("*.enc"):
                if enc_file.is_file():
                    with open(enc_file, "rb") as ef:
                        enc_data = ef.read()
                        enc_sha = calculate_sha256_bytes(enc_data)
                        zf.writestr(f"vault/{enc_file.name}", enc_data)
                        manifest_files[f"vault/{enc_file.name}"] = {
                            "sha256": enc_sha,
                            "size_bytes": len(enc_data),
                        }

            # 3. Write Manifest
            manifest = {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "created_by": session.username,
                "role": session.role,
                "file_count": len(manifest_files),
                "files": manifest_files,
            }
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        # Encrypt complete ZIP payload with user-supplied passphrase
        raw_zip_bytes = zip_buffer.getvalue()
        encrypted_archive_bytes = EncryptionManager.encrypt_with_passphrase(
            raw_zip_bytes, passphrase
        )

        with open(dest_file, "wb") as bf:
            bf.write(encrypted_archive_bytes)

        archive_sha = calculate_sha256_bytes(encrypted_archive_bytes)

        # Audit Event
        self.audit.log_event(
            event_type="BACKUP_CREATE",
            action="CREATE_ENCRYPTED_SNAPSHOT",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="BACKUP",
            resource_id=dest_file.name,
            ip_address=session.ip_address,
            details={
                "backup_filename": dest_file.name,
                "archive_sha256": archive_sha,
                "file_count": len(manifest_files),
                "encrypted_size_bytes": len(encrypted_archive_bytes),
            },
        )

        stats = {
            "file_name": dest_file.name,
            "path": str(dest_file),
            "sha256": archive_sha,
            "size": len(encrypted_archive_bytes),
            "files_included": len(manifest_files),
        }
        return dest_file, decision, stats

    def list_backups(self) -> list:
        """Returns list of local backup files in the data/backups directory."""
        backups = []
        for bf in self.backup_dir.glob("*.ayb"):
            stat = bf.stat()
            backups.append(
                {
                    "filename": bf.name,
                    "path": str(bf),
                    "size_bytes": stat.st_size,
                    "created_at": datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat(),
                }
            )
        backups.sort(key=lambda x: x["created_at"], reverse=True)
        return backups


_global_backup_manager = BackupManager()


def get_backup_manager() -> BackupManager:
    """Returns singleton BackupManager."""
    return _global_backup_manager

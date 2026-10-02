"""
AY Vault - Recovery & Disaster Restoration Manager
Validates encrypted backup integrity, decrypts archives with passphrase,
and restores the vault database and encrypted files.
"""

import io
import json
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from auth.session_manager import UserSession
from audit.audit_logger import get_audit_logger
from config.settings import DB_PATH, VAULT_DIR
from database.database import get_db
from security.access_control import VaultAction
from security.encryption import DecryptionError, EncryptionManager
from security.policy_engine import PolicyDecision, get_policy_engine
from security.security_utils import calculate_sha256_bytes


class RecoveryManager:
    """Manages restoration of encrypted backups with integrity verification."""

    def __init__(self):
        self.db = get_db()
        self.policy = get_policy_engine()
        self.audit = get_audit_logger()

    def restore_backup(
        self,
        backup_path: Path,
        passphrase: str,
        session: UserSession,
    ) -> Tuple[bool, PolicyDecision, str]:
        """
        Decrypts archive, verifies manifest hashes, and restores database and vault.
        Restricted to Administrators.
        """
        decision = self.policy.evaluate(
            session=session,
            action=VaultAction.BACKUP_RESTORE,
            resource=None,
            context={"backup_path": str(backup_path)},
        )
        if not decision.is_permitted:
            return False, decision, decision.reason

        if not backup_path.exists():
            return False, decision, f"Backup file '{backup_path.name}' does not exist."

        try:
            with open(backup_path, "rb") as bf:
                encrypted_payload = bf.read()

            raw_zip_bytes = EncryptionManager.decrypt_with_passphrase(
                encrypted_payload, passphrase
            )
        except DecryptionError as e:
            return False, decision, f"Decryption Failed: {str(e)}"
        except Exception as e:
            return False, decision, f"Corrupted backup payload: {str(e)}"

        try:
            with zipfile.ZipFile(io.BytesIO(raw_zip_bytes), "r") as zf:
                if "manifest.json" not in zf.namelist():
                    return False, decision, "Invalid archive: manifest.json is missing."

                manifest_raw = zf.read("manifest.json").decode("utf-8")
                manifest = json.loads(manifest_raw)
                expected_files = manifest.get("files", {})

                # Verify each file's SHA-256 before applying restoration
                for entry_name, meta in expected_files.items():
                    if entry_name not in zf.namelist():
                        return False, decision, f"Archive missing listed file '{entry_name}'."
                    content = zf.read(entry_name)
                    actual_sha = calculate_sha256_bytes(content)
                    if actual_sha != meta["sha256"]:
                        return (
                            False,
                            decision,
                            f"Integrity check failed for '{entry_name}'! Tampering detected in archive.",
                        )

                # Close current DB connection before overwriting
                self.db.close()

                # Restore database
                if "ayvault.db" in expected_files:
                    with open(DB_PATH, "wb") as df:
                        df.write(zf.read("ayvault.db"))

                # Restore vault files
                VAULT_DIR.mkdir(parents=True, exist_ok=True)
                for entry_name in expected_files:
                    if entry_name.startswith("vault/"):
                        dest_file = VAULT_DIR / Path(entry_name).name
                        with open(dest_file, "wb") as vf:
                            vf.write(zf.read(entry_name))

            # Audit Event
            self.audit.log_event(
                event_type="BACKUP_RESTORE",
                action="RESTORE_ENCRYPTED_SNAPSHOT",
                status="SUCCESS",
                user_id=session.user_id,
                username=session.username,
                resource_type="BACKUP",
                resource_id=backup_path.name,
                ip_address=session.ip_address,
                details={
                    "backup_filename": backup_path.name,
                    "restored_files_count": len(expected_files),
                },
            )

            return True, decision, f"Successfully restored {len(expected_files)} components."

        except Exception as e:
            return False, decision, f"Restoration process failed: {str(e)}"


_global_recovery_manager = RecoveryManager()


def get_recovery_manager() -> RecoveryManager:
    """Returns singleton RecoveryManager."""
    return _global_recovery_manager

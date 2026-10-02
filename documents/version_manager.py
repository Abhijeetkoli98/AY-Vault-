"""
AY Vault - Document Version Manager
Tracks revisions, previous encrypted snapshots, and historical integrity hashes.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List
from database.database import get_db


class VersionManager:
    """Manages document versions and revision records."""

    def __init__(self):
        self.db = get_db()

    def record_version(
        self,
        document_id: str,
        version_number: int,
        stored_filename: str,
        file_size_bytes: int,
        plaintext_sha256: str,
        ciphertext_sha256: str,
        modified_by_id: int,
        modified_by_username: str,
        change_summary: str,
    ) -> int:
        """Records a new version snapshot in the document_versions table."""
        now_str = datetime.now(timezone.utc).isoformat()
        return self.db.execute(
            """
            INSERT INTO document_versions (
                document_id, version_number, stored_filename, file_size_bytes,
                plaintext_sha256, ciphertext_sha256, modified_by,
                modified_by_username, change_summary, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                document_id,
                version_number,
                stored_filename,
                file_size_bytes,
                plaintext_sha256,
                ciphertext_sha256,
                modified_by_id,
                modified_by_username,
                change_summary,
                now_str,
            ),
        )

    def get_versions(self, document_id: str) -> List[Dict[str, Any]]:
        """Retrieves all version snapshots for a given document."""
        return self.db.fetch_all(
            """
            SELECT * FROM document_versions
            WHERE document_id = ?
            ORDER BY version_number DESC;
            """,
            (document_id,),
        )


_global_version_manager = VersionManager()


def get_version_manager() -> VersionManager:
    """Returns singleton VersionManager."""
    return _global_version_manager

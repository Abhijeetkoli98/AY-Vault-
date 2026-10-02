"""
AY Vault - Tamper-Evident Audit Logger
Implements a cryptographically hash-chained append-only security ledger.
Every record seals the hash of the preceding record (blockchain-style ledger).
"""

import datetime
import hashlib
import json
import threading
from typing import Any, Dict, Optional
from database.database import get_db

GENESIS_HASH: str = "0" * 64


def compute_audit_hash(
    previous_hash: str,
    timestamp: str,
    event_type: str,
    username: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    status: str,
    details_str: str,
) -> str:
    """
    Computes deterministic SHA-256 hash across canonical event fields.
    Any single bit alteration in history alters all downstream hashes.
    """
    canonical_payload = (
        f"{previous_hash}|"
        f"{timestamp}|"
        f"{event_type}|"
        f"{username}|"
        f"{action}|"
        f"{resource_type}|"
        f"{resource_id or ''}|"
        f"{status}|"
        f"{details_str}"
    )
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


class AuditLogger:
    """Manages writing hash-chained immutable security audit events."""

    _lock = threading.Lock()

    def __init__(self):
        self.db = get_db()

    def log_event(
        self,
        event_type: str,
        action: str,
        status: str,
        user_id: Optional[int] = None,
        username: str = "SYSTEM",
        resource_type: str = "SYSTEM",
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: str = "127.0.0.1 (Localhost)",
    ) -> Dict[str, Any]:
        """
        Appends an event to the ledger, computing current_hash linked to previous_hash.
        Atomic operation protected by thread lock and database transaction.
        """
        with self._lock:
            details = details or {}
            details_str = json.dumps(details, sort_keys=True)
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

            with self.db.transaction() as cur:
                # Find the current head of the hash chain
                cur.execute(
                    "SELECT id, current_hash FROM audit_log ORDER BY id DESC LIMIT 1;"
                )
                last_row = cur.fetchone()

                if last_row:
                    previous_hash = last_row["current_hash"]
                else:
                    previous_hash = GENESIS_HASH

                current_hash = compute_audit_hash(
                    previous_hash=previous_hash,
                    timestamp=timestamp,
                    event_type=event_type,
                    username=username,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    status=status,
                    details_str=details_str,
                )

                cur.execute(
                    """
                    INSERT INTO audit_log (
                        timestamp, event_type, user_id, username, action,
                        resource_type, resource_id, status, ip_address,
                        details, previous_hash, current_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        timestamp,
                        event_type,
                        user_id,
                        username,
                        action,
                        resource_type,
                        resource_id,
                        status,
                        ip_address,
                        details_str,
                        previous_hash,
                        current_hash,
                    ),
                )
                record_id = cur.lastrowid

            return {
                "id": record_id,
                "timestamp": timestamp,
                "event_type": event_type,
                "username": username,
                "action": action,
                "status": status,
                "current_hash": current_hash,
                "previous_hash": previous_hash,
            }

    def get_recent_events(self, limit: int = 50) -> list:
        """Retrieves recent audit events sorted by latest first."""
        return self.db.fetch_all(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?;", (limit,)
        )

    def get_document_events(self, document_id: str) -> list:
        """Retrieves history of actions on a specific document."""
        return self.db.fetch_all(
            "SELECT * FROM audit_log WHERE resource_type = 'DOCUMENT' AND resource_id = ? ORDER BY id DESC;",
            (document_id,),
        )


_global_audit_logger = AuditLogger()


def get_audit_logger() -> AuditLogger:
    """Returns the singleton AuditLogger."""
    return _global_audit_logger

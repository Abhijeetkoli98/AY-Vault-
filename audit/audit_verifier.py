"""
AY Vault - Audit Ledger Verifier & Forensic Tool
Verifies cryptographically hash-chained audit logs, detects alterations,
and provides forensic simulation capabilities.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from database.database import get_db
from audit.audit_logger import GENESIS_HASH, compute_audit_hash, get_audit_logger


@dataclass
class AuditVerificationReport:
    """Detailed forensic result of the audit chain verification."""
    is_valid: bool
    total_records: int
    verified_records: int
    compromised_record_id: Optional[int]
    error_type: Optional[str]
    error_message: Optional[str]
    details: Dict[str, Any]


class AuditVerifier:
    """Verifies audit ledger cryptographic continuity and detects tampering."""

    def __init__(self):
        self.db = get_db()

    def verify_integrity(self) -> AuditVerificationReport:
        """
        Traverses the full audit chain from record 1 to current head.
        Verifies:
        1. Genesis block references GENESIS_HASH (0*64).
        2. Every subsequent block references previous_record.current_hash.
        3. Recomputed hash across canonical fields matches the stored current_hash.
        """
        records = self.db.fetch_all("SELECT * FROM audit_log ORDER BY id ASC;")
        total = len(records)

        if total == 0:
            return AuditVerificationReport(
                is_valid=True,
                total_records=0,
                verified_records=0,
                compromised_record_id=None,
                error_type=None,
                error_message="Audit log is empty. Integrity intact (0 records).",
                details={},
            )

        expected_prev_hash = GENESIS_HASH

        for idx, rec in enumerate(records):
            rec_id = rec["id"]

            # 1. Check Previous Hash Linkage
            if rec["previous_hash"] != expected_prev_hash:
                return AuditVerificationReport(
                    is_valid=False,
                    total_records=total,
                    verified_records=idx,
                    compromised_record_id=rec_id,
                    error_type="BROKEN_HASH_LINKAGE",
                    error_message=(
                        f"Chain continuity broken at Record #{rec_id}. "
                        f"Expected previous_hash {expected_prev_hash[:16]}..., "
                        f"got {rec['previous_hash'][:16]}..."
                    ),
                    details={
                        "record_id": rec_id,
                        "timestamp": rec["timestamp"],
                        "stored_prev_hash": rec["previous_hash"],
                        "expected_prev_hash": expected_prev_hash,
                    },
                )

            # 2. Recompute Hash from Payload
            recomputed_hash = compute_audit_hash(
                previous_hash=rec["previous_hash"],
                timestamp=rec["timestamp"],
                event_type=rec["event_type"],
                username=rec["username"],
                action=rec["action"],
                resource_type=rec["resource_type"],
                resource_id=rec["resource_id"],
                status=rec["status"],
                details_str=rec["details"],
            )

            if recomputed_hash != rec["current_hash"]:
                return AuditVerificationReport(
                    is_valid=False,
                    total_records=total,
                    verified_records=idx,
                    compromised_record_id=rec_id,
                    error_type="TAMPERED_RECORD_PAYLOAD",
                    error_message=(
                        f"Cryptographic signature mismatch at Record #{rec_id}! "
                        f"Stored hash: {rec['current_hash'][:16]}..., "
                        f"Recomputed hash: {recomputed_hash[:16]}... (Record content was altered)."
                    ),
                    details={
                        "record_id": rec_id,
                        "timestamp": rec["timestamp"],
                        "event_type": rec["event_type"],
                        "username": rec["username"],
                        "stored_hash": rec["current_hash"],
                        "recomputed_hash": recomputed_hash,
                    },
                )

            expected_prev_hash = rec["current_hash"]

        return AuditVerificationReport(
            is_valid=True,
            total_records=total,
            verified_records=total,
            compromised_record_id=None,
            error_type=None,
            error_message="Audit log cryptographic chain is 100% verified. Zero tampering detected.",
            details={"head_hash": expected_prev_hash},
        )

    def simulate_tampering(
        self, record_id: int, new_action: str = "TAMPERED_MODIFIED_DIRECTLY_IN_DATABASE"
    ) -> bool:
        """
        Demonstration tool: Deliberately modifies an audit record's action directly in SQLite
        without recalculating its hash, proving that the verification system detects any database tampering.
        """
        row = self.db.fetch_one("SELECT * FROM audit_log WHERE id = ?;", (record_id,))
        if not row:
            return False

        self.db.execute(
            "UPDATE audit_log SET action = ? WHERE id = ?;",
            (new_action, record_id),
        )
        return True

    def repair_and_reanchor_chain(self, operator_username: str) -> bool:
        """
        Forensic repair utility: Recalculates the hash chain sequentially and appends
        a SYSTEM_REANCHOR audit record documenting the administrative re-anchoring.
        """
        records = self.db.fetch_all("SELECT * FROM audit_log ORDER BY id ASC;")
        if not records:
            return True

        current_prev = GENESIS_HASH
        with self.db.transaction() as cur:
            for rec in records:
                recomputed = compute_audit_hash(
                    previous_hash=current_prev,
                    timestamp=rec["timestamp"],
                    event_type=rec["event_type"],
                    username=rec["username"],
                    action=rec["action"],
                    resource_type=rec["resource_type"],
                    resource_id=rec["resource_id"],
                    status=rec["status"],
                    details_str=rec["details"],
                )
                cur.execute(
                    "UPDATE audit_log SET previous_hash = ?, current_hash = ? WHERE id = ?;",
                    (current_prev, recomputed, rec["id"]),
                )
                current_prev = recomputed

        # Append formal re-anchor audit log
        get_audit_logger().log_event(
            event_type="SECURITY_REANCHOR",
            action="AUDIT_CHAIN_RECALCULATED",
            status="SUCCESS",
            username=operator_username,
            resource_type="AUDIT",
            resource_id="ALL",
            details={"reanchored_by": operator_username, "new_head_hash": current_prev},
        )
        return True


_global_audit_verifier = AuditVerifier()


def get_audit_verifier() -> AuditVerifier:
    """Returns the singleton AuditVerifier."""
    return _global_audit_verifier

"""
AY Vault - Document Business Logic & Lifecycle Manager
Connects the policy engine, storage encryption, versioning, and audit logging.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from auth.session_manager import UserSession
from audit.audit_logger import get_audit_logger
from database.database import get_db
from documents.document_storage import get_doc_storage
from documents.version_manager import get_version_manager
from security.access_control import VaultAction
from security.policy_engine import PolicyDecision, get_policy_engine
from security.security_utils import sanitize_filename, secure_uuid


class DocumentManager:
    """Manages secure document operations with policy enforcement."""

    def __init__(self):
        self.db = get_db()
        self.db.initialize_schema()
        self.storage = get_doc_storage()
        self.versions = get_version_manager()
        self.policy = get_policy_engine()
        self.audit = get_audit_logger()

    def check_duplicate(self, raw_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Returns existing document record if duplicate plaintext sha256 found."""
        from security.security_utils import calculate_sha256_bytes
        plain_sha = calculate_sha256_bytes(raw_bytes)
        row = self.db.fetch_one(
            "SELECT id, title, original_filename, created_at, category FROM documents WHERE plaintext_sha256 = ? AND is_deleted = 0;",
            (plain_sha,),
        )
        return dict(row) if row else None

    def upload_document(
        self,
        title: str,
        original_filename: str,
        raw_bytes: bytes,
        classification_level: str,
        department: str,
        description: str,
        session: UserSession,
        category: str = "General",
        tags: str = "",
        folder_id: Optional[str] = None,
        allow_duplicate: bool = False,
    ) -> Tuple[Optional[Dict[str, Any]], PolicyDecision]:
        """
        Uploads and encrypts a document. Requires policy approval.
        """
        # Formulate hypothetical resource for policy engine evaluation
        simulated_res = {
            "classification_level": classification_level,
            "department": department,
            "owner_id": session.user_id,
        }
        decision = self.policy.evaluate(
            session=session,
            action=VaultAction.DOC_WRITE,
            resource=simulated_res,
            context={"action_intent": "UPLOAD_DOCUMENT", "title": title},
        )
        if not decision.is_permitted:
            return None, decision

        # Duplicate detection check
        if not allow_duplicate:
            dup = self.check_duplicate(raw_bytes)
            if dup:
                dup_decision = PolicyDecision(
                    is_permitted=False,
                    decision_code="DENY_DUPLICATE_FILE",
                    reason=f"Duplicate file detected: Exactly matches '{dup['title']}' ({dup['original_filename']}).",
                    rule_name="POL_DUPLICATE_DETECTION",
                    evaluated_at=datetime.now(timezone.utc).isoformat(),
                    context={"duplicate_doc": dup},
                )
                return None, dup_decision

        doc_id = secure_uuid()
        clean_filename = sanitize_filename(original_filename)
        file_size = len(raw_bytes)
        ext = Path(clean_filename).suffix.lower()
        mime_map = {
            ".pdf": "application/pdf",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".txt": "text/plain",
            ".csv": "text/csv",
            ".json": "application/json",
            ".md": "text/markdown",
            ".png": "image/png",
            ".jpg": "image/jpeg",
        }
        mime_type = mime_map.get(ext, "application/octet-stream")

        # Encrypt and store in vault
        (
            stored_name,
            plaintext_sha,
            ciphertext_sha,
            cipher_size,
        ) = self.storage.store_encrypted_bytes(doc_id, 1, raw_bytes)

        now_str = datetime.now(timezone.utc).isoformat()

        with self.db.transaction() as cur:
            cur.execute(
                """
                INSERT INTO documents (
                    id, title, original_filename, stored_filename, file_size_bytes,
                    mime_type, classification_level, department, category, tags, folder_id,
                    owner_id, owner_username, plaintext_sha256, ciphertext_sha256,
                    encryption_algo, version, description, created_at,
                    updated_at, last_accessed_at, is_deleted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0);
                """,
                (
                    doc_id,
                    title.strip(),
                    clean_filename,
                    stored_name,
                    file_size,
                    mime_type,
                    classification_level,
                    department,
                    category.strip() or "General",
                    tags.strip(),
                    folder_id,
                    session.user_id,
                    session.username,
                    plaintext_sha,
                    ciphertext_sha,
                    "AES-256-GCM",
                    1,
                    description.strip(),
                    now_str,
                    now_str,
                    now_str,
                ),
            )

        # Record initial version
        self.versions.record_version(
            document_id=doc_id,
            version_number=1,
            stored_filename=stored_name,
            file_size_bytes=file_size,
            plaintext_sha256=plaintext_sha,
            ciphertext_sha256=ciphertext_sha,
            modified_by_id=session.user_id,
            modified_by_username=session.username,
            change_summary="Initial encrypted ingest into vault.",
        )

        # Audit Event
        self.audit.log_event(
            event_type="DOC_UPLOAD",
            action="ENCRYPT_AND_STORE",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="DOCUMENT",
            resource_id=doc_id,
            ip_address=session.ip_address,
            details={
                "title": title,
                "classification": classification_level,
                "department": department,
                "plaintext_sha256": plaintext_sha,
                "ciphertext_sha256": ciphertext_sha,
                "encrypted_size_bytes": cipher_size,
            },
        )

        doc_record = self.db.fetch_one("SELECT * FROM documents WHERE id = ?;", (doc_id,))
        return doc_record, decision

    def read_document_content(
        self, document_id: str, session: UserSession
    ) -> Tuple[Optional[bytes], Optional[Dict[str, Any]], PolicyDecision]:
        """
        Decrypts document content in-memory for previewing/inspection.
        Requires DOC_READ policy approval.
        """
        doc = self.db.fetch_one(
            "SELECT * FROM documents WHERE id = ? AND is_deleted = 0;", (document_id,)
        )
        if not doc:
            decision = PolicyDecision(
                is_permitted=False,
                decision_code="DENY_NOT_FOUND",
                reason=f"Document '{document_id}' does not exist or has been deleted.",
                rule_name="POL_000_EXISTENCE",
                evaluated_at=datetime.now(timezone.utc).isoformat(),
                context={"doc_id": document_id},
            )
            return None, None, decision

        decision = self.policy.evaluate(
            session=session,
            action=VaultAction.DOC_READ,
            resource=doc,
            context={"action_intent": "READ_CONTENT"},
        )
        if not decision.is_permitted:
            return None, doc, decision

        # Retrieve and decrypt
        plaintext = self.storage.retrieve_and_decrypt(
            stored_filename=doc["stored_filename"],
            expected_plaintext_sha256=doc["plaintext_sha256"],
        )

        self.audit.log_event(
            event_type="DOC_ACCESS",
            action="DECRYPT_IN_MEMORY_PREVIEW",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="DOCUMENT",
            resource_id=document_id,
            ip_address=session.ip_address,
            details={
                "title": doc["title"],
                "classification": doc["classification_level"],
                "verified_sha256": doc["plaintext_sha256"],
            },
        )
        self.record_access(document_id, session, "PREVIEW")
        return plaintext, doc, decision

    def export_document(
        self, document_id: str, destination_path: Union[str, Path], session: UserSession
    ) -> Tuple[bool, PolicyDecision]:
        """
        Decrypts document and writes to user-selected export destination.
        Requires DOC_DOWNLOAD policy approval.
        """
        doc = self.db.fetch_one(
            "SELECT * FROM documents WHERE id = ? AND is_deleted = 0;", (document_id,)
        )
        if not doc:
            decision = PolicyDecision(
                is_permitted=False,
                decision_code="DENY_NOT_FOUND",
                reason=f"Document '{document_id}' not found.",
                rule_name="POL_000_EXISTENCE",
                evaluated_at=datetime.now(timezone.utc).isoformat(),
                context={"doc_id": document_id},
            )
            return False, decision

        decision = self.policy.evaluate(
            session=session,
            action=VaultAction.DOC_DOWNLOAD,
            resource=doc,
            context={"export_path": str(destination_path)},
        )
        if not decision.is_permitted:
            return False, decision

        plaintext = self.storage.retrieve_and_decrypt(
            stored_filename=doc["stored_filename"],
            expected_plaintext_sha256=doc["plaintext_sha256"],
        )

        dest = Path(destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            f.write(plaintext)

        self.audit.log_event(
            event_type="DOC_DOWNLOAD",
            action="EXPORT_DECRYPTED_FILE",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="DOCUMENT",
            resource_id=document_id,
            ip_address=session.ip_address,
            details={
                "title": doc["title"],
                "destination_filename": dest.name,
                "verified_sha256": doc["plaintext_sha256"],
            },
        )
        self.record_access(document_id, session, "DOWNLOAD")
        return True, decision

    def add_document_version(
        self,
        document_id: str,
        new_bytes: bytes,
        change_summary: str,
        session: UserSession,
    ) -> Tuple[bool, PolicyDecision]:
        """Adds a new encrypted version snapshot to an existing document."""
        doc = self.db.fetch_one(
            "SELECT * FROM documents WHERE id = ? AND is_deleted = 0;", (document_id,)
        )
        if not doc:
            decision = PolicyDecision(
                is_permitted=False,
                decision_code="DENY_NOT_FOUND",
                reason="Document not found.",
                rule_name="POL_000_EXISTENCE",
                evaluated_at=datetime.now(timezone.utc).isoformat(),
                context={"doc_id": document_id},
            )
            return False, decision

        decision = self.policy.evaluate(
            session=session,
            action=VaultAction.DOC_WRITE,
            resource=doc,
            context={"action_intent": "NEW_VERSION"},
        )
        if not decision.is_permitted:
            return False, decision

        next_ver = doc["version"] + 1
        stored_name, plain_sha, cipher_sha, _ = self.storage.store_encrypted_bytes(
            document_id, next_ver, new_bytes
        )

        now_str = datetime.now(timezone.utc).isoformat()
        self.db.execute(
            """
            UPDATE documents SET
                stored_filename = ?,
                file_size_bytes = ?,
                plaintext_sha256 = ?,
                ciphertext_sha256 = ?,
                version = ?,
                updated_at = ?
            WHERE id = ?;
            """,
            (stored_name, len(new_bytes), plain_sha, cipher_sha, next_ver, now_str, document_id),
        )

        self.versions.record_version(
            document_id=document_id,
            version_number=next_ver,
            stored_filename=stored_name,
            file_size_bytes=len(new_bytes),
            plaintext_sha256=plain_sha,
            ciphertext_sha256=cipher_sha,
            modified_by_id=session.user_id,
            modified_by_username=session.username,
            change_summary=change_summary,
        )

        self.audit.log_event(
            event_type="DOC_VERSION",
            action="STORE_NEW_VERSION",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="DOCUMENT",
            resource_id=document_id,
            ip_address=session.ip_address,
            details={
                "version": next_ver,
                "change_summary": change_summary,
                "plaintext_sha256": plain_sha,
            },
        )
        return True, decision

    def delete_document(
        self, document_id: str, session: UserSession
    ) -> Tuple[bool, PolicyDecision]:
        """Soft deletes document record and writes audit trail."""
        doc = self.db.fetch_one(
            "SELECT * FROM documents WHERE id = ? AND is_deleted = 0;", (document_id,)
        )
        if not doc:
            decision = PolicyDecision(
                is_permitted=False,
                decision_code="DENY_NOT_FOUND",
                reason="Document not found.",
                rule_name="POL_000_EXISTENCE",
                evaluated_at=datetime.now(timezone.utc).isoformat(),
                context={"doc_id": document_id},
            )
            return False, decision

        decision = self.policy.evaluate(
            session=session,
            action=VaultAction.DOC_DELETE,
            resource=doc,
            context={"action_intent": "DELETE_DOCUMENT"},
        )
        if not decision.is_permitted:
            return False, decision

        now_str = datetime.now(timezone.utc).isoformat()
        self.db.execute(
            "UPDATE documents SET is_deleted = 1, updated_at = ? WHERE id = ?;",
            (now_str, document_id),
        )

        self.audit.log_event(
            event_type="DOC_DELETE",
            action="SOFT_DELETE_DOCUMENT",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="DOCUMENT",
            resource_id=document_id,
            ip_address=session.ip_address,
            details={"title": doc["title"], "classification": doc["classification_level"]},
        )
        return True, decision

    def list_documents(
        self,
        session: UserSession,
        search_query: Optional[str] = None,
        classification: Optional[str] = None,
        department: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Lists active documents and annotates each with permissions evaluated for the current user.
        """
        query = "SELECT * FROM documents WHERE is_deleted = 0"
        params: List[Any] = []

        if classification and classification != "ALL":
            query += " AND classification_level = ?"
            params.append(classification)

        if department and department != "ALL":
            query += " AND department = ?"
            params.append(department)

        if search_query:
            query += " AND (title LIKE ? OR original_filename LIKE ? OR description LIKE ?)"
            term = f"%{search_query.strip()}%"
            params.extend([term, term, term])

        query += " ORDER BY created_at DESC;"

        rows = self.db.fetch_all(query, tuple(params))

        # Annotate permissions for each document without logging denials for listing
        annotated = []
        for r in rows:
            doc_dict = dict(r)
            can_read = self.policy.evaluate(
                session, VaultAction.DOC_READ, doc_dict, log_denial=False
            ).is_permitted
            can_download = self.policy.evaluate(
                session, VaultAction.DOC_DOWNLOAD, doc_dict, log_denial=False
            ).is_permitted
            can_delete = self.policy.evaluate(
                session, VaultAction.DOC_DELETE, doc_dict, log_denial=False
            ).is_permitted

            doc_dict["can_read"] = can_read
            doc_dict["can_download"] = can_download
            doc_dict["can_delete"] = can_delete
            annotated.append(doc_dict)

    def record_access(self, document_id: str, session: UserSession, action: str = "PREVIEW") -> None:
        """Records access into document_access_log and updates last_accessed_at."""
        now_str = datetime.now(timezone.utc).isoformat()
        try:
            self.db.execute("UPDATE documents SET last_accessed_at = ? WHERE id = ?;", (now_str, document_id))
            self.db.execute(
                "INSERT INTO document_access_log (document_id, user_id, username, action, accessed_at) VALUES (?, ?, ?, ?, ?);",
                (document_id, session.user_id, session.username, action, now_str),
            )
        except Exception:
            pass

    def get_recently_accessed_documents(self, session: UserSession, limit: int = 6) -> List[Dict[str, Any]]:
        """Returns recently accessed documents for current session."""
        rows = self.db.fetch_all(
            """
            SELECT d.*, a.accessed_at as recent_access_time, a.action as access_action
            FROM documents d
            JOIN document_access_log a ON d.id = a.document_id
            WHERE d.is_deleted = 0 AND a.user_id = ?
            ORDER BY a.accessed_at DESC
            LIMIT ?;
            """,
            (session.user_id, limit * 3),
        )
        seen = set()
        results = []
        for r in rows:
            d = dict(r)
            if d["id"] not in seen:
                seen.add(d["id"])
                can_read = self.policy.evaluate(session, VaultAction.DOC_READ, d, log_denial=False).is_permitted
                if can_read:
                    d["can_read"] = True
                    d["can_download"] = self.policy.evaluate(session, VaultAction.DOC_DOWNLOAD, d, log_denial=False).is_permitted
                    d["can_delete"] = self.policy.evaluate(session, VaultAction.DOC_DELETE, d, log_denial=False).is_permitted
                    results.append(d)
                    if len(results) >= limit:
                        break
        return results

    def create_folder(
        self, name: str, parent_id: Optional[str], department: str, session: UserSession
    ) -> Tuple[Optional[Dict[str, Any]], PolicyDecision]:
        """Creates a new folder for organizing documents."""
        decision = self.policy.evaluate(session, VaultAction.DOC_WRITE, {"department": department}, context={"action": "CREATE_FOLDER"})
        if not decision.is_permitted:
            return None, decision

        folder_id = secure_uuid()
        now_str = datetime.now(timezone.utc).isoformat()
        self.db.execute(
            "INSERT INTO folders (id, name, parent_id, created_by, department, created_at, is_deleted) VALUES (?, ?, ?, ?, ?, ?, 0);",
            (folder_id, name.strip(), parent_id, session.user_id, department, now_str),
        )
        self.audit.log_event(
            event_type="FOLDER_CREATE",
            action="CREATE_ORGANIZATIONAL_FOLDER",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="FOLDER",
            resource_id=folder_id,
            ip_address=session.ip_address,
            details={"name": name, "department": department},
        )
        folder = self.db.fetch_one("SELECT * FROM folders WHERE id = ?;", (folder_id,))
        return dict(folder), decision

    def list_folders(self, session: UserSession) -> List[Dict[str, Any]]:
        """Lists active folders with document counts."""
        rows = self.db.fetch_all(
            """
            SELECT f.*, COUNT(d.id) as document_count
            FROM folders f
            LEFT JOIN documents d ON f.id = d.folder_id AND d.is_deleted = 0
            WHERE f.is_deleted = 0
            GROUP BY f.id
            ORDER BY f.name ASC;
            """
        )
        return [dict(r) for r in rows]

    def delete_folder(self, folder_id: str, session: UserSession) -> Tuple[bool, PolicyDecision]:
        """Deletes a folder and moves its contents to root."""
        folder = self.db.fetch_one("SELECT * FROM folders WHERE id = ? AND is_deleted = 0;", (folder_id,))
        if not folder:
            return False, PolicyDecision(is_permitted=False, reason="Folder not found", rule_name="POL_NOT_FOUND")
        decision = self.policy.evaluate(session, VaultAction.DOC_DELETE, dict(folder), context={"action": "DELETE_FOLDER"})
        if not decision.is_permitted:
            return False, decision

        self.db.execute("UPDATE folders SET is_deleted = 1 WHERE id = ?;", (folder_id,))
        self.db.execute("UPDATE documents SET folder_id = NULL WHERE folder_id = ?;", (folder_id,))
        self.audit.log_event(
            event_type="FOLDER_DELETE",
            action="DELETE_ORGANIZATIONAL_FOLDER",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="FOLDER",
            resource_id=folder_id,
            ip_address=session.ip_address,
            details={"name": folder["name"]},
        )
        return True, decision

    def move_document(self, document_id: str, folder_id: Optional[str], session: UserSession) -> Tuple[bool, PolicyDecision]:
        """Moves a document into a folder or back to root."""
        doc = self.db.fetch_one("SELECT * FROM documents WHERE id = ? AND is_deleted = 0;", (document_id,))
        if not doc:
            return False, PolicyDecision(is_permitted=False, reason="Document not found", rule_name="POL_NOT_FOUND")
        decision = self.policy.evaluate(session, VaultAction.DOC_WRITE, dict(doc), context={"action": "MOVE_DOCUMENT"})
        if not decision.is_permitted:
            return False, decision

        now_str = datetime.now(timezone.utc).isoformat()
        self.db.execute("UPDATE documents SET folder_id = ?, updated_at = ? WHERE id = ?;", (folder_id, now_str, document_id))
        self.audit.log_event(
            event_type="DOC_MOVE",
            action="MOVE_DOCUMENT_FOLDER",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="DOCUMENT",
            resource_id=document_id,
            ip_address=session.ip_address,
            details={"new_folder_id": folder_id, "title": doc["title"]},
        )
        return True, decision

    def update_metadata(
        self,
        document_id: str,
        title: Optional[str],
        description: Optional[str],
        category: Optional[str],
        tags: Optional[str],
        folder_id: Optional[str],
        session: UserSession,
    ) -> Tuple[bool, PolicyDecision]:
        """Updates document title, description, category, tags, and folder assignment."""
        doc = self.db.fetch_one("SELECT * FROM documents WHERE id = ? AND is_deleted = 0;", (document_id,))
        if not doc:
            return False, PolicyDecision(is_permitted=False, reason="Document not found", rule_name="POL_NOT_FOUND")
        decision = self.policy.evaluate(session, VaultAction.DOC_WRITE, dict(doc), context={"action": "UPDATE_METADATA"})
        if not decision.is_permitted:
            return False, decision

        new_title = title.strip() if title else doc["title"]
        new_desc = description.strip() if description is not None else doc["description"]
        new_cat = category.strip() if category else doc.get("category", "General")
        new_tags = tags.strip() if tags is not None else doc.get("tags", "")
        new_folder = folder_id if folder_id is not None else doc.get("folder_id")
        now_str = datetime.now(timezone.utc).isoformat()

        self.db.execute(
            """
            UPDATE documents SET
                title = ?, description = ?, category = ?, tags = ?, folder_id = ?, updated_at = ?
            WHERE id = ?;
            """,
            (new_title, new_desc, new_cat, new_tags, new_folder, now_str, document_id),
        )
        self.audit.log_event(
            event_type="DOC_METADATA",
            action="UPDATE_METADATA",
            status="SUCCESS",
            user_id=session.user_id,
            username=session.username,
            resource_type="DOCUMENT",
            resource_id=document_id,
            ip_address=session.ip_address,
            details={"title": new_title, "category": new_cat, "tags": new_tags},
        )
        return True, decision

    def list_document_versions(self, document_id: str, session: UserSession) -> Tuple[List[Dict[str, Any]], PolicyDecision]:
        """Lists all historical versions for a document."""
        doc = self.db.fetch_one("SELECT * FROM documents WHERE id = ? AND is_deleted = 0;", (document_id,))
        if not doc:
            return [], PolicyDecision(is_permitted=False, reason="Document not found", rule_name="POL_NOT_FOUND")
        decision = self.policy.evaluate(session, VaultAction.DOC_READ, dict(doc), context={"action": "LIST_VERSIONS"})
        if not decision.is_permitted:
            return [], decision

        rows = self.db.fetch_all("SELECT * FROM document_versions WHERE document_id = ? ORDER BY version_number DESC;", (document_id,))
        return [dict(r) for r in rows], decision


_global_document_manager = DocumentManager()


def get_document_manager() -> DocumentManager:
    """Returns singleton DocumentManager."""
    return _global_document_manager

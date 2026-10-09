"""
AY Vault - Local Web Server & REST API Gateway
Exposes the modular cybersecurity backend to modern browser clients on localhost.
"""

import io
import json
from pathlib import Path
from typing import Optional
from flask import Flask, jsonify, render_template, request, send_file, session as flask_session
from auth.authentication import get_auth_service
from auth.session_manager import UserSession, get_session_manager
from audit.audit_logger import get_audit_logger
from audit.audit_verifier import get_audit_verifier
from backup.backup_manager import get_backup_manager
from backup.recovery_manager import get_recovery_manager
from config.settings import BACKUP_DIR, THEME
from database.database import get_db
from database.seed import seed_database
from documents.document_manager import get_document_manager
from documents.document_storage import get_doc_storage
from security.access_control import VaultAction
from security.policy_engine import get_policy_engine
from security.security_utils import format_file_size
from users.user_manager import get_user_manager

app = Flask(
    __name__,
    template_folder="web/templates",
    static_folder="web/static",
)
app.secret_key = "AY_VAULT_LOCAL_DEVELOPMENT_SESSION_KEY_2026"

# Singletons
auth_service = get_auth_service()
session_manager = get_session_manager()
doc_manager = get_document_manager()
audit_logger = get_audit_logger()
audit_verifier = get_audit_verifier()
policy_engine = get_policy_engine()
user_manager = get_user_manager()
backup_manager = get_backup_manager()
recovery_manager = get_recovery_manager()
doc_storage = get_doc_storage()
db = get_db()


def get_current_user_session() -> Optional[UserSession]:
    """Retrieves active session from SessionManager matching the request context."""
    token = flask_session.get("token")
    if token:
        sess = session_manager.get_session_by_token(token)
        if sess:
            return sess

    # Rehydrate session if user_id stored in secure cookie
    user_id = flask_session.get("user_id")
    if user_id:
        user = db.fetch_one("SELECT * FROM users WHERE id = ? AND is_locked = 0;", (user_id,))
        if user:
            ip = request.remote_addr or "127.0.0.1"
            sess = session_manager.create_session(user, ip_address=f"{ip} (Browser)")
            flask_session["token"] = sess.token
            return sess

    # Fallback for standalone/Tkinter context
    return session_manager.get_current_session()


@app.route("/")
def index():
    """Serves the main application SPA."""
    return render_template("index.html")


# ===================================================================
# AUTHENTICATION API
# ===================================================================

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    ip = request.remote_addr or "127.0.0.1"

    res = auth_service.login(username, password, ip_address=f"{ip} (Browser)")
    if res.success and res.session:
        flask_session["token"] = res.session.token
        flask_session["user_id"] = res.session.user_id
        return jsonify({
            "success": True,
            "session": {
                "user_id": res.session.user_id,
                "username": res.session.username,
                "full_name": res.session.full_name,
                "role": res.session.role,
                "department": res.session.department,
                "clearance_level": res.session.clearance_level,
                "token": res.session.token,
            },
        })
    return jsonify({
        "success": False,
        "is_locked": res.is_locked,
        "remaining_attempts": res.remaining_attempts,
        "error_message": res.error_message,
    }), 401


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    token = flask_session.get("token")
    auth_service.logout(token)
    flask_session.clear()
    return jsonify({"success": True})


@app.route("/api/auth/session", methods=["GET"])
def api_get_session():
    user_sess = get_current_user_session()
    if user_sess:
        return jsonify({
            "authenticated": True,
            "session": {
                "user_id": user_sess.user_id,
                "username": user_sess.username,
                "full_name": user_sess.full_name,
                "role": user_sess.role,
                "department": user_sess.department,
                "clearance_level": user_sess.clearance_level,
                "token": user_sess.token,
            },
        })
    return jsonify({"authenticated": False, "session": None})


# ===================================================================
# DASHBOARD STATS
# ===================================================================

@app.route("/api/dashboard/stats", methods=["GET"])
def api_dashboard_stats():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"error": "Authentication required"}), 401

    doc_count = db.fetch_one("SELECT COUNT(*) as cnt FROM documents WHERE is_deleted = 0;")
    storage = doc_storage.get_vault_stats()
    user_count = db.fetch_one("SELECT COUNT(*) as cnt FROM users;")
    lockouts = db.fetch_one("SELECT COUNT(*) as cnt FROM users WHERE is_locked = 1;")
    verification = audit_verifier.verify_integrity()
    recent_events = audit_logger.get_recent_events(limit=8)
    recent_docs = doc_manager.get_recently_accessed_documents(user_sess, limit=5)
    backups = backup_manager.list_backups()
    latest_backup = backups[0] if backups else None

    # Categories breakdown
    categories = db.fetch_all("SELECT category, COUNT(*) as cnt FROM documents WHERE is_deleted = 0 GROUP BY category;")

    return jsonify({
        "total_documents": doc_count["cnt"] if doc_count else 0,
        "storage_formatted": format_file_size(storage["total_bytes"]),
        "storage_bytes": storage["total_bytes"],
        "total_users": user_count["cnt"] if user_count else 0,
        "locked_users": lockouts["cnt"] if lockouts else 0,
        "latest_backup": latest_backup,
        "categories": {c["category"]: c["cnt"] for c in categories},
        "audit_status": {
            "is_valid": verification.is_valid,
            "total_records": verification.total_records,
            "verified_records": verification.verified_records,
            "compromised_id": verification.compromised_record_id,
        },
        "recent_audit": recent_events,
        "recent_documents": recent_docs,
    })


# ===================================================================
# DOCUMENTS & FOLDERS API
# ===================================================================

@app.route("/api/folders", methods=["GET"])
def api_list_folders():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify([]), 401
    folders = doc_manager.list_folders(user_sess)
    return jsonify(folders)


@app.route("/api/folders/create", methods=["POST"])
def api_create_folder():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    data = request.get_json() or {}
    name = data.get("name", "").strip()
    parent_id = data.get("parent_id")
    dept = data.get("department", user_sess.department)
    if not name:
        return jsonify({"success": False, "error": "Folder name is required"}), 400

    folder, dec = doc_manager.create_folder(name, parent_id, dept, user_sess)
    return jsonify({
        "success": bool(folder),
        "folder": folder,
        "error": dec.reason if not folder else None,
    }), (200 if folder else 403)


@app.route("/api/folders/delete", methods=["POST"])
def api_delete_folder():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    data = request.get_json() or {}
    folder_id = data.get("folder_id")
    if not folder_id:
        return jsonify({"success": False, "error": "Folder ID is required"}), 400

    succ, dec = doc_manager.delete_folder(folder_id, user_sess)
    return jsonify({
        "success": succ,
        "error": dec.reason if not succ else None,
    }), (200 if succ else 403)


@app.route("/api/documents/recent", methods=["GET"])
def api_recent_documents():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify([]), 401
    docs = doc_manager.get_recently_accessed_documents(user_sess, limit=8)
    return jsonify(docs)


@app.route("/api/documents", methods=["GET"])
def api_list_documents():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify([]), 401

    search_query = request.args.get("search")
    classification = request.args.get("classification")
    department = request.args.get("department")
    folder_id = request.args.get("folder_id")
    category = request.args.get("category")

    docs = doc_manager.list_documents(
        user_sess,
        search_query=search_query,
        classification=classification,
        department=department,
    )

    # Filter by folder_id if requested
    if folder_id:
        if folder_id == "root":
            docs = [d for d in docs if not d.get("folder_id")]
        else:
            docs = [d for d in docs if d.get("folder_id") == folder_id]

    # Filter by category if requested
    if category and category != "ALL":
        docs = [d for d in docs if d.get("category") == category]

    return jsonify(docs)


@app.route("/api/documents/decrypt", methods=["POST"])
def api_decrypt_document():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"permitted": False, "error": "Authentication required"}), 401

    data = request.get_json() or {}
    doc_id = data.get("document_id")

    plaintext_bytes, doc_rec, decision = doc_manager.read_document_content(doc_id, user_sess)
    if not decision.is_permitted or plaintext_bytes is None:
        return jsonify({
            "permitted": False,
            "decision": decision.to_dict() if decision else None,
            "error": decision.reason if decision else "Access denied",
        }), 403

    try:
        content_str = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content_str = f"Binary content ({len(plaintext_bytes)} bytes)\n\nHex Preview:\n" + " ".join(f"{b:02X}" for b in plaintext_bytes[:512])

    return jsonify({
        "permitted": True,
        "document": doc_rec,
        "plaintext_content": content_str,
        "decision": decision.to_dict(),
    })


@app.route("/api/documents/download/<doc_id>", methods=["GET"])
def api_download_document(doc_id):
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"permitted": False, "error": "Authentication required"}), 401

    doc = db.fetch_one("SELECT * FROM documents WHERE id = ? AND is_deleted = 0;", (doc_id,))
    if not doc:
        return jsonify({"permitted": False, "error": "Document not found"}), 404

    # Strict evaluation of DOC_DOWNLOAD permission
    decision = policy_engine.evaluate(
        session=user_sess,
        action=VaultAction.DOC_DOWNLOAD,
        resource=doc,
        context={"action_intent": "DOWNLOAD_DOCUMENT", "doc_id": doc_id},
    )
    if not decision.is_permitted:
        return jsonify({
            "permitted": False,
            "decision": decision.to_dict(),
            "error": decision.reason,
        }), 403

    try:
        plaintext_bytes = doc_storage.retrieve_and_decrypt(
            stored_filename=doc["stored_filename"],
            expected_plaintext_sha256=doc["plaintext_sha256"],
        )
    except Exception as e:
        return jsonify({"permitted": False, "error": f"Decryption failure: {str(e)}"}), 500

    doc_manager.record_access(doc_id, user_sess, "DOWNLOAD")

    audit_logger.log_event(
        event_type="DOC_DOWNLOAD",
        action="EXPORT_DECRYPTED_FILE",
        status="SUCCESS",
        user_id=user_sess.user_id,
        username=user_sess.username,
        resource_type="DOCUMENT",
        resource_id=doc_id,
        ip_address=user_sess.ip_address,
        details={
            "title": doc["title"],
            "classification": doc["classification_level"],
            "file_size": len(plaintext_bytes),
        },
    )

    return send_file(
        io.BytesIO(plaintext_bytes),
        download_name=doc["original_filename"],
        as_attachment=True,
    )


@app.route("/api/documents/check-duplicate", methods=["POST"])
def api_check_duplicate():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"error": "Authentication required"}), 401

    uploaded_file = request.files.get("file")
    if not uploaded_file:
        return jsonify({"duplicate": False}), 400

    raw_bytes = uploaded_file.read()
    dup = doc_manager.check_duplicate(raw_bytes)
    return jsonify({
        "duplicate": bool(dup),
        "existing_document": dup,
    })


@app.route("/api/documents/upload", methods=["POST"])
def api_upload_document():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    title = request.form.get("title", "").strip()
    cls_level = request.form.get("classification_level", "UNRESTRICTED")
    dept = request.form.get("department", "Security")
    category = request.form.get("category", "General").strip()
    tags = request.form.get("tags", "").strip()
    folder_id = request.form.get("folder_id") or None
    allow_dup = request.form.get("allow_duplicate", "false").lower() == "true"
    desc = request.form.get("description", "").strip()

    uploaded_file = request.files.get("file")
    if not uploaded_file or not title:
        return jsonify({"success": False, "error": "Missing title or file payload"}), 400

    raw_bytes = uploaded_file.read()
    filename = uploaded_file.filename or f"{title}.dat"

    doc_record, decision = doc_manager.upload_document(
        title=title,
        original_filename=filename,
        raw_bytes=raw_bytes,
        classification_level=cls_level,
        department=dept,
        description=desc,
        session=user_sess,
        category=category,
        tags=tags,
        folder_id=folder_id,
        allow_duplicate=allow_dup,
    )

    if not decision.is_permitted:
        return jsonify({
            "success": False,
            "decision": decision.to_dict(),
            "error": decision.reason,
            "duplicate": decision.decision_code == "DENY_DUPLICATE_FILE",
        }), 403

    return jsonify({
        "success": True,
        "document": doc_record,
        "decision": decision.to_dict(),
    })


@app.route("/api/documents/move", methods=["POST"])
def api_move_document():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    data = request.get_json() or {}
    doc_id = data.get("document_id")
    folder_id = data.get("folder_id")
    if not doc_id:
        return jsonify({"success": False, "error": "Document ID required"}), 400

    succ, decision = doc_manager.move_document(doc_id, folder_id, user_sess)
    return jsonify({
        "success": succ,
        "error": decision.reason if not succ else None,
    }), (200 if succ else 403)


@app.route("/api/documents/metadata", methods=["POST"])
def api_update_metadata():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    data = request.get_json() or {}
    doc_id = data.get("document_id")
    if not doc_id:
        return jsonify({"success": False, "error": "Document ID required"}), 400

    succ, decision = doc_manager.update_metadata(
        document_id=doc_id,
        title=data.get("title"),
        description=data.get("description"),
        category=data.get("category"),
        tags=data.get("tags"),
        folder_id=data.get("folder_id"),
        session=user_sess,
    )
    return jsonify({
        "success": succ,
        "error": decision.reason if not succ else None,
    }), (200 if succ else 403)


@app.route("/api/documents/<doc_id>/versions", methods=["GET"])
def api_get_versions(doc_id):
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"versions": []}), 401

    vers, dec = doc_manager.list_document_versions(doc_id, user_sess)
    return jsonify({"versions": vers, "permitted": dec.is_permitted})


@app.route("/api/documents/<doc_id>/versions", methods=["POST"])
def api_add_version(doc_id):
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    uploaded = request.files.get("file")
    summary = request.form.get("change_summary", "Updated document version")
    if not uploaded:
        return jsonify({"success": False, "error": "Missing new version file payload"}), 400

    succ, dec = doc_manager.add_document_version(doc_id, uploaded.read(), summary, user_sess)
    return jsonify({
        "success": succ,
        "error": dec.reason if not succ else None,
    }), (200 if succ else 403)


@app.route("/api/documents/delete", methods=["POST"])
def api_delete_document():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    data = request.get_json() or {}
    doc_id = data.get("document_id")
    if not doc_id:
        return jsonify({"success": False, "error": "Document ID required"}), 400

    succ, decision = doc_manager.delete_document(doc_id, user_sess)
    return jsonify({
        "success": succ,
        "decision": decision.to_dict() if decision else None,
        "error": decision.reason if not succ and decision else None,
    }), (200 if succ else 403)


# ===================================================================
# AUDIT & FORENSICS API
# ===================================================================

@app.route("/api/audit/logs", methods=["GET"])
def api_audit_logs():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify([]), 401
    logs = db.fetch_all("SELECT * FROM audit_log ORDER BY id DESC;")
    return jsonify(logs)


@app.route("/api/audit/verify", methods=["POST"])
def api_verify_audit():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"is_valid": False, "error": "Authentication required"}), 401

    rep = audit_verifier.verify_integrity()
    return jsonify({
        "is_valid": rep.is_valid,
        "total_records": rep.total_records,
        "verified_records": rep.verified_records,
        "compromised_record_id": rep.compromised_record_id,
        "error_type": rep.error_type,
        "error_message": rep.error_message,
        "details": rep.details,
    })


@app.route("/api/audit/tamper", methods=["POST"])
def api_tamper_audit():
    user_sess = get_current_user_session()
    if not user_sess or user_sess.role != "Admin":
        return jsonify({"success": False, "error": "Administrator privilege required"}), 403

    data = request.get_json() or {}
    block_id = data.get("block_id", 2)
    succ = audit_verifier.simulate_tampering(int(block_id), "UNAUTHORIZED_DATA_EXFILTRATION_TAMPERED")
    if succ:
        return jsonify({"success": True, "tampered_block": block_id})
    return jsonify({"success": False, "error": f"Block #{block_id} not found."}), 400


@app.route("/api/audit/reanchor", methods=["POST"])
def api_reanchor_audit():
    user_sess = get_current_user_session()
    if not user_sess or user_sess.role != "Admin":
        return jsonify({"success": False, "error": "Administrator privilege required"}), 403

    username = user_sess.username
    succ = audit_verifier.repair_and_reanchor_chain(username)
    return jsonify({"success": succ})


@app.route("/api/audit/export/csv", methods=["GET"])
def api_export_audit_csv():
    user_sess = get_current_user_session()
    if not user_sess:
        return "Authentication required", 401

    records = db.fetch_all("SELECT * FROM audit_log ORDER BY id ASC;")
    if not records:
        return "No audit records", 400

    output = io.StringIO()
    import csv
    writer = csv.DictWriter(output, fieldnames=records[0].keys())
    writer.writeheader()
    writer.writerows(records)

    mem = io.BytesIO()
    mem.write(output.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, download_name="ayvault_audit_ledger.csv", as_attachment=True, mimetype="text/csv")


# ===================================================================
# POLICY SIMULATOR API
# ===================================================================

@app.route("/api/policy/simulate", methods=["POST"])
def api_simulate_policy():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"is_permitted": False, "rule_name": "ERROR", "reason": "Authentication required."}), 401

    data = request.get_json() or {}
    user_id = data.get("user_id")
    doc_id = data.get("document_id")
    action_str = data.get("action", "doc:read")

    target_user = db.fetch_one("SELECT * FROM users WHERE id = ?;", (user_id,))
    target_doc = db.fetch_one("SELECT * FROM documents WHERE id = ?;", (doc_id,))

    if not target_user or not target_doc:
        return jsonify({"is_permitted": False, "rule_name": "ERROR", "reason": "Target user or document not found."})

    from datetime import datetime, timezone
    sim_session = UserSession(
        user_id=target_user["id"],
        username=target_user["username"],
        full_name=target_user["full_name"],
        role=target_user["role"],
        department=target_user["department"],
        clearance_level=target_user["clearance_level"],
        token="sim_token",
        created_at=datetime.now(timezone.utc),
        last_activity=datetime.now(timezone.utc),
    )

    try:
        action_enum = VaultAction(action_str)
    except ValueError:
        return jsonify({
            "is_permitted": False,
            "rule_name": "INVALID_ACTION",
            "reason": f"Action '{action_str}' is not recognized in the security policy matrix."
        }), 400

    decision = policy_engine.evaluate(
        session=sim_session,
        action=action_enum,
        resource=target_doc,
        context={"simulation": True},
        log_denial=False,
    )
    return jsonify(decision.to_dict())


# ===================================================================
# ADMIN API
# ===================================================================

@app.route("/api/admin/users", methods=["GET"])
def api_admin_users():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"users": []}), 401

    # If Admin, return full security attributes; if non-admin, return sanitized list for policy simulation
    if user_sess.role == "Admin":
        users = db.fetch_all("SELECT id, username, full_name, role, department, clearance_level, failed_login_attempts, is_locked, created_at, last_login FROM users ORDER BY id ASC;")
    else:
        users = db.fetch_all("SELECT id, username, full_name, role, department, clearance_level FROM users WHERE is_locked = 0 ORDER BY id ASC;")
    return jsonify({"users": users})


@app.route("/api/admin/users/create", methods=["POST"])
def api_admin_create_user():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    data = request.get_json() or {}
    succ, dec, msg = user_manager.create_user(
        username=data.get("username", ""),
        password=data.get("password", ""),
        full_name=data.get("full_name", ""),
        role=data.get("role", "Viewer"),
        department=data.get("department", "Operations"),
        clearance_level=data.get("clearance_level", "UNRESTRICTED"),
        session=user_sess,
    )
    return jsonify({
        "success": succ,
        "error": msg if not succ else None,
        "decision": dec.to_dict() if dec else None
    }), (200 if succ else 403 if dec and not dec.is_permitted else 400)


@app.route("/api/admin/users/unlock", methods=["POST"])
def api_admin_unlock():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    data = request.get_json() or {}
    user_id = data.get("user_id")
    if user_id is None:
        return jsonify({"success": False, "error": "User ID is required"}), 400

    try:
        user_id_int = int(user_id)
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid User ID format"}), 400

    succ, dec, msg = user_manager.unlock_user(user_id_int, user_sess)
    return jsonify({
        "success": succ,
        "error": msg if not succ else None,
        "decision": dec.to_dict() if dec else None
    }), (200 if succ else 403 if dec and not dec.is_permitted else 400)


@app.route("/api/admin/backups", methods=["GET"])
def api_admin_backups():
    user_sess = get_current_user_session()
    if not user_sess or user_sess.role != "Admin":
        return jsonify([]), 403

    backups = backup_manager.list_backups()
    return jsonify(backups)


@app.route("/api/admin/backup/create", methods=["POST"])
def api_admin_backup_create():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    data = request.get_json() or {}
    passphrase = data.get("passphrase", "AYVaultMasterBackup2026!")

    dest, dec, stats = backup_manager.create_encrypted_backup(passphrase, user_sess)
    if dest:
        return jsonify({"success": True, "stats": stats})
    return jsonify({
        "success": False,
        "error": dec.reason if dec else "Backup failed",
        "decision": dec.to_dict() if dec else None
    }), (403 if dec and not dec.is_permitted else 400)


@app.route("/api/admin/backup/download/<filename>", methods=["GET"])
def api_admin_backup_download(filename):
    user_sess = get_current_user_session()
    if not user_sess or user_sess.role != "Admin":
        return jsonify({"error": "Administrator privilege required"}), 403

    target = (BACKUP_DIR / filename).resolve()
    if not target.exists() or not str(target).startswith(str(BACKUP_DIR.resolve())):
        return jsonify({"error": "Backup archive file not found"}), 404

    return send_file(target, download_name=filename, as_attachment=True)


@app.route("/api/admin/backup/restore", methods=["POST"])
def api_admin_backup_restore():
    user_sess = get_current_user_session()
    if not user_sess or user_sess.role != "Admin":
        return jsonify({"success": False, "error": "Administrator privilege required"}), 403

    data = request.get_json() or {}
    filename = data.get("filename", "")
    passphrase = data.get("passphrase", "")

    target = (BACKUP_DIR / filename).resolve()
    if not target.exists() or not str(target).startswith(str(BACKUP_DIR.resolve())):
        return jsonify({"success": False, "error": "Backup file not found"}), 404

    succ, dec, msg = recovery_manager.restore_backup(target, passphrase, user_sess)
    return jsonify({
        "success": succ,
        "error": msg if not succ else None,
        "decision": dec.to_dict() if dec else None,
    }), (200 if succ else 400)


def start_server(port: int = 5000):
    seed_database(force_reseed=False)
    print(f"AY Vault Web Server listening on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    start_server(5000)

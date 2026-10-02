"""
AY Vault - Local Web Server & REST API Gateway
Exposes the modular cybersecurity backend to modern browser clients on localhost.
"""

import io
import json
from pathlib import Path
from flask import Flask, jsonify, render_template, request, send_file, session as flask_session
from auth.authentication import get_auth_service
from auth.session_manager import UserSession, get_session_manager
from audit.audit_logger import get_audit_logger
from audit.audit_verifier import get_audit_verifier
from backup.backup_manager import get_backup_manager
from backup.recovery_manager import get_recovery_manager
from config.settings import THEME
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


def get_current_user_session() -> UserSession:
    """Retrieves active session from SessionManager."""
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
    auth_service.logout()
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
    doc_count = db.fetch_one("SELECT COUNT(*) as cnt FROM documents WHERE is_deleted = 0;")
    storage = doc_storage.get_vault_stats()
    lockouts = db.fetch_one("SELECT COUNT(*) as cnt FROM users WHERE is_locked = 1;")
    verification = audit_verifier.verify_integrity()
    recent_events = audit_logger.get_recent_events(limit=8)

    return jsonify({
        "total_documents": doc_count["cnt"] if doc_count else 0,
        "storage_formatted": format_file_size(storage["total_bytes"]),
        "locked_users": lockouts["cnt"] if lockouts else 0,
        "audit_status": {
            "is_valid": verification.is_valid,
            "total_records": verification.total_records,
            "verified_records": verification.verified_records,
            "compromised_id": verification.compromised_record_id,
        },
        "recent_audit": recent_events,
    })


# ===================================================================
# DOCUMENTS API
# ===================================================================

@app.route("/api/documents", methods=["GET"])
def api_list_documents():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify([]), 401
    docs = doc_manager.list_documents(user_sess)
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
            "decision": decision.to_dict(),
        })

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
        return "Authentication required", 401

    plaintext_bytes, doc_rec, decision = doc_manager.read_document_content(doc_id, user_sess)
    if not decision.is_permitted or plaintext_bytes is None:
        return f"Access Denied: {decision.reason}", 403

    return send_file(
        io.BytesIO(plaintext_bytes),
        download_name=doc_rec["original_filename"],
        as_attachment=True,
    )


@app.route("/api/documents/upload", methods=["POST"])
def api_upload_document():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    title = request.form.get("title", "").strip()
    cls_level = request.form.get("classification_level", "UNRESTRICTED")
    dept = request.form.get("department", "Security")
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
    )

    if not decision.is_permitted:
        return jsonify({
            "success": False,
            "decision": decision.to_dict(),
        })

    return jsonify({
        "success": True,
        "document": doc_record,
        "decision": decision.to_dict(),
    })


# ===================================================================
# AUDIT & FORENSICS API
# ===================================================================

@app.route("/api/audit/logs", methods=["GET"])
def api_audit_logs():
    logs = db.fetch_all("SELECT * FROM audit_log ORDER BY id DESC;")
    return jsonify(logs)


@app.route("/api/audit/verify", methods=["POST"])
def api_verify_audit():
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
    data = request.get_json() or {}
    block_id = data.get("block_id", 2)
    succ = audit_verifier.simulate_tampering(int(block_id), "UNAUTHORIZED_DATA_EXFILTRATION_TAMPERED")
    if succ:
        return jsonify({"success": True, "tampered_block": block_id})
    return jsonify({"success": False, "error": f"Block #{block_id} not found."}), 400


@app.route("/api/audit/reanchor", methods=["POST"])
def api_reanchor_audit():
    user_sess = get_current_user_session()
    username = user_sess.username if user_sess else "admin"
    succ = audit_verifier.repair_and_reanchor_chain(username)
    return jsonify({"success": succ})


@app.route("/api/audit/export/csv", methods=["GET"])
def api_export_audit_csv():
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

    action_enum = VaultAction(action_str)
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
    users = db.fetch_all("SELECT id, username, full_name, role, department, clearance_level, failed_login_attempts, is_locked FROM users ORDER BY id ASC;")
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
    })


@app.route("/api/admin/users/unlock", methods=["POST"])
def api_admin_unlock():
    user_sess = get_current_user_session()
    if not user_sess:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    data = request.get_json() or {}
    user_id = data.get("user_id")
    succ, dec, msg = user_manager.unlock_user(int(user_id), user_sess)
    return jsonify({
        "success": succ,
        "error": msg if not succ else None,
        "decision": dec.to_dict() if dec else None
    })


@app.route("/api/admin/backups", methods=["GET"])
def api_admin_backups():
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
    })


def start_server(port: int = 5000):
    seed_database(force_reseed=False)
    print(f"AY Vault Web Server listening on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    start_server(5000)

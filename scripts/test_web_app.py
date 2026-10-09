"""
Comprehensive Test Suite for AY Vault Web Application & REST API
Tests all endpoints, security mechanisms, RBAC, Bell-LaPadula MLS, lockout enforcement,
audit chain verification and tampering, backups, and edge cases.
"""

import io
import json
import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import unittest
from server import app, db
from database.seed import seed_database
from config.settings import MAX_FAILED_LOGINS

class TestAYVaultWebApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        seed_database(force_reseed=True)
        cls.client = app.test_client()

    def login(self, username, password):
        return self.client.post("/api/auth/login", json={"username": username, "password": password})

    def logout(self):
        return self.client.post("/api/auth/logout")

    def test_01_index_page_loads(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"AY VAULT", res.data)

    def test_02_auth_login_invalid(self):
        res = self.login("admin", "WrongPassword123!")
        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Invalid credentials", data["error_message"])

    def test_03_auth_login_success_admin(self):
        res = self.login("admin", "Admin@AYVault2026!")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["session"]["username"], "admin")
        self.assertEqual(data["session"]["role"], "Admin")

    def test_04_session_endpoint(self):
        res = self.client.get("/api/auth/session")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["session"]["username"], "admin")

    def test_05_dashboard_stats(self):
        res = self.client.get("/api/dashboard/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("total_documents", data)
        self.assertIn("storage_formatted", data)
        self.assertIn("audit_status", data)
        self.assertTrue(data["audit_status"]["is_valid"])

    def test_06_documents_list(self):
        res = self.client.get("/api/documents")
        self.assertEqual(res.status_code, 200)
        docs = res.get_json()
        self.assertIsInstance(docs, list)
        self.assertGreater(len(docs), 0)

    def test_07_document_decrypt(self):
        res = self.client.get("/api/documents")
        docs = res.get_json()
        first_doc = docs[0]
        res_decrypt = self.client.post("/api/documents/decrypt", json={"document_id": first_doc["id"]})
        self.assertEqual(res_decrypt.status_code, 200)
        data = res_decrypt.get_json()
        self.assertTrue(data["permitted"])
        self.assertIn("plaintext_content", data)

    def test_08_document_download(self):
        res = self.client.get("/api/documents")
        docs = res.get_json()
        first_doc = docs[0]
        res_dl = self.client.get(f"/api/documents/download/{first_doc['id']}")
        self.assertEqual(res_dl.status_code, 200)
        self.assertGreater(len(res_dl.data), 0)

    def test_09_document_upload(self):
        data = {
            "title": "QA Automated Test Document",
            "classification_level": "CONFIDENTIAL",
            "department": "Security",
            "description": "Uploaded during automated QA verification",
            "file": (io.BytesIO(b"Hello AY Vault Security Testing Plaintext Payload!"), "qa_test.txt"),
        }
        res = self.client.post("/api/documents/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 200)
        res_data = res.get_json()
        self.assertTrue(res_data["success"])
        self.assertEqual(res_data["document"]["title"], "QA Automated Test Document")

    def test_10_audit_verify_and_tamper(self):
        res_verify = self.client.post("/api/audit/verify")
        self.assertEqual(res_verify.status_code, 200)
        self.assertTrue(res_verify.get_json()["is_valid"])

        # Tamper block 2
        res_tamper = self.client.post("/api/audit/tamper", json={"block_id": 2})
        self.assertEqual(res_tamper.status_code, 200)

        # Verification must now fail!
        res_verify2 = self.client.post("/api/audit/verify")
        self.assertEqual(res_verify2.status_code, 200)
        self.assertFalse(res_verify2.get_json()["is_valid"])

        # Reanchor to heal chain
        res_reanchor = self.client.post("/api/audit/reanchor")
        self.assertEqual(res_reanchor.status_code, 200)
        self.assertTrue(res_reanchor.get_json()["success"])

        # Verification must now succeed
        res_verify3 = self.client.post("/api/audit/verify")
        self.assertEqual(res_verify3.status_code, 200)
        self.assertTrue(res_verify3.get_json()["is_valid"])

    def test_11_policy_simulate(self):
        # Admin simulating Viewer trying to read Top Secret
        users = self.client.get("/api/admin/users").get_json()["users"]
        viewer = next(u for u in users if u["role"] == "Viewer")
        docs = self.client.get("/api/documents").get_json()
        top_secret_doc = next(d for d in docs if d["classification_level"] == "TOP_SECRET")

        res_sim = self.client.post("/api/policy/simulate", json={
            "user_id": viewer["id"],
            "document_id": top_secret_doc["id"],
            "action": "doc:read"
        })
        self.assertEqual(res_sim.status_code, 200)
        data = res_sim.get_json()
        self.assertFalse(data["permitted"])
        self.assertIn("POL_003_MLS_NO_READ_UP", data["rule_name"])

    def test_12_account_lockout_enforcement(self):
        # Lockout user with 5 failed attempts
        temp_user = "test_lockout_user"
        # First create user
        self.client.post("/api/admin/users/create", json={
            "username": temp_user,
            "password": "Password123!",
            "full_name": "Test Lockout User",
            "role": "Viewer",
            "department": "Operations",
            "clearance_level": "UNRESTRICTED"
        })
        self.logout()

        for _ in range(MAX_FAILED_LOGINS):
            self.login(temp_user, "WrongPassword!")

        # 6th attempt should return locked
        res_locked = self.login(temp_user, "Password123!")
        self.assertEqual(res_locked.status_code, 401)
        self.assertTrue(res_locked.get_json()["is_locked"])

        # Login as admin to unlock
        self.login("admin", "Admin@AYVault2026!")
        users = self.client.get("/api/admin/users").get_json()["users"]
        locked_u = next(u for u in users if u["username"] == temp_user)
        self.assertTrue(locked_u["is_locked"])

        res_unlock = self.client.post("/api/admin/users/unlock", json={"user_id": locked_u["id"]})
        self.assertEqual(res_unlock.status_code, 200)
        self.assertTrue(res_unlock.get_json()["success"])

        # Should now be able to login
        self.logout()
        res_ok = self.login(temp_user, "Password123!")
        self.assertEqual(res_ok.status_code, 200)
        self.assertTrue(res_ok.get_json()["success"])

    def test_13_document_deletion_policy(self):
        # Admin uploads a document and deletes it
        self.login("admin", "Admin@AYVault2026!")
        data = {
            "title": "Document To Delete",
            "classification_level": "UNRESTRICTED",
            "department": "Security",
            "description": "Temp file",
            "file": (io.BytesIO(b"Delete me"), "delete_me.txt"),
        }
        res_up = self.client.post("/api/documents/upload", data=data, content_type="multipart/form-data")
        doc_id = res_up.get_json()["document"]["id"]

        # Viewer attempts deletion -> 403 Forbidden
        self.login("bob_viewer", "Viewer@AYVault2026!")
        res_del_denied = self.client.post("/api/documents/delete", json={"document_id": doc_id})
        self.assertEqual(res_del_denied.status_code, 403)

        # Admin deletes -> 200 OK
        self.login("admin", "Admin@AYVault2026!")
        res_del_ok = self.client.post("/api/documents/delete", json={"document_id": doc_id})
        self.assertEqual(res_del_ok.status_code, 200)
        self.assertTrue(res_del_ok.get_json()["success"])

    def test_14_backup_create_download_restore(self):
        self.login("admin", "Admin@AYVault2026!")
        # Create backup
        res_bc = self.client.post("/api/admin/backup/create", json={"passphrase": "SecretBackupPass2026!"})
        self.assertEqual(res_bc.status_code, 200)
        backup_stats = res_bc.get_json()["stats"]
        file_name = backup_stats["file_name"]

        # List backups
        res_bl = self.client.get("/api/admin/backups")
        self.assertEqual(res_bl.status_code, 200)
        backups = res_bl.get_json()
        self.assertTrue(any(b["file_name"] == file_name for b in backups))

        # Download backup
        res_bd = self.client.get(f"/api/admin/backup/download/{file_name}")
        self.assertEqual(res_bd.status_code, 200)
        self.assertGreater(len(res_bd.data), 0)

        # Restore backup with correct passphrase
        res_br = self.client.post("/api/admin/backup/restore", json={
            "filename": file_name,
            "passphrase": "SecretBackupPass2026!"
        })
        self.assertEqual(res_br.status_code, 200)
        self.assertTrue(res_br.get_json()["success"])

    def test_15_unauthenticated_protections(self):
        self.logout()
        # Dashboard stats should require auth
        self.assertEqual(self.client.get("/api/dashboard/stats").status_code, 401)
        # Document list should require auth
        self.assertEqual(self.client.get("/api/documents").status_code, 401)
        # Audit logs should require auth
        self.assertEqual(self.client.get("/api/audit/logs").status_code, 401)
        # Admin users should require auth
        self.assertEqual(self.client.get("/api/admin/users").status_code, 401)


if __name__ == "__main__":
    unittest.main()

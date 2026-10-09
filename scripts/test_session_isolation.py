"""
Test Session Isolation and Concurrent Sessions
"""

import os
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import unittest
from server import app
from database.seed import seed_database

class TestSessionIsolation(unittest.TestCase):
    def setUp(self):
        seed_database(force_reseed=True)

    def test_session_isolation_between_two_clients(self):
        client_viewer = app.test_client()
        client_admin = app.test_client()

        # 1. Viewer logs in on client 1
        res1 = client_viewer.post("/api/auth/login", json={"username": "bob_viewer", "password": "Viewer@AYVault2026!"})
        self.assertEqual(res1.status_code, 200)

        # 2. Check viewer's session
        res_v_sess = client_viewer.get("/api/auth/session").get_json()
        self.assertEqual(res_v_sess["session"]["username"], "bob_viewer")

        # 3. Admin logs in on client 2
        res2 = client_admin.post("/api/auth/login", json={"username": "admin", "password": "Admin@AYVault2026!"})
        self.assertEqual(res2.status_code, 200)

        # 4. NOW: What does client 1 (viewer) see at /api/auth/session?
        res_v_sess2 = client_viewer.get("/api/auth/session").get_json()
        print(f"Client 1 session after Admin logged in: {res_v_sess2['session']['username']}")
        
        # Can client 1 create an admin user?
        res_create = client_viewer.post("/api/admin/users/create", json={
            "username": "hacked_user",
            "password": "Password123!",
            "full_name": "Hacked",
            "role": "Admin",
            "department": "Security",
            "clearance_level": "TOP_SECRET"
        })
        print(f"Client 1 creating user status: {res_create.status_code}, data: {res_create.get_json()}")

        # Assert viewer is still viewer and cannot perform admin actions!
        self.assertEqual(res_v_sess2["session"]["username"], "bob_viewer")
        self.assertFalse(res_create.get_json()["success"])

if __name__ == "__main__":
    unittest.main()

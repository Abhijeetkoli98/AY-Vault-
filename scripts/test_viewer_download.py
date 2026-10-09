"""
Test Viewer Downloading Documents
"""
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import unittest
from server import app
from database.seed import seed_database

class TestViewerDownloadBug(unittest.TestCase):
    def setUp(self):
        seed_database(force_reseed=True)

    def test_viewer_should_not_download(self):
        client = app.test_client()
        # Login as viewer
        client.post("/api/auth/login", json={"username": "bob_viewer", "password": "Viewer@AYVault2026!"})
        docs = client.get("/api/documents").get_json()
        unrestricted_doc = next(d for d in docs if d["classification_level"] == "UNRESTRICTED")
        
        # Download document
        res = client.get(f"/api/documents/download/{unrestricted_doc['id']}")
        print(f"Viewer download status: {res.status_code}")
        # Viewer should be denied (403), but let's see what happens!
        self.assertEqual(res.status_code, 403)

if __name__ == "__main__":
    unittest.main()

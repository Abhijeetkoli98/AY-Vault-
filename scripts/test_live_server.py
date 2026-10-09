"""
Live HTTP Integration Test against running server at http://127.0.0.1:5000
"""

import urllib.request
import urllib.parse
import json
import http.cookiejar

BASE_URL = "http://127.0.0.1:5000"

def run_live_tests():
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    print(f"[*] Testing connection to {BASE_URL}...")
    req = urllib.request.Request(f"{BASE_URL}/")
    with opener.open(req) as resp:
        html = resp.read().decode("utf-8")
        assert "AY VAULT" in html
        print("[+] Root SPA index.html loads successfully (HTTP 200).")

    print("[*] Testing Admin Login...")
    login_data = json.dumps({"username": "admin", "password": "Admin@AYVault2026!"}).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}/api/auth/login", data=login_data, headers={"Content-Type": "application/json"})
    with opener.open(req) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        assert res["success"] is True
        print(f"[+] Admin logged in: {res['session']['username']} ({res['session']['role']})")

    print("[*] Testing Session endpoint...")
    req = urllib.request.Request(f"{BASE_URL}/api/auth/session")
    with opener.open(req) as resp:
        sess = json.loads(resp.read().decode("utf-8"))
        assert sess["authenticated"] is True
        assert sess["session"]["username"] == "admin"
        print(f"[+] Active session verified for user: {sess['session']['username']}")

    print("[*] Testing Dashboard stats...")
    req = urllib.request.Request(f"{BASE_URL}/api/dashboard/stats")
    with opener.open(req) as resp:
        stats = json.loads(resp.read().decode("utf-8"))
        print(f"[+] Total docs: {stats['total_documents']}, Storage: {stats['storage_formatted']}, Audit valid: {stats['audit_status']['is_valid']}")

    print("[*] Testing Documents list & decrypt...")
    req = urllib.request.Request(f"{BASE_URL}/api/documents")
    with opener.open(req) as resp:
        docs = json.loads(resp.read().decode("utf-8"))
        print(f"[+] Retrieved {len(docs)} documents.")
        first_doc = docs[0]

    decrypt_payload = json.dumps({"document_id": first_doc["id"]}).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}/api/documents/decrypt", data=decrypt_payload, headers={"Content-Type": "application/json"})
    with opener.open(req) as resp:
        dec = json.loads(resp.read().decode("utf-8"))
        assert dec["permitted"] is True
        print(f"[+] Document '{first_doc['title']}' decrypted in-memory: {len(dec['plaintext_content'])} chars.")

    print("[*] Testing Audit verification...")
    req = urllib.request.Request(f"{BASE_URL}/api/audit/verify", data=b"{}", headers={"Content-Type": "application/json"})
    with opener.open(req) as resp:
        v = json.loads(resp.read().decode("utf-8"))
        assert v["is_valid"] is True
        print(f"[+] Forensic audit integrity verified: {v['verified_records']} blocks intact.")

    print("[*] Testing Policy Simulation...")
    users_req = urllib.request.Request(f"{BASE_URL}/api/admin/users")
    with opener.open(users_req) as resp:
        users = json.loads(resp.read().decode("utf-8"))["users"]

    viewer = next(u for u in users if u["role"] == "Viewer")
    top_secret_doc = next(d for d in docs if d["classification_level"] == "TOP_SECRET")

    sim_payload = json.dumps({
        "user_id": viewer["id"],
        "document_id": top_secret_doc["id"],
        "action": "doc:read"
    }).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}/api/policy/simulate", data=sim_payload, headers={"Content-Type": "application/json"})
    with opener.open(req) as resp:
        decision = json.loads(resp.read().decode("utf-8"))
        assert decision["permitted"] is False
        assert decision["rule_name"] == "POL_003_MLS_NO_READ_UP"
        print(f"[+] Policy Simulation correctly denied Viewer access to TOP_SECRET doc: {decision['rule_name']}")

    print("[*] Testing User Creation...")
    new_user_data = json.dumps({
        "username": "live_test_user",
        "full_name": "Live Test Engineer",
        "role": "Viewer",
        "department": "Engineering",
        "clearance_level": "UNRESTRICTED",
        "password": "LivePass@AYVault2026!"
    }).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}/api/admin/users/create", data=new_user_data, headers={"Content-Type": "application/json"})
    with opener.open(req) as resp:
        res_u = json.loads(resp.read().decode("utf-8"))
        assert res_u["success"] is True
        print("[+] User 'live_test_user' created successfully via API.")

    print("[*] Testing Encrypted Backup Creation & Listing...")
    backup_data = json.dumps({"passphrase": "LiveMasterBackup2026!"}).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}/api/admin/backup/create", data=backup_data, headers={"Content-Type": "application/json"})
    with opener.open(req) as resp:
        res_b = json.loads(resp.read().decode("utf-8"))
        assert res_b["success"] is True
        print(f"[+] Backup generated: {res_b['stats']['file_name']}")

    req = urllib.request.Request(f"{BASE_URL}/api/admin/backups")
    with opener.open(req) as resp:
        backups = json.loads(resp.read().decode("utf-8"))
        assert len(backups) > 0
        print(f"[+] Backups list retrieved: {len(backups)} archives found.")

    print("\n[=== ALL LIVE INTEGRATION TESTS PASSED WITH 100% SUCCESS ===]\n")

if __name__ == "__main__":
    run_live_tests()

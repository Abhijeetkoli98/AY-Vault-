# AY Vault — Secure Offline Document Management System

![Security Badge](https://img.shields.io/badge/Security-AES--256--GCM-blue)
![Auth Badge](https://img.shields.io/badge/Auth-Argon2id-green)
![Integrity Badge](https://img.shields.io/badge/Audit-SHA--256--Chained-cyan)
![Storage Badge](https://img.shields.io/badge/Storage-Offline--Encrypted-orange)
![License](https://img.shields.io/badge/Architecture-Modular-purple)

**AY Vault** is a high-assurance, offline-first secure document vault and record-management desktop application built with **Python 3**, **Tkinter**, and **SQLite**. Designed for air-gapped workstations, sensitive enterprise data compartments, and defense-in-depth security environments, it provides authenticated symmetric encryption at rest, multilevel access control (Bell-LaPadula MLS), account lockout safeguards, tamper-evident hash-chained audit logging, and encrypted disaster recovery.

---

## 🏛️ System Architecture

AY Vault strictly decouples responsibilities across isolated modules. The user interface layer never interacts directly with low-level disk I/O or raw cryptography; every sensitive operation passes through a central authorization policy engine.

```
AY_Vault/
│
├── main.py                     # Application entry point & lifecycle controller
├── requirements.txt            # Minimal verified dependencies
├── README.md                   # Comprehensive documentation & security rationale
│
├── config/
│   └── settings.py             # System paths, crypto constants, roles, and UI theme
│
├── database/
│   ├── database.py             # SQLite WAL-mode transaction & connection manager
│   ├── schema.py               # Table definitions, indices, and constraints
│   └── seed.py                 # Mock enterprise identities, encrypted docs & audit ledger
│
├── auth/
│   ├── authentication.py       # Login service, 5-attempt lockout enforcement & audit hooks
│   ├── password_manager.py     # RFC 9106 Argon2id password hashing & complexity validator
│   └── session_manager.py      # Authenticated context, token lifecycle & inactivity timeout
│
├── security/
│   ├── encryption.py           # AES-256-GCM AEAD encryption, envelope keys & PBKDF2 KDF
│   ├── access_control.py       # RBAC action taxonomy & clearance hierarchy ranks
│   ├── policy_engine.py        # Central Bell-LaPadula MLS & Compartmentalization engine
│   └── security_utils.py       # Path sanitization, constant-time compare & SHA-256 routines
│
├── documents/
│   ├── document_manager.py     # Document lifecycle (upload, decrypt preview, export, delete)
│   ├── document_storage.py     # Physical encrypted blob storage in data/vault/
│   └── version_manager.py      # Historical version snapshots & plaintext/ciphertext hashes
│
├── audit/
│   ├── audit_logger.py         # Append-only hash-chained ledger (Blockchain-style SHA-256)
│   └── audit_verifier.py       # Forensic integrity scanner & live tampering simulation
│
├── backup/
│   ├── backup_manager.py       # Passphrase-encrypted archives (.ayb) with JSON integrity manifests
│   └── recovery_manager.py     # Archive decryption, manifest SHA-256 checks & restoration
│
├── users/
│   ├── user_manager.py         # Identity provisioning, role updates, and password resets
│   └── role_manager.py         # Role catalog, descriptions, and permission mapping
│
├── ui/
│   ├── styles.py               # Dark slate cybersecurity theme & ttk configurations
│   ├── components.py           # Stat cards, badges, policy decision dialogs & previewers
│   ├── main_window.py          # Persistent navigation sidebar & active view router
│   ├── login_view.py           # Authentication card with quick persona selectors
│   ├── dashboard_view.py       # High-level metrics, health status, and live audit feed
│   ├── document_view.py        # Vault explorer with search, MLS filters & export tools
│   ├── upload_view.py          # Zero-knowledge file ingest with live cryptographic hashing
│   ├── audit_view.py           # Blockchain ledger table, forensic verify & tamper simulator
│   ├── security_view.py        # Subsystem health, live policy sandbox & lockout monitor
│   └── admin_view.py           # User management & encrypted backup/recovery tools
│
├── data/
│   ├── vault/                  # Stored encrypted files (*.enc)
│   ├── backups/                # Generated encrypted system snapshots (*.ayb)
│   ├── ayvault.db              # SQLite transactional database
│   └── .master.key             # 256-bit vault master key
│
└── assets/
    └── icons/                  # Visual assets & emblems
```

---

## 🔐 Core Security Mechanisms

### 1. Zero-Plaintext Document Storage (AES-256-GCM)
- Files uploaded to AY Vault are never written to disk in plaintext.
- Each document payload is encrypted using **AES-256-GCM** (Galois/Counter Mode) via Python's `cryptography` library.
- Format: `[12-byte Unique Random Nonce] + [Ciphertext + 16-byte GCM Authentication Tag]`.
- Tampering with ciphertext or bit-flipping on disk causes `cryptography.exceptions.InvalidTag`, which raises a `DecryptionError` and aborts decryption before any data reaches memory.
- Metadata stores both `plaintext_sha256` and `ciphertext_sha256` to guarantee end-to-end integrity.

### 2. Password Hashing & Strict Account Lockout (Argon2id)
- Passwords are encrypted with **Argon2id** (RFC 9106) using memory-hard parameters:
  - Memory cost: 64 MB (`65536` KiB)
  - Time iterations: 3 passes
  - Parallelism: 4 threads
- **5-Attempt Lockout Enforcement**: Accounts track consecutive failed logins. Upon the **5th consecutive failed attempt**, the account is locked (`is_locked = 1`), an `AUTH_LOCKOUT` audit event is logged, and subsequent attempts are blocked until an Administrator unlocks the account.

### 3. Central Security Policy Engine (MLS & Compartmentalization)
Every sensitive operation queries `PolicyEngine.evaluate(...)` with `(Subject, Action, Resource, Context)` before executing:
1. **Authentication Gate**: Rejects unauthenticated or expired sessions.
2. **RBAC Baseline**: Confirms role has baseline capability (`Admin`, `Manager`, `Viewer`).
3. **Bell-LaPadula Multilevel Security (MLS)**:
   - Hierarchy: `UNRESTRICTED (1) < CONFIDENTIAL (2) < RESTRICTED (3) < TOP_SECRET (4)`.
   - **No Read Up**: A user cannot read or download documents above their clearance level.
4. **Need-to-Know Compartmentalization**: Users cannot access documents outside their assigned department (e.g. `Finance` vs `Engineering`), unless they hold `Admin` status or `Executive` clearance.
5. **Deletion Authority**: Restricted to System Administrators or the Manager who authored the document.
6. **Live Policy Sandbox**: Built-in interactive simulator to test and explain decisions for any user/document combination.

### 4. Tamper-Evident Hash-Chained Audit Ledger
- All critical security actions (logins, lockouts, document accesses, downloads, uploads, denials, administrative changes) are recorded in an append-only SQLite ledger.
- Each record calculates:
  $$\text{Block Hash} = \text{SHA-256}(\text{prev\_hash} \parallel \text{timestamp} \parallel \text{event} \parallel \text{user} \parallel \text{action} \parallel \text{res\_type} \parallel \text{res\_id} \parallel \text{status} \parallel \text{details})$$
- The genesis block seals `0000000000000000000000000000000000000000000000000000000000000000`.
- **Integrity Scanner**: Traverses the chain from block 1 to current head, checking hash linkage and canonical payload signatures.
- **Forensic Tamper Simulation**: Built-in demonstration button allows modifying a record's text directly in SQLite, then running verification to observe real-time detection pinpointing the exact corrupted block.

### 5. Passphrase-Encrypted Backup & Disaster Recovery
- Backups package the database and encrypted vault into a zip archive with a cryptographic `manifest.json`.
- The archive is encrypted using AES-256-GCM with a key derived from a user passphrase using **PBKDF2-HMAC-SHA256** (200,000 iterations).
- The restoration engine checks every individual file's SHA-256 checksum against the manifest before restoring.

---

## 👥 Default Demo Credentials

The system seeds with pre-configured personas to demonstrate RBAC, MLS clearance ranks, departmental compartmentalization, and lockout states:

| Username | Password | Role | Clearance Level | Department | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **admin** | `Admin@AYVault2026!` | Admin | `TOP_SECRET` | Security | Full administrative access, audit verification, user provisioning, backup/restore. |
| **sarah_mgr** | `Manager@AYVault2026!` | Manager | `RESTRICTED` | Engineering | Can create, version, and view documents up to RESTRICTED in Engineering. |
| **bob_viewer** | `Viewer@AYVault2026!` | Viewer | `CONFIDENTIAL` | Finance | Read-only access within Finance up to CONFIDENTIAL. Denied for TOP_SECRET. |
| **dave_locked** | `Locked@AYVault2026!` | Viewer | `UNRESTRICTED` | Operations | **Pre-locked account** (5 failed attempts) to test lockout banner and admin unlock. |

> **Note:** The login screen provides quick one-click credential buttons to conveniently test each persona.

---

## 🚀 Installation & Execution

### Prerequisites
- Python 3.10+ (Tested on Python 3.11, 3.12, 3.13, 3.14)
- Tkinter (included with standard Python desktop installations)

### 1. Clone or Open Workspace
```bash
cd "c:\Users\ABHIJEET\OneDrive\Desktop\AY-Vault-"
```

### 2. Install Required Dependencies
External dependencies are strictly limited to standard security libraries:
```bash
pip install -r requirements.txt
```
*(Dependencies: `cryptography>=42.0.0`, `passlib>=1.7.4`, `argon2-cffi>=23.1.0`)*

### 3. Launch AY Vault
```bash
python main.py
```
*(On first startup, the database `data/ayvault.db` and initial encrypted vault documents are automatically seeded and verified).*

---

## 🧪 Step-by-Step Demonstration Workflow

Follow this workflow to demonstrate the full security lifecycle:

```text
[Login] ➔ [Authentication & Lockout] ➔ [Policy Check] ➔ [Document Access] ➔ [AES-256-GCM] ➔ [Audit Ledger]
```

### Flow 1: Successful Access & In-Memory Decryption
1. Log in as **admin** (`Admin@AYVault2026!`).
2. Navigate to **Document Vault**. Notice the clearance badges and authorized status indicators.
3. Select `AY-SEC-2026 Incident Response & Breach Containment Plan` (Classification: `TOP_SECRET`).
4. Click **Inspect Decrypted Content**.
5. Observe the verified AES-256-GCM tag banner and exact matching SHA-256 hash.

### Flow 2: Bell-LaPadula Multilevel Security Denial
1. Click **Terminate Session** in the sidebar.
2. Log in as **bob_viewer** (Clearance: `CONFIDENTIAL`, Department: `Finance`).
3. In **Document Vault**, try to view the `TOP_SECRET` Incident Response Plan.
4. **Result:** Access is blocked. The **Security Policy Decision Inspector** modal appears, highlighting:
   - Rule: `POL_003_MLS_NO_READ_UP`
   - Code: `DENY_INSUFFICIENT_CLEARANCE`
   - Rationale: Clearance `CONFIDENTIAL` (Rank 2) is below Document Classification `TOP_SECRET` (Rank 4).
   - A `POLICY_DENIAL` entry is logged to the immutable audit ledger.

### Flow 3: Department Compartmentalization Denial
1. Still logged in as **bob_viewer** (`Finance`), locate `Cloud-Infrastructure-Architecture-Blueprint.md` (Classification: `CONFIDENTIAL`, Department: `Engineering`).
2. Click **Inspect Decrypted Content**.
3. **Result:** Blocked by `POL_004_DEPARTMENT_SILO` because the document is restricted to Engineering.

### Flow 4: Account Lockout after 5 Failed Attempts
1. Log out. Enter username `bob_viewer` and enter an incorrect password 5 consecutive times.
2. Observe the countdown: `4 attempt(s) remaining`, `3 attempt(s) remaining`...
3. On the 5th attempt, the account is locked and a prominent red banner appears:
   `⚠️ Account 'bob_viewer' has been LOCKED. Failed 5 consecutive login attempts.`
4. Log in as **admin**.
5. Go to **Security Center** or **Administration** ➔ **Account Lockout Monitor**.
6. Select `bob_viewer` and click **Unlock Selected**.

### Flow 5: Cryptographic Audit Verification & Tampering Forensics
1. Log in as **admin** and go to **Audit & Forensics**.
2. Click **Verify Audit Integrity**. The system verifies 100% of blocks and shows a green success badge.
3. Select an audit block from the table (e.g. Block #2).
4. Click **Simulate Record Tampering**. Confirm the prompt. The action string in SQLite is altered directly without updating the hash chain.
5. Click **Verify Audit Integrity**.
6. **Result:** The system triggers a critical red alert:
   `ALERT: TAMPERING DETECTED AT BLOCK #2! Cryptographic signature mismatch!`
   It pinpoints the exact corrupted block, stored hash, and recomputed hash.
7. Click **Re-Anchor Chain** to demonstrate administrative forensic re-anchoring and receipt logging.

### Flow 6: Encrypted Backup & Disaster Recovery
1. In **Administration**, open the **Encrypted Backup & Recovery** tab.
2. Click **Create Encrypted Backup Archive (.ayb)** and provide a passphrase.
3. An AES-256-GCM archive containing the database, vault payloads, and manifest checksums is generated in `data/backups/`.
4. Click **Restore System from Backup Archive**, select the archive, enter the passphrase, and verify how the recovery manager checks every file's SHA-256 hash before restoring.

---

## ⚠️ Academic Prototype & Security Limitations

In adherence to rigorous cybersecurity engineering principles, this project is explicitly documented as a **security-focused academic prototype and desktop reference architecture**. It is **not** claimed to be "100% unhackable", "military grade", or automatically HIPAA/GDPR/SOC2 compliant out of the box.

### Known Limitations:
1. **Local Key Storage**: The AES-256 master vault key resides in `data/.master.key` on the local file system. In an enterprise production deployment, this key should be managed by a Hardware Security Module (HSM), TPM 2.0 chip, or cloud KMS (e.g. AWS KMS / HashiCorp Vault).
2. **Operating System Memory**: Decrypted plaintext exists in volatile Python memory during in-memory previewing. Hostile processes with OS administrative/debugger privileges (e.g. `ReadProcessMemory`) could theoretically inspect memory buffers.
3. **Database Ledger Anchoring**: The hash-chained audit ledger is stored locally in SQLite. While any tampering is immediately detected by the verification algorithm, an attacker with full root filesystem access could delete the entire database file. In production, head hashes should be mirrored to an external, write-once immutable syslog or witness server.
4. **Single-Node Offline Architecture**: Built as an offline workstation solution; multi-user concurrent network synchronization requires an authenticated network gateway and mTLS transport.

---

## 📄 License & Attribution

Developed as a cybersecurity portfolio demonstration illustrating defense-in-depth principles:
- **Argon2id** Password Hashing (RFC 9106)
- **AES-256-GCM** Authenticated Encryption with Associated Data (AEAD)
- **Bell-LaPadula Multilevel Security (MLS)** & Department Compartmentalization
- **Blockchain-Style SHA-256 Hash-Chained Audit Ledger**
- **PBKDF2-HMAC-SHA256 Encrypted Archives & Forensic Recovery**

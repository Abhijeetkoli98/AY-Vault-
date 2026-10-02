# ARCHITECTURE.md — AY Vault System Architecture

## Architecture Overview

```mermaid
graph TD
    Client[Web Browser / Tkinter GUI] --> Router[REST API / Controller Layer]
    Router --> Auth[Auth Service & Session Manager]
    Router --> Policy[Bell-LaPadula Policy Engine]
    Router --> DocMgr[Document Manager]
    Router --> AuditVerif[Audit Verifier & Forensics]
    
    Auth --> PassMgr[Argon2id Password Hasher]
    Policy --> AuditLog[Tamper-Evident Audit Logger]
    DocMgr --> Crypto[AES-256-GCM AEAD Engine]
    DocMgr --> Storage[Encrypted File Storage]
    
    AuditLog --> DB[(SQLite WAL Ledger)]
    Auth --> DB
    DocMgr --> DB
```

## Security Layers
1. **At-Rest Protection**: Payload encrypted via AES-256-GCM with PBKDF2/Argon2 derived keys.
2. **Authorization Gate**: Every document read, export, modify, or delete passes through `PolicyEngine.evaluate()`.
3. **Forensic Integrity**: Tamper-detection via SHA-256 hash chaining prevents log alteration.

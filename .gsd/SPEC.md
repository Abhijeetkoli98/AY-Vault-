# SPEC.md — Project Specification: AY Vault

> **Status**: `FINALIZED`
> **Version**: 1.0.0
> **System**: AY Vault — Secure Offline Document Management System

## Vision
AY Vault is a high-assurance, offline-first cybersecurity document management system designed to protect sensitive enterprise documents using authenticated symmetric encryption (AES-256-GCM), Argon2id key derivation, multilevel access control (Bell-LaPadula MLS with departmental compartmentalization), and a tamper-evident SHA-256 Merkle-style audit ledger.

## Core Capabilities & Goals
1. **Authenticated Encryption (Zero Plaintext Footprint)**: All document payloads are encrypted in memory with unique 96-bit nonces before touching disk. Plaintext is decrypted on demand in volatile RAM only.
2. **Access Control Engine**: Enforces strict Multi-Level Security (MLS) with "no read up" and departmental need-to-know isolation across 4 classifications (UNRESTRICTED, CONFIDENTIAL, RESTRICTED, TOP_SECRET).
3. **Tamper-Evident Forensic Audit Ledger**: Every security event is cryptographically hash-chained using previous block digests. Real-time forensic verification detects any bit modifications.
4. **Dual Interfaces**:
   - Modern enterprise web dashboard (`http://127.0.0.1:5000/`) with clean typography, human-readable activity feeds, identifier masking, and policy simulation.
   - Native Python desktop GUI (`python main.py`) with zero external network connectivity.
5. **Backup & Disaster Recovery**: Encrypted `.ayb` archive generation with SHA-256 manifest integrity checks and passphrase-protected PBKDF2 envelope encryption.

## Non-Goals (Out of Scope)
- Cloud storage integration (strictly air-gapped / local-first architecture).
- Multi-tenant SaaS infrastructure (designed for sovereign offline nodes).
- Biometric authentication hardware integration.

## Target Personas
- **Security Administrators** (`Alex` / `admin`): Clearance `TOP_SECRET`, full audit verification, forensic simulation, user provisioning.
- **Department Managers** (`Sarah` / `sarah_mgr`): Clearance `RESTRICTED`, document ingestion, policy management within department.
- **Viewers** (`Bob` / `bob_viewer`): Clearance `CONFIDENTIAL`, read-only access to authorized departmental documents.
- **Auditors**: Forensic inspection of the hash-chained security ledger.

## Constraints & Security Assumptions
- Pure local execution with zero telemetry.
- Supported runtime: Python 3.10+ on Windows, Linux, and macOS.
- Minimal external dependencies: `cryptography`, `passlib`, `argon2-cffi`, `flask`.

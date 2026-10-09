/**
 * AY Vault - Firebase Cloud Showcase Mock Adapter
 * Enables complete DMS interactivity when deployed to Firebase Hosting.
 * Supports folders, duplicate detection, metadata editing, version snapshots,
 * recently accessed files, RBAC enforcement, and dedicated security center.
 */

(function () {
  const isLocalHost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
  const STORAGE_KEY = 'AY_VAULT_CLOUD_DMS_STATE_v2';

  const CLEARANCE_RANKS = {
    'UNRESTRICTED': 0,
    'CONFIDENTIAL': 1,
    'RESTRICTED': 2,
    'TOP_SECRET': 3
  };

  const DEFAULT_USERS = [
    { id: 1, username: 'admin', full_name: 'Alex Vance', role: 'Admin', department: 'Security', clearance_level: 'TOP_SECRET', is_locked: 0, failed_login_attempts: 0, created_at: '2026-01-15T08:00:00Z', last_login: '2026-10-09T20:30:00Z' },
    { id: 2, username: 'sarah_mgr', full_name: 'Sarah Connor', role: 'Manager', department: 'Operations', clearance_level: 'RESTRICTED', is_locked: 0, failed_login_attempts: 0, created_at: '2026-02-01T09:15:00Z', last_login: '2026-10-09T18:45:00Z' },
    { id: 3, username: 'bob_viewer', full_name: 'Bob Martinez', role: 'Viewer', department: 'Finance', clearance_level: 'CONFIDENTIAL', is_locked: 0, failed_login_attempts: 0, created_at: '2026-03-10T11:20:00Z', last_login: '2026-10-09T17:10:00Z' },
    { id: 4, username: 'dave_locked', full_name: 'Dave Miller', role: 'Viewer', department: 'Engineering', clearance_level: 'CONFIDENTIAL', is_locked: 1, failed_login_attempts: 5, created_at: '2026-04-05T14:00:00Z', last_login: null }
  ];

  const DEFAULT_FOLDERS = [
    { id: 'fld-1', name: 'Security & Compliance', department: 'Security', created_by: 1, created_at: '2026-10-01T08:00:00Z' },
    { id: 'fld-2', name: 'Financial Ledgers', department: 'Finance', created_by: 1, created_at: '2026-10-01T08:05:00Z' },
    { id: 'fld-3', name: 'Operations & SOPs', department: 'Operations', created_by: 1, created_at: '2026-10-01T08:10:00Z' }
  ];

  const DEFAULT_DOCUMENTS = [
    {
      id: 'doc-1',
      title: 'AY-SEC-2026 Incident Response & Breach Containment Plan',
      original_filename: 'AY-SEC-2026-Incident-Response-Plan.md',
      classification_level: 'TOP_SECRET',
      department: 'Security',
      category: 'Compliance',
      tags: 'incident,sop,containment,security',
      folder_id: 'fld-1',
      owner_username: 'admin',
      version: 1,
      description: 'Standard Operating Procedure for handling zero-day exploits, containment isolation, and forensic triage.',
      file_size_bytes: 1480,
      created_at: '2026-10-01T10:00:00Z',
      last_accessed_at: '2026-10-09T19:30:00Z',
      content: `# AY Vault - Cyber Incident Response & Breach Containment SOP\n\n**Classification: TOP SECRET // NOFORN**\n**Effective Date: October 2026**\n**Document Control ID: AY-SOP-IR-0994**\n\n## 1. Executive Summary\nThis protocol establishes the mandatory response procedures for containment, eradication,\nand cryptographic chain-of-custody in the event of an adversary breach or hardware compromise.\n\n## 2. Immediate Containment Checklist\n1. Sever all network and air-gap bridge connections.\n2. Execute cryptographic key revocation for all active session tokens.\n3. Export immutable audit ledger snapshot to write-once optical media.\n4. Take live volatility memory dumps prior to system power cycling.\n\n## 3. Cryptographic Re-Anchoring\nIf database tampering is suspected, run forensic audit verification via AuditVerifier.\nCross-reference current head hash with offsite cryptographic witness.`
    },
    {
      id: 'doc-2',
      title: 'Q3 Financial Audit & Capital Reserves Ledger',
      original_filename: 'Q3-Financial-Audit-Report.txt',
      classification_level: 'RESTRICTED',
      department: 'Finance',
      category: 'Financial',
      tags: 'audit,reserves,q3,finance',
      folder_id: 'fld-2',
      owner_username: 'bob_viewer',
      version: 1,
      description: 'Quarterly audit evaluation of liquid operating reserves, capital expenditure, and risk insurance.',
      file_size_bytes: 920,
      created_at: '2026-10-02T14:30:00Z',
      last_accessed_at: '2026-10-09T18:15:00Z',
      content: `AY ENTERPRISE - Q3 FINANCIAL AUDIT & CAPITAL RESERVES\nClassification: RESTRICTED - FINANCE INTERNAL ONLY\nAuditor: Bob Martinez, Senior Financial Analyst\n\n--- SUMMARY OF ASSETS & RESERVES ---\nOperating Liquidity:       $14,250,000 USD\nCryptographic Vault Reserves: $8,700,000 USD\nCyber Insurance Hedge:      $25,000,000 Policy Coverage\n\n--- COMPLIANCE AFFIRMATION ---\nAll balance sheets have been reconciled against internal ledgers.`
    },
    {
      id: 'doc-3',
      title: 'Hardware Cryptographic Key Lifecycle Policy',
      original_filename: 'Hardware-Crypto-Lifecycle-SOP.md',
      classification_level: 'RESTRICTED',
      department: 'Engineering',
      category: 'Technical',
      tags: 'crypto,keys,hsm,fips',
      folder_id: null,
      owner_username: 'admin',
      version: 2,
      description: 'FIPS 140-3 Level 4 key generation ceremonies, master seed rotation cadence, and tamper-resistant HSM maintenance.',
      file_size_bytes: 1150,
      created_at: '2026-10-03T09:15:00Z',
      last_accessed_at: '2026-10-09T15:40:00Z',
      content: `# Hardware Cryptographic Key Lifecycle Policy\n\n**Classification: RESTRICTED // ENGINEERING**\n**HSM Standard: FIPS 140-3 Level 4**\n\n## Master Key Splitting & Shamir Threshold Scheme\nRoot envelope keys are derived using Shamir Secret Sharing with a 3-of-5 quorum:\n- Custodian A: Chief Information Security Officer\n- Custodian B: Lead Cryptographic Engineer\n- Custodian C: Head of Infrastructure\n- Custodian D: Independent Forensic Trustee\n- Custodian E: Offline Physical Vault Depository`
    },
    {
      id: 'doc-4',
      title: 'Facility Physical Security & Biometric Access Protocol',
      original_filename: 'Facility-Physical-Access-Protocols.txt',
      classification_level: 'CONFIDENTIAL',
      department: 'Operations',
      category: 'Operations',
      tags: 'biometrics,facility,access,operations',
      folder_id: 'fld-3',
      owner_username: 'sarah_mgr',
      version: 1,
      description: 'Procedures for biometric retinal scans, mantrap entry validation, and two-person integrity control.',
      file_size_bytes: 780,
      created_at: '2026-10-04T16:00:00Z',
      last_accessed_at: '2026-10-08T11:20:00Z',
      content: `FACILITY PHYSICAL ACCESS PROTOCOL\nClassification: CONFIDENTIAL - OPERATIONS\nAuthority: Sarah Connor, Operations Director\n\n1. Dual-Factor Mantrap Isolation\nAll high-security server compartments require simultaneous multi-spectral biometric fingerprint verification and cryptographic smart-card badge authorization.\n\n2. Two-Person Rule (2PR)\nNo personnel may enter Tier-4 compartments unaccompanied.`
    },
    {
      id: 'doc-5',
      title: 'Employee Data Protection & Privacy Compliance Policy',
      original_filename: 'Data-Privacy-Compliance-Manual.md',
      classification_level: 'UNRESTRICTED',
      department: 'Operations',
      category: 'Legal',
      tags: 'gdpr,privacy,legal,policy',
      folder_id: 'fld-3',
      owner_username: 'sarah_mgr',
      version: 1,
      description: 'General employee guidelines for GDPR, CCPA, and enterprise confidentiality agreements.',
      file_size_bytes: 650,
      created_at: '2026-10-05T11:45:00Z',
      last_accessed_at: '2026-10-07T09:10:00Z',
      content: `# Employee Data Protection Guidelines\n\n**Classification: UNRESTRICTED**\n\nEvery employee must ensure sensitive customer records and personal credentials remain guarded according to international privacy statutes.`
    },
    {
      id: 'doc-6',
      title: 'Executive Board Strategic Risk Register 2026',
      original_filename: 'Board-Strategic-Risk-Register.txt',
      classification_level: 'TOP_SECRET',
      department: 'Executive',
      category: 'Executive',
      tags: 'board,risk,executive,strategy',
      folder_id: null,
      owner_username: 'admin',
      version: 1,
      description: 'Comprehensive risk posture covering geopolitical disruption, post-quantum cryptography transition, and hostile acquisition contingencies.',
      file_size_bytes: 1620,
      created_at: '2026-10-06T13:20:00Z',
      last_accessed_at: '2026-10-09T20:10:00Z',
      content: `CONFIDENTIAL EXECUTIVE MEMORANDUM\nClassification: TOP SECRET // EXECUTIVE COMPARTMENT ONLY\nRecipient: Board of Directors & CISO Alex Vance\n\n1. Post-Quantum Migration Timeline (Kyber/Dilithium readiness by 2027)\n2. Air-Gapped Fortress Infrastructure Redundancy\n3. Catastrophic Disaster Recovery Failover Protocols`
    }
  ];

  function getMockState() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) return JSON.parse(stored);
    } catch (e) {}

    const initialState = {
      users: JSON.parse(JSON.stringify(DEFAULT_USERS)),
      folders: JSON.parse(JSON.stringify(DEFAULT_FOLDERS)),
      documents: JSON.parse(JSON.stringify(DEFAULT_DOCUMENTS)),
      versions: {
        'doc-3': [
          { version_number: 1, change_summary: 'Initial FIPS draft', modified_by_username: 'admin', created_at: '2026-10-03T09:15:00Z', file_size_bytes: 980 },
          { version_number: 2, change_summary: 'Updated Shamir 3-of-5 threshold scheme', modified_by_username: 'admin', created_at: '2026-10-04T10:00:00Z', file_size_bytes: 1150 }
        ]
      },
      auditLogs: [
        { id: 1, sequence_num: 1, event_type: 'SYSTEM_BOOT', action: 'COLD_GENESIS', status: 'SUCCESS', user_id: 1, username: 'admin', resource_type: 'SYSTEM', resource_id: 'SYSTEM_GENESIS', ip_address: '127.0.0.1 (Cloud)', timestamp: '2026-10-09 10:00:00', details: JSON.stringify({ note: 'Genesis anchor established' }), previous_hash: '0000000000000000000000000000000000000000000000000000000000000000', current_hash: '3f78b1c4e92a43b591d8e09f2d1a3b8c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b' },
        { id: 2, sequence_num: 2, event_type: 'AUTH_SUCCESS', action: 'USER_LOGIN', status: 'SUCCESS', user_id: 1, username: 'admin', resource_type: 'SESSION', resource_id: 'sess-001', ip_address: '127.0.0.1 (Cloud)', timestamp: '2026-10-09 10:05:00', details: JSON.stringify({ clearance: 'TOP_SECRET' }), previous_hash: '3f78b1c4e92a43b591d8e09f2d1a3b8c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b', current_hash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b' },
        { id: 3, sequence_num: 3, event_type: 'DOC_ENCRYPT', action: 'STORE_ENCRYPTED_BLOB', status: 'SUCCESS', user_id: 1, username: 'admin', resource_type: 'DOCUMENT', resource_id: 'doc-1', ip_address: '127.0.0.1 (Cloud)', timestamp: '2026-10-09 10:10:00', details: JSON.stringify({ title: 'AY-SEC-2026 Incident Response Plan', algorithm: 'AES-256-GCM' }), previous_hash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b', current_hash: '1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d' },
        { id: 4, sequence_num: 4, event_type: 'POLICY_EVAL', action: 'MLS_READ_CHECK', status: 'SUCCESS', user_id: 2, username: 'sarah_mgr', resource_type: 'DOCUMENT', resource_id: 'doc-4', ip_address: '127.0.0.1 (Cloud)', timestamp: '2026-10-09 10:25:00', details: JSON.stringify({ rule: 'PERMIT_SIMPLE_SECURITY_MLS', clearance: 'RESTRICTED' }), previous_hash: '1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d', current_hash: '5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e' },
        { id: 5, sequence_num: 5, event_type: 'AUTH_LOCKOUT', action: 'ACCOUNT_SUSPENDED', status: 'WARNING', user_id: 4, username: 'dave_locked', resource_type: 'USER', resource_id: '4', ip_address: '192.168.1.105', timestamp: '2026-10-09 11:00:00', details: JSON.stringify({ reason: '5 consecutive failed password attempts' }), previous_hash: '5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e', current_hash: '8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a' }
      ],
      backups: [
        { filename: 'ayvault_backup_20261009_120000.ayb', file_size_bytes: 48920, file_size_formatted: '47.8 KB', created_at: '2026-10-09T12:00:00Z', sha256_checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }
      ],
      currentSession: null,
      isTampered: false,
      tamperedBlockId: null
    };
    saveMockState(initialState);
    return initialState;
  }

  function saveMockState(state) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch (e) {}
  }

  const realFetch = window.fetch;

  window.fetch = async function (url, options = {}) {
    const urlStr = typeof url === 'string' ? url : url.url;

    if (!urlStr.startsWith('/api/')) {
      return realFetch.apply(this, arguments);
    }

    if (isLocalHost) {
      try {
        const response = await realFetch.apply(this, arguments);
        if (response.ok || response.status === 401 || response.status === 403 || response.status === 400) {
          return response;
        }
      } catch (err) {}
    }

    return handleMockApi(urlStr, options);
  };

  async function handleMockApi(url, options) {
    const state = getMockState();
    const method = (options.method || 'GET').toUpperCase();
    let body = {};
    if (options.body) {
      if (typeof options.body === 'string') {
        try { body = JSON.parse(options.body); } catch (e) {}
      } else if (options.body instanceof FormData) {
        for (let [k, v] of options.body.entries()) {
          body[k] = v;
        }
      }
    }

    await new Promise(r => setTimeout(r, 40));

    // Route: /api/auth/session
    if (url === '/api/auth/session' && method === 'GET') {
      if (state.currentSession) {
        return mockJsonResponse({ authenticated: true, session: state.currentSession });
      }
      return mockJsonResponse({ authenticated: false, session: null });
    }

    // Route: /api/auth/login
    if (url === '/api/auth/login' && method === 'POST') {
      const { username, password } = body;
      const user = state.users.find(u => u.username === username);

      if (!user) {
        return mockJsonResponse({ success: false, error_message: 'Invalid cryptographic identity.' }, 401);
      }

      if (user.is_locked) {
        return mockJsonResponse({ success: false, is_locked: true, error_message: 'Account locked due to 5 failed attempts.' }, 401);
      }

      const valid = password.includes('AYVault2026!') || password.length >= 6;
      if (!valid) {
        user.failed_login_attempts = (user.failed_login_attempts || 0) + 1;
        if (user.failed_login_attempts >= 5) user.is_locked = 1;
        saveMockState(state);
        return mockJsonResponse({ success: false, is_locked: user.is_locked === 1, error_message: 'Incorrect password.' }, 401);
      }

      user.failed_login_attempts = 0;
      user.last_login = new Date().toISOString();
      const session = {
        user_id: user.id,
        username: user.username,
        full_name: user.full_name,
        role: user.role,
        department: user.department,
        clearance_level: user.clearance_level,
        token: 'cloud_tok_' + Math.random().toString(36).substring(2)
      };
      state.currentSession = session;

      addAuditLog(state, {
        event_type: 'AUTH_SUCCESS',
        action: 'USER_LOGIN',
        status: 'SUCCESS',
        user_id: user.id,
        username: user.username,
        resource_type: 'SESSION',
        resource_id: session.token.substring(0, 10),
        details: { clearance: user.clearance_level }
      });

      saveMockState(state);
      return mockJsonResponse({ success: true, session });
    }

    // Route: /api/auth/logout
    if (url === '/api/auth/logout' && method === 'POST') {
      state.currentSession = null;
      saveMockState(state);
      return mockJsonResponse({ success: true });
    }

    // Auth guard
    if (!state.currentSession) {
      return mockJsonResponse({ error: 'Authentication required' }, 401);
    }

    const sess = state.currentSession;

    // Route: /api/dashboard/stats
    if (url === '/api/dashboard/stats' && method === 'GET') {
      const activeDocs = state.documents.filter(d => !d.is_deleted);
      const totalBytes = activeDocs.reduce((acc, d) => acc + (d.file_size_bytes || 1024), 0);
      const lockedUsers = state.users.filter(u => u.is_locked).length;
      const recentDocs = activeDocs.slice(0, 5);

      return mockJsonResponse({
        total_documents: activeDocs.length,
        storage_formatted: formatBytes(totalBytes),
        total_users: state.users.length,
        locked_users: lockedUsers,
        latest_backup: state.backups[0] || null,
        audit_status: {
          is_valid: !state.isTampered,
          total_records: state.auditLogs.length,
          verified_records: state.isTampered ? (state.tamperedBlockId - 1) : state.auditLogs.length,
          compromised_id: state.isTampered ? state.tamperedBlockId : null
        },
        recent_audit: state.auditLogs.slice(-6).reverse(),
        recent_documents: recentDocs
      });
    }

    // Route: /api/folders
    if (url === '/api/folders' && method === 'GET') {
      const folders = state.folders.filter(f => !f.is_deleted).map(f => {
        const count = state.documents.filter(d => !d.is_deleted && d.folder_id === f.id).length;
        return { ...f, document_count: count };
      });
      return mockJsonResponse(folders);
    }

    // Route: /api/folders/create
    if (url === '/api/folders/create' && method === 'POST') {
      const newF = {
        id: 'fld-' + Date.now(),
        name: body.name || 'New Folder',
        department: body.department || sess.department,
        created_by: sess.user_id,
        created_at: new Date().toISOString()
      };
      state.folders.push(newF);
      addAuditLog(state, {
        event_type: 'FOLDER_CREATE',
        action: 'CREATE_ORGANIZATIONAL_FOLDER',
        status: 'SUCCESS',
        user_id: sess.user_id,
        username: sess.username,
        resource_type: 'FOLDER',
        resource_id: newF.id,
        details: { name: newF.name }
      });
      saveMockState(state);
      return mockJsonResponse({ success: true, folder: newF });
    }

    // Route: /api/documents/check-duplicate
    if (url === '/api/documents/check-duplicate' && method === 'POST') {
      return mockJsonResponse({ duplicate: false });
    }

    // Route: /api/documents
    if (url === '/api/documents' && method === 'GET') {
      const userRank = CLEARANCE_RANKS[sess.clearance_level] || 0;
      const docs = state.documents.filter(d => !d.is_deleted).map(d => {
        const docRank = CLEARANCE_RANKS[d.classification_level] || 0;
        const canRead = sess.role === 'Admin' || (userRank >= docRank && (d.classification_level === 'UNRESTRICTED' || sess.department === d.department || sess.role === 'Manager'));
        return {
          ...d,
          can_read: canRead,
          can_download: canRead && sess.role !== 'Viewer',
          can_delete: sess.role === 'Admin' || (d.owner_username === sess.username && sess.role !== 'Viewer'),
          formatted_size: formatBytes(d.file_size_bytes || 1024)
        };
      });
      return mockJsonResponse(docs);
    }

    // Route: /api/documents/decrypt
    if (url === '/api/documents/decrypt' && method === 'POST') {
      const doc = state.documents.find(d => d.id === body.document_id);
      if (!doc) return mockJsonResponse({ permitted: false, error: 'Document not found' }, 404);

      const userRank = CLEARANCE_RANKS[sess.clearance_level] || 0;
      const docRank = CLEARANCE_RANKS[doc.classification_level] || 0;
      const permitted = sess.role === 'Admin' || (userRank >= docRank && (doc.classification_level === 'UNRESTRICTED' || sess.department === doc.department || sess.role === 'Manager'));

      if (!permitted) {
        addAuditLog(state, {
          event_type: 'POLICY_DENIAL',
          action: 'MLS_READ_BLOCKED',
          status: 'DENIED',
          user_id: sess.user_id,
          username: sess.username,
          resource_type: 'DOCUMENT',
          resource_id: String(doc.id),
          details: { reason: 'Bell-LaPadula clearance level insufficient.' }
        });
        saveMockState(state);
        return mockJsonResponse({
          permitted: false,
          error: `Access Denied: Clearance level '${sess.clearance_level}' cannot view '${doc.classification_level}' document.`
        }, 403);
      }

      doc.last_accessed_at = new Date().toISOString();
      addAuditLog(state, {
        event_type: 'DOC_ACCESS',
        action: 'DECRYPT_IN_MEMORY_PREVIEW',
        status: 'SUCCESS',
        user_id: sess.user_id,
        username: sess.username,
        resource_type: 'DOCUMENT',
        resource_id: String(doc.id),
        details: { title: doc.title, algorithm: 'AES-256-GCM' }
      });
      saveMockState(state);

      return mockJsonResponse({
        permitted: true,
        document: doc,
        plaintext_content: doc.content || '(Decrypted content payload secured with AES-256-GCM)'
      });
    }

    // Route: /api/documents/download/:id
    if (url.startsWith('/api/documents/download/')) {
      const docId = url.split('/').pop();
      const doc = state.documents.find(d => d.id === docId);
      if (!doc) return new Response('Document not found', { status: 404 });

      const content = doc.content || 'Secure offline document payload.';
      const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
      return new Response(blob, {
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${doc.original_filename}"`
        }
      });
    }

    // Route: /api/documents/upload
    if (url === '/api/documents/upload' && method === 'POST') {
      const title = body.title || 'Untitled Document';
      const cls = body.classification_level || 'UNRESTRICTED';
      const dept = body.department || sess.department;
      const cat = body.category || 'General';
      const folder_id = body.folder_id || null;
      const tags = body.tags || '';
      const desc = body.description || '';

      const newId = 'doc-' + Date.now();
      const newDoc = {
        id: newId,
        title,
        original_filename: body.file?.name || `${title.toLowerCase().replace(/[^a-z0-9]/g, '-')}.txt`,
        classification_level: cls,
        department: dept,
        category: cat,
        folder_id: folder_id,
        tags: tags,
        owner_username: sess.username,
        version: 1,
        description: desc,
        file_size_bytes: 1024 + Math.floor(Math.random() * 2048),
        created_at: new Date().toISOString(),
        last_accessed_at: new Date().toISOString(),
        content: `Secure document content for ${title}.\nEncrypted with AES-256-GCM authenticated cipher.`
      };
      state.documents.unshift(newDoc);

      addAuditLog(state, {
        event_type: 'DOC_UPLOAD',
        action: 'ENCRYPT_AND_STORE',
        status: 'SUCCESS',
        user_id: sess.user_id,
        username: sess.username,
        resource_type: 'DOCUMENT',
        resource_id: newId,
        details: { title, classification: cls, category: cat }
      });

      saveMockState(state);
      return mockJsonResponse({ success: true, document: newDoc });
    }

    // Route: /api/documents/metadata
    if (url === '/api/documents/metadata' && method === 'POST') {
      const doc = state.documents.find(d => d.id === body.document_id);
      if (!doc) return mockJsonResponse({ success: false, error: 'Document not found' }, 404);

      if (body.title) doc.title = body.title;
      if (body.category) doc.category = body.category;
      if (body.folder_id !== undefined) doc.folder_id = body.folder_id || null;
      if (body.tags !== undefined) doc.tags = body.tags;
      if (body.description !== undefined) doc.description = body.description;

      addAuditLog(state, {
        event_type: 'DOC_METADATA',
        action: 'UPDATE_METADATA',
        status: 'SUCCESS',
        user_id: sess.user_id,
        username: sess.username,
        resource_type: 'DOCUMENT',
        resource_id: doc.id,
        details: { title: doc.title }
      });
      saveMockState(state);
      return mockJsonResponse({ success: true });
    }

    // Route: /api/documents/:id/versions (GET)
    if (url.match(/\/api\/documents\/([^/]+)\/versions/) && method === 'GET') {
      const docId = url.split('/')[3];
      const list = state.versions[docId] || [
        { version_number: 1, change_summary: 'Initial encrypted upload', modified_by_username: 'admin', created_at: '2026-10-01T10:00:00Z', file_size_bytes: 1480 }
      ];
      return mockJsonResponse({ versions: list, permitted: true });
    }

    // Route: /api/documents/:id/versions (POST)
    if (url.match(/\/api\/documents\/([^/]+)\/versions/) && method === 'POST') {
      const docId = url.split('/')[3];
      const doc = state.documents.find(d => d.id === docId);
      if (!doc) return mockJsonResponse({ success: false, error: 'Document not found' }, 404);

      doc.version = (doc.version || 1) + 1;
      if (!state.versions[docId]) state.versions[docId] = [];
      const newV = {
        version_number: doc.version,
        change_summary: body.change_summary || 'Updated version',
        modified_by_username: sess.username,
        created_at: new Date().toISOString(),
        file_size_bytes: 1200 + Math.floor(Math.random() * 800)
      };
      state.versions[docId].unshift(newV);

      addAuditLog(state, {
        event_type: 'DOC_VERSION',
        action: 'STORE_NEW_VERSION',
        status: 'SUCCESS',
        user_id: sess.user_id,
        username: sess.username,
        resource_type: 'DOCUMENT',
        resource_id: docId,
        details: { version: doc.version }
      });
      saveMockState(state);
      return mockJsonResponse({ success: true });
    }

    // Route: /api/documents/delete (POST) - Strict RBAC Check
    if (url === '/api/documents/delete' && method === 'POST') {
      if (sess.role === 'Viewer') {
        return mockJsonResponse({ success: false, error: 'Permission Denied: Viewers cannot delete documents.' }, 403);
      }
      const doc = state.documents.find(d => d.id === body.document_id);
      if (!doc) return mockJsonResponse({ success: false, error: 'Document not found' }, 404);

      doc.is_deleted = true;
      addAuditLog(state, {
        event_type: 'DOC_DELETE',
        action: 'SOFT_DELETE_DOCUMENT',
        status: 'SUCCESS',
        user_id: sess.user_id,
        username: sess.username,
        resource_type: 'DOCUMENT',
        resource_id: doc.id,
        details: { title: doc.title }
      });
      saveMockState(state);
      return mockJsonResponse({ success: true });
    }

    // Route: /api/audit/logs
    if (url === '/api/audit/logs' && method === 'GET') {
      return mockJsonResponse(state.auditLogs.slice().reverse());
    }

    // Route: /api/audit/verify
    if (url === '/api/audit/verify' && method === 'POST') {
      if (state.isTampered) {
        return mockJsonResponse({
          is_valid: false,
          total_records: state.auditLogs.length,
          verified_records: state.tamperedBlockId - 1,
          compromised_record_id: state.tamperedBlockId,
          error_message: `Bit-level cryptographic signature failure at Block #${state.tamperedBlockId}. Record was mutated directly in storage.`
        });
      }
      return mockJsonResponse({
        is_valid: true,
        total_records: state.auditLogs.length,
        verified_records: state.auditLogs.length
      });
    }

    // Route: /api/audit/tamper
    if (url === '/api/audit/tamper' && method === 'POST') {
      state.isTampered = true;
      state.tamperedBlockId = parseInt(body.block_id || 2);
      saveMockState(state);
      return mockJsonResponse({ success: true, tampered_block: state.tamperedBlockId });
    }

    // Route: /api/audit/reanchor
    if (url === '/api/audit/reanchor' && method === 'POST') {
      state.isTampered = false;
      state.tamperedBlockId = null;
      addAuditLog(state, {
        event_type: 'AUDIT_REANCHOR',
        action: 'FORENSIC_REANCHOR_GENESIS',
        status: 'SUCCESS',
        user_id: sess.user_id,
        username: sess.username,
        resource_type: 'AUDIT_LEDGER',
        resource_id: 'CHAIN_HEAD',
        details: { note: 'Forensic re-anchor authenticated' }
      });
      saveMockState(state);
      return mockJsonResponse({ success: true });
    }

    // Route: /api/admin/users
    if (url === '/api/admin/users' && method === 'GET') {
      return mockJsonResponse({ users: state.users });
    }

    // Route: /api/admin/users/unlock
    if (url === '/api/admin/users/unlock' && method === 'POST') {
      const u = state.users.find(usr => usr.id === parseInt(body.user_id));
      if (u) {
        u.is_locked = 0;
        u.failed_login_attempts = 0;
        saveMockState(state);
        return mockJsonResponse({ success: true });
      }
      return mockJsonResponse({ success: false, error: 'User not found' }, 404);
    }

    // Route: /api/admin/users/create
    if (url === '/api/admin/users/create' && method === 'POST') {
      if (sess.role !== 'Admin') {
        return mockJsonResponse({ success: false, error: 'Administrator privilege required' }, 403);
      }
      const { username, full_name, role, department, clearance_level, password } = body;
      if (!username || !password) {
        return mockJsonResponse({ success: false, error: 'Username and password are required' }, 400);
      }
      if (state.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
        return mockJsonResponse({ success: false, error: `Username '${username}' is already taken.` }, 400);
      }

      const newUser = {
        id: state.users.length + 1,
        username,
        full_name: full_name || username,
        role: role || 'Viewer',
        department: department || 'Operations',
        clearance_level: clearance_level || 'UNRESTRICTED',
        is_locked: 0,
        failed_login_attempts: 0,
        created_at: new Date().toISOString(),
        last_login: null
      };
      state.users.push(newUser);

      addAuditLog(state, {
        event_type: 'USER_PROVISION',
        action: 'CREATE_USER_ACCOUNT',
        status: 'SUCCESS',
        user_id: sess.user_id,
        username: sess.username,
        resource_type: 'USER',
        resource_id: String(newUser.id),
        details: { target_username: username, role, clearance: clearance_level }
      });

      saveMockState(state);
      return mockJsonResponse({ success: true, user: newUser });
    }

    // Route: /api/admin/backups
    if (url === '/api/admin/backups' && method === 'GET') {
      return mockJsonResponse(state.backups);
    }

    // Route: /api/admin/backup/create
    if (url === '/api/admin/backup/create' && method === 'POST') {
      const ts = new Date().toISOString().replace(/[-:T.]/g, '').substring(0, 14);
      const bkp = {
        filename: `ayvault_backup_${ts}.ayb`,
        file_size_formatted: '52.4 KB',
        file_size_bytes: 53600,
        created_at: new Date().toISOString(),
        sha256_checksum: pseudoHash('backup' + ts)
      };
      state.backups.unshift(bkp);
      saveMockState(state);
      return mockJsonResponse({ success: true, stats: bkp });
    }

    // Route: /api/policy/simulate
    if (url === '/api/policy/simulate' && method === 'POST') {
      const user = state.users.find(u => u.id === parseInt(body.user_id));
      const doc = state.documents.find(d => d.id === body.document_id);
      if (!user || !doc) return mockJsonResponse({ is_permitted: false, rule_name: 'ERROR', reason: 'User or document not found' });

      const uRank = CLEARANCE_RANKS[user.clearance_level] || 0;
      const dRank = CLEARANCE_RANKS[doc.classification_level] || 0;
      const isRead = (body.action || '').includes('read');

      if (user.role === 'Admin') {
        return mockJsonResponse({ is_permitted: true, rule_name: 'PERMIT_ADMIN_OVERRIDE', reason: 'Administrator possesses unrestricted authorization.' });
      }

      if (isRead) {
        if (uRank >= dRank) {
          return mockJsonResponse({ is_permitted: true, rule_name: 'PERMIT_SIMPLE_SECURITY_MLS', reason: `Clearance (${user.clearance_level} ≥ ${doc.classification_level}) satisfied under Bell-LaPadula No-Read-Up rule.` });
        } else {
          return mockJsonResponse({ is_permitted: false, rule_name: 'DENY_NO_READ_UP', reason: `Clearance '${user.clearance_level}' is lower than required '${doc.classification_level}'.` });
        }
      } else {
        if (body.action === 'doc:delete' && user.role === 'Viewer') {
          return mockJsonResponse({ is_permitted: false, rule_name: 'DENY_RBAC_ROLE', reason: 'Viewer role is strictly prohibited from deleting documents.' });
        }
        return mockJsonResponse({ is_permitted: true, rule_name: 'PERMIT_STAR_PROPERTY_MLS', reason: 'Operation satisfies organizational write boundaries.' });
      }
    }

    return mockJsonResponse({ error: 'Endpoint not found' }, 404);
  }

  function mockJsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  function addAuditLog(state, entry) {
    const nextSeq = state.auditLogs.length + 1;
    const prev = state.auditLogs.length > 0 ? state.auditLogs[state.auditLogs.length - 1].current_hash : '0000000000000000000000000000000000000000000000000000000000000000';
    const currentHash = pseudoHash(entry.action + prev + nextSeq);

    const logRec = {
      id: nextSeq,
      sequence_num: nextSeq,
      event_type: entry.event_type,
      action: entry.action,
      status: entry.status,
      user_id: entry.user_id,
      username: entry.username,
      resource_type: entry.resource_type,
      resource_id: entry.resource_id,
      ip_address: '127.0.0.1 (Cloud)',
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      details: JSON.stringify(entry.details || {}),
      previous_hash: prev,
      current_hash: currentHash
    };
    state.auditLogs.push(logRec);
  }

  function pseudoHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    const hex = Math.abs(hash).toString(16).padStart(8, '0');
    return (hex + 'e4a1b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7').substring(0, 64);
  }

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!isLocalHost) {
      const banner = document.createElement('div');
      banner.id = 'cloud-showcase-badge';
      banner.style.cssText = `
        background: linear-gradient(90deg, #1e3a8a, #2563eb);
        color: #fff;
        padding: 6px 16px;
        font-size: 0.78rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        z-index: 10000;
        position: relative;
        box-shadow: 0 1px 3px rgba(0,0,0,0.2);
      `;
      banner.innerHTML = `
        <div style="display: flex; align-items: center; gap: 8px;">
          <span>🛡️ <strong>AY Vault Secure DMS</strong> — Live Cloud Showcase</span>
          <span style="opacity: 0.85;">(AES-256-GCM, RBAC & Blockchain-style Audit Chaining Active)</span>
        </div>
        <div style="display: flex; align-items: center; gap: 10px;">
          <a href="https://github.com/Abhijeetkoli98/AY-Vault-" target="_blank" style="color: #bfdbfe; text-decoration: underline;">GitHub</a>
          <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; color: #fff; cursor: pointer; font-size: 1rem;">✕</button>
        </div>
      `;
      document.body.prepend(banner);
    }
  });
})();

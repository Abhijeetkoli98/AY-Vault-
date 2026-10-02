/**
 * AY Vault - Frontend Application Controller
 * Professional, clean enterprise security dashboard implementation.
 */

let currentSession = null;
let currentPreviewDoc = null;
let allDocuments = [];
let allAuditLogs = [];
let maskIdentifiers = true;

document.addEventListener('DOMContentLoaded', () => {
  checkSession();

  // Close dropdown menu when clicking anywhere outside
  document.addEventListener('click', (e) => {
    const dropdown = document.getElementById('user-dropdown-menu');
    if (dropdown && !e.target.closest('.user-menu-btn')) {
      dropdown.classList.remove('active');
    }
  });
});

// ===================================================================
// AUTHENTICATION & SESSION
// ===================================================================

async function checkSession() {
  try {
    const res = await fetch('/api/auth/session');
    const data = await res.json();
    if (data.authenticated && data.session) {
      setAuthenticatedState(data.session);
    } else {
      showLoginModal();
    }
  } catch (err) {
    showLoginModal();
  }
}

function fillCreds(u, p) {
  document.getElementById('login-username').value = u;
  document.getElementById('login-password').value = p;
  const alertEl = document.getElementById('login-alert');
  alertEl.style.display = 'none';
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const alertEl = document.getElementById('login-alert');

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (data.success && data.session) {
      alertEl.style.display = 'none';
      setAuthenticatedState(data.session);
    } else {
      alertEl.style.display = 'block';
      if (data.is_locked) {
        alertEl.style.background = 'var(--danger-bg)';
        alertEl.style.color = '#f87171';
        alertEl.style.border = '1px solid var(--danger-border)';
        alertEl.innerHTML = `<strong>Account Locked:</strong> ${data.error_message}`;
      } else {
        alertEl.style.background = 'var(--warning-bg)';
        alertEl.style.color = '#fbbf24';
        alertEl.style.border = '1px solid var(--warning-border)';
        alertEl.innerHTML = `<strong>Sign In Failed:</strong> ${data.error_message}`;
      }
    }
  } catch (err) {
    alertEl.style.display = 'block';
    alertEl.style.background = 'var(--danger-bg)';
    alertEl.style.color = '#f87171';
    alertEl.innerText = 'Unable to connect to local vault server.';
  }
}

function setAuthenticatedState(session) {
  currentSession = session;
  document.getElementById('login-overlay').classList.remove('active');

  // Friendly short name for greeting
  const firstName = session.full_name ? session.full_name.split(' ')[0] : session.username;

  // Sidebar User Info
  document.getElementById('user-display-name').innerText = firstName;
  document.getElementById('user-display-role').innerText = session.role;
  document.getElementById('sidebar-user-avatar').innerText = firstName.charAt(0).toUpperCase();

  // Top Dropdown Info
  document.getElementById('dropdown-user-name').innerText = session.full_name;
  document.getElementById('dropdown-user-role').innerText = `${session.role} • ${session.clearance_level}`;

  // Welcome Greeting
  const greetingEl = document.getElementById('dashboard-greeting');
  if (greetingEl) {
    greetingEl.innerText = `Welcome back, ${firstName}`;
  }

  // Initial view
  switchView('dashboard');
}

async function handleLogout() {
  if (confirm('Are you sure you want to sign out and lock your vault session?')) {
    await fetch('/api/auth/logout', { method: 'POST' });
    currentSession = null;
    showLoginModal();
  }
}

function showLoginModal() {
  document.getElementById('login-overlay').classList.add('active');
}

function toggleUserDropdown(e) {
  e.stopPropagation();
  const dropdown = document.getElementById('user-dropdown-menu');
  if (dropdown) dropdown.classList.toggle('active');
}

function toggleMobileSidebar() {
  const sidebar = document.getElementById('app-sidebar');
  if (sidebar) sidebar.classList.toggle('open');
}

// ===================================================================
// NAVIGATION & ROUTING
// ===================================================================

function switchView(viewName) {
  const views = ['dashboard', 'documents', 'upload', 'audit', 'security', 'settings'];
  views.forEach(v => {
    const el = document.getElementById(`view-${v}`);
    const nav = document.getElementById(`nav-${v}`);
    if (el) el.style.display = v === viewName ? 'block' : 'none';
    if (nav) {
      if (v === viewName) nav.classList.add('active');
      else nav.classList.remove('active');
    }
  });

  // Close mobile sidebar if open
  const sidebar = document.getElementById('app-sidebar');
  if (sidebar) sidebar.classList.remove('open');

  // Close user dropdown if open
  const dropdown = document.getElementById('user-dropdown-menu');
  if (dropdown) dropdown.classList.remove('active');

  const titles = {
    dashboard: 'Security Dashboard',
    documents: 'Documents',
    upload: 'Secure Upload',
    audit: 'Audit Logs',
    security: 'Security Policies',
    settings: 'Settings & Security Details'
  };
  document.getElementById('header-title').innerText = titles[viewName] || 'Security Dashboard';

  // Trigger data load
  if (viewName === 'dashboard') loadDashboardData();
  else if (viewName === 'documents') loadDocuments();
  else if (viewName === 'audit') loadAuditLedger();
  else if (viewName === 'security') loadPolicySimulatorData();
  else if (viewName === 'settings') loadSettingsData();
}

// ===================================================================
// DASHBOARD VIEW
// ===================================================================

async function loadDashboardData() {
  try {
    const res = await fetch('/api/dashboard/stats');
    const data = await res.json();

    // 1. Documents Count
    document.getElementById('stat-doc-count').innerText = data.total_documents;

    // 2. Storage Size
    document.getElementById('stat-storage-size').innerText = data.storage_formatted;

    // 3. Security Status Card
    const secStatusEl = document.getElementById('stat-security-status');
    const secDescEl = document.getElementById('stat-security-desc');
    const banner = document.getElementById('dashboard-security-banner');
    const bannerIcon = document.getElementById('banner-icon');
    const bannerText = document.getElementById('banner-text');
    const bannerAction = document.getElementById('banner-action');
    const sysDot = document.querySelector('.status-dot');
    const sysText = document.getElementById('system-status-text');

    if (data.locked_users > 0) {
      secStatusEl.innerText = 'Action Required';
      secStatusEl.className = 'summary-card-value status-warning';
      secDescEl.innerText = `${data.locked_users} account locked (failed logins)`;

      banner.className = 'status-alert-banner warning';
      bannerIcon.innerText = '⚠️';
      bannerText.innerText = `${data.locked_users} account temporarily locked due to failed login attempts.`;
      bannerAction.style.display = 'inline';

      sysDot.className = 'status-dot warning';
      sysText.innerText = 'Action Required';
    } else {
      secStatusEl.innerText = 'Healthy';
      secStatusEl.className = 'summary-card-value status-healthy';
      secDescEl.innerText = 'No active security issues';

      banner.className = 'status-alert-banner healthy';
      bannerIcon.innerText = '✓';
      bannerText.innerText = 'System secure — All cryptographic protections active';
      bannerAction.style.display = 'none';

      sysDot.className = 'status-dot';
      sysText.innerText = 'System Secure';
    }

    // 4. Audit Status Card
    const auditStatusEl = document.getElementById('stat-audit-status');
    const auditDescEl = document.getElementById('stat-audit-desc');
    if (data.audit_status && data.audit_status.is_valid) {
      auditStatusEl.innerText = 'Verified';
      auditStatusEl.className = 'summary-card-value status-healthy';
      auditDescEl.innerText = 'Audit logs are intact';
    } else {
      auditStatusEl.innerText = 'Alert';
      auditStatusEl.className = 'summary-card-value status-warning';
      auditDescEl.innerText = 'Audit chain violation detected';
    }

    // Render Recent 5 Activities (Human-Readable)
    renderRecentActivities(data.recent_audit ? data.recent_audit.slice(0, 5) : []);

  } catch (err) {
    console.error('Failed to load dashboard stats:', err);
  }
}

function handleBannerClick() {
  switchView('security');
}

async function handleSecurityCheck() {
  try {
    const res = await fetch('/api/audit/verify', { method: 'POST' });
    const data = await res.json();
    if (data.is_valid) {
      showSecurityCheckModal(true, `All ${data.verified_records} ledger blocks verified intact with SHA-256 hash chaining. All documents secured with AES-256-GCM authenticated encryption.`);
    } else {
      showSecurityCheckModal(false, `Audit chain integrity anomaly detected at Block #${data.compromised_record_id}: ${data.error_message}`);
    }
    loadDashboardData();
  } catch (err) {
    showSecurityCheckModal(false, 'Unable to complete security integrity scan: ' + err.message);
  }
}

function showSecurityCheckModal(isValid, message) {
  document.getElementById('sec-check-status-badge').className = isValid ? 'badge badge-success' : 'badge badge-danger';
  document.getElementById('sec-check-status-badge').innerText = isValid ? 'SYSTEM HEALTHY' : 'SECURITY ALERT';
  document.getElementById('sec-check-message').innerText = message;
  openModal('modal-security-check');
}

// ===================================================================
// HUMAN-READABLE ACTIVITY FORMATTING
// ===================================================================

function formatActivity(item) {
  const action = item.action || '';
  const event = item.event_type || '';
  const status = item.status || 'SUCCESS';

  let title = 'Activity logged';
  let icon = '📄';
  let badgeClass = 'badge-success';
  let badgeLabel = 'Success';

  if (action === 'USER_LOGIN_SUCCESS' || event === 'AUTH_LOGIN') {
    title = 'User signed in';
    icon = '👤';
  } else if (action === 'USER_LOGOUT' || event === 'AUTH_LOGOUT') {
    title = 'User signed out';
    icon = '🚪';
  } else if (action.includes('LOCKED') || event === 'AUTH_LOCKOUT') {
    title = 'Account temporarily locked';
    icon = '⚠️';
    badgeClass = 'badge-danger';
    badgeLabel = 'Warning';
  } else if (action.includes('BAD_CREDENTIALS') || event === 'AUTH_FAILED') {
    title = 'Login attempt failed';
    icon = '⚠️';
    badgeClass = 'badge-warning';
    badgeLabel = 'Warning';
  } else if (action === 'ENCRYPT_AND_STORE' || event === 'DOC_UPLOAD') {
    title = 'Document uploaded';
    icon = '📥';
  } else if (action === 'DECRYPT_IN_MEMORY_PREVIEW' || event === 'DOC_ACCESS') {
    title = 'Document accessed';
    icon = '👁️';
  } else if (action.includes('EXPORT') || event === 'DOC_DOWNLOAD') {
    title = 'Document exported';
    icon = '💾';
  } else if (action.includes('DELETE') || event === 'DOC_DELETE') {
    title = 'Document deleted';
    icon = '🗑️';
    badgeClass = 'badge-neutral';
    badgeLabel = 'Notice';
  } else if (action.includes('DENIED') || status === 'DENIED') {
    title = 'Access denied by policy';
    icon = '⛔';
    badgeClass = 'badge-warning';
    badgeLabel = 'Warning';
  } else if (action.includes('UNLOCK') || event === 'USER_UNLOCK') {
    title = 'User account unlocked';
    icon = '🔓';
  } else if (action.includes('SNAPSHOT') || event === 'BACKUP_CREATE') {
    title = 'System backup created';
    icon = '📦';
  } else if (event === 'SYSTEM_INIT') {
    title = 'System initialized';
    icon = '🛡️';
  }

  if (status === 'FAILURE') {
    badgeClass = 'badge-danger';
    badgeLabel = 'Failed';
  }

  return { title, icon, badgeClass, badgeLabel };
}

function formatRelativeTime(isoString) {
  if (!isoString) return '';
  const date = new Date(isoString);
  const now = new Date();
  const diffMs = now - date;
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);

  if (diffSec < 45) return 'Just now';
  if (diffMin < 60) return `${diffMin} min ago`;
  if (diffHour < 24) return `${diffHour} hr${diffHour > 1 ? 's' : ''} ago`;
  if (diffDay === 1) return 'Yesterday';
  return `${diffDay} days ago`;
}

function renderRecentActivities(items) {
  const container = document.getElementById('activity-list-container');
  if (!container) return;
  container.innerHTML = '';

  if (items.length === 0) {
    container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 20px;">No recent activities logged.</div>`;
    return;
  }

  items.forEach(item => {
    const formatted = formatActivity(item);
    const timeStr = formatRelativeTime(item.timestamp);

    const div = document.createElement('div');
    div.className = 'activity-item';
    div.innerHTML = `
      <div class="activity-left">
        <div class="activity-icon">${formatted.icon}</div>
        <div class="activity-details">
          <div class="activity-name">${formatted.title}</div>
          <div class="activity-meta">by ${item.username || 'System'}</div>
        </div>
      </div>
      <div class="activity-right">
        <span class="activity-time">${timeStr}</span>
        <span class="badge ${formatted.badgeClass}">${formatted.badgeLabel}</span>
      </div>
    `;
    container.appendChild(div);
  });
}

// ===================================================================
// DOCUMENTS VIEW
// ===================================================================

async function loadDocuments() {
  try {
    const res = await fetch('/api/documents');
    allDocuments = await res.json();
    renderDocuments(allDocuments);
  } catch (err) {
    console.error('Failed to load documents:', err);
  }
}

function filterDocuments() {
  const query = document.getElementById('doc-search').value.toLowerCase();
  const cls = document.getElementById('doc-filter-class').value;
  const dept = document.getElementById('doc-filter-dept').value;

  const filtered = allDocuments.filter(d => {
    const matchQuery = !query || d.title.toLowerCase().includes(query) || d.original_filename.toLowerCase().includes(query);
    const matchClass = cls === 'ALL' || d.classification_level === cls;
    const matchDept = dept === 'ALL' || d.department === dept;
    return matchQuery && matchClass && matchDept;
  });
  renderDocuments(filtered);
}

function renderDocuments(docs) {
  const tbody = document.getElementById('documents-table-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (docs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 24px; color: var(--text-muted);">No documents found.</td></tr>`;
    return;
  }

  docs.forEach(d => {
    const tr = document.createElement('tr');
    const accessBadge = d.can_read 
      ? `<span class="badge badge-success">Allowed</span>`
      : `<span class="badge badge-warning">Restricted</span>`;

    tr.innerHTML = `
      <td>
        <div style="font-weight: 500;">${d.title}</div>
        <div style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">${d.original_filename}</div>
      </td>
      <td><span class="badge badge-${d.classification_level}">${d.classification_level}</span></td>
      <td>${d.department}</td>
      <td>${d.owner_username}</td>
      <td>${formatBytes(d.file_size_bytes)}</td>
      <td>v${d.version}</td>
      <td>${accessBadge}</td>
      <td>
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-secondary btn-sm" onclick="inspectDocument('${d.id}')">View</button>
          <button class="btn btn-secondary btn-sm" onclick="downloadDocument('${d.id}')">Export</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function inspectDocument(id) {
  try {
    const res = await fetch('/api/documents/decrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ document_id: id })
    });
    const data = await res.json();

    if (data.permitted && data.document) {
      currentPreviewDoc = data.document;
      document.getElementById('preview-title').innerText = data.document.title;
      document.getElementById('preview-filename').innerText = data.document.original_filename;
      
      const badge = document.getElementById('preview-badge');
      badge.className = `badge badge-${data.document.classification_level}`;
      badge.innerText = data.document.classification_level;

      document.getElementById('preview-content').innerText = data.plaintext_content;
      openModal('modal-doc-preview');
    } else {
      showPolicyInspector(data.decision);
    }
  } catch (err) {
    alert('Error accessing document: ' + err.message);
  }
}

function downloadDocument(id) {
  window.location.href = `/api/documents/download/${id}`;
}

function downloadCurrentPreview() {
  if (currentPreviewDoc) {
    window.location.href = `/api/documents/download/${currentPreviewDoc.id}`;
  }
}

// ===================================================================
// SECURE UPLOAD
// ===================================================================

function handleFileSelected(e) {
  // If title is empty, prefill from filename
  const file = e.target.files[0];
  const titleInput = document.getElementById('upload-title');
  if (file && titleInput && !titleInput.value.trim()) {
    const cleanName = file.name.replace(/\.[^/.]+$/, '').replace(/[-_]/g, ' ');
    titleInput.value = cleanName.charAt(0).toUpperCase() + cleanName.slice(1);
  }
}

async function handleUpload(e) {
  e.preventDefault();
  const title = document.getElementById('upload-title').value.trim();
  const fileInput = document.getElementById('upload-file');
  const cls = document.getElementById('upload-class').value;
  const dept = document.getElementById('upload-dept').value;
  const desc = document.getElementById('upload-desc').value;

  const formData = new FormData();
  formData.append('title', title);
  formData.append('classification_level', cls);
  formData.append('department', dept);
  formData.append('description', desc);

  if (fileInput.files.length > 0) {
    formData.append('file', fileInput.files[0]);
  } else {
    // Treat description as text payload
    const textData = desc || `Document: ${title}\nClassification: ${cls}\nDepartment: ${dept}`;
    const blob = new Blob([textData], { type: 'text/plain' });
    formData.append('file', blob, `${title.replace(/\s+/g, '_')}.txt`);
  }

  try {
    const res = await fetch('/api/documents/upload', {
      method: 'POST',
      body: formData
    });
    const data = await res.json();

    if (data.success && data.document) {
      alert(`✓ Document successfully encrypted and stored.\n\nTitle: ${data.document.title}\nClassification: ${data.document.classification_level}`);
      switchView('documents');
    } else {
      showPolicyInspector(data.decision);
    }
  } catch (err) {
    alert('Upload failed: ' + err.message);
  }
}

// ===================================================================
// AUDIT LOGS & FORENSICS (WITH MASKING)
// ===================================================================

async function loadAuditLedger() {
  try {
    const res = await fetch('/api/audit/logs');
    allAuditLogs = await res.json();
    renderAuditLogs();
  } catch (err) {
    console.error('Failed to load audit logs:', err);
  }
}

function toggleIdentifierMasking() {
  maskIdentifiers = !maskIdentifiers;
  const btn = document.getElementById('btn-toggle-masking');
  if (btn) {
    btn.innerText = maskIdentifiers ? '👁️ Show Raw Identifiers' : '🔒 Mask Identifiers';
  }
  renderAuditLogs();
}

function maskString(str, visibleChars = 4) {
  if (!str) return '—';
  if (!maskIdentifiers) return str;
  if (str.length <= visibleChars * 2) return str;
  return `${str.slice(0, visibleChars)}••••••${str.slice(-visibleChars)}`;
}

function renderAuditLogs() {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  allAuditLogs.forEach(row => {
    const formatted = formatActivity(row);
    const tr = document.createElement('tr');

    // Mask resource identifiers
    let displayResource = row.resource_type || 'System';
    if (row.resource_id) {
      displayResource += ` (${maskString(row.resource_id, 4)})`;
    }

    // Mask current hash
    const displayHash = maskString(row.current_hash, 4);

    tr.innerHTML = `
      <td class="font-mono">#${row.id}</td>
      <td style="font-size: 0.8rem; color: var(--text-muted);">${row.timestamp ? row.timestamp.slice(0, 19).replace('T', ' ') : ''}</td>
      <td><strong>${formatted.title}</strong></td>
      <td>${row.username || 'System'}</td>
      <td style="font-size: 0.82rem;">${displayResource}</td>
      <td><span class="badge ${formatted.badgeClass}">${formatted.badgeLabel}</span></td>
      <td class="font-mono" style="font-size: 0.78rem; color: var(--text-muted);">${displayHash}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function handleVerifyAudit() {
  try {
    const res = await fetch('/api/audit/verify', { method: 'POST' });
    const data = await res.json();

    if (data.is_valid) {
      alert(`✓ Audit Verification Passed!\n\nAll ${data.verified_records} log entries are intact with zero tampering detected.`);
    } else {
      alert(`⚠️ Audit Tampering Detected!\n\nViolation at Block #${data.compromised_record_id}:\n${data.error_message}`);
    }
    loadAuditLedger();
    loadDashboardData();
  } catch (err) {
    alert('Verification error: ' + err.message);
  }
}

async function handleSimulateTamperPrompt() {
  const blockId = prompt('Enter the Audit Block # to simulate tampering (e.g. 2):', '2');
  if (!blockId) return;

  try {
    const res = await fetch('/api/audit/tamper', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ block_id: parseInt(blockId) })
    });
    const data = await res.json();
    if (data.success) {
      alert(`⚠️ Simulated tampering applied to Block #${blockId}.\n\nClick "Verify Audit Integrity" to test forensic detection.`);
      loadAuditLedger();
      loadDashboardData();
    } else {
      alert('Error: ' + data.error);
    }
  } catch (err) {
    alert('Tamper simulation error: ' + err.message);
  }
}

async function handleReanchorAudit() {
  if (confirm('Re-anchor audit ledger? This sequentially recalculates hashes and appends an administrative re-anchor record.')) {
    const res = await fetch('/api/audit/reanchor', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      alert('✓ Audit ledger successfully re-anchored.');
      loadAuditLedger();
      loadDashboardData();
    }
  }
}

function handleExportAudit() {
  window.location.href = '/api/audit/export/csv';
}

// ===================================================================
// SECURITY POLICIES & LOCKOUTS
// ===================================================================

async function loadPolicySimulatorData() {
  try {
    // Populate Subject Users
    const resUsers = await fetch('/api/admin/users');
    const dataUsers = await resUsers.json();
    const uSelect = document.getElementById('sim-user');
    if (uSelect) {
      uSelect.innerHTML = '';
      dataUsers.users.forEach(u => {
        const opt = document.createElement('option');
        opt.value = u.id;
        opt.innerText = `${u.username} (${u.role} • ${u.clearance_level})`;
        uSelect.appendChild(opt);
      });
    }

    // Populate Target Documents
    const resDocs = await fetch('/api/documents');
    const docs = await resDocs.json();
    const dSelect = document.getElementById('sim-doc');
    if (dSelect) {
      dSelect.innerHTML = '';
      docs.forEach(d => {
        const opt = document.createElement('option');
        opt.value = d.id;
        opt.innerText = `${d.title} [${d.classification_level}]`;
        dSelect.appendChild(opt);
      });
    }

    // Load Lockouts Table
    loadLockoutsTable(dataUsers.users);
  } catch (err) {
    console.error('Failed to load policy simulator:', err);
  }
}

function loadLockoutsTable(users) {
  const tbody = document.getElementById('lockout-table-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  users.forEach(u => {
    const tr = document.createElement('tr');
    const isLocked = u.is_locked;
    const badge = isLocked 
      ? `<span class="badge badge-danger">Locked</span>` 
      : (u.failed_login_attempts > 0 ? `<span class="badge badge-warning">${u.failed_login_attempts} failed</span>` : `<span class="badge badge-success">Normal</span>`);

    tr.innerHTML = `
      <td><strong>${u.username}</strong></td>
      <td>${u.failed_login_attempts} / 5</td>
      <td>${badge}</td>
      <td>
        ${isLocked || u.failed_login_attempts > 0 ? `<button class="btn btn-secondary btn-sm" onclick="unlockUser(${u.id}, '${u.username}')">Unlock</button>` : `<span style="color:var(--text-muted); font-size:0.75rem;">—</span>`}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function handleSimulatePolicy(e) {
  e.preventDefault();
  const userId = document.getElementById('sim-user').value;
  const docId = document.getElementById('sim-doc').value;
  const action = document.getElementById('sim-action').value;

  try {
    const res = await fetch('/api/policy/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: parseInt(userId), document_id: docId, action })
    });
    const decision = await res.json();

    const box = document.getElementById('sim-decision-box');
    const badge = document.getElementById('sim-decision-badge');
    const rule = document.getElementById('sim-decision-rule');
    const reason = document.getElementById('sim-decision-reason');

    box.style.display = 'block';
    const isAllowed = decision.permitted === true || decision.is_permitted === true;
    if (isAllowed) {
      badge.className = 'badge badge-success';
      badge.innerText = 'PERMITTED';
    } else {
      badge.className = 'badge badge-danger';
      badge.innerText = 'DENIED BY POLICY';
    }

    rule.innerText = `Evaluated Rule: ${decision.rule_name || 'POL_SECURITY_RULE'}`;
    reason.innerText = decision.reason || (isAllowed ? 'Access granted under current policy.' : 'Access denied.');
  } catch (err) {
    alert('Simulation error: ' + err.message);
  }
}

async function unlockUser(id, username) {
  try {
    const res = await fetch('/api/admin/users/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: id })
    });
    const data = await res.json();
    if (data.success) {
      alert(`Account '${username}' has been unlocked.`);
      loadPolicySimulatorData();
      loadDashboardData();
    } else {
      if (data.decision) {
        showPolicyInspector(data.decision);
      } else {
        alert('Permission Denied: ' + (data.error || 'Administrator privilege required to unlock accounts.'));
      }
    }
  } catch (err) {
    alert('Unlock error: ' + err.message);
  }
}

// ===================================================================
// SETTINGS & SYSTEM DETAILS
// ===================================================================

function loadSettingsData() {
  // Settings view is static architecture information & actions
}

function openCreateUserModal() {
  const username = prompt('Enter Username:');
  if (!username) return;
  const fullName = prompt('Enter Full Name:');
  if (!fullName) return;
  const role = prompt('Role (Admin, Manager, Viewer):', 'Viewer');
  const dept = prompt('Department (Security, Engineering, Finance, Operations):', 'Operations');
  const clearance = prompt('Clearance (UNRESTRICTED, CONFIDENTIAL, RESTRICTED, TOP_SECRET):', 'UNRESTRICTED');
  const pwd = prompt('Initial Password (min 8 chars):', 'UserPass@2026!');

  fetch('/api/admin/users/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username, full_name: fullName, role, department: dept, clearance_level: clearance, password: pwd
    })
  })
  .then(res => res.json())
  .then(data => {
    if (data.success) {
      alert('✓ User created successfully!');
    } else {
      if (data.decision) {
        showPolicyInspector(data.decision);
      } else {
        alert('Permission Denied: ' + (data.error || 'Administrator privilege required.'));
      }
    }
  });
}

async function handleCreateBackupPrompt() {
  const pass = prompt('Enter Passphrase to Encrypt Backup Archive (.ayb):', 'AYVaultMasterBackup2026!');
  if (!pass) return;

  try {
    const res = await fetch('/api/admin/backup/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase: pass })
    });
    const data = await res.json();
    if (data.success) {
      alert(`✓ Encrypted Backup Generated!\n\nFilename: ${data.stats.file_name}\nSize: ${formatBytes(data.stats.size)}`);
    } else {
      if (data.decision) {
        showPolicyInspector(data.decision);
      } else {
        alert('Backup Failed: ' + (data.error || 'Authorization denied.'));
      }
    }
  } catch (err) {
    alert('Backup failed: ' + err.message);
  }
}

// ===================================================================
// MODALS
// ===================================================================

function showPolicyInspector(decision) {
  if (!decision) return;
  document.getElementById('inspector-rule').innerText = decision.rule_name || 'POL_SECURITY_GATE';
  document.getElementById('inspector-reason').innerText = decision.reason || 'Operation not permitted.';

  const banner = document.getElementById('inspector-banner');
  const title = document.getElementById('inspector-status-title');

  const isAllowed = decision.permitted === true || decision.is_permitted === true;
  if (isAllowed) {
    banner.className = 'status-alert-banner healthy';
    title.innerText = 'Access Permitted';
  } else {
    banner.className = 'status-alert-banner warning';
    title.innerText = 'Access Denied by Policy';
  }

  openModal('modal-policy-inspector');
}

function openModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add('active');
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('active');
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

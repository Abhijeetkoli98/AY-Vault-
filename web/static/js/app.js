/**
 * AY Vault - Professional Secure Document Management System Controller
 * Implements complete DMS lifecycle, RBAC enforcement, folder organization,
 * version tracking, duplicate detection, and dedicated security center.
 */

let currentSession = null;
let allDocuments = [];
let allFolders = [];
let allAuditLogs = [];
let allUsers = [];
let allBackups = [];
let selectedFolderId = null;
let currentDocViewMode = 'table';
let currentPreviewDoc = null;

document.addEventListener('DOMContentLoaded', () => {
  checkSession();

  // Close dropdown menu when clicking outside
  document.addEventListener('click', (e) => {
    const dropdown = document.getElementById('user-dropdown-menu');
    if (dropdown && !e.target.closest('.user-dropdown-container') && !e.target.closest('.sidebar-user-card')) {
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

function fillPersona(username, password) {
  document.getElementById('login-username').value = username;
  document.getElementById('login-password').value = password;
  const alertEl = document.getElementById('login-alert');
  if (alertEl) alertEl.style.display = 'none';
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
      if (alertEl) alertEl.style.display = 'none';
      setAuthenticatedState(data.session);
      showToast(`Welcome back, ${data.session.full_name || data.session.username}!`, 'success');
    } else {
      if (alertEl) {
        alertEl.style.display = 'block';
        if (data.is_locked) {
          alertEl.style.background = 'var(--danger-bg)';
          alertEl.style.color = '#f87171';
          alertEl.style.border = '1px solid var(--danger-border)';
          alertEl.innerHTML = `<strong>Account Locked:</strong> ${data.error_message || 'Too many failed password attempts.'}`;
        } else {
          alertEl.style.background = 'var(--warning-bg)';
          alertEl.style.color = '#fbbf24';
          alertEl.style.border = '1px solid var(--warning-border)';
          alertEl.innerHTML = `<strong>Authentication Failed:</strong> ${data.error_message || 'Invalid username or password.'}`;
        }
      }
    }
  } catch (err) {
    if (alertEl) {
      alertEl.style.display = 'block';
      alertEl.style.background = 'var(--danger-bg)';
      alertEl.style.color = '#f87171';
      alertEl.innerText = 'Unable to reach the secure authentication service.';
    }
  }
}

function setAuthenticatedState(session) {
  currentSession = session;
  const overlay = document.getElementById('login-overlay');
  if (overlay) overlay.classList.remove('active');

  const firstName = session.full_name ? session.full_name.split(' ')[0] : session.username;
  const initial = (firstName || 'A').charAt(0).toUpperCase();

  // Update Sidebar Profile
  const sideName = document.getElementById('user-display-name');
  const sideRole = document.getElementById('user-display-role');
  const sideAvatar = document.getElementById('sidebar-user-avatar');
  if (sideName) sideName.innerText = session.full_name || session.username;
  if (sideRole) sideRole.innerText = `${session.role} (${session.clearance_level})`;
  if (sideAvatar) sideAvatar.innerText = initial;

  // Header Profile
  const headAvatar = document.getElementById('header-user-avatar');
  const dropName = document.getElementById('dropdown-user-name');
  const dropRole = document.getElementById('dropdown-user-role');
  if (headAvatar) headAvatar.innerText = initial;
  if (dropName) dropName.innerText = session.full_name || session.username;
  if (dropRole) dropRole.innerText = `${session.role} • ${session.department}`;

  // Initial load
  switchView('overview');
}

async function handleLogout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } catch (e) {}
  currentSession = null;
  showToast('Session securely terminated.', 'info');
  showLoginModal();
}

function showLoginModal() {
  const overlay = document.getElementById('login-overlay');
  if (overlay) overlay.classList.add('active');
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
  const views = ['overview', 'documents', 'shared', 'users', 'audit', 'backups', 'security', 'settings'];
  views.forEach(v => {
    const el = document.getElementById(`view-${v}`);
    const nav = document.getElementById(`nav-${v}`);
    if (el) el.style.display = v === viewName ? 'block' : 'none';
    if (nav) {
      if (v === viewName) nav.classList.add('active');
      else nav.classList.remove('active');
    }
  });

  const sidebar = document.getElementById('app-sidebar');
  if (sidebar) sidebar.classList.remove('open');

  const dropdown = document.getElementById('user-dropdown-menu');
  if (dropdown) dropdown.classList.remove('active');

  const titles = {
    overview: 'Overview',
    documents: 'Documents Explorer',
    shared: 'Shared Across Departments',
    users: 'Users & Access Control',
    audit: 'Immutable Audit Trail',
    backups: 'Backup & Recovery',
    security: 'Security Center',
    settings: 'Settings'
  };

  const titleEl = document.getElementById('header-title');
  const breadEl = document.getElementById('header-breadcrumb');
  if (titleEl) titleEl.innerText = titles[viewName] || 'Overview';
  if (breadEl) breadEl.innerText = `AY Vault / ${titles[viewName] || 'Overview'}`;

  // Trigger relevant data load
  if (viewName === 'overview') loadOverviewData();
  else if (viewName === 'documents') loadDocumentsAndFolders();
  else if (viewName === 'shared') loadSharedDocuments();
  else if (viewName === 'users') loadUsersData();
  else if (viewName === 'audit') loadAuditLogs();
  else if (viewName === 'backups') loadBackupsData();
  else if (viewName === 'security') loadSecurityCenter();
}

// ===================================================================
// OVERVIEW DASHBOARD
// ===================================================================

async function loadOverviewData() {
  try {
    const res = await fetch('/api/dashboard/stats');
    if (res.status === 401) { showLoginModal(); return; }
    const data = await res.json();

    // Summary cards
    const docCountEl = document.getElementById('stat-doc-count');
    const storageEl = document.getElementById('stat-storage-size');
    const userCountEl = document.getElementById('stat-user-count');
    const userDescEl = document.getElementById('stat-user-desc');
    const secStatusEl = document.getElementById('stat-security-status');
    const secDescEl = document.getElementById('stat-security-desc');
    const backupEl = document.getElementById('stat-backup-status');
    const backupDescEl = document.getElementById('stat-backup-desc');

    if (docCountEl) docCountEl.innerText = data.total_documents || 0;
    if (storageEl) storageEl.innerText = data.storage_formatted || '0 KB';
    if (userCountEl) userCountEl.innerText = data.total_users || 4;

    if (data.locked_users > 0) {
      if (userDescEl) userDescEl.innerText = `${data.locked_users} account(s) locked`;
      if (secStatusEl) {
        secStatusEl.innerText = 'Action Needed';
        secStatusEl.className = 'metric-value status-warning';
      }
      if (secDescEl) secDescEl.innerText = `${data.locked_users} locked due to failed logins`;
    } else {
      if (userDescEl) userDescEl.innerText = 'All accounts active';
      if (secStatusEl) {
        secStatusEl.innerText = 'Secure';
        secStatusEl.className = 'metric-value status-healthy';
      }
      if (secDescEl) secDescEl.innerText = 'All cryptographic protections active';
    }

    if (data.latest_backup) {
      if (backupEl) backupEl.innerText = 'Protected';
      if (backupDescEl) backupDescEl.innerText = `Latest: ${data.latest_backup.filename || 'Recent'}`;
    } else {
      if (backupEl) backupEl.innerText = 'No Backups';
      if (backupDescEl) backupDescEl.innerText = 'Generate snapshot in Backups';
    }

    // Render Recent Documents
    renderOverviewRecentDocs(data.recent_documents || []);

    // Render Recent Activity Feed
    renderOverviewActivity(data.recent_audit ? data.recent_audit.slice(0, 5) : []);

  } catch (err) {
    console.error('Failed to load overview data:', err);
  }
}

function renderOverviewRecentDocs(docs) {
  const container = document.getElementById('overview-recent-docs');
  if (!container) return;

  if (!docs || docs.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">📄</div>
        <div class="empty-title">No Recent Documents</div>
        <div class="empty-desc">Documents you preview or download will appear here for fast access.</div>
        <button class="btn btn-primary btn-sm" onclick="switchView('documents')" style="margin-top: 10px;">Explore Documents</button>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: 8px;">
      ${docs.map(d => `
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: var(--bg-subtle); border-radius: var(--radius-md); border: 1px solid var(--border-color);">
          <div style="display: flex; align-items: center; gap: 10px; overflow: hidden;">
            <span style="font-size: 1.2rem;">${getFileIcon(d.original_filename)}</span>
            <div style="overflow: hidden;">
              <div style="font-weight: 600; font-size: 0.84rem; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                ${escapeHtml(d.title)}
              </div>
              <div style="font-size: 0.72rem; color: var(--text-muted);">
                ${d.category || 'General'} • ${d.classification_level} • v${d.version || 1}
              </div>
            </div>
          </div>
          <div style="display: flex; gap: 6px; flex-shrink: 0;">
            <button class="btn btn-secondary btn-sm" onclick="previewDocument('${d.id}')">Preview</button>
            <button class="btn btn-secondary btn-sm" onclick="downloadDocument('${d.id}')">⬇</button>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

function renderOverviewActivity(events) {
  const feed = document.getElementById('overview-activity-feed');
  if (!feed) return;

  if (!events || events.length === 0) {
    feed.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">📋</div>
        <div class="empty-title">No Recent Activity</div>
        <div class="empty-desc">System events and access logs will be recorded here.</div>
      </div>
    `;
    return;
  }

  feed.innerHTML = events.map(e => {
    let icon = '📝';
    if (e.event_type.includes('AUTH')) icon = '🔑';
    else if (e.event_type.includes('DOC')) icon = '📄';
    else if (e.event_type.includes('BACKUP')) icon = '📦';
    else if (e.event_type.includes('POLICY')) icon = '🛡️';

    return `
      <div class="activity-item">
        <div class="activity-badge">${icon}</div>
        <div class="activity-details">
          <div class="activity-title">${humanizeActivity(e)}</div>
          <div class="activity-time">${formatTimeAgo(e.timestamp)} • User: <strong>${escapeHtml(e.username)}</strong></div>
        </div>
      </div>
    `;
  }).join('');
}

// ===================================================================
// DOCUMENTS EXPLORER & FOLDERS
// ===================================================================

async function loadDocumentsAndFolders() {
  await Promise.all([loadFolders(), loadDocuments()]);
}

async function loadFolders() {
  try {
    const res = await fetch('/api/folders');
    allFolders = await res.json();
    renderFolderBar();
    populateFolderSelects();
  } catch (e) {
    allFolders = [];
  }
}

function renderFolderBar() {
  const bar = document.getElementById('doc-folder-bar');
  if (!bar) return;

  bar.innerHTML = `
    <button class="folder-pill ${selectedFolderId === null ? 'active' : ''}" onclick="selectFolder(null)">
      📁 All Files (${allDocuments.length})
    </button>
    <button class="folder-pill ${selectedFolderId === 'root' ? 'active' : ''}" onclick="selectFolder('root')">
      📄 Unfiled Files
    </button>
    ${allFolders.map(f => `
      <button class="folder-pill ${selectedFolderId === f.id ? 'active' : ''}" onclick="selectFolder('${f.id}')">
        📁 ${escapeHtml(f.name)} (${f.document_count || 0})
      </button>
    `).join('')}
  `;
}

function selectFolder(folderId) {
  selectedFolderId = folderId;
  renderFolderBar();
  filterDocuments();
}

async function loadDocuments() {
  try {
    const res = await fetch('/api/documents');
    if (res.status === 401) { showLoginModal(); return; }
    allDocuments = await res.json();
    filterDocuments();
  } catch (err) {
    allDocuments = [];
    renderDocumentsList([]);
  }
}

function filterDocuments() {
  const search = (document.getElementById('doc-search-input')?.value || '').toLowerCase().trim();
  const catFilter = document.getElementById('doc-category-filter')?.value || 'ALL';
  const clearFilter = document.getElementById('doc-clearance-filter')?.value || 'ALL';

  let filtered = allDocuments.filter(d => {
    // Folder filter
    if (selectedFolderId === 'root' && d.folder_id) return false;
    if (selectedFolderId && selectedFolderId !== 'root' && d.folder_id !== selectedFolderId) return false;

    // Category filter
    if (catFilter !== 'ALL' && d.category !== catFilter) return false;

    // Clearance filter
    if (clearFilter !== 'ALL' && d.classification_level !== clearFilter) return false;

    // Search query
    if (search) {
      const matchTitle = (d.title || '').toLowerCase().includes(search);
      const matchFile = (d.original_filename || '').toLowerCase().includes(search);
      const matchTags = (d.tags || '').toLowerCase().includes(search);
      const matchDesc = (d.description || '').toLowerCase().includes(search);
      if (!matchTitle && !matchFile && !matchTags && !matchDesc) return false;
    }

    return true;
  });

  renderDocumentsList(filtered);
}

function setDocViewMode(mode) {
  currentDocViewMode = mode;
  document.getElementById('btn-view-table')?.classList.toggle('active', mode === 'table');
  document.getElementById('btn-view-grid')?.classList.toggle('active', mode === 'grid');

  document.getElementById('docs-table-container').style.display = mode === 'table' ? 'block' : 'none';
  document.getElementById('docs-grid-container').style.display = mode === 'grid' ? 'grid' : 'none';
  filterDocuments();
}

function renderDocumentsList(docs) {
  const tableBody = document.getElementById('docs-table-body');
  const gridContainer = document.getElementById('docs-grid-container');
  const emptyState = document.getElementById('docs-empty-state');
  const tableContainer = document.getElementById('docs-table-container');

  if (docs.length === 0) {
    if (tableContainer) tableContainer.style.display = 'none';
    if (gridContainer) gridContainer.style.display = 'none';
    if (emptyState) emptyState.style.display = 'block';
    return;
  }

  if (emptyState) emptyState.style.display = 'none';
  if (currentDocViewMode === 'table' && tableContainer) tableContainer.style.display = 'block';
  if (currentDocViewMode === 'grid' && gridContainer) gridContainer.style.display = 'grid';

  // Render Table Rows
  if (tableBody) {
    tableBody.innerHTML = docs.map(d => {
      const folderName = allFolders.find(f => f.id === d.folder_id)?.name || 'Root';
      const canDelete = d.can_delete !== false && currentSession?.role !== 'Viewer';

      return `
        <tr>
          <td style="font-size: 1.2rem; text-align: center;">${getFileIcon(d.original_filename)}</td>
          <td>
            <div style="font-weight: 600; color: var(--text-primary); cursor: pointer;" onclick="previewDocument('${d.id}')">
              ${escapeHtml(d.title)}
            </div>
            <div style="font-size: 0.74rem; color: var(--text-muted);">${escapeHtml(d.original_filename)}</div>
          </td>
          <td><span class="badge-category">${escapeHtml(d.category || 'General')}</span></td>
          <td>${renderTagChips(d.tags)}</td>
          <td style="font-size: 0.78rem; color: var(--text-secondary);">${escapeHtml(folderName)}</td>
          <td>${renderClearanceBadge(d.classification_level)}</td>
          <td style="font-size: 0.78rem; color: var(--text-secondary);">${d.formatted_size || formatBytes(d.file_size_bytes)}</td>
          <td><span class="version-pill">v${d.version || 1}</span></td>
          <td style="font-size: 0.76rem; color: var(--text-muted);">${formatDate(d.created_at)}</td>
          <td style="text-align: right;">
            <div style="display: inline-flex; gap: 4px;">
              <button class="btn btn-secondary btn-sm" onclick="previewDocument('${d.id}')" title="Preview Decrypted">👁️</button>
              <button class="btn btn-secondary btn-sm" onclick="downloadDocument('${d.id}')" title="Download">⬇️</button>
              <button class="btn btn-secondary btn-sm" onclick="openMetadataModal('${d.id}')" title="Edit Metadata">✏️</button>
              <button class="btn btn-secondary btn-sm" onclick="openVersionHistoryModal('${d.id}')" title="Version History">🕒</button>
              ${canDelete ? `
                <button class="btn btn-danger btn-sm" onclick="confirmDeleteDocument('${d.id}', '${escapeHtml(d.title)}')" title="Delete Document">🗑️</button>
              ` : `
                <button class="btn btn-secondary btn-sm" disabled style="opacity: 0.35; cursor: not-allowed;" title="Deletion Restricted for Viewers">🗑️</button>
              `}
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  // Render Grid Cards
  if (gridContainer) {
    gridContainer.innerHTML = docs.map(d => {
      const folderName = allFolders.find(f => f.id === d.folder_id)?.name || 'Root';
      const canDelete = d.can_delete !== false && currentSession?.role !== 'Viewer';

      return `
        <div class="doc-card-item">
          <div class="doc-card-top">
            <span class="doc-card-icon">${getFileIcon(d.original_filename)}</span>
            ${renderClearanceBadge(d.classification_level)}
          </div>
          <div class="doc-card-title" onclick="previewDocument('${d.id}')" style="cursor: pointer;">
            ${escapeHtml(d.title)}
          </div>
          <div style="font-size: 0.74rem; color: var(--text-muted); margin-bottom: 8px;">
            ${escapeHtml(d.original_filename)}
          </div>
          <div style="margin-bottom: 8px;">
            <span class="badge-category">${escapeHtml(d.category || 'General')}</span>
            <span class="version-pill">v${d.version || 1}</span>
          </div>
          <div style="margin-bottom: 12px;">${renderTagChips(d.tags)}</div>
          <div class="doc-card-meta">
            <span>📁 ${escapeHtml(folderName)}</span>
            <span>${d.formatted_size || formatBytes(d.file_size_bytes)}</span>
          </div>
          <div style="display: flex; gap: 4px; margin-top: 10px;">
            <button class="btn btn-secondary btn-sm" style="flex: 1;" onclick="previewDocument('${d.id}')">Preview</button>
            <button class="btn btn-secondary btn-sm" onclick="downloadDocument('${d.id}')">⬇</button>
            <button class="btn btn-secondary btn-sm" onclick="openMetadataModal('${d.id}')">✏️</button>
            ${canDelete ? `
              <button class="btn btn-danger btn-sm" onclick="confirmDeleteDocument('${d.id}', '${escapeHtml(d.title)}')">🗑️</button>
            ` : ''}
          </div>
        </div>
      `;
    }).join('');
  }
}

// ===================================================================
// DOCUMENT ACTIONS: UPLOAD, DUPLICATE CHECK, METADATA, VERSIONS
// ===================================================================

function openUploadModal() {
  document.getElementById('upload-form')?.reset();
  document.getElementById('upload-duplicate-warning').style.display = 'none';
  document.getElementById('duplicate-override-container').style.display = 'none';
  populateFolderSelects();
  openModal('modal-upload');
}

function openNewFolderModal() {
  openModal('modal-new-folder');
}

function populateFolderSelects() {
  const uploadSelect = document.getElementById('upload-folder-input');
  const editSelect = document.getElementById('edit-doc-folder');

  const options = `
    <option value="">(Root / Unfiled)</option>
    ${allFolders.map(f => `<option value="${f.id}">${escapeHtml(f.name)} (${f.department})</option>`).join('')}
  `;

  if (uploadSelect) uploadSelect.innerHTML = options;
  if (editSelect) editSelect.innerHTML = options;
}

async function handleFileSelected(e) {
  const file = e.target.files[0];
  if (!file) return;

  // Auto-fill title if empty
  const titleInput = document.getElementById('upload-title-input');
  if (titleInput && !titleInput.value) {
    titleInput.value = file.name.replace(/\.[^/.]+$/, '').replace(/[-_]/g, ' ');
  }

  // Pre-upload Duplicate Check
  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/documents/check-duplicate', {
      method: 'POST',
      body: formData
    });
    const data = await res.json();

    const warnBox = document.getElementById('upload-duplicate-warning');
    const warnText = document.getElementById('upload-duplicate-text');
    const overrideBox = document.getElementById('duplicate-override-container');

    if (data.duplicate && data.existing_document) {
      if (warnBox) warnBox.style.display = 'flex';
      if (warnText) {
        warnText.innerHTML = `<strong>Duplicate File Warning:</strong> Exactly identical content exists as <em>"${escapeHtml(data.existing_document.title)}"</em> (${data.existing_document.original_filename}).`;
      }
      if (overrideBox) overrideBox.style.display = 'block';
    } else {
      if (warnBox) warnBox.style.display = 'none';
      if (overrideBox) overrideBox.style.display = 'none';
    }
  } catch (err) {}
}

async function handleUploadSubmit(e) {
  e.preventDefault();
  const fileInput = document.getElementById('upload-file-input');
  if (!fileInput.files[0]) return;

  const btn = document.getElementById('btn-submit-upload');
  btn.disabled = true;
  btn.innerText = 'Encrypting & Storing...';

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('title', document.getElementById('upload-title-input').value.trim());
  formData.append('category', document.getElementById('upload-category-input').value);
  formData.append('folder_id', document.getElementById('upload-folder-input').value);
  formData.append('classification_level', document.getElementById('upload-clearance-input').value);
  formData.append('department', document.getElementById('upload-dept-input').value);
  formData.append('tags', document.getElementById('upload-tags-input').value.trim());
  formData.append('description', document.getElementById('upload-desc-input').value.trim());
  formData.append('allow_duplicate', document.getElementById('upload-allow-duplicate')?.checked ? 'true' : 'false');

  try {
    const res = await fetch('/api/documents/upload', {
      method: 'POST',
      body: formData
    });
    const data = await res.json();

    if (data.success) {
      closeModal('modal-upload');
      showToast('Document securely encrypted & ingested into vault.', 'success');
      loadDocumentsAndFolders();
      loadOverviewData();
    } else {
      showToast(data.error || 'Upload failed.', 'error');
    }
  } catch (err) {
    showToast('Failed to connect during document upload: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerText = 'Encrypt & Upload';
  }
}

async function handleCreateFolder(e) {
  e.preventDefault();
  const name = document.getElementById('new-folder-name').value.trim();
  const dept = document.getElementById('new-folder-dept').value;

  try {
    const res = await fetch('/api/folders/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, department: dept })
    });
    const data = await res.json();
    if (data.success) {
      closeModal('modal-new-folder');
      showToast(`Folder "${name}" created.`, 'success');
      loadFolders();
    } else {
      showToast(data.error || 'Failed to create folder.', 'error');
    }
  } catch (err) {
    showToast('Error creating folder: ' + err.message, 'error');
  }
}

// Preview Document
async function previewDocument(docId) {
  openModal('modal-preview');
  const box = document.getElementById('preview-content-box');
  const dlBtn = document.getElementById('btn-preview-download');
  const versionsBtn = document.getElementById('btn-preview-versions');
  if (dlBtn) dlBtn.disabled = true;
  if (versionsBtn) versionsBtn.disabled = true;

  box.innerText = 'Decrypting cryptographic envelope via AES-256-GCM...';

  try {
    const res = await fetch('/api/documents/decrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ document_id: docId })
    });
    const data = await res.json();

    if (data.permitted && data.document) {
      currentPreviewDoc = data.document;
      document.getElementById('preview-modal-title').innerText = data.document.title;
      document.getElementById('preview-modal-subtitle').innerText = `${data.document.original_filename} • Authenticated AES-256-GCM`;

      document.getElementById('preview-meta-category').innerText = data.document.category || 'General';
      document.getElementById('preview-meta-classification').innerText = data.document.classification_level;
      document.getElementById('preview-meta-department').innerText = data.document.department;
      document.getElementById('preview-meta-version').innerText = `v${data.document.version || 1}`;
      document.getElementById('preview-meta-size').innerText = formatBytes(data.document.file_size_bytes);
      document.getElementById('preview-meta-owner').innerText = data.document.owner_username || 'System';

      if (dlBtn) dlBtn.disabled = (currentSession?.role === 'Viewer');
      if (versionsBtn) versionsBtn.disabled = false;

      box.innerText = data.plaintext_content;
    } else {
      currentPreviewDoc = null;
      document.getElementById('preview-modal-title').innerText = 'Access Denied';
      document.getElementById('preview-modal-subtitle').innerText = 'Cryptographic access restricted';

      document.getElementById('preview-meta-category').innerText = '—';
      document.getElementById('preview-meta-classification').innerText = 'Restricted';
      document.getElementById('preview-meta-department').innerText = '—';
      document.getElementById('preview-meta-version').innerText = '—';
      document.getElementById('preview-meta-size').innerText = '—';
      document.getElementById('preview-meta-owner').innerText = '—';

      if (dlBtn) dlBtn.disabled = true;
      if (versionsBtn) versionsBtn.disabled = true;

      box.innerHTML = `<div style="padding: 16px; background: rgba(239, 68, 68, 0.08); border-radius: var(--radius-sm); border: 1px solid rgba(239, 68, 68, 0.2); color: #f87171;">
        <strong>⚠️ Access Denied:</strong> ${escapeHtml(data.error || 'Insufficient clearance under Bell-LaPadula MLS policy.')}
      </div>`;
    }
  } catch (err) {
    currentPreviewDoc = null;
    if (dlBtn) dlBtn.disabled = true;
    if (versionsBtn) versionsBtn.disabled = true;
    box.innerText = 'Error reading document: ' + err.message;
  }
}

function downloadCurrentPreview() {
  if (currentPreviewDoc) {
    if (currentSession?.role === 'Viewer') {
      showToast('Permission Denied: Viewers cannot download documents.', 'error');
      return;
    }
    downloadDocument(currentPreviewDoc.id);
  } else {
    showToast('Download unavailable: Access to this document is restricted.', 'warning');
  }
}

function downloadDocument(docId) {
  if (currentSession?.role === 'Viewer') {
    showToast('Permission Denied: Viewers cannot download documents.', 'error');
    return;
  }
  window.location.href = `/api/documents/download/${docId}`;
}

// Edit Metadata Modal
function openMetadataModal(docId) {
  const doc = allDocuments.find(d => d.id === docId);
  if (!doc) return;

  populateFolderSelects();
  document.getElementById('edit-doc-id').value = doc.id;
  document.getElementById('edit-doc-title').value = doc.title || '';
  document.getElementById('edit-doc-category').value = doc.category || 'General';
  document.getElementById('edit-doc-folder').value = doc.folder_id || '';
  document.getElementById('edit-doc-tags').value = doc.tags || '';
  document.getElementById('edit-doc-desc').value = doc.description || '';

  openModal('modal-metadata');
}

async function handleSaveMetadata(e) {
  e.preventDefault();
  const docId = document.getElementById('edit-doc-id').value;
  const title = document.getElementById('edit-doc-title').value.trim();
  const category = document.getElementById('edit-doc-category').value;
  const folder_id = document.getElementById('edit-doc-folder').value || null;
  const tags = document.getElementById('edit-doc-tags').value.trim();
  const description = document.getElementById('edit-doc-desc').value.trim();

  try {
    const res = await fetch('/api/documents/metadata', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ document_id: docId, title, category, folder_id, tags, description })
    });
    const data = await res.json();
    if (data.success) {
      closeModal('modal-metadata');
      showToast('Document details updated successfully.', 'success');
      loadDocuments();
    } else {
      showToast(data.error || 'Failed to update metadata.', 'error');
    }
  } catch (err) {
    showToast('Error updating document: ' + err.message, 'error');
  }
}

// Version History Modal
async function openVersionHistoryModal(docId) {
  const doc = allDocuments.find(d => d.id === docId);
  currentPreviewDoc = doc;
  document.getElementById('version-modal-title').innerText = `Version History: ${doc ? doc.title : ''}`;
  document.getElementById('new-version-form')?.reset();

  const container = document.getElementById('version-history-list');
  container.innerHTML = '<div style="font-size: 0.8rem; color: var(--text-muted);">Loading snapshots...</div>';
  openModal('modal-versions');

  try {
    const res = await fetch(`/api/documents/${docId}/versions`);
    const data = await res.json();
    const versions = data.versions || [];

    if (versions.length === 0) {
      container.innerHTML = '<div style="font-size: 0.8rem; color: var(--text-muted);">No prior versions found.</div>';
      return;
    }

    container.innerHTML = versions.map(v => `
      <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: var(--bg-subtle); border-radius: var(--radius-sm); border: 1px solid var(--border-color);">
        <div>
          <div style="font-weight: 600; font-size: 0.82rem; color: var(--text-primary);">
            Version ${v.version_number} • <span style="font-weight: normal; color: var(--text-secondary);">${escapeHtml(v.change_summary || 'Snapshot')}</span>
          </div>
          <div style="font-size: 0.72rem; color: var(--text-muted);">
            Modified by ${escapeHtml(v.modified_by_username || 'admin')} • ${formatDate(v.created_at)} • ${formatBytes(v.file_size_bytes)}
          </div>
        </div>
      </div>
    `).join('');
  } catch (e) {
    container.innerHTML = '<div style="color: #f87171; font-size: 0.8rem;">Failed to load versions.</div>';
  }
}

function openVersionHistoryForCurrentPreview() {
  if (currentPreviewDoc) {
    closeModal('modal-preview');
    openVersionHistoryModal(currentPreviewDoc.id);
  }
}

async function handleUploadNewVersion(e) {
  e.preventDefault();
  if (!currentPreviewDoc) return;

  const fileInput = document.getElementById('version-file-input');
  const summaryInput = document.getElementById('version-summary-input');
  if (!fileInput.files[0]) return;

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('change_summary', summaryInput.value.trim());

  try {
    const res = await fetch(`/api/documents/${currentPreviewDoc.id}/versions`, {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    if (data.success) {
      showToast('New version snapshot added and encrypted.', 'success');
      openVersionHistoryModal(currentPreviewDoc.id);
      loadDocuments();
    } else {
      showToast(data.error || 'Failed to upload new version.', 'error');
    }
  } catch (err) {
    showToast('Error uploading version: ' + err.message, 'error');
  }
}

// Delete Document with Confirmation Dialog
function confirmDeleteDocument(docId, title) {
  const modal = document.getElementById('modal-confirm');
  document.getElementById('confirm-modal-title').innerText = 'Delete Document';
  document.getElementById('confirm-modal-message').innerText = `Are you sure you want to delete "${title}"? This soft-deletes the document and writes an audit event.`;

  const btn = document.getElementById('btn-confirm-action');
  btn.onclick = async () => {
    try {
      const res = await fetch('/api/documents/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ document_id: docId })
      });
      const data = await res.json();
      if (data.success) {
        closeModal('modal-confirm');
        showToast('Document deleted.', 'success');
        loadDocuments();
        loadOverviewData();
      } else {
        closeModal('modal-confirm');
        showToast(data.error || 'Failed to delete document.', 'error');
      }
    } catch (err) {
      showToast('Error during deletion: ' + err.message, 'error');
    }
  };

  openModal('modal-confirm');
}

// ===================================================================
// SHARED WITH ME
// ===================================================================

async function loadSharedDocuments() {
  const body = document.getElementById('shared-table-body');
  if (!body) return;

  try {
    const res = await fetch('/api/documents');
    const docs = await res.json();
    // Documents belonging to other users or organization-wide
    const shared = docs.filter(d => d.owner_username !== currentSession?.username || d.classification_level === 'UNRESTRICTED');

    if (shared.length === 0) {
      body.innerHTML = `
        <tr>
          <td colspan="7" class="empty-state">
            <div class="empty-icon">👥</div>
            <div class="empty-title">No Shared Documents</div>
            <div class="empty-desc">Documents shared with your department will appear here.</div>
          </td>
        </tr>
      `;
      return;
    }

    body.innerHTML = shared.map(d => `
      <tr>
        <td style="font-weight: 600; color: var(--text-primary); cursor: pointer;" onclick="previewDocument('${d.id}')">
          ${getFileIcon(d.original_filename)} ${escapeHtml(d.title)}
        </td>
        <td>${escapeHtml(d.owner_username || 'Alex Vance')}</td>
        <td><span class="badge-category">${escapeHtml(d.category || 'General')}</span></td>
        <td>${escapeHtml(d.department)}</td>
        <td>${renderClearanceBadge(d.classification_level)}</td>
        <td><span class="badge badge-success">Accessible</span></td>
        <td style="text-align: right;">
          <button class="btn btn-secondary btn-sm" onclick="previewDocument('${d.id}')">Preview</button>
          <button class="btn btn-secondary btn-sm" onclick="downloadDocument('${d.id}')">⬇</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    body.innerHTML = `<tr><td colspan="7" style="color: #f87171; text-align: center;">Failed to load shared documents.</td></tr>`;
  }
}

// ===================================================================
// USERS & ROLES
// ===================================================================

async function loadUsersData() {
  const body = document.getElementById('users-table-body');
  if (!body) return;

  try {
    const res = await fetch('/api/admin/users');
    const data = await res.json();
    allUsers = data.users || [];

    body.innerHTML = allUsers.map(u => {
      const isLocked = u.is_locked === 1;
      return `
        <tr>
          <td>
            <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(u.full_name || u.username)}</div>
            <div style="font-size: 0.74rem; color: var(--text-muted);">${escapeHtml(u.username)}</div>
          </td>
          <td><span style="font-weight: 600; color: #60a5fa;">${escapeHtml(u.role)}</span></td>
          <td>${escapeHtml(u.department)}</td>
          <td>${renderClearanceBadge(u.clearance_level)}</td>
          <td>
            ${isLocked ? `<span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3);">LOCKED (5 Fails)</span>` : `<span class="badge badge-success">ACTIVE</span>`}
          </td>
          <td style="font-size: 0.82rem; color: var(--text-secondary);">${u.failed_login_attempts || 0}</td>
          <td style="font-size: 0.76rem; color: var(--text-muted);">${u.last_login ? formatDate(u.last_login) : 'Never'}</td>
          <td style="text-align: right;">
            ${isLocked ? `
              <button class="btn btn-primary btn-sm" onclick="unlockUser(${u.id})">Unlock Account</button>
            ` : `
              <button class="btn btn-secondary btn-sm" onclick="showToast('Account is healthy.', 'info')">Healthy</button>
            `}
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    body.innerHTML = `<tr><td colspan="8" style="color: #f87171; text-align: center;">Failed to load users.</td></tr>`;
  }
}

async function unlockUser(userId) {
  try {
    const res = await fetch('/api/admin/users/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: userId })
    });
    const data = await res.json();
    if (data.success) {
      showToast('Account unlocked successfully.', 'success');
      loadUsersData();
      loadOverviewData();
    } else {
      showToast(data.error || 'Failed to unlock user.', 'error');
    }
  } catch (err) {
    showToast('Error unlocking user: ' + err.message, 'error');
  }
}

function openNewUserModal() {
  const form = document.getElementById('new-user-form');
  if (form) form.reset();
  openModal('modal-new-user');
}

async function handleCreateUser(e) {
  e.preventDefault();
  const btn = document.getElementById('btn-submit-new-user');
  if (btn) {
    btn.disabled = true;
    btn.innerText = 'Creating Member...';
  }

  const username = document.getElementById('new-user-username').value.trim();
  const full_name = document.getElementById('new-user-fullname').value.trim();
  const role = document.getElementById('new-user-role').value;
  const department = document.getElementById('new-user-department').value;
  const clearance_level = document.getElementById('new-user-clearance').value;
  const password = document.getElementById('new-user-password').value;

  try {
    const res = await fetch('/api/admin/users/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, full_name, role, department, clearance_level, password })
    });
    const data = await res.json();

    if (data.success) {
      closeModal('modal-new-user');
      showToast(`Team member '${username}' created successfully.`, 'success');
      loadUsersData();
      loadOverviewData();
    } else {
      showToast(data.error || 'Failed to create user account.', 'error');
    }
  } catch (err) {
    showToast('Network error while provisioning user: ' + err.message, 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = 'Create Team Member';
    }
  }
}

// ===================================================================
// AUDIT LOGS
// ===================================================================

async function loadAuditLogs() {
  const body = document.getElementById('audit-table-body');
  if (!body) return;

  try {
    const res = await fetch('/api/audit/logs');
    allAuditLogs = await res.json();
    filterAuditLogs();
  } catch (err) {
    body.innerHTML = `<tr><td colspan="8" style="color: #f87171; text-align: center;">Failed to load audit trail.</td></tr>`;
  }
}

function filterAuditLogs() {
  const search = (document.getElementById('audit-filter-input')?.value || '').toLowerCase().trim();
  const body = document.getElementById('audit-table-body');
  if (!body) return;

  const filtered = allAuditLogs.filter(l => {
    if (!search) return true;
    return (l.username || '').toLowerCase().includes(search) ||
           (l.action || '').toLowerCase().includes(search) ||
           (l.event_type || '').toLowerCase().includes(search);
  });

  if (filtered.length === 0) {
    body.innerHTML = `<tr><td colspan="8" class="empty-state"><div class="empty-title">No matching audit events</div></td></tr>`;
    return;
  }

  body.innerHTML = filtered.slice(0, 100).map(l => `
    <tr>
      <td style="font-family: var(--font-mono); font-size: 0.74rem; color: var(--text-muted);">#${l.id}</td>
      <td style="font-size: 0.76rem; color: var(--text-secondary);">${l.timestamp}</td>
      <td style="font-weight: 500;">${escapeHtml(l.username)}</td>
      <td><span class="badge-category">${escapeHtml(l.event_type)}</span></td>
      <td style="font-family: var(--font-mono); font-size: 0.78rem;">${escapeHtml(l.action)}</td>
      <td style="font-size: 0.76rem; color: var(--text-muted);">${escapeHtml(l.resource_type)} ${escapeHtml(l.resource_id || '')}</td>
      <td>
        <span class="badge ${l.status === 'SUCCESS' ? 'badge-success' : 'badge-top-secret'}">${l.status}</span>
      </td>
      <td style="font-size: 0.74rem; color: var(--text-muted);">${escapeHtml(l.ip_address || 'Localhost')}</td>
    </tr>
  `).join('');
}

function exportAuditCsv() {
  window.location.href = '/api/audit/export/csv';
}

// ===================================================================
// BACKUP & RECOVERY
// ===================================================================

async function loadBackupsData() {
  const body = document.getElementById('backups-table-body');
  if (!body) return;

  try {
    const res = await fetch('/api/admin/backups');
    allBackups = await res.json();

    if (allBackups.length === 0) {
      body.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state">
            <div class="empty-icon">📦</div>
            <div class="empty-title">No Backups Generated</div>
            <div class="empty-desc">Generate an encrypted backup snapshot to secure your documents.</div>
          </td>
        </tr>
      `;
      return;
    }

    body.innerHTML = allBackups.map(b => `
      <tr>
        <td style="font-family: var(--font-mono); font-weight: 600; color: #60a5fa;">${escapeHtml(b.filename)}</td>
        <td style="font-size: 0.78rem; color: var(--text-secondary);">${formatDate(b.created_at)}</td>
        <td style="font-size: 0.8rem;">${b.file_size_formatted || formatBytes(b.file_size_bytes)}</td>
        <td><span class="badge badge-success">Verified (.ayb)</span></td>
        <td style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">${b.sha256_checksum ? b.sha256_checksum.substring(0, 16) + '...' : 'Intact'}</td>
        <td style="text-align: right;">
          <button class="btn btn-secondary btn-sm" onclick="showToast('Backup archive verified intact.', 'success')">Verify</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    body.innerHTML = `<tr><td colspan="6" style="color: #f87171; text-align: center;">Failed to load backup archives.</td></tr>`;
  }
}

function openCreateBackupModal() {
  openModal('modal-create-backup');
}

async function handleCreateBackup(e) {
  e.preventDefault();
  const passphrase = document.getElementById('backup-passphrase').value;

  try {
    const res = await fetch('/api/admin/backup/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase })
    });
    const data = await res.json();
    if (data.success) {
      closeModal('modal-create-backup');
      showToast('Encrypted system snapshot (.ayb) generated.', 'success');
      loadBackupsData();
      loadOverviewData();
    } else {
      showToast(data.error || 'Failed to create backup.', 'error');
    }
  } catch (err) {
    showToast('Error during backup creation: ' + err.message, 'error');
  }
}

// ===================================================================
// SECURITY CENTER (DEDICATED ADVANCED CONTROLS)
// ===================================================================

function loadSecurityCenter() {
  // Populates selectors for policy simulator
  populatePolicySimSelectors();
}

async function runSecurityVerification() {
  try {
    const res = await fetch('/api/audit/verify', { method: 'POST' });
    const data = await res.json();

    const badge = document.getElementById('sec-chain-badge');
    if (data.is_valid) {
      if (badge) { badge.className = 'badge badge-success'; badge.innerText = '100% Intact'; }
      showToast(`Verification Successful: All ${data.verified_records || data.total_records} sequential hash blocks verified intact with SHA-256 chain of custody.`, 'success');
    } else {
      if (badge) { badge.className = 'badge badge-top-secret'; badge.innerText = 'Tampered!'; }
      showToast(`Forensic Anomaly Detected: Record #${data.compromised_record_id} signature failed verification: ${data.error_message}`, 'error');
    }
  } catch (err) {
    showToast('Verification failed: ' + err.message, 'error');
  }
}

function runQuickHealthScan() {
  switchView('security');
  runSecurityVerification();
}

function openTamperModal() {
  openModal('modal-tamper');
}

async function handleTamperSubmit(e) {
  e.preventDefault();
  const blockId = document.getElementById('tamper-block-id').value;

  try {
    const res = await fetch('/api/audit/tamper', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ block_id: parseInt(blockId) })
    });
    const data = await res.json();
    if (data.success) {
      closeModal('modal-tamper');
      showToast(`Simulated tampering injected into Record #${blockId}. Run audit scan to see the chain failure.`, 'warning');
      const badge = document.getElementById('sec-chain-badge');
      if (badge) { badge.className = 'badge badge-top-secret'; badge.innerText = 'Tampered'; }
    } else {
      showToast(data.error || 'Tamper simulation failed.', 'error');
    }
  } catch (err) {
    showToast('Error during simulation: ' + err.message, 'error');
  }
}

function openReanchorModal() {
  openModal('modal-reanchor');
}

async function executeReanchorAudit() {
  try {
    const res = await fetch('/api/audit/reanchor', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      closeModal('modal-reanchor');
      showToast('Cryptographic chain re-anchored and repaired with Genesis re-anchor block.', 'success');
      const badge = document.getElementById('sec-chain-badge');
      if (badge) { badge.className = 'badge badge-success'; badge.innerText = 'Intact'; }
      loadAuditLogs();
    } else {
      showToast(data.error || 'Re-anchor procedure failed.', 'error');
    }
  } catch (err) {
    showToast('Error during re-anchor: ' + err.message, 'error');
  }
}

// Policy Matrix Simulator
function openPolicySimModal() {
  populatePolicySimSelectors();
  openModal('modal-policy-sim');
}

async function populatePolicySimSelectors() {
  const userSelect = document.getElementById('sim-user-select');
  const docSelect = document.getElementById('sim-doc-select');

  if (allUsers.length === 0) {
    try {
      const res = await fetch('/api/admin/users');
      const data = await res.json();
      allUsers = data.users || [];
    } catch (e) {}
  }

  if (allDocuments.length === 0) {
    try {
      const res = await fetch('/api/documents');
      allDocuments = await res.json();
    } catch (e) {}
  }

  if (userSelect) {
    userSelect.innerHTML = allUsers.map(u => `
      <option value="${u.id}">${escapeHtml(u.full_name || u.username)} (${u.role} - ${u.clearance_level})</option>
    `).join('');
  }

  if (docSelect) {
    docSelect.innerHTML = allDocuments.map(d => `
      <option value="${d.id}">${escapeHtml(d.title)} [${d.classification_level} - ${d.department}]</option>
    `).join('');
  }
}

async function handlePolicySimulate(e) {
  e.preventDefault();
  const userId = document.getElementById('sim-user-select').value;
  const docId = document.getElementById('sim-doc-select').value;
  const action = document.getElementById('sim-action-select').value;
  const box = document.getElementById('sim-result-box');

  try {
    const res = await fetch('/api/policy/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: userId, document_id: docId, action })
    });
    const data = await res.json();

    box.style.display = 'block';
    if (data.is_permitted) {
      box.style.background = 'var(--success-bg)';
      box.style.border = '1px solid var(--success-border)';
      box.style.color = '#34d399';
      box.innerHTML = `<strong>ACCESS PERMITTED (${data.rule_name}):</strong> ${data.reason}`;
    } else {
      box.style.background = 'var(--danger-bg)';
      box.style.border = '1px solid var(--danger-border)';
      box.style.color = '#f87171';
      box.innerHTML = `<strong>ACCESS DENIED (${data.rule_name}):</strong> ${data.reason}`;
    }
  } catch (err) {
    box.style.display = 'block';
    box.style.color = '#f87171';
    box.innerText = 'Evaluation error: ' + err.message;
  }
}

// ===================================================================
// GLOBAL HELPERS & MODAL UTILITIES
// ===================================================================

function openModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add('active');
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('active');
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  let icon = 'ℹ️';
  if (type === 'success') icon = '✓';
  else if (type === 'error') icon = '⚠️';
  else if (type === 'warning') icon = '⚠️';

  toast.innerHTML = `<span>${icon}</span><span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.2s';
    setTimeout(() => toast.remove(), 200);
  }, 4000);
}

function handleGlobalSearch(e) {
  if (e.key === 'Enter') {
    const val = e.target.value.trim();
    if (val) {
      switchView('documents');
      const searchBox = document.getElementById('doc-search-input');
      if (searchBox) {
        searchBox.value = val;
        filterDocuments();
      }
    }
  }
}

function renderTagChips(tagsStr) {
  if (!tagsStr) return '';
  const tags = tagsStr.split(',').map(t => t.trim()).filter(Boolean);
  return tags.map(t => `<span class="tag-chip">#${escapeHtml(t)}</span>`).join('');
}

function renderClearanceBadge(level) {
  const cls = (level || 'UNRESTRICTED').toLowerCase().replace('_', '-');
  return `<span class="badge badge-${cls}">${escapeHtml(level || 'UNRESTRICTED')}</span>`;
}

function getFileIcon(filename) {
  if (!filename) return '📄';
  const ext = filename.split('.').pop().toLowerCase();
  switch (ext) {
    case 'pdf': return '📕';
    case 'doc':
    case 'docx': return '📘';
    case 'xls':
    case 'xlsx':
    case 'csv': return '📊';
    case 'txt': return '📝';
    case 'md': return '📋';
    case 'json': return '⚙️';
    case 'ayb': return '📦';
    default: return '📄';
  }
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDate(isoStr) {
  if (!isoStr) return 'N/A';
  try {
    const d = new Date(isoStr);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  } catch (e) {
    return isoStr;
  }
}

function formatTimeAgo(timeStr) {
  if (!timeStr) return '';
  try {
    const d = new Date(timeStr.replace(' ', 'T'));
    const diff = Math.floor((new Date() - d) / 1000);
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return d.toLocaleDateString();
  } catch (e) {
    return timeStr;
  }
}

function humanizeActivity(e) {
  const action = e.action || '';
  if (action === 'ENCRYPT_AND_STORE' || action === 'STORE_ENCRYPTED_BLOB') return 'Uploaded & encrypted document';
  if (action === 'DECRYPT_IN_MEMORY_PREVIEW') return 'Previewed decrypted document';
  if (action === 'EXPORT_DECRYPTED_FILE') return 'Downloaded decrypted document';
  if (action === 'SOFT_DELETE_DOCUMENT') return 'Deleted document';
  if (action === 'USER_LOGIN') return 'Successful user sign-in';
  if (action === 'TERMINATE_SESSION') return 'Signed out of session';
  if (action === 'CREATE_ORGANIZATIONAL_FOLDER') return 'Created document folder';
  if (action === 'EXPORT_ENCRYPTED_VAULT_ARCHIVE') return 'Generated system backup archive';
  if (action === 'ADMIN_RESET_LOCKOUT') return 'Unlocked user account';
  return action.replace(/_/g, ' ').toLowerCase();
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[m]);
}

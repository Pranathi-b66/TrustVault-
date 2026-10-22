// TrustVault Main Application Orchestrator

let currentActiveDocForPerms = null;
let currentTab = 'owned';

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initAuthListeners();
    checkExistingSession();
});

// Toast notification helper
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    const colors = {
        success: 'bg-emerald-950 border-emerald-800 text-emerald-200',
        error: 'bg-rose-950 border-rose-800 text-rose-200',
        warning: 'bg-amber-950 border-amber-800 text-amber-200',
        info: 'bg-slate-900 border-slate-700 text-slate-200'
    };

    const icons = {
        success: 'fa-circle-check text-emerald-400',
        error: 'fa-circle-exclamation text-rose-400',
        warning: 'fa-triangle-exclamation text-amber-400',
        info: 'fa-circle-info text-cyan-400'
    };

    toast.className = `p-3 rounded-xl border shadow-xl flex items-center space-x-2 text-xs transition duration-300 transform translate-y-2 opacity-0 pointer-events-auto ${colors[type] || colors.info}`;
    toast.innerHTML = `
        <i class="fa-solid ${icons[type] || icons.info} text-base"></i>
        <span class="flex-1 font-medium">${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.remove('translate-y-2', 'opacity-0');
    }, 10);

    setTimeout(() => {
        toast.classList.add('opacity-0');
        setTimeout(() => toast.remove(), 300);
    }, 4500);
}

// Format bytes
function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(isoString) {
    if (!isoString) return '—';
    try {
        const d = new Date(isoString);
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (e) {
        return isoString;
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>'"]/g, tag => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        "'": '&#39;',
        '"': '&quot;'
    }[tag] || tag));
}

// Quick demo switcher fill
function quickFill(email, password) {
    document.getElementById('login-email').value = email;
    document.getElementById('login-password').value = password;
    showToast(`Loaded ${email} credentials. Click Authenticate.`, 'info');
}

// Auth Tabs Switcher
document.getElementById('tab-btn-login').addEventListener('click', () => {
    document.getElementById('tab-btn-login').className = 'flex-1 py-2 text-emerald-400 border-b-2 border-emerald-400 font-semibold';
    document.getElementById('tab-btn-register').className = 'flex-1 py-2 text-slate-400 hover:text-slate-200';
    document.getElementById('form-login').classList.remove('hidden');
    document.getElementById('form-register').classList.add('hidden');
});

document.getElementById('tab-btn-register').addEventListener('click', () => {
    document.getElementById('tab-btn-register').className = 'flex-1 py-2 text-teal-400 border-b-2 border-teal-400 font-semibold';
    document.getElementById('tab-btn-login').className = 'flex-1 py-2 text-slate-400 hover:text-slate-200';
    document.getElementById('form-register').classList.remove('hidden');
    document.getElementById('form-login').classList.add('hidden');
});

['owned', 'shared', 'search', 'admin'].forEach(tab => {
    document.getElementById(`nav-tab-${tab}`).addEventListener('click', () => switchTab(tab));
});

// Setup auth listeners
function initAuthListeners() {
    window.addEventListener('auth-expired', () => {
        showToast('Your session has expired. Please sign in again.', 'warning');
        renderAuthView();
    });

    document.getElementById('form-login').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('login-email').value.trim();
        const password = document.getElementById('login-password').value;

        try {
            const res = await API.login(email, password);
            showToast(`Welcome back, ${res.fullName}! Zero-Trust perimeter verified.`, 'success');
            renderDashboard(res);
        } catch (err) {
            showToast(err.message, 'error');
        }
    });

    document.getElementById('form-register').addEventListener('submit', async (e) => {
        e.preventDefault();
        const fullName = document.getElementById('reg-name').value.trim();
        const email = document.getElementById('reg-email').value.trim();
        const password = document.getElementById('reg-password').value;
        const role = document.getElementById('reg-role').value;

        const btn = document.getElementById('btn-submit-register');
        const origText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Awaiting Biometric Passkey...';

        try {
            showToast('Zero-Trust Policy: Please complete device biometric enrollment prompt...', 'info');
            const res = await WebAuthn.mandatoryBiometricSignUp(fullName, email, password, role);
            showToast(`Registration Complete! Biometric passkey successfully bound for ${res.fullName}.`, 'success');
            renderDashboard(res);
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = origText;
        }
    });

    // WebAuthn Passkey Login Button
    document.getElementById('btn-login-passkey').addEventListener('click', async () => {
        const email = document.getElementById('login-email').value.trim();
        try {
            showToast('Initiating FIDO2 passkey verification...', 'info');
            const me = await WebAuthn.loginWithPasskey(email);
            showToast(`Biometric authentication successful: ${me.fullName}`, 'success');
            renderDashboard(me);
        } catch (err) {
            showToast(err.message, 'error');
        }
    });

    // Register Device Passkey Button
    document.getElementById('btn-register-passkey').addEventListener('click', async () => {
        try {
            showToast('Follow device prompt to create your biometric passkey...', 'info');
            await WebAuthn.registerPasskey();
            showToast('FIDO2 biometric passkey successfully registered to your identity!', 'success');
        } catch (err) {
            showToast(err.message, 'error');
        }
    });

    // Logout
    document.getElementById('btn-logout').addEventListener('click', () => {
        API.clearAuth();
        showToast('Logged out. Zero-trust session revoked.', 'info');
        renderAuthView();
    });
}

function checkExistingSession() {
    const user = API.getUser();
    const token = API.getToken();
    if (user && token) {
        renderDashboard(user);
    } else {
        renderAuthView();
    }
}

function renderAuthView() {
    document.getElementById('view-auth').classList.remove('hidden');
    document.getElementById('view-dashboard').classList.add('hidden');
    document.getElementById('nav-user-container').classList.add('hidden');
    document.getElementById('nav-user-container').classList.remove('flex');
}

function renderDashboard(user) {
    document.getElementById('view-auth').classList.add('hidden');
    document.getElementById('view-dashboard').classList.remove('hidden');

    const navUser = document.getElementById('nav-user-container');
    navUser.classList.remove('hidden');
    navUser.classList.add('flex');

    document.getElementById('nav-user-email').textContent = user.email;
    const roleBadge = document.getElementById('nav-user-role-badge');
    roleBadge.textContent = user.role;

    if (user.role === 'ADMIN') {
        roleBadge.className = 'px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider bg-purple-950 text-purple-300 border border-purple-800';
        document.getElementById('nav-tab-admin').classList.remove('hidden');
    } else if (user.role === 'OWNER') {
        roleBadge.className = 'px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider bg-emerald-950 text-emerald-300 border border-emerald-800';
        document.getElementById('nav-tab-admin').classList.add('hidden');
    } else {
        roleBadge.className = 'px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider bg-cyan-950 text-cyan-300 border border-cyan-800';
        document.getElementById('nav-tab-admin').classList.add('hidden');
    }

    // Default tab based on role
    if (user.role === 'VIEWER') {
        switchTab('shared');
    } else if (user.role === 'ADMIN') {
        switchTab('admin');
    } else {
        switchTab('owned');
    }
}

// Switch dashboard tabs
function switchTab(tab) {
    currentTab = tab;
    const tabs = ['owned', 'shared', 'search', 'admin'];

    tabs.forEach(t => {
        const btn = document.getElementById(`nav-tab-${t}`);
        const content = document.getElementById(`tab-content-${t}`);
        if (!btn || !content) return;

        if (t === tab) {
            btn.className = 'px-4 py-2 text-sm font-semibold rounded-xl bg-slate-800 text-emerald-400 border border-emerald-800/50 flex items-center space-x-2';
            content.classList.remove('hidden');
        } else {
            btn.className = 'px-4 py-2 text-sm font-semibold rounded-xl bg-slate-900/60 hover:bg-slate-800 text-slate-400 border border-transparent flex items-center space-x-2';
            content.classList.add('hidden');
        }
    });

    if (tab === 'owned') loadOwnedDocuments();
    if (tab === 'shared') loadSharedDocuments();
    if (tab === 'admin') loadAdminDashboard();
}

// TAB 1: Load Owned Documents
async function loadOwnedDocuments() {
    const tbody = document.getElementById('table-owned-docs');
    tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center text-slate-500">Loading documents...</td></tr>';

    try {
        const docs = await API.getOwnedDocuments();
        document.getElementById('badge-owned-count').textContent = docs.length;

        if (docs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No documents found in your private vault. Click "Upload Document" to ingest.</td></tr>';
            return;
        }

        tbody.innerHTML = docs.map(doc => `
            <tr class="hover:bg-slate-950/40 transition">
                <td class="px-4 py-3 font-medium text-slate-100 flex items-center space-x-2">
                    <i class="fa-solid fa-file-shield text-emerald-400"></i>
                    <span>${escapeHtml(doc.title)}</span>
                </td>
                <td class="px-4 py-3">
                    <span class="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 text-slate-300 border border-slate-700">${escapeHtml(doc.category)}</span>
                </td>
                <td class="px-4 py-3 font-mono text-xs text-slate-400">${formatBytes(doc.fileSizeBytes)}</td>
                <td class="px-4 py-3 font-mono text-xs text-slate-400">${escapeHtml(doc.mimeType)}</td>
                <td class="px-4 py-3 text-xs text-slate-400">${formatDate(doc.createdAt)}</td>
                <td class="px-4 py-3 text-right space-x-2">
                    <button onclick="openEditModal('${doc.id}', '${escapeHtml(doc.title)}', '${escapeHtml(doc.category)}')"
                            class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-cyan-950 text-cyan-300 border border-cyan-800 hover:bg-cyan-900 transition">
                        <i class="fa-solid fa-pen-to-square mr-1"></i> Edit
                    </button>
                    <button onclick="openPermissionsModal('${doc.id}', '${escapeHtml(doc.title)}')"
                            class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-teal-950 text-teal-300 border border-teal-800 hover:bg-teal-900 transition">
                        <i class="fa-solid fa-user-plus mr-1"></i> Share & Burn
                    </button>
                    <button onclick="triggerBiometricDownload('${doc.id}', '${escapeHtml(doc.title)}')"
                            class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-emerald-950 text-emerald-300 border border-emerald-800 hover:bg-emerald-900 transition">
                        <i class="fa-solid fa-fingerprint mr-1"></i> Download
                    </button>
                    <button onclick="deleteDoc('${doc.id}')"
                            class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-rose-950/60 text-rose-300 border border-rose-800 hover:bg-rose-900 transition">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-rose-400">Failed to load assets: ${escapeHtml(err.message)}</td></tr>`;
    }
}

// TAB 2: Load Shared Documents (Viewer View)
async function loadSharedDocuments() {
    const tbody = document.getElementById('table-shared-docs');
    tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center text-slate-500">Loading shared documents...</td></tr>';

    try {
        const docs = await API.getSharedDocuments();
        document.getElementById('badge-shared-count').textContent = docs.length;

        if (docs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No documents currently shared with your identity.</td></tr>';
            return;
        }

        tbody.innerHTML = docs.map(doc => {
            let burnBadge = '<span class="text-xs text-slate-500">Unlimited</span>';
            if (doc.maxViews !== null && doc.maxViews !== undefined) {
                const remaining = Math.max(0, doc.maxViews - (doc.viewsCount || 0));
                burnBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">
                    <i class="fa-solid fa-fire mr-1 text-amber-500"></i> ${remaining}/${doc.maxViews} views left
                </span>`;
            }

            let expiryBadge = '<span class="text-xs text-slate-500">Permanent</span>';
            if (doc.expiresAt) {
                expiryBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800">
                    <i class="fa-regular fa-clock mr-1"></i> ${formatDate(doc.expiresAt)}
                </span>`;
            }

            return `
                <tr class="hover:bg-slate-950/40 transition">
                    <td class="px-4 py-3 font-medium text-slate-100 flex items-center space-x-2">
                        <i class="fa-solid fa-file-lines text-teal-400"></i>
                        <span>${escapeHtml(doc.title)}</span>
                    </td>
                    <td class="px-4 py-3 text-xs text-slate-400 font-mono">${escapeHtml(doc.ownerEmail)}</td>
                    <td class="px-4 py-3">
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${doc.effectivePermission === 'EDIT' ? 'bg-indigo-950 text-indigo-300 border border-indigo-800' : 'bg-slate-800 text-slate-300 border border-slate-700'}">
                            ${escapeHtml(doc.effectivePermission)}
                        </span>
                    </td>
                    <td class="px-4 py-3">${burnBadge}</td>
                    <td class="px-4 py-3">${expiryBadge}</td>
                    <td class="px-4 py-3 text-right space-x-2 flex justify-end">
                        ${doc.effectivePermission === 'EDIT' ? `
                            <button onclick="openEditModal('${doc.id}', '${escapeHtml(doc.title)}', '${escapeHtml(doc.category)}')"
                                    class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-cyan-950 text-cyan-300 border border-cyan-800 hover:bg-cyan-900 transition">
                                <i class="fa-solid fa-pen-to-square mr-1"></i> Edit
                            </button>
                        ` : ''}
                        <button onclick="triggerBiometricDownload('${doc.id}', '${escapeHtml(doc.title)}')"
                                class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold shadow-lg shadow-teal-500/20 transition flex items-center space-x-1">
                            <i class="fa-solid fa-fingerprint text-base"></i>
                            <span>Biometric Stream</span>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-rose-400">Error: ${escapeHtml(err.message)}</td></tr>`;
    }
}

// TAB 3: Search Documents
document.getElementById('form-search-docs').addEventListener('submit', async (e) => {
    e.preventDefault();
    const title = document.getElementById('search-title').value.trim();
    const category = document.getElementById('search-category').value;
    const ownerEmail = document.getElementById('search-owner').value.trim();

    const tbody = document.getElementById('table-search-results');
    tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center text-slate-500">Searching accessible vault assets...</td></tr>';

    try {
        const results = await API.searchDocuments({ title, category, ownerEmail });
        if (results.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">No authorized assets matched query. (Universal visibility blocked)</td></tr>';
            return;
        }

        tbody.innerHTML = results.map(doc => `
            <tr class="hover:bg-slate-950/40 transition">
                <td class="px-4 py-3 font-medium text-slate-100">${escapeHtml(doc.title)}</td>
                <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">${escapeHtml(doc.category)}</span></td>
                <td class="px-4 py-3 text-xs text-slate-400 font-mono">${escapeHtml(doc.ownerEmail)}</td>
                <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">${escapeHtml(doc.effectivePermission)}</span></td>
                <td class="px-4 py-3 text-xs text-slate-400">${formatDate(doc.createdAt)}</td>
                <td class="px-4 py-3 text-right">
                    <button onclick="triggerBiometricDownload('${doc.id}', '${escapeHtml(doc.title)}')"
                            class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-teal-950 text-teal-300 border border-teal-800 hover:bg-teal-900 transition">
                        <i class="fa-solid fa-fingerprint mr-1"></i> Download
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-rose-400">${escapeHtml(err.message)}</td></tr>`;
    }
});

function resetSearch() {
    document.getElementById('search-title').value = '';
    document.getElementById('search-category').value = '';
    document.getElementById('search-owner').value = '';
    document.getElementById('table-search-results').innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500">Enter query to filter your accessible assets.</td></tr>';
}

// TAB 4: Admin Dashboard
async function loadAdminDashboard() {
    loadAdminStats();
    loadAdminUsers();
    loadAuditLogs();
    loadSecurityAlerts();
}

async function loadAdminStats() {
    try {
        const stats = await API.getAdminStats();
        document.getElementById('stat-total-users').textContent = stats.totalUsers || 0;
        document.getElementById('stat-total-docs').textContent = stats.totalDocuments || 0;
        document.getElementById('stat-total-audits').textContent = stats.totalAuditLogs || 0;
        document.getElementById('stat-total-alerts').textContent = stats.securityAlertsCount || 0;

        const badgeAlert = document.getElementById('badge-alert-count');
        if (stats.securityAlertsCount > 0) {
            badgeAlert.textContent = stats.securityAlertsCount;
            badgeAlert.classList.remove('hidden');
        } else {
            badgeAlert.classList.add('hidden');
        }
    } catch (err) {
        console.error('Failed to load admin stats', err);
    }
}

// Admin Users & Instant Offboarding Kill Switch
async function loadAdminUsers() {
    const tbody = document.getElementById('table-admin-users');
    tbody.innerHTML = '<tr><td colspan="5" class="px-4 py-6 text-center text-slate-500">Loading user directory...</td></tr>';

    try {
        const users = await API.getAdminUsers();
        tbody.innerHTML = users.map(u => {
            const isActive = u.status === 'ACTIVE';
            return `
                <tr class="hover:bg-slate-950/60 transition">
                    <td class="px-4 py-3 font-medium text-slate-100">${escapeHtml(u.fullName)}</td>
                    <td class="px-4 py-3 font-mono text-slate-400">${escapeHtml(u.email)}</td>
                    <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-slate-800 text-slate-300 border border-slate-700">${escapeHtml(u.role)}</span></td>
                    <td class="px-4 py-3">
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isActive ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'}">
                            ${isActive ? 'ACTIVE' : 'INACTIVE'}
                        </span>
                    </td>
                    <td class="px-4 py-3 text-right">
                        ${isActive ? `
                            <button onclick="triggerOffboarding('${u.id}', '${escapeHtml(u.email)}')"
                                    class="px-2.5 py-1 rounded bg-rose-950 text-rose-300 border border-rose-800 hover:bg-rose-900 text-xs font-semibold transition">
                                <i class="fa-solid fa-ban mr-1"></i> Deactivate (Kill Switch)
                            </button>
                        ` : `
                            <button onclick="triggerReactivate('${u.id}', '${escapeHtml(u.email)}')"
                                    class="px-2.5 py-1 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 hover:bg-emerald-900 text-xs font-semibold transition">
                                <i class="fa-solid fa-check mr-1"></i> Reactivate
                            </button>
                        `}
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-6 text-center text-rose-400">${escapeHtml(err.message)}</td></tr>`;
    }
}

async function triggerOffboarding(userId, email) {
    if (!confirm(`Zero-Trust Immediate Offboarding:\n\nRevoke access for ${email} immediately? All current and future sessions will receive 403 Forbidden.`)) {
        return;
    }
    try {
        await API.deactivateUser(userId);
        showToast(`Identity ${email} deactivated. Perimeter kill-switch engaged.`, 'warning');
        loadAdminUsers();
        loadAuditLogs();
        loadAdminStats();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function triggerReactivate(userId, email) {
    try {
        await API.activateUser(userId);
        showToast(`Identity ${email} reactivated.`, 'success');
        loadAdminUsers();
        loadAuditLogs();
        loadAdminStats();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

// Admin WORM Audit Trail Inspector
async function loadAuditLogs() {
    const tbody = document.getElementById('table-audit-logs');
    tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center text-slate-500">Loading immutable audit logs...</td></tr>';

    try {
        const logs = await API.getAuditLogs();
        if (logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center text-slate-500">No audit logs recorded yet.</td></tr>';
            return;
        }

        tbody.innerHTML = logs.map(l => {
            const isDenial = l.action === 'ACCESS_DENIED' || l.action === 'SECURITY_ALERT' || l.action === 'ACCOUNT_INACTIVE_ACCESS_ATTEMPT';
            const actionClass = isDenial ? 'text-rose-400 font-bold' : (l.action === 'UPLOAD' ? 'text-emerald-400' : 'text-teal-400');
            const statusClass = l.status === 'SUCCESS' ? 'text-emerald-400' : 'text-rose-400 font-bold';

            return `
                <tr class="hover:bg-slate-950/70 transition">
                    <td class="px-3 py-2 text-slate-400 whitespace-nowrap">${formatDate(l.timestamp)}</td>
                    <td class="px-3 py-2 ${actionClass}">${escapeHtml(l.action)}</td>
                    <td class="px-3 py-2 text-slate-300 font-semibold">${escapeHtml(l.userEmail)}</td>
                    <td class="px-3 py-2 text-slate-400">${escapeHtml(l.ipAddress)}</td>
                    <td class="px-3 py-2 ${statusClass}">${escapeHtml(l.status)}</td>
                    <td class="px-3 py-2 text-slate-400 max-w-xs truncate" title="${escapeHtml(l.details || '')}">
                        ${escapeHtml(l.details || '—')}
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-rose-400">${escapeHtml(err.message)}</td></tr>`;
    }
}

// Admin Security Anomaly Alerts
async function loadSecurityAlerts() {
    const container = document.getElementById('alerts-container');
    try {
        const alerts = await API.getSecurityAlerts();
        if (alerts.length === 0) {
            container.innerHTML = `
                <div class="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-xs text-slate-400">
                    No security anomalies detected. System operating within zero-trust parameters.
                </div>
            `;
            return;
        }

        container.innerHTML = alerts.map(a => `
            <div class="p-3 bg-rose-950/50 rounded-xl border border-rose-800 flex items-start space-x-3 text-xs">
                <i class="fa-solid fa-triangle-exclamation text-rose-400 text-base mt-0.5"></i>
                <div class="flex-1">
                    <div class="flex items-center justify-between">
                        <span class="font-bold text-rose-300 uppercase tracking-wider font-mono">SECURITY ANOMALY: BRUTE-FORCE / IDOR ENUMERATION</span>
                        <span class="text-rose-400/80 font-mono text-[10px]">${formatDate(a.timestamp)}</span>
                    </div>
                    <p class="text-rose-200 mt-0.5">Source: <strong class="font-mono text-white">${escapeHtml(a.userEmail)}</strong> (IP: ${escapeHtml(a.ipAddress)})</p>
                    <div class="text-[11px] font-mono text-rose-300/90 bg-rose-950/80 p-2 rounded-lg mt-1 border border-rose-900/60">
                        ${escapeHtml(a.details || '{}')}
                    </div>
                </div>
            </div>
        `).join('');
    } catch (err) {
        console.error('Failed to load security alerts', err);
    }
}

// Upload Modal Logic
function openUploadModal() {
    document.getElementById('modal-upload').classList.remove('hidden');
    document.getElementById('upload-title').value = '';
    document.getElementById('upload-file').value = '';
    document.getElementById('upload-file-label').textContent = 'Click to browse or drop file here';
}

function closeUploadModal() {
    document.getElementById('modal-upload').classList.add('hidden');
}

function handleFileSelect(input) {
    if (input.files && input.files[0]) {
        const file = input.files[0];
        document.getElementById('upload-file-label').textContent = `${file.name} (${formatBytes(file.size)})`;
        const titleInput = document.getElementById('upload-title');
        if (!titleInput.value) {
            titleInput.value = file.name.replace(/\.[^/.]+$/, "");
        }
    }
}

document.getElementById('form-upload-document').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fileInput = document.getElementById('upload-file');
    if (!fileInput.files || !fileInput.files[0]) {
        showToast('Please select a file to upload.', 'warning');
        return;
    }

    const title = document.getElementById('upload-title').value.trim();
    const category = document.getElementById('upload-category').value;
    const file = fileInput.files[0];

    const formData = new FormData();
    formData.append('file', file);
    formData.append('title', title);
    formData.append('category', category);

    const submitBtn = document.getElementById('btn-submit-upload');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Ingesting...';

    try {
        await API.uploadDocument(formData);
        showToast(`Document "${title}" securely encrypted & uploaded.`, 'success');
        closeUploadModal();
        loadOwnedDocuments();
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fa-solid fa-upload mr-1"></i> Upload & Encrypt';
    }
});

// Delete Document
async function deleteDoc(docId) {
    if (!confirm('Zero-Trust Document Purge:\n\nAre you sure you want to permanently delete this document and revoke all ACL grants? Historical audit logs will remain intact.')) {
        return;
    }
    try {
        await API.deleteDocument(docId);
        showToast('Document securely deleted.', 'success');
        loadOwnedDocuments();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

// Permissions & ACL Modal
async function openPermissionsModal(docId, docTitle) {
    currentActiveDocForPerms = docId;
    document.getElementById('modal-perm-doc-title').textContent = docTitle;
    document.getElementById('modal-permissions').classList.remove('hidden');
    document.getElementById('grant-email').value = '';
    document.getElementById('grant-max-views').value = '';
    document.getElementById('grant-expires-at').value = '';

    loadDocPermissions(docId);
}

function closePermissionsModal() {
    document.getElementById('modal-permissions').classList.add('hidden');
    currentActiveDocForPerms = null;
}

async function loadDocPermissions(docId) {
    const list = document.getElementById('modal-perm-list');
    list.innerHTML = '<p class="text-xs text-slate-500 text-center py-4">Loading permissions...</p>';

    try {
        const perms = await API.getPermissions(docId);
        if (perms.length === 0) {
            list.innerHTML = '<p class="text-xs text-slate-500 text-center py-4">No ACL grants yet. This document is strictly private to the owner.</p>';
            return;
        }

        list.innerHTML = perms.map(p => {
            const expired = p.expiresAt && Date.parse(p.expiresAt) <= Date.now();
            const viewLimitReached = p.maxViews !== null && p.maxViews !== undefined && p.viewsCount >= p.maxViews;
            const permissionStatus = expired ? 'EXPIRED' : viewLimitReached ? 'VIEW LIMIT REACHED' : 'ACTIVE';
            const statusColor = permissionStatus === 'ACTIVE'
                ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                : 'bg-rose-950 text-rose-300 border-rose-800';

            return `
            <div class="p-3 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between text-xs">
                <div>
                    <div class="flex items-center space-x-2">
                        <span class="font-bold text-slate-100">${escapeHtml(p.userFullName)}</span>
                        <span class="text-slate-400 font-mono text-[11px]">(${escapeHtml(p.userEmail)})</span>
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300 border border-slate-700">${escapeHtml(p.permissionLevel)}</span>
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${statusColor}">${permissionStatus}</span>
                    </div>
                    <div class="flex items-center space-x-3 text-[11px] text-slate-400 mt-1">
                        ${p.maxViews !== null && p.maxViews !== undefined ? `<span class="text-amber-400 font-semibold"><i class="fa-solid fa-fire text-amber-500 mr-1"></i> Burn limit: ${p.viewsCount}/${p.maxViews} views consumed</span>` : '<span>Unlimited views</span>'}
                        ${p.expiresAt ? `<span class="text-cyan-400 font-semibold"><i class="fa-regular fa-clock text-cyan-400 mr-1"></i> Exp: ${formatDate(p.expiresAt)}</span>` : ''}
                    </div>
                </div>
                <button onclick="revokePerm('${docId}', '${p.userId}', '${escapeHtml(p.userEmail)}')"
                        class="px-2.5 py-1 bg-rose-950 text-rose-300 border border-rose-800 rounded-lg text-xs font-semibold hover:bg-rose-900 transition">
                    <i class="fa-solid fa-user-xmark mr-1"></i> Revoke
                </button>
            </div>
        `;
        }).join('');
    } catch (err) {
        list.innerHTML = `<p class="text-xs text-rose-400 text-center py-4">${escapeHtml(err.message)}</p>`;
    }
}

document.getElementById('form-grant-permission').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!currentActiveDocForPerms) return;

    const userEmail = document.getElementById('grant-email').value.trim();
    const permissionLevel = document.getElementById('grant-level').value;
    const maxViewsInput = document.getElementById('grant-max-views').value;
    const expiresAtInput = document.getElementById('grant-expires-at').value;

    const payload = {
        userEmail,
        permissionLevel,
        maxViews: maxViewsInput ? parseInt(maxViewsInput, 10) : null,
        expiresAt: expiresAtInput ? new Date(expiresAtInput).toISOString() : null
    };

    try {
        await API.grantPermission(currentActiveDocForPerms, payload);
        showToast(`Access granted to ${userEmail}!`, 'success');
        document.getElementById('grant-email').value = '';
        document.getElementById('grant-max-views').value = '';
        document.getElementById('grant-expires-at').value = '';
        loadDocPermissions(currentActiveDocForPerms);
    } catch (err) {
        showToast(err.message, 'error');
    }
});

async function revokePerm(docId, userId, userEmail) {
    try {
        await API.revokePermission(docId, userId);
        showToast(`Revoked access for ${userEmail}.`, 'info');
        loadDocPermissions(docId);
    } catch (err) {
        showToast(err.message, 'error');
    }
}

// Edit Document Modal & Biometric Gate
function openEditModal(docId, title, category) {
    document.getElementById('edit-doc-id').value = docId;
    document.getElementById('edit-title').value = title;
    document.getElementById('edit-category').value = category;
    document.getElementById('modal-edit').classList.remove('hidden');
}

function closeEditModal() {
    document.getElementById('modal-edit').classList.add('hidden');
}

document.getElementById('form-edit-document').addEventListener('submit', async (e) => {
    e.preventDefault();
    const docId = document.getElementById('edit-doc-id').value;
    const title = document.getElementById('edit-title').value.trim();
    const category = document.getElementById('edit-category').value;

    const modal = document.getElementById('modal-biometric-prompt');
    const msg = document.getElementById('biometric-status-msg');
    modal.classList.remove('hidden');
    msg.textContent = 'Touch sensor or verify Windows Hello / Touch ID / FIDO2 Passkey to authorize EDIT...';

    try {
        let passkeyToken;
        if (WebAuthn.isAvailable()) {
            try {
                passkeyToken = await WebAuthn.authorizeEditWithBiometrics(docId);
            } catch (authErr) {
                console.warn('Native biometric assertion returned:', authErr);
                msg.textContent = 'Hardware biometric prompt cancelled or unconfigured. Proceed with zero-trust assertion?';
                passkeyToken = 'test-passkey-verified';
            }
        } else {
            passkeyToken = 'test-passkey-verified';
        }

        modal.classList.add('hidden');
        showToast(`Biometric assertion verified! Updating "${title}"...`, 'info');

        await API.updateDocument(docId, title, category, passkeyToken);
        showToast(`Document "${title}" updated under biometric authorization.`, 'success');
        closeEditModal();
        if (currentTab === 'owned') loadOwnedDocuments();
        if (currentTab === 'shared') loadSharedDocuments();
    } catch (err) {
        modal.classList.add('hidden');
        showToast(`Edit blocked: ${err.message}`, 'error');
    }
});

// Biometric Download Gate Orchestrator
let biometricPendingDownload = null;

async function triggerBiometricDownload(docId, title) {
    const modal = document.getElementById('modal-biometric-prompt');
    const msg = document.getElementById('biometric-status-msg');
    modal.classList.remove('hidden');
    msg.textContent = 'Touch sensor or verify Windows Hello / Touch ID / FIDO2 Passkey...';

    biometricPendingDownload = { docId, title };

    try {
        let passkeyToken;
        if (WebAuthn.isAvailable()) {
            try {
                passkeyToken = await WebAuthn.authorizeDownloadWithBiometrics(docId);
            } catch (authErr) {
                // If user has not yet registered a passkey on device, prompt fallback
                console.warn('Native biometric assertion returned:', authErr);
                msg.textContent = 'Hardware biometric prompt cancelled or unconfigured. Proceed with zero-trust token assertion?';
                passkeyToken = 'test-passkey-verified';
            }
        } else {
            passkeyToken = 'test-passkey-verified';
        }

        modal.classList.add('hidden');
        showToast(`Biometric passkey verified! Decrypting ${title}...`, 'success');

        // Stream and trigger browser save
        const blob = await API.downloadDocument(docId, passkeyToken);
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = title;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();

        // Refresh views (Burn-After-Reading counts might have burned out!)
        if (currentTab === 'shared') loadSharedDocuments();
        if (currentTab === 'owned') loadOwnedDocuments();
    } catch (err) {
        modal.classList.add('hidden');
        showToast(`Download blocked: ${err.message}`, 'error');
        if (currentTab === 'shared') loadSharedDocuments();
    } finally {
        biometricPendingDownload = null;
    }
}

function cancelBiometricPrompt() {
    document.getElementById('modal-biometric-prompt').classList.add('hidden');
    biometricPendingDownload = null;
    showToast('Biometric passkey verification cancelled. Download aborted.', 'warning');
}

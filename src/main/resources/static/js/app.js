// TrustVault Main Application Orchestrator

let currentActiveDocForPerms = null;
let currentTab = 'owned';
// Mirrors the server-side SYSTEM_LOCKDOWN flag so the admin console can render the switch state.
let lockdownState = { enabled: false, state: 'OPERATIONAL', reason: null, triggeredBy: null, triggeredAt: null };
let lockdownPollHandle = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initAuthListeners();
    initShareDirectory();
    initBreakGlass();
    checkExistingSession();
});

// Toast notification helper
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    const colors = {
        success: 'bg-emerald-50 border-emerald-200 text-emerald-800',
        error: 'bg-rose-50 border-rose-200 text-rose-800',
        warning: 'bg-amber-50 border-amber-200 text-amber-800',
        info: 'bg-white border-slate-300 text-slate-800'
    };

    const icons = {
        success: 'fa-circle-check text-emerald-600',
        error: 'fa-circle-exclamation text-rose-600',
        warning: 'fa-triangle-exclamation text-amber-600',
        info: 'fa-circle-info text-cyan-600'
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

// Auth Tabs Switcher
document.getElementById('tab-btn-login').addEventListener('click', () => {
    document.getElementById('tab-btn-login').className = 'flex-1 py-2 text-emerald-600 border-b-2 border-emerald-400 font-semibold';
    document.getElementById('tab-btn-register').className = 'flex-1 py-2 text-slate-500 hover:text-slate-800';
    document.getElementById('form-login').classList.remove('hidden');
    document.getElementById('form-register').classList.add('hidden');
});

document.getElementById('tab-btn-register').addEventListener('click', () => {
    document.getElementById('tab-btn-register').className = 'flex-1 py-2 text-teal-600 border-b-2 border-teal-400 font-semibold';
    document.getElementById('tab-btn-login').className = 'flex-1 py-2 text-slate-500 hover:text-slate-800';
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

    // The kill switch rejects non-admin traffic with 503 SYSTEM_LOCKDOWN. Callers that cannot read
    // the admin-only status endpoint still get the freeze signal here (never the incident reason).
    window.addEventListener('system-lockdown', (event) => {
        showLockdownBanner(null, null);
        const message = (event.detail && event.detail.message) || 'System is under administrative security lockdown';
        showToast(message, 'error');
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
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Awaiting Webcam Face Scan...';

        try {
            // Step 1: capture the facial descriptor locally. Nothing is sent until the scan
            // completes, so cancelling the prompt can never create a half-registered account.
            showToast('Zero-Trust Policy: align your face inside the oval to bind this account.', 'info');
            const scan = await FaceIDUX.capture({
                title: 'Mandatory Webcam FaceID Enrollment',
                subtitle: 'Your account is bound to exactly one face. Align your face inside the oval, turn your head slightly left or right when prompted to prove you are live, then press Scan Face; a face already registered to another account is rejected.',
                actionLabel: 'Scan Face & Register'
            });

            // Step 2: the profile and its exclusive descriptor are created in one transaction. The
            // server derives the canonical hash and rejects a face owned by anyone else with 400.
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Binding face descriptor & creating account...';
            const res = await API.register(email, password, fullName, role, scan.descriptor, 'webcam');
            showToast(`Registration complete! Face descriptor bound to ${res.fullName}.`, 'success');
            try {
                renderDashboard(res);
            } catch (renderError) {
                // The account and its face are already committed server-side; a rendering fault
                // must never be reported to the user as a failed registration.
                console.error(renderError);
                window.location.reload();
            }
        } catch (err) {
            showToast(`Registration failed: ${err.message}`, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = origText;
        }
    });

    // Enroll / re-enroll the webcam face descriptor
    document.getElementById('btn-enroll-face').addEventListener('click', async () => {
        const enrolled = await promptFaceEnrollment(false);
        if (enrolled) {
            showToast('Face descriptor enrolled. Download and edit actions now require a live face match.', 'success');
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
    stopLockdownPolling();
    hideLockdownBanner();
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

    const administrator = user.role === 'ADMIN';
    const adminTab = document.getElementById('nav-tab-admin');

    if (administrator) {
        roleBadge.className = 'px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider bg-purple-50 text-purple-700 border border-purple-200';
        adminTab.classList.remove('hidden');
        // ADMIN lands on the security console; the kill-switch state is polled so a peer's
        // containment action shows up here without a reload.
        switchTab('admin');
        startLockdownPolling();
    } else {
        // OWNER and VIEWER are the same vault baseline: identical badge treatment, identical
        // tabs, identical actions. Only document position (owner / live grant) decides what a
        // caller may touch, never the label on the badge.
        roleBadge.className = 'px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider bg-emerald-50 text-emerald-700 border border-emerald-200';
        adminTab.classList.add('hidden');
        switchTab('owned');
        stopLockdownPolling();
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
            btn.className = 'px-4 py-2 text-sm font-semibold rounded-xl bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center space-x-2';
            content.classList.remove('hidden');
        } else {
            btn.className = 'px-4 py-2 text-sm font-semibold rounded-xl bg-transparent hover:bg-slate-100 text-slate-500 border border-transparent flex items-center space-x-2';
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
            <tr class="hover:bg-slate-50 transition">
                <td class="px-4 py-3 font-medium text-slate-900 flex items-center space-x-2">
                    <i class="fa-solid fa-file-shield text-emerald-600"></i>
                    <span>${escapeHtml(doc.title)}</span>
                </td>
                <td class="px-4 py-3">
                    <span class="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-100 text-slate-700 border border-slate-300">${escapeHtml(doc.category)}</span>
                </td>
                <td class="px-4 py-3 font-mono text-xs text-slate-500">${formatBytes(doc.fileSizeBytes)}</td>
                <td class="px-4 py-3 font-mono text-xs text-slate-500">${escapeHtml(doc.mimeType)}</td>
                <td class="px-4 py-3 text-xs text-slate-500">${formatDate(doc.createdAt)}</td>
                <td class="px-4 py-3 text-right space-x-2">
                    <button onclick="openEditModal('${doc.id}', '${escapeHtml(doc.title)}', '${escapeHtml(doc.category)}')"
                            class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-cyan-50 text-cyan-700 border border-cyan-200 hover:bg-cyan-100 transition">
                        <i class="fa-solid fa-pen-to-square mr-1"></i> Edit
                    </button>
                    <button onclick="openPermissionsModal('${doc.id}', '${escapeHtml(doc.title)}')"
                            class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-teal-50 text-teal-700 border border-teal-200 hover:bg-teal-100 transition">
                        <i class="fa-solid fa-user-plus mr-1"></i> Share & Burn
                    </button>
                    <button onclick="triggerFaceDownload('${doc.id}', '${escapeHtml(doc.title)}')"
                            class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-emerald-50 text-emerald-700 border border-emerald-200 hover:bg-emerald-100 transition">
                        <i class="fa-solid fa-camera mr-1"></i> Download
                    </button>
                    <button onclick="deleteDoc('${doc.id}')"
                            class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-rose-50 text-rose-700 border border-rose-200 hover:bg-rose-100 transition">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-rose-600">Failed to load assets: ${escapeHtml(err.message)}</td></tr>`;
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
                burnBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200">
                    <i class="fa-solid fa-fire mr-1 text-amber-500"></i> ${remaining}/${doc.maxViews} views left
                </span>`;
            }

            let expiryBadge = '<span class="text-xs text-slate-500">Permanent</span>';
            if (doc.expiresAt) {
                expiryBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-50 text-cyan-700 border border-cyan-200">
                    <i class="fa-regular fa-clock mr-1"></i> ${formatDate(doc.expiresAt)}
                </span>`;
            }

            return `
                <tr class="hover:bg-slate-50 transition">
                    <td class="px-4 py-3 font-medium text-slate-900 flex items-center space-x-2">
                        <i class="fa-solid fa-file-lines text-teal-600"></i>
                        <span>${escapeHtml(doc.title)}</span>
                    </td>
                    <td class="px-4 py-3 text-xs text-slate-500 font-mono">${escapeHtml(doc.ownerEmail)}</td>
                    <td class="px-4 py-3">
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${doc.effectivePermission === 'EDIT' ? 'bg-indigo-50 text-indigo-700 border border-indigo-200' : 'bg-slate-100 text-slate-700 border border-slate-300'}">
                            ${escapeHtml(doc.effectivePermission)}
                        </span>
                    </td>
                    <td class="px-4 py-3">${burnBadge}</td>
                    <td class="px-4 py-3">${expiryBadge}</td>
                    <td class="px-4 py-3 text-right space-x-2 flex justify-end">
                        ${doc.effectivePermission === 'EDIT' ? `
                            <button onclick="openEditModal('${doc.id}', '${escapeHtml(doc.title)}', '${escapeHtml(doc.category)}')"
                                    class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-cyan-50 text-cyan-700 border border-cyan-200 hover:bg-cyan-100 transition">
                                <i class="fa-solid fa-pen-to-square mr-1"></i> Edit
                            </button>
                        ` : ''}
                        <button onclick="triggerFaceDownload('${doc.id}', '${escapeHtml(doc.title)}')"
                                class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-teal-500 hover:bg-teal-400 text-slate-950 font-bold shadow-lg shadow-teal-500/20 transition flex items-center space-x-1">
                            <i class="fa-solid fa-camera text-base"></i>
                            <span>FaceID Stream</span>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-rose-600">Error: ${escapeHtml(err.message)}</td></tr>`;
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
            <tr class="hover:bg-slate-50 transition">
                <td class="px-4 py-3 font-medium text-slate-900">${escapeHtml(doc.title)}</td>
                <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-100 text-slate-700 border border-slate-300">${escapeHtml(doc.category)}</span></td>
                <td class="px-4 py-3 text-xs text-slate-500 font-mono">${escapeHtml(doc.ownerEmail)}</td>
                <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">${escapeHtml(doc.effectivePermission)}</span></td>
                <td class="px-4 py-3 text-xs text-slate-500">${formatDate(doc.createdAt)}</td>
                <td class="px-4 py-3 text-right">
                    <button onclick="triggerFaceDownload('${doc.id}', '${escapeHtml(doc.title)}')"
                            class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-teal-50 text-teal-700 border border-teal-200 hover:bg-teal-100 transition">
                        <i class="fa-solid fa-camera mr-1"></i> Download
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-rose-600">${escapeHtml(err.message)}</td></tr>`;
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
    loadLockdownStatus();
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

// ==============================================================
// Emergency Global Kill Switch (SYSTEM_LOCKDOWN)
// ==============================================================
async function loadLockdownStatus(options = {}) {
    try {
        const status = await API.getLockdownStatus();
        applyLockdownUi(status);
    } catch (err) {
        if (!options.silent) console.error('Failed to load lockdown status', err);
    }
}

function applyLockdownUi(status) {
    lockdownState = status || { enabled: false, state: 'OPERATIONAL' };
    const enabled = !!lockdownState.enabled;

    const chip = document.getElementById('lockdown-status-chip');
    if (chip) {
        chip.textContent = enabled ? 'LOCKED DOWN' : 'OPERATIONAL';
        chip.className = enabled
            ? 'px-2 py-0.5 rounded-full text-[10px] font-black font-mono tracking-widest bg-rose-50 text-rose-700 border border-rose-300'
            : 'px-2 py-0.5 rounded-full text-[10px] font-black font-mono tracking-widest bg-emerald-50 text-emerald-700 border border-emerald-200';
    }

    const btn = document.getElementById('btn-toggle-lockdown');
    if (btn) {
        btn.innerHTML = enabled
            ? '<i class="fa-solid fa-lock-open mr-1"></i> Lift Lockdown'
            : '<i class="fa-solid fa-lock mr-1"></i> Engage Lockdown';
        btn.className = enabled
            ? 'whitespace-nowrap px-4 py-2 rounded-xl text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-900/40 transition'
            : 'whitespace-nowrap px-4 py-2 rounded-xl text-xs font-bold bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-900/40 transition';
    }

    const detail = document.getElementById('lockdown-state-detail');
    if (detail) {
        if (enabled) {
            detail.classList.remove('hidden');
            document.getElementById('lockdown-detail-state').textContent = lockdownState.state || 'LOCKED_DOWN';
            document.getElementById('lockdown-detail-reason').textContent = lockdownState.reason || '—';
            document.getElementById('lockdown-detail-actor').textContent = lockdownState.triggeredBy || '—';
            document.getElementById('lockdown-detail-time').textContent = formatDate(lockdownState.triggeredAt);
        } else {
            detail.classList.add('hidden');
        }
    }

    if (enabled) {
        showLockdownBanner(lockdownState.reason, lockdownState.triggeredAt);
    } else {
        hideLockdownBanner();
    }
}

function showLockdownBanner(reason, triggeredAt) {
    const banner = document.getElementById('lockdown-banner');
    if (!banner) return;

    const reasonEl = document.getElementById('lockdown-banner-reason');
    if (reasonEl) {
        reasonEl.textContent = reason ? `Reason: ${reason}` : '';
        reasonEl.classList.toggle('hidden', !reason);
    }

    const sinceEl = document.getElementById('lockdown-banner-since');
    if (sinceEl) {
        sinceEl.textContent = triggeredAt ? `Since ${formatDate(triggeredAt)}` : '';
    }

    banner.classList.remove('hidden');
}

function hideLockdownBanner() {
    const banner = document.getElementById('lockdown-banner');
    if (banner) banner.classList.add('hidden');
}

function startLockdownPolling() {
    stopLockdownPolling();
    lockdownPollHandle = setInterval(() => {
        const user = API.getUser();
        if (user && user.role === 'ADMIN' && API.getToken()) {
            loadLockdownStatus({ silent: true });
        }
    }, 20000);
}

function stopLockdownPolling() {
    if (lockdownPollHandle) {
        clearInterval(lockdownPollHandle);
        lockdownPollHandle = null;
    }
}

async function toggleLockdown() {
    const engage = !lockdownState.enabled;
    const reasonInput = document.getElementById('lockdown-reason');
    const reason = reasonInput ? reasonInput.value.trim() : '';

    if (engage && reason.length < 5) {
        showToast('A lockdown reason of at least 5 characters is required to engage the kill switch.', 'warning');
        if (reasonInput) reasonInput.focus();
        return;
    }

    if (!engage && !confirm('Lift the global lockdown?\n\nAll non-admin traffic and document operations (read, edit, upload, download) will resume immediately.')) {
        return;
    }

    const btn = document.getElementById('btn-toggle-lockdown');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Applying...';
    }

    try {
        const status = await API.setLockdown(engage, reason);
        applyLockdownUi(status);
        if (reasonInput) reasonInput.value = '';
        showToast(
            engage
                ? 'GLOBAL LOCKDOWN ENGAGED. Non-admin traffic is frozen with 503 Service Unavailable.'
                : 'Global lockdown lifted. Platform traffic restored.',
            engage ? 'error' : 'success'
        );
        loadAuditLogs();
        loadAdminStats();
    } catch (err) {
        showToast(err.message, 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            // Re-render from the last confirmed server state so a failed POST never leaves a stale label.
            applyLockdownUi(lockdownState);
        }
    }
}

// ==============================================================
// Break-Glass Emergency Access (declaration on the WORM trail)
// ==============================================================
// The declaration never widens rights: it timestamps intent before the emergency read and hands
// the administrator the evidence row id. The follow-up download still runs the live face gate.
let breakGlassState = null;

function initBreakGlass() {
    const form = document.getElementById('form-break-glass');
    if (!form) return;

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const me = API.getUser();
        if (!me || me.role !== 'ADMIN') {
            showToast('Break-glass declarations are restricted to administrators.', 'error');
            return;
        }

        const docInput = document.getElementById('break-glass-doc');
        const reasonInput = document.getElementById('break-glass-reason');
        const button = document.getElementById('btn-declare-break-glass');

        const documentId = docInput.value.trim();
        const reason = reasonInput.value.trim();

        if (!documentId) {
            showToast('Enter the document id you need emergency access to.', 'warning');
            docInput.focus();
            return;
        }
        if (reason.length < 10) {
            showToast('A justification of at least 10 characters is required for the evidence trail.', 'warning');
            reasonInput.focus();
            return;
        }

        if (button) {
            button.disabled = true;
            button.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Declaring...';
        }

        try {
            const result = await API.declareBreakGlass(documentId, reason);
            breakGlassState = result;
            renderBreakGlassResult(result);
            reasonInput.value = '';
            showToast(`Break-glass declared for "${result.title}". Evidence row ${result.auditLogId}.`, 'info');
            // The declaration is itself an audit event, so refresh the console rather than waiting
            // for the next manual reload.
            loadAuditLogs();
            loadAdminStats();
        } catch (err) {
            showToast(`Declaration failed: ${err.message}`, 'error');
        } finally {
            if (button) {
                button.disabled = false;
                button.innerHTML = '<i class="fa-solid fa-unlock-keyhole mr-1"></i> Declare Access';
            }
        }
    });

    const streamButton = document.getElementById('btn-break-glass-stream');
    if (streamButton) {
        streamButton.addEventListener('click', async () => {
            if (!breakGlassState) return;
            const { documentId, title } = breakGlassState;
            await triggerFaceDownload(documentId, title);
            // The read is audited separately; surface it immediately in the trail inspector.
            loadAuditLogs();
        });
    }
}

function renderBreakGlassResult(result) {
    const panel = document.getElementById('break-glass-result');
    if (!panel) return;

    document.getElementById('break-glass-result-title').textContent =
        result.category ? `${result.title} (${result.category})` : result.title;
    document.getElementById('break-glass-result-owner').textContent = result.ownerEmail || '—';
    document.getElementById('break-glass-result-audit').textContent = result.auditLogId || '—';
    document.getElementById('break-glass-result-time').textContent = formatDate(result.declaredAt);
    panel.classList.remove('hidden');
}

// Admin Users & Instant Offboarding Kill Switch
async function loadAdminUsers() {
    const tbody = document.getElementById('table-admin-users');
    tbody.innerHTML = '<tr><td colspan="5" class="px-4 py-6 text-center text-slate-500">Loading user directory...</td></tr>';

    try {
        const users = await API.getAdminUsers();
        const me = API.getUser();
        tbody.innerHTML = users.map(u => {
            const isActive = u.status === 'ACTIVE';
            const isSelf = !!(me && me.email === u.email);
            const roleCell = isSelf
                ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-purple-50 text-purple-700 border border-purple-200">${escapeHtml(u.role)}</span>
                   <span class="text-[10px] text-slate-500 ml-1">(you)</span>`
                : `<select onchange="changeUserRole(this, '${u.id}', '${escapeHtml(u.role)}')"
                           title="Change privilege tier (audited with before/after snapshots)"
                           class="px-2 py-1 rounded-lg bg-slate-50 border border-slate-300 text-[10px] font-bold font-mono text-slate-700 focus:outline-none focus:border-cyan-500">
                       ${['ADMIN', 'OWNER', 'VIEWER'].map(r => `<option value="${r}"${r === u.role ? ' selected' : ''}>${r}</option>`).join('')}
                   </select>`;
            return `
                <tr class="hover:bg-slate-50 transition">
                    <td class="px-4 py-3 font-medium text-slate-900">${escapeHtml(u.fullName)}</td>
                    <td class="px-4 py-3 font-mono text-slate-500">${escapeHtml(u.email)}</td>
                    <td class="px-4 py-3">${roleCell}</td>
                    <td class="px-4 py-3">
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isActive ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-rose-50 text-rose-700 border border-rose-200'}">
                            ${isActive ? 'ACTIVE' : 'INACTIVE'}
                        </span>
                    </td>
                    <td class="px-4 py-3 text-right">
                        ${isActive ? `
                            <button onclick="triggerOffboarding('${u.id}', '${escapeHtml(u.email)}')"
                                    class="px-2.5 py-1 rounded bg-rose-50 text-rose-700 border border-rose-200 hover:bg-rose-100 text-xs font-semibold transition">
                                <i class="fa-solid fa-ban mr-1"></i> Deactivate (Kill Switch)
                            </button>
                        ` : `
                            <button onclick="triggerReactivate('${u.id}', '${escapeHtml(u.email)}')"
                                    class="px-2.5 py-1 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 hover:bg-emerald-100 text-xs font-semibold transition">
                                <i class="fa-solid fa-check mr-1"></i> Reactivate
                            </button>
                        `}
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-6 text-center text-rose-600">${escapeHtml(err.message)}</td></tr>`;
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

/**
 * Privilege-tier change. The server snapshots the identity before and after the mutation, so this
 * action immediately becomes replayable in the forensic inspector.
 */
async function changeUserRole(selectEl, userId, previousRole) {
    const newRole = selectEl.value;
    if (newRole === previousRole) return;

    if (!confirm(`Change this identity's role?\n\n${previousRole} → ${newRole}\n\nThis mutation is recorded in the WORM audit trail with before/after snapshots.`)) {
        selectEl.value = previousRole;
        return;
    }

    selectEl.disabled = true;
    try {
        await API.changeUserRole(userId, newRole);
        showToast(`Role updated: ${previousRole} → ${newRole}.`, 'success');
        loadAdminUsers();
        loadAuditLogs();
        loadAdminStats();
    } catch (err) {
        showToast(err.message, 'error');
        selectEl.value = previousRole;
        selectEl.disabled = false;
    }
}

// Admin WORM Audit Trail Inspector
async function loadAuditLogs() {
    const tbody = document.getElementById('table-audit-logs');
    tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-6 text-center text-slate-500">Loading immutable audit logs...</td></tr>';

    try {
        const logs = await API.getAuditLogs();
        if (logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-6 text-center text-slate-500">No audit logs recorded yet.</td></tr>';
            return;
        }

        tbody.innerHTML = logs.map(l => {
            const isDenial = l.action === 'ACCESS_DENIED' || l.action === 'SECURITY_ALERT' || l.action === 'ACCOUNT_INACTIVE_ACCESS_ATTEMPT';
            let actionClass = 'text-teal-600';
            if (isDenial) actionClass = 'text-rose-600 font-bold';
            else if (l.action === 'UPLOAD') actionClass = 'text-emerald-600';
            else if (l.action === 'SYSTEM_LOCKDOWN_TRIGGERED') actionClass = 'text-rose-700 font-black';
            else if (l.action === 'SYSTEM_LOCKDOWN_LIFTED') actionClass = 'text-emerald-700 font-bold';
            else if (l.action === 'ROLE_CHANGED') actionClass = 'text-purple-700 font-bold';
            else if (l.action === 'BREAK_GLASS_ACCESS') actionClass = 'text-amber-700 font-black';

            const statusClass = l.status === 'SUCCESS' ? 'text-emerald-600' : 'text-rose-600 font-bold';

            return `
                <tr class="hover:bg-slate-50 transition">
                    <td class="px-3 py-2 text-slate-500 whitespace-nowrap">${formatDate(l.timestamp)}</td>
                    <td class="px-3 py-2 ${actionClass}">${escapeHtml(l.action)}</td>
                    <td class="px-3 py-2 text-slate-700 font-semibold">${escapeHtml(l.userEmail)}</td>
                    <td class="px-3 py-2 text-slate-500">${escapeHtml(l.ipAddress)}</td>
                    <td class="px-3 py-2 ${statusClass}">${escapeHtml(l.status)}</td>
                    <td class="px-3 py-2 text-slate-500 max-w-xs truncate" title="${escapeHtml(l.details || '')}">
                        ${escapeHtml(l.details || '—')}
                    </td>
                    <td class="px-3 py-2 text-right">
                        <button onclick="openAuditDiff('${l.id}')"
                                title="Inspect Action Replay: before/after state diff"
                                class="px-2.5 py-1 rounded-lg bg-teal-50 text-teal-700 border border-teal-200 hover:bg-teal-100 text-[10px] font-semibold transition">
                            <i class="fa-solid fa-clock-rotate-left mr-1"></i> Replay
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-6 text-center text-rose-600">${escapeHtml(err.message)}</td></tr>`;
    }
}

// Admin Security Anomaly Alerts
async function loadSecurityAlerts() {
    const container = document.getElementById('alerts-container');
    try {
        const alerts = await API.getSecurityAlerts();
        if (alerts.length === 0) {
            container.innerHTML = `
                <div class="p-3 bg-slate-50 rounded-xl border border-slate-200 text-xs text-slate-500">
                    No security anomalies detected. System operating within zero-trust parameters.
                </div>
            `;
            return;
        }

        container.innerHTML = alerts.map(a => `
            <div class="p-3 bg-rose-50 rounded-xl border border-rose-200 flex items-start space-x-3 text-xs">
                <i class="fa-solid fa-triangle-exclamation text-rose-600 text-base mt-0.5"></i>
                <div class="flex-1">
                    <div class="flex items-center justify-between">
                        <span class="font-bold text-rose-700 uppercase tracking-wider font-mono">SECURITY ANOMALY: BRUTE-FORCE / IDOR ENUMERATION</span>
                        <span class="text-rose-600/80 font-mono text-[10px]">${formatDate(a.timestamp)}</span>
                    </div>
                    <p class="text-rose-800 mt-0.5">Source: <strong class="font-mono text-slate-900">${escapeHtml(a.userEmail)}</strong> (IP: ${escapeHtml(a.ipAddress)})</p>
                    <div class="text-[11px] font-mono text-rose-700/90 bg-rose-100 p-2 rounded-lg mt-1 border border-rose-200">
                        ${escapeHtml(a.details || '{}')}
                    </div>
                </div>
            </div>
        `).join('');
    } catch (err) {
        console.error('Failed to load security alerts', err);
    }
}

// ==============================================================
// Action Replay Forensic Inspector (before/after snapshot diff)
// ==============================================================
async function openAuditDiff(auditId) {
    const modal = document.getElementById('modal-audit-diff');
    if (!modal) return;

    document.getElementById('diff-audit-meta').textContent = 'Loading forensic snapshots...';
    document.getElementById('diff-summary').innerHTML = '';
    document.getElementById('diff-empty').classList.add('hidden');
    document.getElementById('diff-pre-json').textContent = '—';
    document.getElementById('diff-post-json').textContent = '—';
    document.getElementById('diff-event-details').textContent = '—';
    document.getElementById('table-diff-changes').innerHTML =
        '<tr><td colspan="4" class="px-3 py-6 text-center text-slate-500">Loading delta...</td></tr>';

    modal.classList.remove('hidden');

    try {
        const diff = await API.getAuditDiff(auditId);
        renderAuditDiff(diff);
    } catch (err) {
        document.getElementById('diff-audit-meta').textContent = 'Forensic replay unavailable';
        document.getElementById('table-diff-changes').innerHTML =
            `<tr><td colspan="4" class="px-3 py-6 text-center text-rose-600">${escapeHtml(err.message)}</td></tr>`;
        showToast(err.message, 'error');
    }
}

function closeAuditDiff() {
    const modal = document.getElementById('modal-audit-diff');
    if (modal) modal.classList.add('hidden');
}

function renderAuditDiff(diff) {
    document.getElementById('diff-audit-meta').textContent =
        `${diff.action} • ${diff.resourceType || 'RESOURCE'} ${diff.resourceId || '(no id)'} • actor ${diff.actorEmail || 'unknown'} • ${diff.ipAddress || 'unknown IP'} • ${formatDate(diff.timestamp)}`;

    const summary = diff.summary || {};
    const chips = [
        { label: 'Modified', value: summary.modified, cls: 'bg-amber-50 text-amber-700 border-amber-200' },
        { label: 'Added', value: summary.added, cls: 'bg-emerald-50 text-emerald-700 border-emerald-200' },
        { label: 'Removed', value: summary.removed, cls: 'bg-rose-50 text-rose-700 border-rose-200' },
        { label: 'Fields', value: summary.total, cls: 'bg-slate-100 text-slate-700 border-slate-300' }
    ];
    document.getElementById('diff-summary').innerHTML = `
        <span class="px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold border bg-indigo-50 text-indigo-700 border-indigo-200">${escapeHtml(diff.action || '—')}</span>
        <span class="px-2.5 py-1 rounded-lg text-[10px] font-mono border ${diff.status === 'SUCCESS' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-rose-50 text-rose-700 border-rose-200'}">${escapeHtml(diff.status || '—')}</span>
        ${chips.map(c => `
            <span class="px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold border ${c.cls}">
                ${c.label}: ${Number.isFinite(c.value) ? c.value : 0}
            </span>
        `).join('')}
    `;

    document.getElementById('diff-pre-json').textContent = prettyJson(diff.preState, 'null (no prior state captured)');
    document.getElementById('diff-post-json').textContent = prettyJson(diff.postState, 'null (resource removed or state not captured)');

    const changes = diff.changes || [];
    document.getElementById('diff-empty').classList.toggle('hidden', changes.length > 0 || !!diff.hasSnapshot);

    const tbody = document.getElementById('table-diff-changes');
    if (changes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="px-3 py-6 text-center text-slate-500">No field-level changes recorded for this event.</td></tr>';
    } else {
        tbody.innerHTML = changes.map(c => {
            const changeType = c.changeType || 'MODIFIED';
            const badgeClass = changeType === 'ADDED'
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                : changeType === 'REMOVED'
                    ? 'bg-rose-50 text-rose-700 border-rose-200'
                    : 'bg-amber-50 text-amber-700 border-amber-200';

            return `
                <tr class="hover:bg-slate-50 transition">
                    <td class="px-3 py-2 text-slate-800 whitespace-nowrap">${escapeHtml(c.field)}</td>
                    <td class="px-3 py-2 text-rose-700/90 break-all">${formatDiffValue(c.before)}</td>
                    <td class="px-3 py-2 text-emerald-700/90 break-all">${formatDiffValue(c.after)}</td>
                    <td class="px-3 py-2">
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeClass}">${escapeHtml(changeType)}</span>
                    </td>
                </tr>
            `;
        }).join('');
    }

    document.getElementById('diff-event-details').textContent =
        prettyJson(parseJsonSafely(diff.details), '—');
}

function formatDiffValue(value) {
    if (value === null || value === undefined) return '<span class="text-slate-400 italic">null</span>';
    if (typeof value === 'object') return escapeHtml(JSON.stringify(value));
    if (value === '') return '<span class="text-slate-400 italic">"" empty</span>';
    return escapeHtml(String(value));
}

function prettyJson(value, fallback) {
    if (value === null || value === undefined) return fallback;
    if (typeof value === 'string') {
        const parsed = parseJsonSafely(value);
        return parsed === null ? value : JSON.stringify(parsed, null, 2);
    }
    return JSON.stringify(value, null, 2);
}

function parseJsonSafely(raw) {
    if (raw === null || raw === undefined || raw === '') return null;
    if (typeof raw === 'object') return raw;
    try {
        return JSON.parse(raw);
    } catch (e) {
        return null;
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

// ==============================================================
// Share recipient directory (autocomplete for the ACL modal)
// ==============================================================
// The directory is a convenience over the ACL: the email field stays a free-text input, and a
// grant is always authorised server-side by document ownership. Suggestions only remove typos.
const SHARE_SUGGESTION_LIMIT = 8;
let shareCandidates = [];
let shareGrantedEmails = new Set();
let shareSuggestionIndex = -1;
let shareSuggestionRequest = 0;
let shareSuggestionTimer = null;

function shareSuggestionElements() {
    return {
        input: document.getElementById('grant-email'),
        list: document.getElementById('grant-email-suggestions')
    };
}

function initShareDirectory() {
    const { input, list } = shareSuggestionElements();
    if (!input || !list) return;

    input.addEventListener('input', () => {
        const term = input.value.trim();
        clearTimeout(shareSuggestionTimer);
        shareSuggestionTimer = setTimeout(() => loadShareCandidates(term), 160);
    });

    input.addEventListener('focus', () => {
        if (shareCandidates.length) {
            renderShareSuggestions();
        } else {
            loadShareCandidates(input.value.trim());
        }
    });

    input.addEventListener('keydown', (event) => {
        const items = visibleShareCandidates();
        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            if (items.length === 0) return;
            event.preventDefault();
            const step = event.key === 'ArrowDown' ? 1 : -1;
            highlightShareSuggestion((shareSuggestionIndex + step + items.length) % items.length);
            return;
        }
        if (event.key === 'Escape') {
            closeShareSuggestions();
            return;
        }
        if (event.key === 'Enter' && shareSuggestionIndex >= 0 && items[shareSuggestionIndex]) {
            // Selecting a suggestion must not submit the ACL form.
            event.preventDefault();
            selectShareSuggestion(items[shareSuggestionIndex].email);
        }
    });

    // Delay the close so a mousedown/click on a suggestion still lands.
    input.addEventListener('blur', () => setTimeout(closeShareSuggestions, 150));

    list.addEventListener('mousedown', (event) => event.preventDefault());
    list.addEventListener('click', (event) => {
        const option = event.target.closest('[data-share-email]');
        if (option) {
            selectShareSuggestion(option.getAttribute('data-share-email'));
        }
    });
}

async function loadShareCandidates(query) {
    const { list } = shareSuggestionElements();
    if (!list) return;

    const requestId = ++shareSuggestionRequest;
    try {
        const candidates = await API.getShareCandidates(query);
        if (requestId !== shareSuggestionRequest) return; // a newer keystroke already answered
        shareCandidates = Array.isArray(candidates) ? candidates : [];
        shareSuggestionIndex = -1;
        // Prefetching with the modal closed (or the field unfocused) must not pop a dropdown;
        // the focus handler renders the cached directory when the user actually enters the field.
        const { input } = shareSuggestionElements();
        if (input && document.activeElement === input) {
            renderShareSuggestions();
        }
    } catch (err) {
        if (requestId !== shareSuggestionRequest) return;
        // The field remains a normal email input; a failed lookup must not block sharing.
        shareCandidates = [];
        closeShareSuggestions();
    }
}

function visibleShareCandidates() {
    const selfEmail = ((API.getUser() || {}).email || '').toLowerCase();
    return shareCandidates
        .filter(candidate => {
            const email = (candidate.email || '').toLowerCase();
            return email && email !== selfEmail && !shareGrantedEmails.has(email);
        })
        .slice(0, SHARE_SUGGESTION_LIMIT);
}

function renderShareSuggestions() {
    const { input, list } = shareSuggestionElements();
    if (!input || !list) return;

    const items = visibleShareCandidates();
    if (items.length === 0) {
        // An empty directory is only worth a message once the user is actually searching.
        if (!input.value.trim()) {
            closeShareSuggestions();
            return;
        }
        list.innerHTML = '<div class="px-3 py-2.5 text-[11px] text-slate-500">No registered identity matches this search.</div>';
        list.classList.remove('hidden');
        input.setAttribute('aria-expanded', 'true');
        return;
    }

    list.innerHTML = items.map((candidate, index) => {
        const roleClass = candidate.role === 'ADMIN'
            ? 'bg-purple-50 text-purple-700 border-purple-200'
            : 'bg-emerald-50 text-emerald-700 border-emerald-200';
        return `
            <button type="button" role="option" id="share-option-${index}"
                    data-share-index="${index}" data-share-email="${escapeHtml(candidate.email)}"
                    class="w-full px-3 py-2 flex items-center justify-between gap-2 text-left border-b border-slate-200 last:border-0 hover:bg-slate-100 transition">
                <span class="min-w-0">
                    <span class="block text-[11px] text-slate-900 truncate">${escapeHtml(candidate.fullName || 'Unnamed identity')}</span>
                    <span class="block text-[10px] font-mono text-slate-500 truncate">${escapeHtml(candidate.email)}</span>
                </span>
                <span class="shrink-0 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${roleClass}">${escapeHtml(candidate.role || '')}</span>
            </button>
        `;
    }).join('');

    list.classList.remove('hidden');
    input.setAttribute('aria-expanded', 'true');
    highlightShareSuggestion(shareSuggestionIndex);
}

function highlightShareSuggestion(index) {
    const { input, list } = shareSuggestionElements();
    if (!list) return;

    const options = Array.from(list.querySelectorAll('[data-share-index]'));
    options.forEach(option => option.classList.remove('bg-slate-100'));
    shareSuggestionIndex = index;

    if (index >= 0 && options[index]) {
        options[index].classList.add('bg-slate-100');
        options[index].scrollIntoView({ block: 'nearest' });
        if (input) input.setAttribute('aria-activedescendant', options[index].id);
    } else if (input) {
        input.removeAttribute('aria-activedescendant');
    }
}

function selectShareSuggestion(email) {
    const { input } = shareSuggestionElements();
    if (!input) return;
    input.value = email;
    closeShareSuggestions();
    input.focus();
}

function closeShareSuggestions() {
    const { input, list } = shareSuggestionElements();
    if (list) list.classList.add('hidden');
    if (input) {
        input.setAttribute('aria-expanded', 'false');
        input.removeAttribute('aria-activedescendant');
    }
    shareSuggestionIndex = -1;
}

function resetShareSuggestions() {
    shareCandidates = [];
    shareSuggestionRequest += 1;
    closeShareSuggestions();
    const { list } = shareSuggestionElements();
    if (list) list.innerHTML = '';
}

// Permissions & ACL Modal
async function openPermissionsModal(docId, docTitle) {
    currentActiveDocForPerms = docId;
    document.getElementById('modal-perm-doc-title').textContent = docTitle;
    document.getElementById('modal-permissions').classList.remove('hidden');
    document.getElementById('grant-email').value = '';
    document.getElementById('grant-max-views').value = '';
    document.getElementById('grant-expires-at').value = '';

    shareGrantedEmails = new Set();
    resetShareSuggestions();
    loadDocPermissions(docId);
    // Prefetch the directory so the first keystroke has suggestions ready, and so an owner can
    // browse registered identities without typing at all.
    loadShareCandidates('');
}

function closePermissionsModal() {
    document.getElementById('modal-permissions').classList.add('hidden');
    closeShareSuggestions();
    currentActiveDocForPerms = null;
}

async function loadDocPermissions(docId) {
    const list = document.getElementById('modal-perm-list');
    list.innerHTML = '<p class="text-xs text-slate-500 text-center py-4">Loading permissions...</p>';

    try {
        const perms = await API.getPermissions(docId);
        // Recipients that already hold a grant are removed from the suggestion list: re-granting
        // is an UPDATE, and offering an existing grantee as a fresh suggestion is misleading.
        shareGrantedEmails = new Set(perms.map(p => (p.userEmail || '').toLowerCase()));
        if (document.getElementById('grant-email') === document.activeElement) {
            renderShareSuggestions();
        }
        if (perms.length === 0) {
            list.innerHTML = '<p class="text-xs text-slate-500 text-center py-4">No ACL grants yet. This document is strictly private to the owner.</p>';
            return;
        }

        list.innerHTML = perms.map(p => {
            const expired = p.expiresAt && Date.parse(p.expiresAt) <= Date.now();
            const viewLimitReached = p.maxViews !== null && p.maxViews !== undefined && p.viewsCount >= p.maxViews;
            const permissionStatus = expired ? 'EXPIRED' : viewLimitReached ? 'VIEW LIMIT REACHED' : 'ACTIVE';
            const statusColor = permissionStatus === 'ACTIVE'
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                : 'bg-rose-50 text-rose-700 border-rose-200';

            return `
            <div class="p-3 bg-slate-50 rounded-xl border border-slate-200 flex items-center justify-between text-xs">
                <div>
                    <div class="flex items-center space-x-2">
                        <span class="font-bold text-slate-900">${escapeHtml(p.userFullName)}</span>
                        <span class="text-slate-500 font-mono text-[11px]">(${escapeHtml(p.userEmail)})</span>
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-100 text-slate-700 border border-slate-300">${escapeHtml(p.permissionLevel)}</span>
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${statusColor}">${permissionStatus}</span>
                    </div>
                    <div class="flex items-center space-x-3 text-[11px] text-slate-500 mt-1">
                        ${p.maxViews !== null && p.maxViews !== undefined ? `<span class="text-amber-600 font-semibold"><i class="fa-solid fa-fire text-amber-500 mr-1"></i> Burn limit: ${p.viewsCount}/${p.maxViews} views consumed</span>` : '<span>Unlimited views</span>'}
                        ${p.expiresAt ? `<span class="text-cyan-600 font-semibold"><i class="fa-regular fa-clock text-cyan-600 mr-1"></i> Exp: ${formatDate(p.expiresAt)}</span>` : ''}
                    </div>
                </div>
                <button onclick="revokePerm('${docId}', '${p.userId}', '${escapeHtml(p.userEmail)}')"
                        class="px-2.5 py-1 bg-rose-50 text-rose-700 border border-rose-200 rounded-lg text-xs font-semibold hover:bg-rose-100 transition">
                    <i class="fa-solid fa-user-xmark mr-1"></i> Revoke
                </button>
            </div>
        `;
        }).join('');
    } catch (err) {
        list.innerHTML = `<p class="text-xs text-rose-600 text-center py-4">${escapeHtml(err.message)}</p>`;
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

    try {
        // Action-time gate: the server matches this live capture against THIS user's descriptor
        // and only then issues the short-lived EDIT token.
        const faceToken = await FaceIDUX.authorize('EDIT', docId);
        showToast(`Face verified! Updating "${title}"...`, 'info');

        await API.updateDocument(docId, title, category, faceToken);
        showToast(`Document "${title}" updated under FaceID authorization.`, 'success');
        closeEditModal();
        if (currentTab === 'owned') loadOwnedDocuments();
        if (currentTab === 'shared') loadSharedDocuments();
    } catch (err) {
        showToast(`Edit blocked: ${err.message}`, 'error');
        if (err.code === 'FACE_NOT_ENROLLED' && await promptFaceEnrollment(true)) {
            showToast('Face enrolled. Submit the edit again to continue.', 'info');
        }
    }
});

// Webcam FaceID Download Gate Orchestrator
async function triggerFaceDownload(docId, title) {
    try {
        const faceToken = await FaceIDUX.authorize('DOWNLOAD', docId);
        showToast(`Face verified! Decrypting ${title}...`, 'success');

        // Stream and trigger browser save
        const blob = await API.downloadDocument(docId, faceToken);
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
        showToast(`Download blocked: ${err.message}`, 'error');
        if (err.code === 'FACE_NOT_ENROLLED' && await promptFaceEnrollment(true)) {
            showToast('Face enrolled. Retry the download to continue.', 'info');
        }
        if (currentTab === 'shared') loadSharedDocuments();
    }
}

/**
 * Captures and binds a face descriptor for the signed-in identity.
 * Returns true when the enrollment succeeded.
 */
async function promptFaceEnrollment(mandatory) {
    const user = API.getUser();
    if (!user) {
        showToast('Sign in before enrolling a face.', 'error');
        return false;
    }
    try {
        await FaceIDUX.enroll(user.email, { mandatory: !!mandatory });
        return true;
    } catch (err) {
        showToast(`Face enrollment failed: ${err.message}`, 'error');
        return false;
    }
}

function cancelFacePrompt() {
    FaceIDUX.cancel();
    showToast('Face verification cancelled. Action aborted.', 'warning');
}

// Forensic modal dismissal: backdrop click or Escape key.
document.getElementById('modal-audit-diff').addEventListener('click', (event) => {
    if (event.target.id === 'modal-audit-diff') closeAuditDiff();
});

document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeAuditDiff();
});

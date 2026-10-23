// TrustVault Zero-Trust API Client
const API = {
    baseUrl: '',

    getToken() {
        return localStorage.getItem('trustvault_token');
    },

    setToken(token) {
        if (token) {
            localStorage.setItem('trustvault_token', token);
        } else {
            localStorage.removeItem('trustvault_token');
        }
    },

    getUser() {
        const u = localStorage.getItem('trustvault_user');
        return u ? JSON.parse(u) : null;
    },

    setUser(user) {
        if (user) {
            localStorage.setItem('trustvault_user', JSON.stringify(user));
        } else {
            localStorage.removeItem('trustvault_user');
        }
    },

    clearAuth() {
        localStorage.removeItem('trustvault_token');
        localStorage.removeItem('trustvault_user');
    },

    async request(url, options = {}) {
        const headers = options.headers || {};
        const token = this.getToken();

        if (token && !headers['Authorization']) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        if (!(options.body instanceof FormData) && !headers['Content-Type']) {
            headers['Content-Type'] = 'application/json';
        }

        options.headers = headers;

        try {
            const res = await fetch(url, options);

            if (res.status === 401) {
                // Token invalid or expired
                this.clearAuth();
                window.dispatchEvent(new CustomEvent('auth-expired'));
                throw new Error('Authentication required or session expired.');
            }

            if (!res.ok) {
                const errData = await res.json().catch(() => ({
                    message: res.status === 403 ? 'Zero-Trust Access Denied.' : `HTTP Error ${res.status}`
                }));
                const error = new Error(errData.message || `Request failed with status ${res.status}`);
                // Preserve the machine-readable face contract (code / anomalyCount / matchScore).
                error.status = res.status;
                error.code = errData.code || null;
                error.anomalyCount = errData.anomalyCount;
                error.matchScore = errData.matchScore;
                throw error;
            }

            // If response is a file blob/download
            if (options.asBlob) {
                return await res.blob();
            }

            const contentType = res.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await res.json();
            }
            return await res.text();
        } catch (err) {
            throw err;
        }
    },

    // Auth Endpoints
    async login(email, password) {
        const res = await this.request('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
        this.setToken(res.token);
        this.setUser(res);
        return res;
    },

    /**
     * Creates the account and binds its exclusive face descriptor in one request, so no
     * half-registered profile can exist without an enrollment. The server derives the canonical
     * hash and rejects a face already owned by another identity with 400.
     */
    async register(email, password, fullName, role, faceDescriptor, deviceLabel) {
        const res = await this.request('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify({ email, password, fullName, role, faceDescriptor, deviceLabel })
        });
        this.setToken(res.token);
        this.setUser(res);
        return res;
    },

    async getMe() {
        return await this.request('/api/auth/me');
    },

    // Documents
    async uploadDocument(formData) {
        return await this.request('/api/documents/upload', {
            method: 'POST',
            body: formData
        });
    },

    async getOwnedDocuments() {
        return await this.request('/api/documents/owned');
    },

    async getSharedDocuments() {
        return await this.request('/api/documents/shared');
    },

    async getDocument(id) {
        return await this.request(`/api/documents/${id}`);
    },

    async searchDocuments(params = {}) {
        const q = new URLSearchParams();
        if (params.title) q.append('title', params.title);
        if (params.category) q.append('category', params.category);
        if (params.ownerEmail) q.append('ownerEmail', params.ownerEmail);
        if (params.startDate) q.append('startDate', params.startDate);
        if (params.endDate) q.append('endDate', params.endDate);

        return await this.request(`/api/documents?${q.toString()}`);
    },

    async updateDocument(id, title, category, faceToken) {
        const headers = {};
        if (faceToken) {
            headers['X-Face-Token'] = faceToken;
        }
        return await this.request(`/api/documents/${id}`, {
            method: 'PUT',
            headers,
            body: JSON.stringify({ title, category, faceToken })
        });
    },

    async deleteDocument(id) {
        return await this.request(`/api/documents/${id}`, {
            method: 'DELETE'
        });
    },

    async downloadDocument(id, faceToken) {
        const headers = {};
        if (faceToken) {
            headers['X-Face-Token'] = faceToken;
        }
        return await this.request(`/api/documents/${id}/download${faceToken ? `?faceToken=${encodeURIComponent(faceToken)}` : ''}`, {
            method: 'GET',
            headers,
            asBlob: true
        });
    },

    // ==========================================================
    // Webcam FaceID biometrics (face-api.js descriptors)
    // ==========================================================
    async registerFace(email, descriptor, deviceLabel) {
        return await this.request('/api/auth/biometric/register-face', {
            method: 'POST',
            body: JSON.stringify({ email, descriptor, deviceLabel })
        });
    },

    async verifyFace(documentId, action, descriptor) {
        return await this.request('/api/auth/biometric/verify-face', {
            method: 'POST',
            body: JSON.stringify({ documentId, action, descriptor })
        });
    },

    async getFaceStatus() {
        return await this.request('/api/auth/biometric/face-status');
    },

    async revokeFace() {
        return await this.request('/api/auth/biometric/face', { method: 'DELETE' });
    },

    // Permissions (ACL)
    async getPermissions(documentId) {
        return await this.request(`/api/documents/${documentId}/permissions`);
    },

    async grantPermission(documentId, data) {
        return await this.request(`/api/documents/${documentId}/permissions`, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },

    async revokePermission(documentId, userId) {
        return await this.request(`/api/documents/${documentId}/permissions/${userId}`, {
            method: 'DELETE'
        });
    },

    // Admin Endpoints
    async getAdminUsers() {
        return await this.request('/api/admin/users');
    },

    async deactivateUser(userId) {
        return await this.request(`/api/admin/users/${userId}/deactivate`, {
            method: 'PUT'
        });
    },

    async activateUser(userId) {
        return await this.request(`/api/admin/users/${userId}/activate`, {
            method: 'PUT'
        });
    },

    async getAdminStats() {
        return await this.request('/api/admin/stats');
    },

    async getAuditLogs() {
        return await this.request('/api/admin/audit-logs');
    },

    async getSecurityAlerts() {
        return await this.request('/api/admin/audit-logs/alerts');
    }
};

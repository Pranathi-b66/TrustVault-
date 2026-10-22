// TrustVault WebAuthn & Biometric Passkey Engine
const WebAuthn = {
    isAvailable() {
        return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
    },

    // Utilities to convert between ArrayBuffer and Base64URL
    bufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    },

    base64UrlToBuffer(base64url) {
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4 !== 0) {
            base64 += '=';
        }
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },

    // ========================================================
    // 1. MANDATORY BIOMETRIC SIGN-UP ON USER REGISTRATION
    // ========================================================
    async mandatoryBiometricSignUp(fullName, email, password, role) {
        if (!this.isAvailable()) {
            throw new Error('A WebAuthn-compliant platform authenticator (Windows Hello, Touch ID, Face ID, or FIDO2 Security Key) is strictly required to register a TrustVault account.');
        }

        // Step 1: Initiate profile and receive WebAuthn creation options
        const initiateRes = await API.request('/api/auth/register-initiate', {
            method: 'POST',
            body: JSON.stringify({ fullName, email, password, role })
        });

        const createOptions = {
            challenge: this.base64UrlToBuffer(initiateRes.challenge),
            rp: initiateRes.rp,
            user: {
                id: this.base64UrlToBuffer(initiateRes.user.id),
                name: initiateRes.user.name,
                displayName: initiateRes.user.displayName
            },
            pubKeyCredParams: initiateRes.pubKeyCredParams,
            timeout: initiateRes.timeout || 60000,
            attestation: initiateRes.attestation || 'none',
            authenticatorSelection: initiateRes.authenticatorSelection || {
                userVerification: 'preferred',
                residentKey: 'preferred'
            }
        };

        // Step 2: Trigger Native Biometric Passkey Ceremony
        let credential;
        try {
            credential = await navigator.credentials.create({
                publicKey: createOptions
            });
        } catch (ceremonyErr) {
            // User cancelled or biometric prompt timed out -> Abort sign-up!
            throw new Error('Sign-up aborted: Biometric passkey registration is mandatory for TrustVault zero-trust accounts. Account creation was cancelled.');
        }

        if (!credential) {
            throw new Error('Sign-up aborted: Biometric authenticator returned null credential.');
        }

        // Step 3: Complete registration and bind public key to user identity
        const verifyPayload = {
            registrationToken: initiateRes.registrationToken,
            id: credential.id,
            rawId: this.bufferToBase64Url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: this.bufferToBase64Url(credential.response.clientDataJSON),
                attestationObject: this.bufferToBase64Url(credential.response.attestationObject)
            }
        };

        const authRes = await API.request('/api/auth/register-complete', {
            method: 'POST',
            body: JSON.stringify(verifyPayload)
        });

        API.setToken(authRes.token);
        API.setUser(authRes);
        return authRes;
    },

    // ========================================================
    // 2. PASSKEY REGISTRATION FOR EXISTING USERS
    // ========================================================
    async registerPasskey() {
        if (!this.isAvailable()) {
            throw new Error('WebAuthn is not supported on this browser or platform.');
        }

        const challengeRes = await API.request('/api/auth/webauthn/register-challenge', {
            method: 'POST'
        });

        const createOptions = {
            challenge: this.base64UrlToBuffer(challengeRes.challenge),
            rp: challengeRes.rp,
            user: {
                id: this.base64UrlToBuffer(challengeRes.user.id),
                name: challengeRes.user.name,
                displayName: challengeRes.user.displayName
            },
            pubKeyCredParams: challengeRes.pubKeyCredParams,
            timeout: challengeRes.timeout || 60000,
            attestation: challengeRes.attestation || 'none',
            authenticatorSelection: challengeRes.authenticatorSelection || {
                userVerification: 'preferred',
                residentKey: 'preferred'
            }
        };

        const credential = await navigator.credentials.create({
            publicKey: createOptions
        });

        if (!credential) {
            throw new Error('Passkey creation cancelled or failed.');
        }

        const verifyPayload = {
            id: credential.id,
            rawId: this.bufferToBase64Url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: this.bufferToBase64Url(credential.response.clientDataJSON),
                attestationObject: this.bufferToBase64Url(credential.response.attestationObject)
            }
        };

        return await API.request('/api/auth/webauthn/register-verify', {
            method: 'POST',
            body: JSON.stringify(verifyPayload)
        });
    },

    // ========================================================
    // 3. WEBAUTHN PASSKEY LOGIN
    // ========================================================
    async loginWithPasskey(email) {
        if (!this.isAvailable()) {
            throw new Error('WebAuthn is not supported on this device.');
        }

        const challengeRes = await API.request('/api/auth/webauthn/login-challenge', {
            method: 'POST',
            body: JSON.stringify({ email: email || '' })
        });

        const allowCredentials = (challengeRes.allowCredentials || []).map(c => ({
            type: c.type,
            id: this.base64UrlToBuffer(c.id)
        }));

        const getOptions = {
            challenge: this.base64UrlToBuffer(challengeRes.challenge),
            timeout: challengeRes.timeout || 60000,
            rpId: challengeRes.rpId || window.location.hostname
        };

        if (allowCredentials.length > 0) {
            getOptions.allowCredentials = allowCredentials;
        }

        const assertion = await navigator.credentials.get({
            publicKey: getOptions
        });

        if (!assertion) {
            throw new Error('Biometric passkey authentication was cancelled.');
        }

        const verifyPayload = {
            id: assertion.id,
            rawId: this.bufferToBase64Url(assertion.rawId),
            type: assertion.type,
            response: {
                clientDataJSON: this.bufferToBase64Url(assertion.response.clientDataJSON),
                authenticatorData: this.bufferToBase64Url(assertion.response.authenticatorData),
                signature: this.bufferToBase64Url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? this.bufferToBase64Url(assertion.response.userHandle) : null
            }
        };

        const res = await API.request('/api/auth/webauthn/login-verify', {
            method: 'POST',
            body: JSON.stringify(verifyPayload)
        });

        API.setToken(res.token);
        const me = await API.getMe();
        API.setUser(me);
        return me;
    },

    // =========================================================================
    // 4. ACTION-TIME BIOMETRIC VERIFICATION (DOWNLOAD & EDIT)
    // =========================================================================
    async authorizeActionWithBiometrics(documentId, action = 'DOWNLOAD') {
        const effectiveAction = action.toUpperCase();

        if (!this.isAvailable()) {
            throw new Error(`WebAuthn Biometric verification is required before ${effectiveAction} action.`);
        }

        // 1. Request action challenge
        const challengeRes = await API.request(`/api/auth/webauthn/action-challenge?docId=${encodeURIComponent(documentId)}&action=${effectiveAction}`, {
            method: 'POST'
        });

        const allowCredentials = (challengeRes.allowCredentials || []).map(c => ({
            type: c.type,
            id: this.base64UrlToBuffer(c.id)
        }));

        const getOptions = {
            challenge: this.base64UrlToBuffer(challengeRes.challenge),
            timeout: challengeRes.timeout || 60000,
            rpId: challengeRes.rpId || window.location.hostname
        };

        if (allowCredentials.length > 0) {
            getOptions.allowCredentials = allowCredentials;
        }

        // 2. Prompt user device authenticator (Fingerprint, Face, Windows Hello, YubiKey)
        let assertion;
        try {
            assertion = await navigator.credentials.get({
                publicKey: getOptions
            });
        } catch (err) {
            throw new Error(`Biometric verification cancelled. Zero-trust ${effectiveAction} action terminated.`);
        }

        if (!assertion) {
            throw new Error(`Biometric assertion missing. ${effectiveAction} action blocked.`);
        }

        // 3. Verify assertion on server
        const verifyPayload = {
            id: assertion.id,
            rawId: this.bufferToBase64Url(assertion.rawId),
            type: assertion.type,
            documentId: documentId,
            response: {
                clientDataJSON: this.bufferToBase64Url(assertion.response.clientDataJSON),
                authenticatorData: this.bufferToBase64Url(assertion.response.authenticatorData),
                signature: this.bufferToBase64Url(assertion.response.signature)
            }
        };

        const verifyRes = await API.request(`/api/auth/webauthn/action-verify?docId=${encodeURIComponent(documentId)}&action=${effectiveAction}`, {
            method: 'POST',
            body: JSON.stringify(verifyPayload)
        });

        return verifyRes.passkeyToken;
    },

    async authorizeDownloadWithBiometrics(documentId) {
        return await this.authorizeActionWithBiometrics(documentId, 'DOWNLOAD');
    },

    async authorizeEditWithBiometrics(documentId) {
        return await this.authorizeActionWithBiometrics(documentId, 'EDIT');
    }
};

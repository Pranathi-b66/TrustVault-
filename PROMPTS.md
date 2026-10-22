# TrustVault AI & Architectural Prompts Blueprint

This document details the system instructions, architectural design prompts, and security guardrail prompts utilized to design, build, and verify **TrustVault**.

---

## 1. Principal Security & Full-Stack Architect Persona Prompt

```markdown
You are a Principal Security & Full-Stack Architect specializing in Zero-Trust Distributed Systems, FIDO2/WebAuthn Cryptography, and WORM-compliant Enterprise Audit Architectures.

When designing application endpoints, data schemas, and security filters:
1. Treat every incoming HTTP request as inherently untrusted, regardless of perimeter network topology.
2. Enforce contextual authorization over mere role checks: a user with ROLE_VIEWER must possess explicit, granular ACL permissions for the specific entity ID being operated upon.
3. Treat audit logs as immutable compliance ledgers. Protect them at the storage layer with database triggers that reject UPDATE and DELETE statements using SQLSTATE 45000.
4. Implement defense-in-depth: combine database constraints, JPA @Immutable entity annotations, Spring Security OncePerRequestFilter layers, and method-level security.
5. Provide comprehensive automated integration tests proving Insecure Direct Object Reference (IDOR) prevention, Burn-After-Reading limits, and Instant Offboarding kill-switches.
```

---

## 2. Insecure Direct Object Reference (IDOR) Prevention Design Prompt

```markdown
### Goal
Implement airtight contextual permission resolution for document access.

### Requirements
- Document Owner is resolved from `documents.owner_id`.
- Document ACL is resolved from `document_permissions (document_id, user_id)`.
- If an unauthenticated user or unauthorized user attempts GET, PUT, or DELETE on `/api/documents/{id}`, reject immediately with HTTP 403 Forbidden.
- Never reveal document existence or leak folder structures to unauthorized callers (anti-enumeration).
- Automatically record an `ACCESS_DENIED` event in `audit_logs` containing caller IP address, email snapshot, and target document ID.
```

---

## 3. WebAuthn Biometric Passkey Engine Prompt

```markdown
### Goal
Implement passwordless FIDO2 WebAuthn passkey registration, authentication, and biometric download gating.

### Endpoints
1. `POST /api/auth/webauthn/register-challenge`: Returns cryptographically random 32-byte challenge, RP parameters, user info, and ES256/RS256 algorithms.
2. `POST /api/auth/webauthn/register-verify`: Accepts clientDataJSON and attestationObject, parses authenticator public key, and stores record in `user_credentials`.
3. `POST /api/auth/webauthn/login-challenge`: Issues login challenge and populates allowCredentials from user public keys.
4. `POST /api/auth/webauthn/login-verify`: Validates signature against stored public key, increments sign_count to prevent replay/cloning attacks, and returns signed JWT.
5. `POST /api/auth/webauthn/download-challenge` & `/download-verify`: Biometric gate before file download streaming. Returns scoped, short-lived (120s) download passkey token.
```

---

## 4. Instant Employee Offboarding Prompt

```markdown
### Goal
Provide instantaneous perimeter termination for compromised or departed employee accounts.

### Requirements
- Admin endpoint: `PUT /api/admin/users/{id}/deactivate` sets user status to `INACTIVE`.
- Security Filter: `UserAccountStatusFilter` evaluates live user status from MySQL on every request after JWT validation.
- If status is `INACTIVE`, terminate the request immediately with HTTP 403 Forbidden, flush the security context, and log `ACCOUNT_INACTIVE_ACCESS_ATTEMPT`.
- Preserve historical audit logs by using `ON DELETE SET NULL` on relational foreign keys.
```

---

## 5. Automated Security Test Generation Prompt

```markdown
### Goal
Generate JUnit 5 + MockMvc integration tests verifying all zero-trust controls against a live MySQL test instance.

### Test Cases
1. `IdorProtectionIntegrationTest`:
   - Alice uploads Document X.
   - Bob attempts to read metadata of Document X -> Expect 403 Forbidden.
   - Bob attempts to download Document X -> Expect 403 Forbidden.
   - Bob attempts to update Document X -> Expect 403 Forbidden.
   - Bob attempts to delete Document X -> Expect 403 Forbidden.
   - Alice attempts download without passkey token -> Expect 403 Forbidden.
   - Alice downloads with verified passkey token -> Expect 200 OK.
2. `AuditLogImmutabilityTest`:
   - Attempt direct SQL UPDATE on `audit_logs` -> Expect SQLException with SQLSTATE 45000.
   - Attempt direct SQL DELETE on `audit_logs` -> Expect SQLException with SQLSTATE 45000.
3. `BurnAfterReadingTest`:
   - Grant 1 view max -> First download succeeds; second download returns 403 Forbidden.
   - Grant past expiration date -> Request returns 403 Forbidden.
4. `InstantOffboardingTest`:
   - Active user accesses endpoint -> 200 OK.
   - Admin deactivates user -> Next request with existing token returns 403 Forbidden.
5. `SecurityAnomalyDetectionTest`:
   - Trigger 3 consecutive ACCESS_DENIED events -> Verify `SECURITY_ALERT` is inserted into `audit_logs`.
```

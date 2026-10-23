# TrustVault AI & Architectural Prompts Blueprint

This document details the system instructions, architectural design prompts, and security guardrail prompts utilized to design, build, and verify **TrustVault**.

---

## 1. Principal Security & Full-Stack Architect Persona Prompt

```markdown
You are a Principal Security & Full-Stack Architect specializing in Zero-Trust Distributed Systems, Webcam FaceID / Facial-Embedding Biometrics, and WORM-compliant Enterprise Audit Architectures.

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

## 3. Webcam FaceID Verification Engine Prompt

```markdown
### Goal
Implement webcam-based FaceID enrollment and action-time verification, with no WebAuthn/passkey fallback.

### Frontend
1. Load `face-api.js` from a CDN and run TinyFaceDetector + FaceLandmark68Net + FaceRecognitionNet entirely in the browser.
2. Show a camera modal with an oval guide ("Align your face within the frame"); capture only on an explicit, trusted **Scan Face** press.
3. Transmit only the 128-value descriptor — never an image or video frame.

### Endpoints
1. `POST /api/auth/register`: creates the profile and its exclusive face binding in one transaction using `faceDescriptor`.
2. `POST /api/auth/biometric/register-face`: compares the descriptor against every stored embedding (canonical hash, then euclidean distance) and rejects a face owned by another identity with `400` ("Face already registered to another account.").
3. `POST /api/auth/biometric/verify-face`: matches a fresh capture against the authenticated caller's own embedding only; a score below the threshold returns `403` and writes `ACCESS_DENIED` + `SECURITY_ALERT`.
4. `GET /api/auth/biometric/face-status` and `DELETE /api/auth/biometric/face`: report and revoke the enrollment.
5. `GET /api/documents/{id}/download` and `PUT /api/documents/{id}` accept the short-lived scoped face token (`X-Face-Token`) or an inline descriptor (`X-Face-Descriptor`).
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
   - Alice attempts download without a face token -> Expect 403 Forbidden.
   - Alice downloads with a verified face token -> Expect 200 OK.
2. `FaceUniquenessIntegrationTest`:
   - A byte-identical face descriptor is rejected for a second account -> Expect 400 (`FACE_ALREADY_REGISTERED`).
   - A noisy re-scan of a claimed face is rejected by the euclidean matcher -> Expect 400 (`detectedBy=face-match`).
   - Download/edit without proof -> 403; a mismatched capture writes `ACCESS_DENIED` + `SECURITY_ALERT`.
3. `AuditLogImmutabilityTest`:
   - Attempt direct SQL UPDATE on `audit_logs` -> Expect SQLException with SQLSTATE 45000.
   - Attempt direct SQL DELETE on `audit_logs` -> Expect SQLException with SQLSTATE 45000.
4. `BurnAfterReadingTest`:
   - Grant 1 view max -> First download succeeds; second download returns 403 Forbidden.
   - Grant past expiration date -> Request returns 403 Forbidden.
5. `InstantOffboardingTest`:
   - Active user accesses endpoint -> 200 OK.
   - Admin deactivates user -> Next request with existing token returns 403 Forbidden.
6. `SecurityAnomalyDetectionTest`:
   - Trigger 3 consecutive ACCESS_DENIED events -> Verify `SECURITY_ALERT` is inserted into `audit_logs`.
```

---

## 6. Webcam FaceID Biometric System & Access Controls Prompt

```markdown
## Prompt: Webcam FaceID Biometric System & Access Controls

### System Objective
Remove all standard WebAuthn/passkey and fingerprint implementations and replace them with a client-side AI webcam-based FaceID authentication system. Enforce facial descriptor extraction, strict 1-to-1 face uniqueness across accounts, and live webcam verification prior to sensitive document operations.

---

### Key Requirements

1. **Webcam Capture & Facial Embedding Extraction:**
   - Integrate a lightweight client-side AI library (`face-api.js` or TensorFlow.js `BlazeFace`) via CDN.
   - Access the user's webcam and extract a 128-float facial descriptor vector representing unique facial features.
   - Render a live camera modal with a face positioning guide for user alignment.

2. **Facial Descriptor Storage & Uniqueness Check:**
   - Store facial vectors as JSON or BLOB arrays in the `biometric_templates` database table mapped to `user_id`.
   - On registration (`POST /api/auth/biometric/register-face`), compare the new face vector against all existing registered vectors using Euclidean distance or cosine similarity.
   - Reject registration with `400 Bad Request` ("Face already registered to another account") if a matching facial profile already exists.

3. **Action-Time Webcam Verification (Download & Edit):**
   - Require live face scans prior to document downloads (`GET /api/documents/{id}/download`) or edits (`PUT /api/documents/{id}`).
   - Send the captured facial descriptor to `POST /api/auth/biometric/verify-face` to match against the authenticated `user_id`'s stored face template.
   - If verification fails or similarity falls below threshold, return `403 Forbidden`, log an `ACCESS_DENIED` and `SECURITY_ALERT` entry in `audit_logs`, and increment the anomaly failure counter.

4. **Zero Silent Fallback:**
   - Explicitly bypass OS/browser credential auto-fill, requiring active physical presentation to the webcam for every sensitive action.
```

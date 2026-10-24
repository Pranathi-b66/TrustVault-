# TrustVault AI & Architectural Prompts Blueprint

This document details the system instructions, architectural design prompts, and security guardrail prompts utilized to design, build, and verify **TrustVault**, the entry for the Snovasys Fresher Hiring Challenge 2026.

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

---

## 7. Core Biometric & Authorization Hardening Prompts

### Prompt 7.1: WebCam FaceID Liveness & Distance Threshold Tuning
> **Prompt:**
> "Act as a Senior Security Engineer. Upgrade the client-side webcam FaceID authentication system in TrustVault:
> 1. Implement Client-Side Liveness Detection: Integrate motion variance checks (e.g., optical flow / blink / head movement prompts) in `face-api.js` / TensorFlow.js prior to descriptor extraction to prevent presentation attacks using static photos or screen displays.
> 2. Fine-Tune Distance Thresholding: Enforce a strict server-side Euclidean distance matching threshold ($d \le 0.40$) on `POST /api/auth/biometric/verify-face`.
> 3. Real-Time UI Feedback: Provide immediate environmental guidance on the webcam overlay ('Adjust lighting', 'Center face in frame') if frame confidence is low."

---

### Prompt 7.2: Timestamped Cryptographic Challenge Nonces (Anti-Replay)
> **Prompt:**
> "Prevent replay attacks on biometric vector payloads:
> 1. Expose `POST /api/auth/biometric/challenge` to issue a short-lived, single-use cryptographic challenge nonce valid for $< 30$ seconds.
> 2. Mandate that `POST /api/auth/biometric/verify-face` submit this nonce alongside the 128-float facial vector.
> 3. Reject any expired, missing, or previously consumed nonces with `403 Forbidden` and log a `REPLAY_ATTEMPT_DETECTED` anomaly event."

---

### Prompt 7.3: Real-Time Middleware Permission Check (IDOR & Revocation Patch)
> **Prompt:**
> "Fix potential IDOR and stale authorization flaws on document endpoints:
> 1. Ensure `GET /api/documents/{id}/download` and `PUT /api/documents/{id}` NEVER rely solely on cached JWT claims or initial session state.
> 2. Execute a mandatory real-time database query on every transaction verifying that `authenticated_user_id` is the document `owner_id`, an active `ADMIN`, or possesses an explicit active entry in `shared_permissions`.
> 3. Immediately return `403 Forbidden` if permissions were revoked mid-session prior to streaming file bytes."

---

## 8. Advanced Admin Security & Forensics Prompts

### Prompt 8.1: Emergency Global Kill Switch
> **Prompt:**
> "Implement a high-priority administrative control endpoint `POST /api/admin/system/lockdown`:
> 1. When activated (`SYSTEM_LOCKDOWN = true`), maintain an atomic global flag in backend state.
> 2. Intercept all incoming non-Admin requests for document downloads, edits, and uploads, returning `503 Service Unavailable` ('System is under administrative security lockdown').
> 3. Keep administrative controls active so admins can isolate threats and manage system state. Log a high-severity `SYSTEM_LOCKDOWN_TRIGGERED` WORM audit event."

---

### Prompt 8.2: Action Replay Forensic System (Before/After State Diffing)
> **Prompt:**
> "Build an Action Replay Forensic System for compliance and non-repudiation:
> 1. Update the `audit_logs` schema to store JSON structures for `pre_state` and `post_state`.
> 2. On any administrative mutation (role changes, user deletions, policy updates), capture resource snapshots before and immediately after execution.
> 3. Expose `GET /api/admin/audit/{id}/diff` and build a side-by-side visual diff modal in the Admin UI showing highlighted modifications (added, removed, or altered fields)."

---

## 9. Professional UI Design System Prompt

### Prompt 9.1: Enterprise White & Royal Blue Design System
> **Prompt:**
> "Redesign the TrustVault UI into a sleek, professional enterprise platform:
> 1. Palette: White background (`#FFFFFF`), neutral subtle cards (`#F8FAFC`), soft borders (`#E2E8F0`), primary accent Royal/Navy Blue (`#1E40AF` / `#2563EB`), emerald green for security verification (`#10B981`), and crimson for alerts (`#EF4444`).
> 2. FaceID Modal: Frosted glass overlay with a glowing royal blue oval scanner guide and real-time status text.
> 3. Admin Tools: Clean side-by-side green/red diff viewer for Action Replay and a high-visibility toggle switch for the Emergency Kill Switch."

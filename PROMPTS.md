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

---

### Prompt 9.2: Share Email Autocomplete & Production Surface Cleanup
> **Prompt:**
> "Make the workspace indistinguishable from a production deployment:
> 1. Remove every floating demo toggle, mock role switcher, and testing banner — including the quick-fill credential chips on the auth card — so no control implies a sandbox mode.
> 2. Turn the grantee field of the sharing modal into an accessible combobox: query `GET /api/share-candidates?q=`, anchor a keyboard-navigable listbox directly beneath the input, and render each entry as name, email, and role badge.
> 3. Bound the directory: active identities only, the caller excluded, at most 8 rows per query, and only `id`, `email`, `fullName`, `role` in the payload. Strip `%`, `_`, and `\` from the term so a crafted query can never widen the substring search into a registry dump.
> 4. Keep the field free-text for external recipients, suppress the dropdown until the input is actually focused, and never surface an empty-state message for an empty query."

---

### Prompt 9.3: FaceID Liveness Copy Revision (Head-Turn)
> **Prompt:**
> "Revise the FaceID liveness wording across every user-facing surface:
> 1. Replace all blink and nod instructions with one unambiguous phrase: 'Turn head slightly left or right'.
> 2. Apply it to the camera overlay timeline, the Scan Face button label, the enrollment, authorization, and capture subtitles, and both success and failure messages.
> 3. Restrict the change to copy — leave detector internals and thresholds untouched — then re-run `scripts/liveness-simulation.js` and `node --check` to prove the state machine and scripts still behave identically."

---

## 10. Data Lifecycle, Role Consolidation & Operational Readiness Prompts

### Prompt 10.1: Complete Data Purge, WORM-Safe, and Sequence Reset
> **Prompt:**
> "Act as a DBA and produce an idempotent reset script for TrustVault:
> 1. Purge users, biometric_templates, biometric_challenges, documents, document_permissions, audit_logs, and system_settings while foreign keys are disabled, truncating audit_logs with DDL because its append-only triggers reject DELETE.
> 2. Cover tables that may not exist in every environment (`shared_permissions`, `pending_admin_actions`, `user_risk_scores`) by probing `information_schema` and preparing the statement dynamically.
> 3. Reset every primary-key sequence to 1 through a cursor over `information_schema.TABLES`, not a concatenated statement list — a prepared statement carries exactly one statement. The schema uses UUID keys today, so the step is a no-op guard rather than a live counter.
> 4. Finish with a UNION verification that prints the row count of every table, and document that the running JVM must restart so in-memory anomaly counters do not survive the purge."

---

### Prompt 10.2: Unified OWNER/VIEWER Vault Baseline
> **Prompt:**
> "Consolidate authorization roles without over-separating them:
> 1. OWNER and VIEWER are not privilege tiers. Both hold the same vault baseline — upload, search, read, download, and management of the documents they own — and both may hold or receive ACL grants.
> 2. What distinguishes two identities is their position relative to a document (owner row, live grant, or neither), resolved per transaction from the database rather than from the label.
> 3. ADMIN is the only genuine separation: security console, kill switch, immutable-trail access, and ACL override. No document-workspace path may treat an administrator as a superior reader.
> 4. Express the distinction with a single `isAdministrator()` helper and replace every `Role.ADMIN` comparison, so the rule cannot drift back into scattered equality checks."

---

### Prompt 10.3: Break-Glass Emergency Access (Evidence, Not Authorization)
> **Prompt:**
> "Add accountable emergency access without weakening any existing gate:
> 1. Append `BREAK_GLASS_ACCESS` to the `audit_logs.action` enum through a standalone migration that can be applied to an existing database.
> 2. Expose an admin-only `POST /api/admin/break-glass` taking `documentId` and a 10–500 character justification; record actor email, client IP, document id, owner, and reason on the WORM trail, and return the evidence row id.
> 3. The declaration authorizes nothing: the emergency download that follows still requires a live face token, and burn-after-reading quotas still apply. Return `404` for an unknown document without writing evidence.
> 4. Prove it with integration tests covering the evidence row, absent authorization, non-admin rejection, short justification rejection, and the 404 path."

---

### Prompt 10.4: Empty-Start Identity Bootstrap
> **Prompt:**
> "Guarantee that a purged database stays empty:
> 1. Gate the demo account seeding behind `trustvault.bootstrap.seed-default-users=false` and skip it entirely when the flag is off.
> 2. Create the first identity through the FaceID sign-up flow, choosing the administrator role at registration.
> 3. Keep the seeded credentials out of the startup path unless the flag is explicitly enabled, so a fresh deployment has no known accounts."

---

### Prompt 10.5: Manual Verification Runbook for a Fresh System
> **Prompt:**
> "Author an operator runbook that takes a reset database to a verified end state:
> 1. (a) Register an administrator and two members with FaceID enrollment, then prove 1-to-1 uniqueness by attempting a duplicate face and a duplicate email.
> 2. (b) Upload documents, share one through the autocomplete modal, and confirm the burn-after-reading quota is consumed.
> 3. (c) Trigger three consecutive face mismatches and an IDOR read to populate the anomaly feed and audit trail.
> 4. (d) Exercise the kill switch, a break-glass declaration, and the Action Replay JSON diff.
> 5. For every step, list the exact command or UI action, the expected response, and the expected audit action; target one real audit row with an UPDATE to show SQLSTATE 45000, and close with a troubleshooting table."

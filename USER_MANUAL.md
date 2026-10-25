# TrustVault User Manual

TrustVault is a web application for storing documents and sharing them with registered accounts under owner-controlled permissions. What makes it unusual is that a signed-in session is not enough to open a file: every read, download, and metadata change also requires a **live webcam face scan** matched against the face bound to that account, and every attempt — successful or refused — is appended to an audit ledger that the application cannot rewrite.

The instructions below describe the features present in this repository. Account creation, face enrollment, document storage, and sharing all run inside this application; there is no external identity provider and no email-based invitation flow.

**Live application:** open the TrustVault sign-in page at the address your administrator provides. A local installation defaults to `http://localhost:8088`.

---

## Contents

| Section | Covers | Audience |
|---|---|---|
| [1. Introduction](#1-introduction) | What TrustVault is, what it is not, who can do what | Everyone |
| [2. How TrustVault works](#2-how-trustvault-works) | Components, request lifecycles, data model, configuration, security boundaries | Everyone; administrators in depth |
| [3. Getting started](#3-getting-started) | Registration, role choice, FaceID enrollment, liveness, sign-in | Everyone |
| [4. The workspace](#4-the-workspace) | Header, tabs, tables, badges, messages, empty states | Everyone |
| [5. Uploading documents](#5-uploading-documents) | Fields, categories, limits, validation, failure handling | Everyone |
| [6. Opening and downloading](#6-opening-and-downloading) | Face gate, burn-after-reading, what a download really means | Everyone |
| [7. Editing a document](#7-editing-a-document) | Who may edit, what changes, what is recorded | Everyone |
| [8. Deleting a document](#8-deleting-a-document) | Owner/administrator purge, what survives | Everyone |
| [9. Sharing and access control](#9-sharing-and-access-control) | Recipient autocomplete, levels, burn limits, expiry, revocation | Everyone |
| [10. Roles and permissions](#10-roles-and-permissions) | Platform roles, document position, capability matrix | Everyone |
| [11. Searching](#11-searching) | Filters, scoping, why results are always authorized | Everyone |
| [12. FaceID in detail](#12-faceid-in-detail) | Storage, uniqueness, challenges, thresholds, failure codes, privacy | Everyone |
| [13. Audits and anomaly monitoring](#13-audits-and-anomaly-monitoring) | WORM ledger, action catalog, detection, risk posture, response | Everyone; administrators in depth |
| [14. Administrator guide](#14-administrator-guide) | Kill switch, Action Replay, break-glass, offboarding, hardening | Administrators |
| [15. Security and privacy guidance](#15-security-and-privacy-guidance) | Operating rules for everyday use | Everyone |
| [16. Troubleshooting](#16-troubleshooting) | Symptom → cause → action, by area | Everyone |
| [17. FAQ](#17-faq) | Short answers to the questions support hears most | Everyone |
| [18. Quick-start checklist](#18-quick-start-checklist) | First-run and incident checklists | Everyone |
| [19. Appendix](#19-appendix) | Glossary, error codes, configuration, retention, document control | Everyone |

---

## 1. Introduction

### 1.1 What TrustVault does

TrustVault lets a signed-in person:

1. upload a document into a private vault;
2. classify and search it;
3. grant specific registered accounts read or edit access, optionally limited by a view budget or an expiry date;
4. read, download, or edit the document only after a live face match; and
5. see exactly who did what, when, and from which IP address, in an immutable trail.

Administrators get a separate console for containment and forensics: a platform-wide kill switch, an anomaly feed, per-row audit replay, break-glass declarations, identity offboarding, and role changes. Being an administrator does not silently open other people's documents; it adds an override that is itself audited, plus the tools to review that override afterwards.

### 1.2 What TrustVault is not

| Not this | Why it matters |
|---|---|
| An anonymous file-sharing service | There is no public link type. Every recipient must already have an account. |
| A password-only vault | A stolen password opens the workspace but not a single document byte; the face gate still stands in the way. |
| A cloud storage sync client | Files are stored on the server that runs the application, under a randomized name. |
| A version-control system | A document has one current payload. Editing changes metadata, not the file body. |
| A forensic time machine for deleted content | Deletion removes the payload. The audit trail remembers that it existed and who removed it, not its bytes. |
| An email notification system | All feedback is in-app. No invitation, reminder, or alert email is sent. |

### 1.3 Who can do what, at a glance

| Capability | Member (`OWNER` / `VIEWER`) | Administrator (`ADMIN`) |
|---|---|---|
| Sign in with password | Yes | Yes |
| Upload documents | Yes | Yes |
| Search what you may access | Yes | Yes |
| Read/download what you own or were granted | Yes, face-gated | Yes, face-gated |
| Edit what you own or were granted at `EDIT` | Yes, face-gated | Yes, face-gated |
| Delete what you own | Yes | Yes — any document |
| Grant / revoke access | Owner of that document only | No — ownership is required even for admins |
| Inspect a document's ACL | Owner only | Yes |
| Security console, kill switch, WORM trail, replay, break-glass | No | Yes |
| Deactivate identities, change roles | No | Yes |

> **The one-sentence version:** `OWNER` and `VIEWER` are two labels for the same vault workspace; `ADMIN` adds the security console. Access to a specific document is decided by your *position* relative to it — owner, grantee, or neither — never by your label.

### 1.4 How this manual is organized

Sections 2 through 11 explain the product as you will experience it. Sections 12 and 13 explain the security machinery underneath it. Section 14 is the administrator runbook. Sections 15 through 19 are reference material you can jump to when something goes wrong.

---

## 2. How TrustVault Works

### 2.1 The components

| Component | Technology | Responsibility |
|---|---|---|
| Browser client | Static HTML, Tailwind CSS, vanilla JavaScript | Renders the workspace, captures the webcam stream, computes a face descriptor locally, drives the liveness state machine |
| Face library | `face-api.js` 1.7.15 from a CDN, with models loaded from the same CDN | Tiny face detection, 68-point landmarks, 128-value face embedding |
| API server | Spring Boot 3.3.x on Java 24, stateless Spring Security | Authentication, authorization, face verification, audit writes, file streaming |
| Database | MySQL 8.0 | Identities, documents, ACL grants, biometric templates, challenges, audit ledger, platform settings |
| File store | Filesystem directory configured by `trustvault.upload.dir` (default `uploads/`) | Holds document payloads under UUID filenames |
| Crypto | AES-256-GCM (biometric templates only), BCrypt (passwords), JJWT (tokens) | Seals descriptors, hashes passwords, mints sessions and short-lived action tokens |

A request travels through five gates in a fixed order. Each gate is independent; passing one grants nothing to the next.

```
Browser  ── HTTPS + "Authorization: Bearer <jwt>" ──▶  Spring Boot API
                                                          │
                                    1. JwtAuthenticationFilter
                                    2. UserAccountStatusFilter
                                    3. SystemLockdownFilter
                                    4. PermissionService  (live ACL, per transaction)
                                    5. FaceGateService    (challenge / action token)
                                                          │
                                                          ▼
                        MySQL: users, documents, document_permissions,
                               biometric_templates, biometric_challenges,
                               audit_logs, system_settings
                        Disk:  uploads/<uuid>.<ext>
```

### 2.2 Gate 1 — identity

Signing in exchanges your email and password for a signed JSON Web Token that lives for 24 hours. The token carries your user id, email, and role, and the browser sends it on every request.

A token is evidence of *who signed in earlier*, not proof of *who is calling now*. That is why the next gate exists.

### 2.3 Gate 2 — live account status

On every request, the server re-reads your account row. If the account was deactivated or its role was changed after your token was minted, the new truth wins immediately:

| Change made by an administrator | Effect on your open session |
|---|---|
| Deactivation | Next request returns `403`; the token is useless from that moment |
| Role change (e.g. `ADMIN` → `VIEWER`) | Next request is authorized with the new role, not the badge in your browser |
| Deletion | Next request reports an authentication failure |

No re-login dance is required for the change to bite, and no cached claim can delay it.

### 2.4 Gate 3 — the global kill switch

If an administrator has engaged the lockdown flag, every non-administrator request and **every** document operation returns `503 Service Unavailable` with a fixed message. Administrators keep the console so they can investigate and lift the lockdown. The stored incident reason is never disclosed to blocked callers.

### 2.5 Gate 4 — authorization against the live ACL

Before any document byte is read or any field is mutated, `PermissionService` answers one question from the database:

1. Are you the owner of this document? → allowed at owner level.
2. Are you an administrator *right now*? → allowed at admin level.
3. Do you hold an active grant that satisfies the required level, is not expired, and has budget left? → allowed at that level.
4. Otherwise → `403` and an `ACCESS_DENIED` row, before anything is read or changed.

Because the answer is recomputed on every transaction, a revoked grant cannot survive in a stale tab. The only delay is your own next click.

### 2.6 Gate 5 — the live face

For downloads and metadata edits, an ACL is not enough. You must also present face proof in one of two forms:

| Proof | What it is | Lifetime |
|---|---|---|
| Action token | Minted by `POST /api/auth/biometric/verify-face` after a successful match; bound to your user id, this document, and this action | 2 minutes |
| Fresh descriptor + challenge | A newly captured 128-value embedding sent with the single-use challenge that authorized it | Challenge: 30 seconds |

There is no bypass, no debug flag, and no "remember this scan" option. An unproven request is refused, audited as `ACCESS_DENIED` and `SECURITY_ALERT`, and counted by the anomaly detector.

### 2.7 What happens during each operation

**Signing in**

1. Your password is checked against a BCrypt hash.
2. If the account is `INACTIVE`, sign-in is refused.
3. The server mints a 24-hour token and returns your profile plus a `faceEnrolled` flag.
4. The browser stores the token and renders the dashboard.

**Registering**

1. The browser captures your face locally and computes a descriptor.
2. It submits email, password, full name, role, and descriptor in one request.
3. The server checks the descriptor is not already bound to another identity — inside the scan, an exact hash match and a nearest-neighbour comparison both run.
4. It creates the account and the enrollment in the same transaction.
5. If the face cannot be bound, the account is rolled back with it; no half-registered identity exists.

**Uploading**

1. The server validates size, MIME type, and filename.
2. The file is written to disk under a random name; the extension is preserved but sanitized.
3. A `documents` row is inserted (title, category, size, MIME type, owner, timestamps).
4. An `UPLOAD` audit row is written carrying the document snapshot.
5. The response reports your effective role as `OWNER`.

**Downloading**

1. `requireLiveAccess(..., READ)` re-reads your account and resolves the ACL.
2. `FaceGateService` validates your action token or verifies your descriptor against *your own* template.
3. `evaluateAndConsumeAccess(..., read = true)` applies expiry and view budget, consuming one view.
4. Bytes are read from disk.
5. A `READ` audit row is written and the file is streamed back.

**Editing**

1. `requireLiveAccess(..., EDIT)` accepts owner, administrator, or `EDIT` grant only.
2. The face gate runs for the `EDIT` action.
3. A `pre_state` snapshot is taken.
4. Title and/or category are updated, then a `post_state` snapshot is taken.
5. An `EDIT` row is written with both snapshots, making the change replayable.

**Sharing**

1. The server confirms you own the document.
2. The recipient must be a registered identity, and cannot be you.
3. An existing grant is updated in place; otherwise a new one is created with a view counter at zero.
4. A `GRANT` row records `policyAction: CREATE` or `policyAction: UPDATE` with before/after policy snapshots.

### 2.8 The data model

| Table | Entity | Key columns | Purpose |
|---|---|---|---|
| `users` | `User` | `id` (UUID), `email` (unique), `password_hash`, `full_name`, `role`, `status` | Identities and their platform role |
| `documents` | `Document` | `id`, `title`, `file_path`, `file_size_bytes`, `mime_type`, `category`, `owner_id`, timestamps | Document metadata and payload location |
| `document_permissions` | `DocumentPermission` | `id`, `document_id`, `user_id`, `permission_level`, `max_views`, `views_count`, `expires_at`, `granted_by`, `granted_at` | Per-document ACL grants; unique per document + user |
| `biometric_templates` | `FaceEnrollment` | `id`, `user_id` (unique), `email` (unique), `face_hash` (unique), `face_descriptor` (sealed), `algorithm_version`, `embedding_size` | One face per identity, stored encrypted |
| `biometric_challenges` | `BiometricChallenge` | `id`, `user_id`, `document_id`, `action`, `token_hash`, `issued_at`, `expires_at`, `consumed_at`, `client_ip` | Single-use replay-prevention ledger |
| `audit_logs` | `AuditLog` | `id`, `user_id`, `user_email`, `action`, `document_id`, `ip_address`, `status`, `details`, `pre_state`, `post_state`, `timestamp` | Append-only WORM ledger |
| `system_settings` | `SystemSetting` | key/value pairs | Persists the lockdown flag across restarts |

Three unique constraints on `biometric_templates` enforce the biometric contract at the storage layer: one enrollment per account, one per email address, and one account per face hash.

### 2.9 Settings that shape behaviour

| Property | Default | What it controls |
|---|---|---|
| `server.port` | `8088` | HTTP port |
| `spring.servlet.multipart.max-file-size` | `20MB` | Largest accepted upload |
| `spring.servlet.multipart.max-request-size` | `20MB` | Largest accepted multipart request |
| `trustvault.jwt.expiration-ms` | `86400000` | Session lifetime (24 hours) |
| `trustvault.upload.dir` | `uploads` | Where payloads are written |
| `trustvault.bootstrap.seed-default-users` | `false` | Whether demo identities are created at startup |
| `trustvault.face.match-threshold` | `0.40` | Similarity floor used by the duplicate-enrollment scan |
| `trustvault.face.verify-max-distance` | `0.60` | Strict Euclidean ceiling for an identity match (can only be tightened) |
| `trustvault.face.challenge-ttl-seconds` | `30` | Challenge lifetime; values above 30 are clamped |
| `trustvault.face.challenge-clock-skew-seconds` | `5` | Tolerated clock drift when redeeming |
| `trustvault.face.max-candidates` | `5000` | Enrollments compared during a duplicate scan |
| `trustvault.face.descriptor-size` | `128` | Embedding dimension |
| `trustvault.face.encryption-key` | *(configured)* | AES-256-GCM key sealing stored descriptors |

### 2.10 Security boundaries, and who enforces them

| Boundary | Enforced by | Can the UI bypass it? |
|---|---|---|
| Who you are | JWT signature + database lookup | No |
| Whether your account is still allowed | `UserAccountStatusFilter` | No |
| Whether the platform is frozen | `SystemLockdownFilter` | No |
| Whether you may touch this document | `PermissionService` per transaction | No |
| Whether a live person is present | `FaceGateService` + biometric challenge | No |
| Whether a file was uploaded safely | Size, MIME, and filename validation server-side | No |
| Whether history can be rewritten | MySQL row triggers raising `SQLSTATE 45000` | No |
| Whether a payload is encrypted on disk | **Nothing — see 2.11** | Not applicable |

### 2.11 An honest note about encryption at rest

The product interface says "Upload & Encrypt", and the biometric side genuinely is encrypted: each stored face descriptor is sealed with AES-256-GCM and can only be opened with the configured key.

Document payloads in this build are **not** encrypted at the file level. `FileStorageService` writes the uploaded bytes to `trustvault.upload.dir` under a random filename, and `loadFileBytes` reads them back verbatim. Confidentiality for those bytes depends on:

1. the application-layer gates described above (ACL + face) controlling who can request them; and
2. filesystem and volume encryption, plus restrictive file permissions, on the host.

If your organization requires cryptographic protection of stored files, enable full-disk or volume encryption, or place the upload directory on an encrypted mount. Treat this as an operator responsibility, not a shipped feature.

---

## 3. Getting Started

### 3.1 Before you begin

| Requirement | Detail |
|---|---|
| Browser | A current Chromium-based browser, Firefox, or Safari |
| Webcam | Built in or USB, unobstructed and uncovered |
| Lighting | Even front lighting; avoid a bright window behind you |
| Camera permission | Must be granted to the TrustVault origin when prompted |
| Secure context | `https://` or `localhost` — browsers only expose the camera there |
| Internet access | Required on first use: the face library and its models come from a CDN |
| A document to store | Nothing else is needed; an account can exist with an empty vault |

> **Privacy first:** the webcam stream is processed entirely in your browser. No frame or image is uploaded. Only a 128-number embedding is sent, and it is sealed on arrival.

### 3.2 Create your account

1. Open the TrustVault URL.
2. On the **TrustVault Access** card, select the **Register** tab.
3. Enter your **Full Name**. This name appears alongside your email in audit records and recipient suggestions, so use the form your organization recognizes.
4. Enter your **Email Address**. It becomes your permanent audit identity and cannot be changed later by you.
5. Choose a **Password**.
6. Select an **Assigned Platform Role** (see 3.3).
7. Select **Register & Bind FaceID**.
8. The **Mandatory Webcam FaceID Enrollment** dialog opens. Complete the scan described in 3.4.
9. On success you are signed in and land on **My Vault Assets**, with a confirmation toast naming the account the face was bound to.

| Field | Required | Notes |
|---|---|---|
| Full Name | Yes | Stored as entered; used in the UI and in audit context |
| Email Address | Yes | Must be unique; duplicates are rejected before any row is created |
| Password | Yes | Non-empty; hashed with BCrypt; no complexity rule is enforced (see the note below) |
| Platform Role | No | Defaults to `VIEWER` if omitted |
| Face descriptor | Yes | Registration cannot complete without a live scan |

> **Password policy is your responsibility.** This build does not enforce a minimum length or character mix — the form only says "Choose a strong password". Use a long, unique passphrase from a password manager. The face gate limits the damage of a stolen password, but it does not make a weak one acceptable.

> **Registration accepts the role you choose, including `ADMIN`.** That is convenient for a controlled demo and unacceptable for a public deployment. See 14.10 for the hardening step.

### 3.3 Choosing a role label

| Option in the form | Stored value | Choose it when |
|---|---|---|
| MEMBER (Vault Workspace) | `VIEWER` | You work with documents and do not administer the platform |
| MEMBER (Vault Workspace, Owner-Label) | `OWNER` | Same permissions as above; the label is cosmetic |
| ADMIN (Security Console & Operations) | `ADMIN` | You are a security operator and need the console |

The helper text under the selector states the rule plainly: `OWNER` and `VIEWER` share the same vault baseline; only `ADMIN` is separated. Choosing `OWNER` does not give you extra rights over anyone else's documents, and choosing `VIEWER` does not stop you from owning your own.

**What each label actually changes**

| Label | Upload | Manage own documents | Console | Override others' documents |
|---|---|---|---|---|
| `VIEWER` | Yes | Yes | No | No |
| `OWNER` | Yes | Yes | No | No |
| `ADMIN` | Yes | Yes | Yes | Yes, audited |

### 3.4 Bind your FaceID

Enrollment normally happens during registration. You can repeat it later from the header.

1. Select **Enroll Face** in the top navigation bar (or trigger it from a download prompt when no face is enrolled).
2. Read the dialog titled **Mandatory Webcam FaceID Enrollment**.
3. Wait for `Initialising webcam...` to resolve into live video.
4. Center your face inside the oval guide, filling most of it with a small margin.
5. Follow the on-screen cue: **Turn head slightly left or right**.
6. Select **Scan Face & Register** once — the models load from the CDN on first use, which can take a few seconds.
7. Wait for the success toast: *"Face descriptor enrolled. Download and edit actions now require a live face match."*

| Stage | What you see | What it means |
|---|---|---|
| Model load | Status strip shows an activity tone | Three neural networks are downloading |
| Camera start | Live video, mirrored, with an oval | Camera permission granted |
| Guidance | Badge reads "Turn head slightly left or right" | The liveness challenge is armed |
| Capture | Progress or success tone | A descriptor was extracted from a live face |
| Completion | Green confirmation | Template sealed with AES-256-GCM and bound |

> **One face, one identity.** Your descriptor's canonical hash and its nearest-neighbour match are both checked against every other enrollment (up to 5,000) before binding. A face already registered elsewhere is refused with `FACE_ALREADY_REGISTERED`, and the attempt is written to the audit trail as a `SECURITY_ALERT`.

### 3.5 Pass the liveness check

The liveness check exists to defeat the oldest biometric attack: holding up a photograph. TrustVault asks for a head-pose change because a static image cannot turn.

1. Hold still inside the oval for about a second so the detector locks on.
2. When prompted, turn your head **slightly left** — a gentle rotation, not a look over the shoulder.
3. Return to center, then turn **slightly right** if the prompt repeats.
4. Keep both eyes visible and your face inside the guide.
5. Select **Scan Face** (during registration, **Scan Face & Register**).
6. Do not close the dialog while the status strip is active; cancelling releases the camera without consuming anything.

**What the system is measuring**

| Signal | Why it matters |
|---|---|
| Eye aspect ratio | A live face blinks; a printout never does |
| Nose displacement (head pose) | A flat image cannot rotate in depth |
| Frame-to-frame luminance change | A still or paused video is temporally inert |
| Face size and centering | A capture from across the room is too low-quality to enroll |
| Detector confidence | Low-confidence vectors are never submitted |

**If the scan will not complete**

| Message / symptom | Cause | Action |
|---|---|---|
| "The face recognition library could not be loaded" | CDN blocked or offline | Restore internet access or allow `cdn.jsdelivr.net`, then retry |
| "Initialising webcam..." never resolves | Camera permission denied or device busy | Allow camera access, close other apps using it, reload |
| "No face detected" | Too dark, too far, occluded | Move to even front light; remove hats or masks; come closer |
| Face rejected as not live | Head turn too small or too fast | Turn slowly through the requested motion and hold briefly |
| Rejected as a mismatch | A different person is in frame | The enrolled account holder must be present |
| `FACE_ALREADY_REGISTERED` | This face belongs to another account | Contact your administrator; this is an investigation trigger |

### 3.6 Sign in

1. Select the **Sign In** tab.
2. Enter your registered **Email Address** and **Password**.
3. Select **Authenticate**.
4. Your role badge, email, and a live status dot appear in the header; the dashboard loads.

| If this happens | It means | Do this |
|---|---|---|
| "Invalid email or password" | Wrong credentials, or the account does not exist | Check spelling and keyboard layout; confirm with your administrator |
| "Account is inactive" | An administrator offboarded the identity | Ask for reactivation; do not create a second account |
| `503 SYSTEM_LOCKDOWN` | The platform is frozen by an administrator | Wait; contact the incident owner |
| 401 immediately after signing in | Token was cleared or expired | Sign in again |
| Dashboard loads but downloads fail | Face not enrolled, or grants missing | Enroll your face; ask the owner for access |

### 3.7 Sign out

1. Select **Logout** in the header.
2. The browser clears the token and profile and returns to the access card.

On a shared or public device, also close the browser. Signing out ends the session; it does not revoke grants or delete your face enrollment.

### 3.8 First-run and demo bootstrap

A purged database stays empty across restarts: `trustvault.bootstrap.seed-default-users` is `false`, and the first identity is expected to arrive through the FaceID sign-up flow.

For a local showcase you can start the application with the flag enabled:

```bash
java -jar target/trustvault-1.0.0.jar --trustvault.bootstrap.seed-default-users=true
```

That creates three demo identities at `trustvault.internal` — an administrator, an owner, and a viewer — with well-known passwords defined in the source. Treat them as compromised by definition: never enable the flag on a reachable deployment, and change or remove them before any pilot.

> **Note:** seeded demo accounts have no face enrollment. They can sign in, but every download and edit will stop at the face gate until a face is bound to each one.

### 3.9 Account lifecycle

| State | How you get there | What you can do |
|---|---|---|
| `ACTIVE` | Registration, or reactivation by an administrator | Everything your role and grants allow |
| `INACTIVE` | An administrator offboards you | Nothing: sign-in is refused and in-flight tokens get `403` |

Deactivation does not delete documents or grants, and reactivation does not restore grants that were revoked while you were inactive. Documents you owned remain yours; a reactivated account can manage them again, but previous recipients must be re-shared deliberately.

---

## 4. The Workspace

### 4.1 The header

| Element | Meaning |
|---|---|
| TrustVault wordmark and **Zero-Trust** chip | Product identity |
| Subtitle | "Webcam FaceID Biometrics • Immutable WORM Compliance" |
| Role badge | Your live platform role, color-coded |
| Email | Your audit identity |
| Status dot | Green pulse while your session is valid |
| **Enroll Face** | Re-bind or first-bind your biometric |
| **Logout** | End the session |

### 4.2 The tabs

| Tab | What it lists | Visible to |
|---|---|---|
| **My Vault Assets** | Documents you own | Everyone |
| **Shared with Me** | Documents granted to you | Everyone |
| **Zero-Trust Search** | Filtered view of everything you may access | Everyone |
| **Security Console** | Counters, kill switch, break-glass, user registry, anomaly feed, WORM trail | Administrators only |

### 4.3 My Vault Assets

Columns: **title**, **category**, **size**, **MIME type**, **created**, and an action cluster.

| Action | Icon | What it does | Face required |
|---|---|---|---|
| **Edit** | pen | Opens metadata editing | Yes, on save |
| **Share & Burn** | user-plus | Opens the ACL dialog | No |
| **Download** | camera | Face-gated download | Yes |
| **Delete** | trash | Purge with confirmation | No |

The badge on the tab counts your documents. The empty state reads: *"No documents found in your private vault. Click 'Upload Document' to ingest."*

### 4.4 Shared with Me

Columns: **title**, **owner email**, **permission level**, **burn badge**, **expiry badge**, and actions.

| Badge | Meaning |
|---|---|
| `READ` | You may read and download; edit is not offered |
| `EDIT` | You may also edit metadata, and the Edit button appears |
| `3/5 views left` | The owner's view budget; each successful read decrements it |
| `Unlimited` | No view limit on your grant |
| `Permanent` | No expiry on your grant |
| A date under a clock icon | The grant expires at that moment |

Actions here are **FaceID Stream** for downloads and, when you hold `EDIT`, **Edit**. Delete and Share are deliberately absent: you are not the owner.

### 4.5 Zero-Trust Search

Three filters — **Title Query**, **Category**, **Owner Email** — plus **Search** and **Reset**. Results show title, category, owner, your effective permission, created date, and a download action.

The empty state is explicit about the model: *"No authorized assets matched query. (Universal visibility blocked)"*. There is no "show everything" mode, because there is no global visibility feature.

Administrators are the one exception in scope: their search runs across the whole corpus and each foreign document is labelled `ADMIN_VIEW`, because reading it will be recorded as an administrative override.

### 4.6 Messages and banners

| Surface | Behavior |
|---|---|
| Toasts | Top-right stack; success (green), warning (amber), error (red), info (slate). They fade on their own. |
| Lockdown banner | Red bar across the top showing **System Lockdown Active**, the reason, and the moment it started |
| Inline table errors | Rendered in place of rows, usually with the server's message |
| Session expiry | A 401 clears the token and returns you to the access card |

### 4.7 Empty states

| Where | Text | What it means |
|---|---|---|
| My Vault Assets | "No documents found in your private vault" | You own nothing yet |
| Shared with Me | "No documents currently shared with your identity" | Nobody granted you access |
| Search | "Enter query to filter your accessible assets" | Idle state before a query |
| Search results | "No authorized assets matched query" | Nothing you may access matches |
| Anomaly feed | "No security anomalies detected" | No threshold has tripped |
| ACL dialog | "No active access rules" area | Nobody has been granted access yet |

---

## 5. Uploading Documents

### 5.1 Upload a document

1. Select **Upload Document** at the top right of the dashboard.
2. In **Secure Document Ingestion**, enter a **Document Title**. If you pick the file first, the title is pre-filled from the filename (without its extension) and can be edited.
3. Choose a **Classification Category**.
4. Click the dashed drop zone and choose a file, or drag one onto it. The placeholder text is replaced with `filename (size)`.
5. Confirm the file is within 20 MB and of an accepted type.
6. Select **Upload & Encrypt**.
7. Wait for the confirmation toast; the asset appears in **My Vault Assets** and the counter increments.

You become the owner automatically. Ownership is what later allows you to share, edit, and delete it.

### 5.2 Fields

| Field | Required | Default if omitted | Notes |
|---|---|---|---|
| Document Title | Recommended | Original filename | Trimmed on save; drives search |
| Classification Category | No | `General` | Chosen from a fixed list |
| File Payload | Yes | — | Non-empty, ≤ 20 MB, allowed MIME type |

### 5.3 Categories

| Category | Use it for |
|---|---|
| Financial | Invoices, statements, payroll exports, budget models |
| Legal | Contracts, NDAs, regulatory filings, board minutes |
| Engineering | Architecture documents, source exports, test evidence |
| HR | Personnel records, reviews, offer letters |
| Confidential | Anything that must stay restricted but fits nowhere else |
| General | Low-sensitivity operational material |

Categories are labels for search and triage. They do **not** change who can access a document; only ownership and ACL grants do.

### 5.4 Accepted file types

The upload dialog hints at "PDF, DOCX, XLSX, PNG, JPG, TXT, JSON". The server accepts a slightly wider set, matched against the browser-reported MIME type:

| MIME type | Typical extension |
|---|---|
| `application/pdf` | pdf |
| `image/png` | png |
| `image/jpeg`, `image/jpg` | jpg, jpeg |
| `image/gif` | gif |
| `image/webp` | webp |
| `text/plain` | txt |
| `text/csv` | csv |
| `application/json` | json |
| `application/msword` | doc |
| `application/vnd.openxmlformats-officedocument.wordprocessingml.document` | docx |
| `application/vnd.ms-excel` | xls |
| `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | xlsx |
| `application/zip` | zip |
| `application/octet-stream` | any unrecognized binary |

A browser that cannot identify a file reports `application/octet-stream`, which is why that catch-all is accepted. Do not treat it as a safety guarantee: the application stores bytes, it does not scan them for malware.

### 5.5 Validation and rejection rules

| Rule | Enforced where | Message |
|---|---|---|
| File must not be empty | Server | "Cannot store empty file." |
| File must be ≤ 20 MB | Server (and multipart config) | "File size exceeds 20MB limit." |
| MIME type must be on the allow list | Server | "Disallowed MIME type: …" |
| Filename must not contain `..`, `/`, or `\` | Server | "Malicious file name detected: …" |
| A file must be selected in the form | Browser | "Please select a file to upload." |
| Extension is sanitized and preserved | Server | Stored name is `<uuid>.<safe-ext>` |

### 5.6 What happens after upload

1. The payload is written to the upload directory under a random UUID name.
2. A `documents` row records title, category, size, MIME type, owner, and timestamps.
3. An `UPLOAD` audit row is written with the document snapshot in `post_state`.
4. The response reports `effectivePermission: OWNER`.
5. Your **My Vault Assets** table refreshes and the tab counter increases.

Nothing is shared automatically. A fresh upload is visible to you and to administrators; nobody else has a grant until you create one.

### 5.7 Upload troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| "File size exceeds 20MB limit" | Payload too large | Compress, split, or store a link instead |
| "Disallowed MIME type" | Unusual format or a mislabelled extension | Convert to PDF, or zip the file |
| "Malicious file name detected" | The name contains a path separator | Rename the file and retry |
| 413 from the proxy | A reverse proxy has a smaller body limit than the app | Ask the operator to raise it to at least 20 MB |
| Button stays on "Ingesting..." then errors | Server rejected the write (disk permissions, quota) | Check the server logs; confirm the upload directory is writable |
| Upload succeeds but the list is empty | Filter or stale tab | Switch tabs and back, or reload |

---

## 6. Opening and Downloading

### 6.1 What a download actually does

"Download" is the only operation that moves document bytes to your device. It is also the most heavily gated:

1. The server re-reads your account and resolves the ACL — owner, administrator, or an active grant at `READ` or better.
2. The face gate validates your action token, or verifies a fresh descriptor against your own template.
3. Expiry and the view budget are evaluated, and one view is consumed if you hold a limited grant.
4. Bytes are read from disk.
5. A `READ` row is written.
6. The browser receives the file and saves it.

Notice the ordering: the ACL is checked **before** the face, and the view is consumed **after** the face. A failed scan never costs you a view.

### 6.2 Download a document

1. In **My Vault Assets**, select **Download**; in **Shared with Me**, select **FaceID Stream**; in search results, select **Download**.
2. The **Facial Verification** dialog opens with a live camera view.
3. Complete the liveness motion described in 3.5.
4. Select **Scan Face**.
5. On a match, a toast confirms decryption and the browser saves the file.
6. If the match fails, the download is blocked with an explicit message and an audit row.

### 6.3 The gate order, and why it matters

| Step | Failure outcome | Is a view consumed? | Audit rows written |
|---|---|---|---|
| ACL resolution | `403` with the reason | No | `ACCESS_DENIED` |
| Face proof | `403` with a face code | No | `ACCESS_DENIED` + `SECURITY_ALERT` |
| Expiry check | `403` "link has expired" | No — the grant is burned | `REVOKE` + `ACCESS_DENIED` |
| View budget check | `403` "view limit reached" | No — the grant is burned | `REVOKE` + `ACCESS_DENIED` |
| Byte read | `500` if the file is missing on disk | Yes | `READ` may still be written |
| Success | File streams | Yes, for limited grants | `READ` |

### 6.4 Outcome reference

| Condition | Result |
|---|---|
| Owner, valid face | File downloaded; owner has no budget to consume |
| Grantee at `READ`/`EDIT`, valid face, budget remaining | Downloaded; counter increments |
| Administrator with no grant | Downloaded via override; not counted against anyone |
| Administrator who was explicitly granted | Downloaded, and **that grant is consumed** like anyone else's |
| No face enrolled | Refused with an enrollment prompt |
| Challenge older than 30 seconds | Refused; scan again for a fresh challenge |
| Action token older than 2 minutes | Refused; scan again |
| Grant expired | `403`; the grant is deleted and a `REVOKE` row records the policy it had |
| Budget exhausted | `403`; same burn behavior |
| Document deleted by its owner | `403` with a not-found message; the attempt is audited |

### 6.5 Burn-after-reading rules

| Grant setup | Behavior |
|---|---|
| **Max Views** blank | Unlimited reads; the counter still increases so the owner can see usage |
| **Max Views = 1** | Exactly one successful read; the grant is deleted on success and a `REVOKE` row records "consumed final permitted view" |
| **Max Views = N** | N successful reads; the grant is deleted when the Nth completes |
| **Expires At** set | All reads and edits after the timestamp are refused; the grant is burned |
| Both set | Whichever limit is reached first ends the grant |

Everyone counts, including administrators who were explicitly granted access. Only an administrator acting purely through their override (with no grant of their own) reads without consuming a budget.

### 6.6 The honest limits of protection

Once bytes reach your browser, TrustVault cannot un-send them.

| You can | Because |
|---|---|
| Save the file | That is what download means |
| Screenshot it, print it, copy the text | The content is in your browser's memory |
| Share the saved copy out of band | It is now an ordinary file |
| Re-read the audit trail later | The server recorded who downloaded it, and when |

What the platform can do is make each read attributable: the trail answers *who* opened *which* document, *when*, and *from where*. It does not claim to prevent a determined recipient from misusing content they were authorized to see.

### 6.7 Download troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| Camera modal opens but Scan Face is disabled | Models still loading | Wait for the status strip to leave "Initialising" |
| "Zero-Trust Access Denied" | No active grant, or it was revoked | Ask the owner to re-grant |
| "This link has expired" | `expiresAt` has passed | Ask for a new grant |
| "Burn-after-reading view limit reached" | Budget exhausted | Ask for a new grant |
| "Face verification is required" | Request arrived with no proof | Retry from the UI, not from a saved request |
| Download blocked, then a second attempt works | A stale challenge or token | The retry minted a fresh one |
| File saves with no extension | The stored name was built from a filename without one | Rename locally; metadata in the vault is unaffected |

---

## 7. Editing a Document

### 7.1 Who may edit

| Your position | May edit metadata | Face required |
|---|---|---|
| Owner | Yes | Yes |
| Grantee at `EDIT` | Yes | Yes |
| Grantee at `READ` | No | — |
| Administrator | Yes | Yes |
| Nobody | No | — |

### 7.2 Edit steps

1. In **My Vault Assets** or **Shared with Me**, select **Edit**.
2. In **Edit Document Metadata**, change the **Updated Title** and/or **Category**.
3. Read the cyan notice: **FaceID Verification Required**.
4. Select **Verify & Save** and complete the liveness check.
5. On success the table refreshes and the new title appears.

### 7.3 What is recorded

| Artifact | Content |
|---|---|
| `pre_state` | Title, category, owner, size, MIME type, timestamps before the change |
| `post_state` | The same fields after the change |
| `details` | `updatedTitle`, `updatedCategory` |
| ActionResult | `EDIT` at `SUCCESS` |

Because both snapshots exist, an administrator can open the row in Action Replay and see exactly which field moved.

### 7.4 What editing cannot do

| Not possible | Why |
|---|---|
| Replace the file body | This build stores one payload per document; uploading a new file creates a new document |
| Change the owner | Ownership is fixed at upload |
| Change the category to an arbitrary string | The UI offers a fixed list; the API accepts a string, so treat the list as policy |
| Edit while at `READ` | The server requires `EDIT`, owner, or admin |
| Skip the face | No bypass exists |

---

## 8. Deleting a Document

### 8.1 Who may delete

The owner, or an administrator. Grantees never can — not even at `EDIT`.

### 8.2 Delete steps

1. In **My Vault Assets**, select the trash icon. (The browser exposes delete only on documents you own; an administrator purging someone else's document does so through `DELETE /api/documents/{id}`.)
2. Read the confirmation: **Zero-Trust Document Purge**, which states that the document and all ACL grants are permanently deleted while historical audit logs remain intact.
3. Confirm.
4. The row disappears and a toast confirms deletion.

### 8.3 What is destroyed and what survives

| Destroyed | Survives |
|---|---|
| The stored file payload | Every `UPLOAD`, `GRANT`, `READ`, `EDIT`, `REVOKE`, and `DELETE` row |
| All ACL grants for the document | Actor emails and source IPs |
| The document's appearance in search | The `pre_state` snapshot captured at deletion |
| Any share link someone kept | Evidence that the document existed and who removed it |

### 8.4 Delete versus revoke

| Question | Delete | Revoke |
|---|---|---|
| Removes the payload from disk | Yes | No |
| Removes one person's access | Removes everyone's | Removes one grant |
| Reversible | No | Only by granting again |
| Written to the trail | `DELETE` | `REVOKE` |
| Who can do it | Owner or administrator | Owner only |

Deletion is not a way to "reset" a view budget. If you want the same content available again, upload it as a new document and share it deliberately.

---

## 9. Sharing and Access Control

### 9.1 Open the sharing dialog

1. In **My Vault Assets**, select **Share & Burn** on a document you own.
2. The **Manage Document ACL & Burn Links** dialog opens, headed by the document title.
3. The upper panel is **Grant Granular Access**; the lower panel lists **Current Active Access Rules**.

Only the owner can grant or revoke. The server enforces this even for administrators.

### 9.2 Find a recipient with the suggestion list

1. Click **Grantee Email Address** (the field with a magnifier icon).
2. Type at least part of a **name** or **email**. The search matches both.
3. A listbox opens directly beneath the field, showing each matching identity with:
   - full name,
   - email address,
   - role badge.
4. Use the arrow keys to move and Enter to choose, or click an entry. The field fills with the exact registered email.
5. If you prefer, type a complete email address yourself — the field stays free-text.

**How the directory behaves**

| Behavior | Detail |
|---|---|
| Scope | Active registered identities only; deactivated accounts never appear |
| Self-exclusion | You are never suggested to yourself |
| Result cap | At most 8 suggestions per query |
| Term handling | The term is truncated and wildcard characters are stripped, so a crafted query cannot widen into a listing of the whole directory |
| Empty query | No error message is shown; the field can be browsed from a prefetched list |
| External addresses | Not supported as recipients — the account must exist |

> **Suggestions are convenience, not authorization.** Picking a name only prevents typos. The grant is authorized server-side against your ownership of that document.

### 9.3 Choose a permission level

| Level | Grants | Does not grant |
|---|---|---|
| `READ (View & FaceID Download)` | Reading metadata, downloading through the face gate | Editing, re-sharing, deleting |
| `EDIT (Update Metadata)` | Everything `READ` does, plus metadata edits | Re-sharing, deleting, replacing the file |

There is no "owner" level to hand out. Ownership is a property of who uploaded the document.

### 9.4 Add a burn limit or an expiry

| Control | Field | Rules |
|---|---|---|
| View budget | **Max Views (Burn Limit)** | Integer ≥ 1. Leave blank for unlimited. `1` means one successful read. |
| Temporal limit | **Expires At** | A local date-time. After it passes, reads and edits are refused and the grant is burned. |

The two limits combine: whichever is reached first ends the grant.

### 9.5 Apply, update, and re-grant

1. Select **Apply ACL Grant**.
2. The response appears under **Current Active Access Rules** with grantee, level, counters, and dates.
3. A `GRANT` row is written with `policyAction: CREATE` for a new grant or `policyAction: UPDATE` for an existing one, and with before/after policy snapshots.

Re-granting to the same person **updates** their existing rule rather than creating a duplicate. The view counter is preserved, so raising a `1`-view budget to `3` continues from where it was rather than resetting.

### 9.6 Review and revoke access

1. Open **Share & Burn**.
2. Read **Current Active Access Rules**: grantee, level, views used, and expiry.
3. Select **Revoke** on the rule to remove.
4. Confirm.
5. A `REVOKE` row is written carrying the policy that existed at removal (`pre_state`).

Revocation is effective on the recipient's very next request, because authorization is resolved per transaction from the database.

### 9.7 What revocation cannot do

| Cannot | Reason |
|---|---|
| Recall a file already downloaded | It is on their device |
| Un-see a rendered preview | Content reached the browser |
| Cancel a request already in flight | It was authorized when it started |
| Remove the audit evidence of earlier reads | The trail is append-only |
| Prevent a screenshot | No web control can |

### 9.8 Sharing rules and errors

| Attempt | Result |
|---|---|
| Grant to yourself | Rejected: "Cannot grant permissions to yourself (already owner)." |
| Grant to an unregistered email | Rejected: "Target user not found: …" |
| Grant from a non-owner account, including an admin | `403`: "Only the owner can grant access to this document." |
| Grant with no level selected | Defaults to `READ` |
| Grant with a past expiry | Stored as-is; the first access attempt immediately burns it |
| Revoke by a non-owner | `403`: "Only the document owner can revoke permissions." |
| Revoke a grant that does not exist | No error; nothing is written |

---

## 10. Roles and Permissions

### 10.1 The three platform roles

| Role | Stored value | Meaning |
|---|---|---|
| Member | `VIEWER` | Full vault workspace: upload, search, read what is shared, manage what you own |
| Member (owner label) | `OWNER` | Identical to `VIEWER`; the label exists for organizational clarity only |
| Administrator | `ADMIN` | Vault workspace **plus** the security console, the kill switch, audit access, and an ACL override |

`Role.isAdministrator()` returns true only for `ADMIN`. It is never used to decide whether a document may be read; document decisions come from ownership and ACLs.

### 10.2 Your position relative to a document

This is the concept that actually governs access:

| Position | How you get it | What you may do |
|---|---|---|
| Owner | You uploaded it | Everything, including share and delete |
| Grantee at `EDIT` | The owner granted it | Read, download, edit metadata |
| Grantee at `READ` | The owner granted it | Read, download |
| Administrator | Your platform role | Read, download, edit, delete any document |
| Neither | — | Nothing; the document does not appear in your lists |

### 10.3 Capability matrix

| Operation | Owner | `EDIT` grantee | `READ` grantee | Administrator | Stranger |
|---|---|---|---|---|---|
| Find it via search | Yes | Yes | Yes | Yes, labelled `ADMIN_VIEW` | No |
| Open metadata | Yes | Yes | Yes | Yes | No |
| Download (face-gated) | Yes | Yes | Yes | Yes | No |
| Edit metadata (face-gated) | Yes | Yes | No | Yes | No |
| Grant / revoke access | Yes | No | No | No | No |
| Inspect the ACL list | Yes | No | No | Yes | No |
| Delete | Yes | No | No | Yes | No |
| Consume a view budget | n/a | Yes | Yes | Only if explicitly granted | n/a |

### 10.4 How a decision is made, step by step

1. The JWT identifies the caller; the database row confirms the account still exists and is active.
2. If the caller is the document owner, access is granted at owner level.
3. Otherwise, if the caller's **live** role is `ADMIN`, access is granted at admin level.
4. Otherwise, the ACL is queried for an active grant: not expired, not exhausted.
5. If the operation needs `EDIT` and the grant is only `READ`, access is refused.
6. If no grant exists, the request is refused and an `ACCESS_DENIED` row is written with the reason.

No step consults a cached role, a browser flag, or a URL parameter.

### 10.5 What a role change does to an open session

| Change | Immediate effect |
|---|---|
| Promote a member to `ADMIN` | Their next request carries the new privilege; the console tab appears after the profile refreshes |
| Demote an admin to `VIEWER` | Their next request is evaluated as a member; admin surfaces return `403` |
| Deactivate | Their next request returns `403` regardless of role |
| Reactivate | Sign-in works again; revoked grants are not restored |

### 10.6 Common misconceptions

| Belief | Reality |
|---|---|
| "`OWNER` outranks `VIEWER`." | They are the same tier with different labels. |
| "Admins can read anything, so they can share anything." | Admins can read, cannot grant or revoke, and every read through their override is audited. |
| "If I was granted access, admins can't see my reads." | Admins see every audit row, including yours. |
| "Deleting my account removes my documents." | Documents are tied to the identity; offboarding deactivates, it does not delete content. |
| "A `READ` grant lets me download only once." | `READ` means "may read"; the *budget* decides how many times. |

---

## 11. Searching

### 11.1 Search steps

1. Open **Zero-Trust Search**.
2. Fill any combination of the three filters.
3. Select **Search**.
4. Review results: title, category, owner email, your effective permission, created date.
5. Select **Download** on a row to open the face gate.
6. Select **Reset** to clear the filters and the results.

### 11.2 Filters

| Filter | Matches | Case handling | Empty value |
|---|---|---|---|
| Title Query | Substring of the document title | Case-insensitive | Ignored |
| Category | Exact category value | Exact match | "All Categories" ignores it |
| Owner Email | Substring of the owner's email | Case-insensitive | Ignored |

The API also accepts `startDate` and `endDate` (ISO date-time) for time-bounded queries. The browser UI does not expose them today.

### 11.3 Why results are always authorized

Search runs against your accessible set: documents you own plus documents where you hold a grant, plus everything if you are an administrator. A document you could not open never appears, which is why the empty state mentions "Universal visibility blocked".

---

## 12. FaceID in Detail

### 12.1 What happens in your browser

1. The camera stream is drawn into a video element; frames are read into an off-screen canvas.
2. `TinyFaceDetector` locates a face (input size 320, score threshold 0.45).
3. `FaceLandmark68Net` finds 68 landmarks, used for eye aspect ratio and nose position.
4. `FaceRecognitionNet` produces a 128-value embedding.
5. A quality gate rejects bad captures before anything is sent:

| Quality check | Threshold |
|---|---|
| Brightness | 0.28 – 0.94 |
| Detection confidence | ≥ 0.55 |
| Face size relative to frame | ≥ 0.20 |
| Centre offset | ≤ 0.18 |
| Minimum samples in the liveness window | 6 |
| Whole-challenge budget | 20 seconds |

6. The descriptor and the challenge token are submitted to the server.

### 12.2 What the server stores

| Element | Storage | Notes |
|---|---|---|
| Descriptor | AES-256-GCM sealed payload in `biometric_templates.face_descriptor` | Unreadable without `trustvault.face.encryption-key` |
| Canonical hash | `face_hash`, SHA-256, unique | Fast duplicate index and a database-level guard |
| Algorithm | `algorithm_version` | e.g. the FaceRecognitionNet descriptor family |
| Dimensions | `embedding_size` | 128 |
| Linkage | `user_id` unique, `email` unique | One enrollment per identity and per address |

No image, frame, video, or biometric template ever leaves the device in readable form.

### 12.3 One face, one identity

Two checks run in order whenever a face is enrolled:

1. **Exact hash.** If a stored `face_hash` equals the incoming canonical hash, the face is already claimed and the request is refused.
2. **Nearest neighbour.** Up to `max-candidates` (5,000) stored descriptors are decrypted and compared. If similarity ≥ `match-threshold` (0.40) with any other account, the request is refused as `FACE_ALREADY_REGISTERED`.

The duplicate scan runs **before** the profile row is created during sign-up, so a refused face leaves no orphaned account behind.

### 12.4 Why a challenge is required

A face descriptor is not a nonce: a captured request would keep matching forever. The challenge closes that window.

| Phase | What happens |
|---|---|
| Issue | Server mints a signed token bound to `user + document + action`, stores its SHA-256 in `biometric_challenges`, and returns it with `expiresInSeconds` |
| Capture | Browser collects the descriptor and a head-pose/blink sample set |
| Submit | Descriptor plus challenge go to `/verify-face` (or directly to download/edit) |
| Consume | Server re-validates signature, scope, binding, age, and ledger row, then flips `consumed_at` with a conditional update |
| Burn | Consumption runs in its own transaction, so the challenge stays spent even if the face match then fails |

| Rejection | Code | Meaning |
|---|---|---|
| No challenge supplied | `FACE_CHALLENGE_REQUIRED` | Descriptor arrived without a nonce |
| Older than the window | `FACE_CHALLENGE_EXPIRED` | Request a new challenge and rescan |
| Wrong user/document/action | `FACE_CHALLENGE_MISMATCH` | Token was minted for something else |
| Already redeemed | `FACE_CHALLENGE_REUSED` | Replay attempt, or a double-clicked scan |

A challenge is valid for at most 30 seconds, with 5 seconds of tolerated clock drift. Configuration may shorten that window; it can never lengthen it.

### 12.5 Matching thresholds

| Purpose | Setting | Default | Direction |
|---|---|---|---|
| Duplicate-enrollment similarity | `trustvault.face.match-threshold` | 0.40 (≈ distance 0.60) | Higher = stricter |
| Identity verification distance | `trustvault.face.verify-max-distance` | 0.60 | Lower = stricter; 0.60 is a hard ceiling |

Verification accepts a probe when the Euclidean distance to your enrolled template is at or below the ceiling. The 0.60 operating point reflects FaceRecognitionNet's behavior: two captures of the same face typically land 0.4–0.6 apart, so tightening much further starts rejecting genuine users.

### 12.6 The two accepted proofs

| Proof | Produced by | Bound to | Lifetime |
|---|---|---|---|
| Action token | `POST /api/auth/biometric/verify-face` | user id, document id, action | 2 minutes |
| Descriptor + challenge | A live capture | The single-use challenge | 30 seconds |

`FaceGateService` accepts nothing else. A missing proof produces `FACE_PROOF_REQUIRED` and a denial trail.

### 12.7 Failure codes and what they mean

| Code | Meaning | Typical cause |
|---|---|---|
| `FACE_NOT_ENROLLED` | No usable template for this account | Never enrolled, or the sealed payload cannot be opened |
| `FACE_MISMATCH` | Distance exceeded the ceiling | Wrong person, changed appearance, poor lighting |
| `FACE_PROOF_REQUIRED` | Nothing usable was presented | Stale token, or a request replayed by hand |
| `FACE_CHALLENGE_REQUIRED` | Descriptor sent without a challenge | Bypassing the normal UI flow |
| `FACE_CHALLENGE_EXPIRED` | Challenge older than the window | Slow tab, clock skew, long pause mid-scan |
| `FACE_CHALLENGE_MISMATCH` | Binding or signature invalid | Token reused for another document/action |
| `FACE_CHALLENGE_REUSED` | Already redeemed | Replay, or pressing Scan Face twice |
| `FACE_ALREADY_REGISTERED` | Face bound to another account | Duplicate enrollment attempt (HTTP 400) |

Every one of these except the expired-challenge case writes both `ACCESS_DENIED` and `SECURITY_ALERT`. Expiry is treated as an operational nuisance rather than an attack, precisely because replay indicators deserve the alert budget.

### 12.8 Re-enrollment and revocation

| Task | How |
|---|---|
| Re-enroll | Sign in, select **Enroll Face**, complete liveness; the existing template is replaced |
| Revoke your enrollment | `DELETE /api/auth/biometric/face` (API; no dedicated UI button) |
| After revocation | Every download and edit fails with `FACE_NOT_ENROLLED` until you enroll again |
| Lost to a duplicate | An administrator reviews the `SECURITY_ALERT` trail and resolves the conflict |

### 12.9 Privacy summary

| Question | Answer |
|---|---|
| Is my photo stored? | No. Only a 128-number embedding is stored, sealed with AES-256-GCM. |
| Is my camera streamed to the server? | No. Processing happens in your browser. |
| Can the descriptor be reversed into a face? | It is not designed to be, but treat biometric data as sensitive personal data regardless. |
| Can someone replay my verification? | Not with the same challenge or token; both are single-use and time-boxed. |
| What happens if I refuse the camera? | You can sign in and upload, but you cannot read, download, or edit documents. |

---

## 13. Audits and Anomaly Monitoring

### 13.1 The WORM ledger

Every security-relevant action becomes a row in `audit_logs`. "Write Once, Read Many" is not a policy statement here; it is enforced three ways:

1. The entity is mapped as `@Immutable`, so the persistence layer has no update path.
2. A MySQL `BEFORE UPDATE` trigger raises `SIGNAL SQLSTATE '45000'`, aborting any attempt to modify a row.
3. A MySQL `BEFORE DELETE` trigger does the same for deletions.

> **Operator caution.** Row triggers protect rows. `TRUNCATE` is DDL and does not fire row triggers, which is exactly why the reset script can purge the table without dropping the guard. Restrict DDL and `TRUNCATE` to a DBA role; the application account should not hold them.

### 13.2 Anatomy of a record

| Field | Meaning | Example |
|---|---|---|
| `id` | UUID of the event | `7c1e…` |
| `timestamp` | Server-side UTC time | `2026-10-24T18:42:07Z` |
| `action` | Event class | `ACCESS_DENIED` |
| `user_email` | Actor, denormalized so it survives account changes | `alice@trustvault.internal` |
| `user_id` | Actor link where one exists | `usr-…` |
| `document_id` | Target document, when applicable | `4f2a…` |
| `ip_address` | Origin, honoring `X-Forwarded-For` | `10.14.7.22` |
| `status` | `SUCCESS` or `FAILURE` | `FAILURE` |
| `details` | JSON context (reason, title, counters) | `{"reason":"Burn-After-Reading: …"}` |
| `pre_state` | Snapshot before a mutation | document or permission JSON |
| `post_state` | Snapshot after a mutation, `null` if destroyed | document JSON |

Snapshots never contain passwords, hashes, or biometric data.

### 13.3 The action catalog

| Action | Written when |
|---|---|
| `UPLOAD` | A document is stored (snapshot in `post_state`) |
| `READ` | Metadata is opened, or bytes are downloaded |
| `EDIT` | Metadata changes after a face match (both snapshots) |
| `DELETE` | A document is purged (snapshot in `pre_state`) |
| `GRANT` | A grant is created or updated (before/after policy) |
| `REVOKE` | A grant is removed, revoked by hand, expired, or burned |
| `ACCESS_DENIED` | Any gate refuses a request |
| `SECURITY_ALERT` | A threshold, duplicate face, or replay indicator trips |
| `ACCOUNT_DEACTIVATED` | An administrator offboards an identity |
| `ACCOUNT_INACTIVE_ACCESS_ATTEMPT` | A deactivated identity presents a token |
| `ROLE_CHANGED` | An identity moves between tiers |
| `SYSTEM_LOCKDOWN_TRIGGERED` | The kill switch is engaged |
| `SYSTEM_LOCKDOWN_LIFTED` | The kill switch is released |
| `BREAK_GLASS_ACCESS` | An administrator declares emergency access |

### 13.4 Where each row comes from

| Trigger point | Action | Status |
|---|---|---|
| Upload succeeds | `UPLOAD` | `SUCCESS` |
| Metadata GET or file download | `READ` | `SUCCESS` |
| Metadata PUT succeeds | `EDIT` | `SUCCESS` |
| Delete succeeds | `DELETE` | `SUCCESS` |
| Grant created or updated | `GRANT` | `SUCCESS` |
| Grant revoked, expired, or burned | `REVOKE` | `SUCCESS` |
| ACL refuses (no grant, wrong level, expired, exhausted) | `ACCESS_DENIED` | `FAILURE` |
| Face gate refuses | `ACCESS_DENIED` + `SECURITY_ALERT` | `FAILURE` |
| URL-level authorization refuses | `ACCESS_DENIED` | `FAILURE` |
| Duplicate face blocked | `SECURITY_ALERT` | `FAILURE` |
| Threshold crossed | `SECURITY_ALERT` | `FAILURE` |
| Admin mutations | `ROLE_CHANGED`, `ACCOUNT_DEACTIVATED`, `SYSTEM_LOCKDOWN_*`, `BREAK_GLASS_ACCESS` | `SUCCESS` |

### 13.5 Anomaly detection

The detector watches for the pattern that precedes most intrusions: attempts that should succeed but do not.

1. Every refusal writes an `ACCESS_DENIED` row.
2. An in-memory tracker keeps a rolling window per **IP address** and per **identity**.
3. At **3 denials within 5 minutes**, the window resets and a `SECURITY_ALERT` row is written containing the alert class, the threshold, the window, the trigger source, and the target document.
4. If the in-memory window is empty — after a restart or on another node — the server counts recent `ACCESS_DENIED` rows in the database instead, so clustering and restarts cannot be used to evade detection.
5. The alert appears in the console feed immediately.

| Signal | Threshold | Result |
|---|---|---|
| Denials from one IP | 3 per 5 minutes | Correlated `SECURITY_ALERT` |
| Denials by one identity | 3 per 5 minutes | Correlated `SECURITY_ALERT` |
| Face mismatch | Every occurrence | Immediate `SECURITY_ALERT` |
| Duplicate face binding | Every occurrence | Immediate `SECURITY_ALERT` |
| Deactivated token presented | Every occurrence | `ACCOUNT_INACTIVE_ACCESS_ATTEMPT` |

### 13.6 Risk posture

TrustVault expresses risk as a **derived posture**, not a stored score.

> **Why there is no `user_risk_scores` table.** A stored number can be edited by anyone who reaches the table, silently decays when nobody recalculates it, and hides the evidence behind a single figure. TrustVault derives posture from the append-only trail, so the rating can never disagree with the record it summarizes.

| Signal | Evidence | Effect |
|---|---|---|
| Failed FaceID verification | `ACCESS_DENIED` + `SECURITY_ALERT` | Immediate elevation |
| Repeated denials from one origin | Correlated alert at 3 in 5 minutes | High |
| Sequential denials across document ids | `ACCESS_DENIED` pattern | High — suggests enumeration |
| Duplicate face attempt | `SECURITY_ALERT` with `DUPLICATE_FACE_ENROLLMENT_BLOCKED` | Critical — identity conflict |
| Deactivated account presenting a token | `ACCOUNT_INACTIVE_ACCESS_ATTEMPT` | Critical — possible stolen token |
| Break-glass declaration | `BREAK_GLASS_ACCESS` | Review flag, not a threat signal |
| Replay-indicator denial | Spent, re-bound, or mismatched token | High |

| Band | Condition | Operator response |
|---|---|---|
| Low | No alerts in the window | Routine monitoring |
| Elevated | 1–2 denials, no correlated alert | Watch; confirm user intent |
| High | Correlated alert or enumeration pattern | Review the trail; consider deactivation |
| Critical | Inactive-account access, duplicate face, active incident | Contain first, investigate second |

### 13.7 The anomaly feed

1. Open **Security Console**.
2. Find **Real-Time Security Anomaly Feed**.
3. Each entry shows the alert headline, the source identity, the IP address, and the timestamp.
4. The **Security Alerts** counter at the top of the console gives the running total.
5. When nothing has tripped, the panel says: *"No security anomalies detected. System operating within zero-trust parameters."*

### 13.8 Responding to an alert

1. **Read first.** Open the WORM trail and filter to the alerting identity.
2. **Reconstruct.** Identify the target, the action, and the denial reason.
3. **Classify.** A user with a bad webcam and a user probing unrelated document ids look different in the trail.
4. **Contain if ambiguous.** The kill switch is reversible; an exfiltration is not.
5. **Preserve evidence.** Note audit row ids before remediation, because remediation adds rows.
6. **Remediate.** Deactivate the identity, revoke the grant, or reset the biometric binding.
7. **Review afterwards.** Replay every administrative mutation made during the incident.

---

## 14. Administrator Guide

> **Restricted surface.** Every control in this section requires `ADMIN` and is denied at the route level, then checked again against the live database row. Do not operate this console from a shared account; attribution is the entire point.

### 14.1 Becoming an administrator

Two paths exist:

| Path | How |
|---|---|
| Self-selection at registration | Choose **ADMIN (Security Console & Operations)** — convenient for a controlled environment, unsuitable for a public one |
| Role change by an administrator | Another administrator changes the role from the user registry (see 14.7) |

### 14.2 Console tour

| Panel | What it shows | Actions |
|---|---|---|
| Counters | Vault Documents, WORM Audit Logs, Security Alerts | Read-only |
| **Emergency Global Kill Switch** | Status chip, reason input, state detail | Engage / lift |
| **Break-Glass Emergency Access** | Document id + justification form, last declaration result | Declare, then stream with FaceID |
| **Employee Offboarding Fast-Kill Control** | Name, email, role, status per identity | Deactivate / activate |
| **Real-Time Security Anomaly Feed** | Live alerts | Read-only |
| **WORM Compliance Audit Trail (Append-Only)** | Timestamp, action, actor, IP, status, details, Replay button | Replay |

### 14.3 Emergency Global Kill Switch

**Engage**

1. Open **Security Console** and confirm the chip reads `OPERATIONAL`.
2. Type an **Incident reason** (at least 5 characters; 500 maximum). Write it for the reviewer, e.g. *"Suspected token replay from 10.14.7.22."*
3. Select **Engage Lockdown**.
4. Confirm: the chip turns red, the button relabels to **Lift Lockdown**, and the red **System Lockdown Active** banner spans the top of the app.
5. Verify from a non-administrator session that requests now fail with `503`.

**Effect while engaged**

| Surface | Behavior |
|---|---|
| Non-administrator requests | `503` with a fixed message |
| Document operations (anyone, including admins) | `503` for read, edit, upload, download |
| Sign-in endpoint | Reachable, so an administrator can authenticate |
| Static assets | Reachable, so the console loads |
| `/api/admin/**` | Reachable, so the incident can be managed |
| Stored reason in error bodies | Never disclosed; only admins see it via the status endpoint |

**Lift**

1. Confirm containment: the offending identity is deactivated and the grant revoked.
2. Select **Lift Lockdown**.
3. Confirm the prompt. A reason is optional here but strongly recommended.
4. Verify the chip returns to `OPERATIONAL` and the banner disappears.
5. Re-verify normal access with a non-administrator account.

**What is recorded**

| Field | Detail |
|---|---|
| Action | `SYSTEM_LOCKDOWN_TRIGGERED` or `SYSTEM_LOCKDOWN_LIFTED` |
| Actor | Admin id and email |
| IP | Origin of the control action |
| Reason | Stored verbatim, admin-only |
| Transition | `previousState` → `newState` |
| Snapshots | Both states captured for replay |
| Timestamp | When the flag flipped |

> **Fail-safe audit behavior.** The flag enforces containment before the audit row is attempted. If the audit write fails, the error is logged at ERROR level and the control action still returns success, because a retry would only repeat an applied state change. If that ERROR appears in the logs, annotate the incident: the state change is real, the evidence row is missing.

### 14.4 Action Replay

**Steps**

1. Open **WORM Compliance Audit Trail (Append-Only)**.
2. Locate a state-bearing row.
3. Select **Replay** in the **Forensics** column.
4. **Inspect Action Replay** opens with a summary strip and the event metadata.
5. Compare the panes:

   | Pane | Content |
   |---|---|
   | **Before — pre_state** | The resource before the mutation |
   | **After — post_state** | The resource after the mutation |

6. Read the **Field-Level Delta** table (Field, Before, After, Change).
7. Expand **Recorded Event Details (JSON)** for the raw envelope.
8. Select **Close**. The footer reminds you: immutable record, append-only, no updates possible.

**Which actions have snapshots**

| Action | pre_state | post_state |
|---|---|---|
| `UPLOAD` | — | Document as created |
| `EDIT` | Document before | Document after |
| `DELETE` | Document before deletion | `null` |
| `GRANT` | Policy before (none on create) | Policy after |
| `REVOKE` | Policy at removal | `null` |
| `ROLE_CHANGED` | Identity before | Identity after |
| `ACCOUNT_DEACTIVATED` | Identity before | Identity after |
| `SYSTEM_LOCKDOWN_*` | Previous state | New state |
| `BREAK_GLASS_ACCESS` | Document in scope | `null` |
| `READ`, `ACCESS_DENIED`, `SECURITY_ALERT` | — | — |

**Reading a diff like an investigator**

| Field that should not move on its own | Why it matters |
|---|---|
| `owner` | Ownership transfer would be a privilege escalation |
| `role` | Any `→ ADMIN` transition deserves a justification |
| `status` | Reactivation of an offboarded identity |
| `expiresAt`, `maxViews` | Quietly extending a share's life or budget |
| `permissionLevel` | A `READ` grant silently becoming `EDIT` |

If a row has no snapshots, the dialog says so explicitly and still shows the immutable envelope — older events and non-state-bearing actions behave this way.

### 14.5 Break-Glass Emergency Access

> **Evidence, not authorization.** The declaration records intent. It grants nothing. The read that follows still passes the live ACL, still requires a face match, and still consumes burn-after-reading budget.

**Steps**

1. Obtain the target **Document ID** from a share link or the audit trail.
2. Open **Break-Glass Emergency Access**.
3. Enter the **Document ID**.
4. Enter a **Justification** of 10–500 characters. Write it for a reviewer reading it in six months.
5. Select **Declare Access**.
6. Review the result block: Document, Owner, **Evidence Row**, Declared At.
7. Select **Stream With FaceID** and complete the liveness scan.
8. Record the evidence row id in the incident ticket.

**Rules**

| Rule | Behavior |
|---|---|
| Who may declare | `ADMIN` only, re-checked against the live database row |
| Scope recorded | `READ_AND_DOWNLOAD` |
| Face requirement | `requiresLiveFace: true`, always |
| Unknown document | `404`, and **no** evidence row is written |
| Short justification | Rejected by validation (minimum 10 characters) |
| Effect on ACLs | None: no grant is created or widened |
| Evidence deletion | Impossible; the trail rejects updates and deletes |

**What break-glass is not**

| Not this | Explanation |
|---|---|
| A way to bypass the face gate | The subsequent download still requires a live match |
| A way to bypass a burned grant | If your explicit grant is exhausted, it is exhausted |
| A silent superuser mode | The row is visible to every administrator, with your name on it |
| A legal justification | It records your stated reason; it does not validate it |

### 14.6 User registry and offboarding

**Steps**

1. Open **Employee Offboarding Fast-Kill Control**.
2. Review the columns: Employee Name, Email Address, Role, Status, Offboarding Action.
3. Select **Refresh** to reload the registry.
4. Choose the offboarding action on the target row.
5. Confirm the status change and the toast.

| Action | Effect | Reversible |
|---|---|---|
| Deactivate | Sign-in refused; in-flight tokens get `403` on the next request | Yes |
| Activate | Sign-in restored | Yes |
| Change role | New tier applies to the next request | Yes |

Offboarding never deletes documents, grants, or audit history. A deactivated identity's documents remain owned by it, which is why transferring ownership is a separate organizational decision.

### 14.7 Changing a role

1. Find the identity in the registry.
2. Open its **Role** selector.
3. Choose the new role and confirm.
4. The server snapshots the identity before and after.
5. Open **Action Replay** on the resulting row and confirm the delta reads as intended.

> **Least privilege is a process, not a setting.** Grant `ADMIN` for the duration of an incident, remove it afterwards, and let Action Replay prove both directions.

### 14.8 Administrative API reference

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/admin/system/lockdown` | Engage or lift the kill switch (`enabled`, `reason`) |
| `GET` | `/api/admin/system/lockdown` | Current lockdown state, reason, actor, timestamp |
| `POST` | `/api/admin/break-glass` | Declare emergency access (`documentId`, `reason` 10–500) |
| `GET` | `/api/admin/audit-logs` | Recent WORM trail |
| `GET` | `/api/admin/audit-logs/alerts` | Security alert feed |
| `GET` | `/api/admin/audit/{id}/diff` | Snapshots plus computed field delta |
| `GET` | `/api/admin/users` | User registry |
| `PUT` | `/api/admin/users/{id}/deactivate` | Offboarding |
| `PUT` | `/api/admin/users/{id}/activate` | Restore |
| `PUT` | `/api/admin/users/{id}/role` | Change tier (snapshotted) |
| `GET` | `/api/admin/stats` | Console counters |

Document and biometric endpoints an administrator also uses:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/documents/owned` | Documents you own |
| `GET` | `/api/documents/shared` | Documents granted to you |
| `GET` | `/api/documents` | Search (title, category, ownerEmail, startDate, endDate) |
| `POST` | `/api/documents/upload` | Upload (multipart: file, title, category) |
| `GET` | `/api/documents/{id}/download` | Face-gated byte stream |
| `PUT` | `/api/documents/{id}` | Face-gated metadata update |
| `DELETE` | `/api/documents/{id}` | Purge (owner or admin) |
| `GET`/`POST` | `/api/documents/{id}/permissions` | List / create grants |
| `DELETE` | `/api/documents/{id}/permissions/{userId}` | Revoke a grant |
| `GET` | `/api/share-candidates?query=` | Recipient autocomplete |
| `POST` | `/api/auth/biometric/challenge` | Mint a single-use challenge |
| `POST` | `/api/auth/biometric/verify-face` | Verify and mint an action token |
| `GET` | `/api/auth/biometric/face-status` | Enrollment state |
| `DELETE` | `/api/auth/biometric/face` | Revoke an enrollment |

### 14.9 What administrators cannot do

| Cannot | Because |
|---|---|
| Grant or revoke access on someone else's document | `grantPermission` requires ownership |
| Read a document without a face match | The gate has no admin bypass |
| Edit or delete audit rows | Triggers reject both |
| Turn off the lockdown filter, the status filter, or the JWT filter | They are wired into the security chain |
| See descriptors, passwords, or hashes in snapshots | Snapshots are sanitized by construction |
| Declare break-glass on a nonexistent document | `404` before any evidence is written |

### 14.11 Resetting the platform to a pristine state

Use this only when you intend to destroy every identity, document, grant, and audit row. It is appropriate for handing a demo environment to the next team, and never for production.

1. Stop the application. A running JVM caches the lockdown flag and the in-memory anomaly counters.
2. Run the reset script with the MySQL CLI (it uses `DELIMITER`, which a JDBC driver cannot process):

   ```bash
   mysql -u root -p trustvault < src/main/resources/db/reset_fresh_state.sql
   ```

3. Read the verification result at the end of the script. Every counter must read `0` for `users`, `documents`, `document_permissions`, `biometric_templates`, `biometric_challenges`, `user_credentials`, `audit_logs`, and `system_settings`.
4. Confirm `trustvault.bootstrap.seed-default-users=false` so the next start does not recreate demo identities.
5. Start the application and register the first identity through the FaceID sign-up flow.

| What the script does | Why it is safe |
|---|---|
| `TRUNCATE` on data tables | `TRUNCATE` is DDL, so the WORM triggers do not fire and do not need to be dropped |
| Child tables first, then `users` | Respects the foreign-key graph even with checks enabled |
| `DELETE FROM system_settings` | Removes the persisted lockdown flag, returning the platform to `OPERATIONAL` |
| Rewinds any `AUTO_INCREMENT` counters | This schema uses UUID keys, so the loop is a no-op today but stays correct after a migration |
| Leaves schema, indexes, ENUMs, and triggers intact | Only data is removed |

### 14.12 Deployment hardening checklist

| Item | Why | How |
|---|---|---|
| Prevent self-service `ADMIN` registration | The form accepts a client-chosen role | Restrict `/api/auth/register`, provision identities centrally, or remove `ADMIN` from the selector |
| Keep `seed-default-users=false` | Seeded identities have well-known passwords | Leave the flag off outside demos |
| Replace `trustvault.jwt.secret` | The shipped secret is public in source | Supply a strong, per-deployment secret |
| Replace `trustvault.face.encryption-key` | Descriptors are only as private as this key | Use a managed secret; rotate by re-enrolling |
| Terminate TLS in front of the app | Session tokens and descriptors travel in requests | Reverse proxy with HTTPS; forward `X-Forwarded-For` |
| Encrypt the upload volume | Payloads are not encrypted at the file level | LUKS, BitLocker, or an encrypted mount |
| Restrict DB privileges | Triggers protect rows, not DDL | Application account must not own `TRUNCATE` or `ALTER` |
| Raise proxy body limits to ≥ 20 MB | Otherwise uploads fail with 413 | Align proxy and multipart settings |
| Back up, and test restores | WORM prevents edits, not disk loss | Schedule backups; restore into a scratch schema |
| Set a retention policy | The ledger grows forever by design | Archive to immutable storage; never mutate rows |

---

## 15. Security and Privacy Guidance

1. Use a long, unique passphrase. The face gate limits the damage of a stolen password; it does not excuse a weak one.
2. Never share credentials, session tokens, or challenge tokens, including with support staff.
3. Verify the recipient before sharing. There is no recall for a document already downloaded.
4. Grant the minimum level: `READ` unless editing is genuinely required.
5. Set a view budget or expiry for anything time-bound; do not rely on remembering to revoke.
6. Treat downloaded copies as out of TrustVault's control from that moment.
7. Sign out on shared devices, and close the browser as well.
8. Enroll your face on a trusted device; enrollment replaces your existing template.
9. Report unexpected access, duplicate-face errors, or repeated scan failures to your administrator.
10. Do not upload data your organization has not approved for this system.
11. Do not ask an administrator to weaken a control to work around a problem; ask them to fix the cause.
12. If the lockdown banner is active, stop working and wait for the incident owner.

---

## 16. Troubleshooting

### 16.1 Accounts and sign-in

| Problem | What to try |
|---|---|
| Registration fails with no clear reason | Confirm all fields are filled, the email is not already registered, and the face scan completed |
| `Email already registered` | Sign in instead, or ask an administrator to check the account |
| `A webcam face scan is required` | The descriptor never reached the server; allow the camera and rescan |
| `FACE_ALREADY_REGISTERED` | That face is bound to another identity; contact an administrator — this is an investigation trigger, not a bug |
| Wrong role after registering | Roles are chosen at sign-up; ask an administrator to correct it |
| `Account is inactive` | You were offboarded; request reactivation |
| Password forgotten | There is no self-service reset; an administrator must act |
| Sign-in loop or immediate 401 | Token storage was cleared or the session expired; sign in again |

### 16.2 Biometrics

| Problem | What to try |
|---|---|
| Camera dialog never shows video | Grant camera permission, close other apps using the camera, reload |
| "The face recognition library could not be loaded" | The CDN is blocked; allow `cdn.jsdelivr.net` or restore connectivity |
| "No face detected" repeatedly | Better front lighting, closer to the camera, remove occlusions |
| Scan fails only in the evening | Low ambient light; add a lamp in front of you |
| "Face does not match" for the right person | Glasses, beard change, or harsh lighting; try again, or re-enroll |
| Challenge expired mid-scan | The window is 30 seconds; scan promptly after the dialog opens |
| "Already used" on the first attempt | A double click consumed the challenge; rescan |
| Works on one browser, not another | Camera permissions or CDN access differ per browser profile |

### 16.3 Documents

| Problem | What to try |
|---|---|
| Upload rejects the type | Convert to PDF or zip the file |
| Upload rejects the size | Stay under 20 MB per file |
| Download says access denied | No active grant, or it was revoked; ask the owner |
| Download says the link expired | Ask for a new grant with a later expiry |
| Download says the view limit was reached | Ask for a new grant |
| Document missing from a list | It was deleted, revoked, or filtered out; check **All** filters and the search tab |
| Title shows the raw filename | The title field was left blank during upload; edit the metadata |
| Edit button absent | You hold `READ`, not `EDIT` |

### 16.4 Sharing

| Problem | What to try |
|---|---|
| Recipient does not appear in suggestions | They may be deactivated or not registered; type the exact email |
| "Target user not found" | The account does not exist; ask them to register first |
| Cannot grant to yourself | Expected: you already own the document |
| Grant saved but the recipient still cannot open | Confirm the level, expiry, and remaining views |
| Colleague lost access unexpectedly | The grant expired or its budget was consumed; both burn the grant |

### 16.5 Administrators

| Problem | What to try |
|---|---|
| Console tab missing | Your role is not `ADMIN` in the database; re-check via the registry |
| Users still active during a lockdown | Sign-in remains reachable by design; only document and data operations are frozen |
| Lockdown will not engage | The reason is shorter than 5 characters |
| Break-glass returns 404 | The document id is wrong or the document was purged |
| Replay shows no snapshots | The event is not state-bearing, or predates snapshots; the envelope is still authoritative |
| Deactivation seems not to work | The user's very next request is refused; a page already open may still render |
| Audit write ERROR in the log during an incident | The state change is real; annotate the missing row manually |

### 16.6 Platform

| Problem | What to try |
|---|---|
| `503 SYSTEM_LOCKDOWN` for everyone | An administrator engaged the kill switch; contact the incident owner |
| Application fails to start | Check DB connectivity, `ddl-auto=validate` schema mismatches, and the upload directory |
| Port already in use | Another instance is running; stop it or start with `--server.port=…` |
| Changes to Java not taking effect | Restart the process; a running JVM keeps stale classes |
| CSS classes missing in the UI | Rebuild Tailwind (`npm run build`) after editing templates |

---

## 17. FAQ

**Is TrustVault a public file-sharing service?**
No. There is no anonymous link type. Every recipient must hold an account, and every read requires a face match.

**Can a `VIEWER` upload and manage documents?**
Yes. `VIEWER` and `OWNER` share one baseline; ownership is per document, not per label.

**Does an administrator see my documents automatically?**
Administrators can access any document through an audited override, and can see the audit trail. They cannot grant or revoke access on your behalf, and every override read is recorded. Their override appears in search results as `ADMIN_VIEW`; documents they do not own never appear in **My Vault Assets**, and documents not granted to them never appear in **Shared with Me**.

**Can I download without a webcam?**
No. Enrollment is mandatory and there is no fallback credential.

**What if a colleague looks like me?**
The matcher works on distance, not identity documents. Very close matches are rejected at enrollment as duplicates, which is the intended behavior.

**Can I share with someone outside the organization?**
Only if they have an account in this deployment. There is no external-recipient flow.

**How many times can a recipient open a document?**
As many times as the owner's **Max Views** allows, or without limit if the field was left blank.

**Does reading consume a view for the owner?**
No. Owners have no budget. Administrators consume a budget only when they were explicitly granted one.

**Can I recover a deleted document?**
No. Deletion removes the payload. Restore from your own backup if one exists outside TrustVault.

**Is the document encrypted on the server?**
The biometric template is sealed with AES-256-GCM. Document payloads are not encrypted at the file level in this build; protect the upload volume with disk encryption (see 2.11).

**Can I edit the audit log?**
No. Database triggers reject updates and deletes.

**Why did my grant disappear?**
It either expired or its view budget was exhausted; both delete the grant and write a `REVOKE` row explaining which limit was reached.

**What does the lockdown banner mean for me?**
The platform is frozen for containment. Wait; do not attempt workarounds.

**Can I have more than one face enrolled?**
No. One template per identity, enforced by a unique constraint.

---

## 18. Quick-Start Checklist

### 18.1 First day as a member

1. Register with your real name and work email.
2. Choose the member role that matches your duties.
3. Complete the FaceID scan, including the head turn.
4. Sign in and confirm your role badge.
5. Upload one authorized document and pick its category.
6. Share it with a colleague at `READ`, with a 3-view budget.
7. Ask them to confirm they can download it.
8. Review the **Shared with Me** badges to see how budgets appear.

### 18.2 First hour as an owner

1. List which of your documents need sharing at all.
2. For each: choose the minimum level and, where relevant, an expiry.
3. Revoke every stale grant you find.
4. Confirm no document is shared more broadly than intended.
5. Record which documents carry burn limits, and why.

### 18.3 First day as an administrator

1. Confirm your `ADMIN` role in the registry.
2. Read the WORM trail end to end once, to learn the baseline.
3. Test the kill switch on a controlled moment: engage, verify `503`, lift.
4. Perform one break-glass declaration against a test document, then read it with FaceID.
5. Replay one `ROLE_CHANGED` and one `GRANT` row.
6. Confirm backups exist and a restore has been tested.
7. Work through the hardening checklist in 14.10.

### 18.4 Incident checklist

1. Read the anomaly feed and identify the actor and IP.
2. Engage the kill switch with a specific reason.
3. Preserve audit row ids before changing anything.
4. Deactivate the implicated identity.
5. Revoke the implicated grants.
6. Investigate with Action Replay; check for `ROLE_CHANGED` and `maxViews` edits.
7. Lift the lockdown only after containment is verified.
8. Write the post-incident note, including any missing audit row.

---

## 19. Appendix

### 19.1 Glossary

| Term | Definition |
|---|---|
| **Zero-trust** | No request is trusted because of its origin; every request is re-proven |
| **Descriptor / embedding** | A 128-number representation of a face; not an image, not reversible by design |
| **Liveness** | Proof that a real, present human is being scanned — here, blink plus head pose |
| **Challenge** | A signed, single-use, 30-second nonce bound to user, document, and action |
| **Action token** | A 2-minute token minted after a face match, authorizing one specific action |
| **ACL** | Access Control List: the per-document grants naming who may do what |
| **Effective permission** | The level actually granted to you for a document: `OWNER`, `ADMIN`, `EDIT`, or `READ` |
| **Burn-after-reading** | A grant limited by view count or expiry, deleted when the limit is reached |
| **WORM** | Write Once, Read Many — an append-only ledger enforced by database triggers |
| **pre_state / post_state** | Snapshots before and after a mutation, used by Action Replay |
| **Kill switch** | The platform-wide containment flag that returns `503` to non-administrators |
| **Break-glass** | A recorded emergency declaration that produces evidence but grants no rights |
| **Correlated alert** | An alert raised by threshold accumulation rather than a single event |

### 19.2 Error reference

| Status | Code or message | Meaning | Action |
|---|---|---|---|
| 400 | `FACE_ALREADY_REGISTERED` | Face bound to another identity | Escalate to security operations |
| 400 | `Email already registered: …` | Duplicate sign-up | Sign in, or recover the account |
| 400 | `A webcam face scan is required…` | Descriptor missing from sign-up | Allow the camera and rescan |
| 400 | `Disallowed MIME type: …` | Upload type not allowed | Convert or zip |
| 400 | `File size exceeds 20MB limit.` | Upload too large | Compress or split |
| 401 | `Authentication required…` | Missing or expired session | Sign in |
| 403 | `Zero-Trust Access Denied.` | No active grant, or wrong level | Request access |
| 403 | `FACE_NOT_ENROLLED` | No usable template | Enroll |
| 403 | `FACE_MISMATCH` | Distance above the ceiling | Retry in good light |
| 403 | `FACE_CHALLENGE_EXPIRED` | Challenge older than the window | Rescan |
| 403 | `FACE_CHALLENGE_REUSED` | Challenge already redeemed | Rescan |
| 403 | `FACE_CHALLENGE_MISMATCH` | Challenge bound elsewhere | Rescan from the UI |
| 403 | `FACE_PROOF_REQUIRED` | No usable proof presented | Retry from the UI |
| 403 | Burn-after-reading messages | Expired or exhausted grant | Request a new grant |
| 403 | `Account is inactive` | Identity deactivated | Contact an administrator |
| 404 | `Document not found` | Wrong id, or purged | Confirm the id |
| 413 | Payload too large | Proxy or multipart limit | Raise the limit to ≥ 20 MB |
| 422 | Validation failed | Missing or out-of-range field | Check the form (break-glass needs 10+ characters) |
| 500 | Storage errors | Disk permissions or a missing file | Check server logs |
| 503 | `SYSTEM_LOCKDOWN` | Platform frozen | Wait; contact the incident owner |

### 19.3 Configuration reference

| Property | Default | Notes |
|---|---|---|
| `spring.datasource.url` | `jdbc:mysql://localhost:3306/trustvault…` | MySQL 8.0, UTC |
| `spring.jpa.hibernate.ddl-auto` | `validate` | Must stay `validate` to protect the WORM triggers |
| `spring.servlet.multipart.max-file-size` | `20MB` | Align any proxy to this |
| `trustvault.jwt.expiration-ms` | `86400000` | Session lifetime |
| `trustvault.jwt.secret` | *(configured)* | Replace per deployment |
| `trustvault.upload.dir` | `uploads` | Must be writable by the service account |
| `trustvault.bootstrap.seed-default-users` | `false` | Demo only |
| `trustvault.face.match-threshold` | `0.40` | Duplicate-enrollment similarity |
| `trustvault.face.verify-max-distance` | `0.60` | Hard ceiling for identity matching |
| `trustvault.face.challenge-ttl-seconds` | `30` | Clamped to 30 |
| `trustvault.face.challenge-clock-skew-seconds` | `5` | Redemption tolerance |
| `trustvault.face.max-candidates` | `5000` | Duplicate scan breadth |
| `trustvault.face.descriptor-size` | `128` | Embedding dimension |
| `trustvault.face.encryption-key` | *(configured)* | AES-256-GCM sealing key |

### 19.4 Evidence and retention

| Question | Answer |
|---|---|
| How long does the audit trail keep rows? | Indefinitely, unless your organization archives and truncates deliberately |
| Can a row be corrected? | No. Append a compensating event and annotate the incident |
| Are snapshots complete enough to reconstruct a document? | They reconstruct metadata and policy, not file bytes |
| Where should evidence row ids be stored? | In the incident ticket, alongside timestamps and actor emails |
| How is the trail purged? | Only through DDL (`TRUNCATE`) by a DBA, as the reset script does |

### 19.5 Building and running locally

1. Confirm prerequisites: JDK 24, Maven, Node.js with npm, and a MySQL 8.0 server.
2. Create the `trustvault` schema and apply the SQL files in `src/main/resources/db/` (face enrollments, admin security, biometric challenges, break-glass audit, plus the base schema). `ddl-auto=validate` means the application refuses to start if a table, column, or constraint is missing.
3. Install front-end tooling and compile the stylesheet:

   ```bash
   npm install
   npm run build
   ```

4. Package the application:

   ```bash
   mvn -o -DskipTests package
   ```

5. Start it:

   ```bash
   java -jar target/trustvault-1.0.0.jar
   ```

6. Open `http://localhost:8088` and register the first identity.

| Symptom | Cause | Fix |
|---|---|---|
| Startup fails on schema validation | A migration has not been applied | Run the SQL files in order, then restart |
| Port 8088 already in use | Another instance is running | Stop it, or pass `--server.port=8089` |
| UI appears unstyled | Tailwind assets were not built | Run `npm run build` and reload |
| Uploads fail with permission errors | The service account cannot write `uploads/` | Fix ownership, or set `trustvault.upload.dir` to a writable path |
| Face scan never starts | No internet access to the CDN | Allow `cdn.jsdelivr.net`, or host the models locally |

### 19.6 Document control

| Field | Value |
|---|---|
| Product | TrustVault |
| Document | User Manual |
| Version | 2.0 |
| Applies to | TrustVault 1.0.0 — Spring Boot 3.3.x, Java 24, MySQL 8.0 |
| Audience | Vault members, document owners, security administrators |
| Classification | Internal — share with authorized personnel only |
| Support | Your organization's security operations desk |

---

*TrustVault — Webcam FaceID Biometrics • Immutable WORM Compliance • Zero-Trust by construction.*

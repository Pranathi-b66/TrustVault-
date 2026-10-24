# TrustVault — Fresh Reset Runbook

This runbook takes the platform from "existing data" to a pristine, first-boot state and then walks
the full manual verification flow in the browser: identity creation with FaceID, document upload and
sharing, anomaly generation, and the administrator incident tools.

Everything here is manual and observable: each step states the exact input, the endpoint involved,
and what must appear on screen (or in `audit_logs`) if the system is behaving correctly.

---

## 0. Reset the platform

### 0.1 Safety net

```powershell
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqldump.exe" -u root -p trustvault `
    --routines --triggers --result-file="backups\trustvault_before_reset_$stamp.sql"
```

`audit_logs` is protected by `BEFORE UPDATE` / `BEFORE DELETE` triggers that raise
`SQLSTATE '45000'`. The dump contains the triggers by definition; the reset below never updates or
deletes a row individually, so the WORM guard stays armed the whole time.

### 0.2 Apply the break-glass migration (once)

```powershell
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p trustvault `
    -e "source src/main/resources/db/migration_v7_break_glass_audit.sql"
```

Expected: `COLUMN_TYPE` ends with `...,'ROLE_CHANGED','BREAK_GLASS_ACCESS')`. The script is
idempotent, so re-running it is harmless.

### 0.3 Purge all application data

```powershell
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p trustvault `
    -e "source src/main/resources/db/reset_fresh_state.sql"
```

Expected: the verification `UNION` prints `0` for all eight tables. What the script does:

| Table | Handling |
| :--- | :--- |
| `audit_logs` | `TRUNCATE` — DDL never fires the row triggers, so WORM history is cleared without dropping the guard |
| `biometric_challenges` | `TRUNCATE` — replay-protection ledger |
| `biometric_templates` | `TRUNCATE` — face bindings |
| `document_permissions` | `TRUNCATE` — this schema's ACL table (`shared_permissions` does not exist here) |
| `documents` | `TRUNCATE` |
| `user_credentials` | `TRUNCATE` — legacy WebAuthn rows, retained for schema compatibility |
| `users` | `TRUNCATE` — last, children first |
| `system_settings` | `DELETE` — drops `SYSTEM_LOCKDOWN`, returning the platform to `OPERATIONAL` |
| `shared_permissions`, `pending_admin_actions`, `user_risk_scores` | Truncated **only if present** (generated from `information_schema`) |

Primary keys in this schema are `VARCHAR(36)` UUIDs (`DEFAULT (uuid())`), so there is no
`AUTO_INCREMENT` to rewind. Section 8 of the script still rewinds every counter that exists — now or
after a future migration — to `1`, using an `information_schema` cursor loop.

> Anomaly counters live in `AnomalyDetectionService` (in-memory `FailureTracker`) and are backed by
> `audit_logs`. Both are cleared, but a JVM restart is required to drop the in-memory map.

### 0.4 Clear orphaned uploads

The reset deletes the document rows but not the blobs on disk. Move them aside so the vault starts
empty without destroying evidence:

```powershell
$dest = "backups\uploads_before_reset_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $dest -Force | Out-Null
Get-ChildItem uploads -File | Move-Item -Destination $dest -Force
```

### 0.5 Restart and rebuild

```powershell
npm run build          # Tailwind scan of index.html + js/*.js
mvn spring-boot:run
```

The startup log must contain:

```
Demo bootstrap disabled (trustvault.bootstrap.seed-default-users=false); identities must be created through the FaceID sign-up flow.
```

`trustvault.bootstrap.seed-default-users=false` is the default in `application.properties`. With it
enabled, `AuthService` re-creates `admin@`, `owner@` and `viewer@` on every boot, which would
immediately undo this reset. Do not enable it for a production-like run.

---

## 1. Register identities with FaceID

Open `http://localhost:8088`. There is no login form state to reset — the auth view is the landing
page.

### 1.1 First administrator

1. Tab **Register**.
2. Full name `Security Admin`, email `admin@corp.test`, password `Admin@1234`.
3. Assigned Platform Role: **ADMIN (Security Console & Operations)**.
4. The sign-up form opens the webcam modal automatically. Allow camera access, centre your face in
   the oval, press **Scan Face**, and **turn your head slightly left or right** when the prompt
   appears.
5. Submit. Expected: dashboard loads, purple `ADMIN` badge, landing tab is **Admin Console**.

The account and its face binding are created in one transaction — a cancelled or rejected scan
leaves no half-registered user.

### 1.2 Two regular members

Register two more identities, one with **MEMBER (Vault Workspace)** and one with
**MEMBER (Vault Workspace, Owner-Label)**. Use two different faces:

| Email | Role label | Face |
| :--- | :--- | :--- |
| `alice@corp.test` | MEMBER (Vault Workspace, Owner-Label) | Person A |
| `bob@corp.test` | MEMBER (Vault Workspace) | Person B |

Expected: both land on **Owned Documents** with the same green `OWNER` / `VIEWER` badge treatment and
the same tab bar. `OWNER` and `VIEWER` are a labelling difference, not a privilege tier — the
administrative tab stays hidden for both.

### 1.3 Prove the 1-to-1 uniqueness rule

1. Sign out.
2. Register a fourth account, `mallory@corp.test`.
3. When the camera opens, present **Person A's** face (already bound to `alice@corp.test`).
4. Expected: `400 Bad Request`, code `FACE_ALREADY_REGISTERED`, message *"Face already registered to
   another account."* No `users` row is created.

```sql
SELECT COUNT(*) FROM users WHERE email = 'mallory@corp.test';   -- must be 0
```

---

## 2. Upload and share

### 2.1 Upload

Sign in as `alice@corp.test`.

1. **Upload Document** → title `Q4 Financials`, category `FINANCE`, pick any PDF/TXT.
2. Expected toast: *Document "Q4 Financials" securely encrypted & uploaded.*
3. Click **Download** and pass the face gate: the file decrypts and downloads.

### 2.2 Share with email suggestions

1. On the `Q4 Financials` row click **Share & Burn**.
2. Focus the **Grantee Email Address** field **without typing**.
3. Expected: a dropdown lists active identities (`admin@corp.test`, `bob@corp.test`) — the caller is
   excluded, and anyone who already holds a grant is excluded.
4. Type `bo`. Expected: the list narrows to `bob@corp.test` with a role chip.
5. Press **↓** then **Enter** — the field fills with `bob@corp.test` and the ACL form is *not*
   submitted.
6. Set **Permission Level** `READ`, **Burn limit** `2`, leave expiry empty, press **Grant Access**.
7. Expected: the grant appears below with `Burn limit: 0/2 views consumed` and status `ACTIVE`.
   Re-opening the suggestion list no longer offers `bob@corp.test`.

Endpoint behind the dropdown: `GET /api/share-candidates?query=bo` → at most 8 rows of
`{id, email, fullName, role}`. The field remains a free-text input; a failed lookup never blocks a
grant.

### 2.3 Consume the burn link

1. Sign in as `bob@corp.test` → **Shared With Me** → `Q4 Financials` is listed.
2. Download twice (face gate each time). The counter advances `1/2`, then `2/2`.
3. A third attempt returns `403 Forbidden` and the row shows `VIEW LIMIT REACHED`.

---

## 3. Trigger and inspect anomalies

### 3.1 Consecutive FaceID mismatches

1. Sign in as `alice@corp.test` and start a download of any document she owns.
2. At the face gate, present **Person B's** face (or a photo/screen replay) three times within five
   minutes.
3. Expected: each attempt returns `403 Forbidden`; the third inserts a `SECURITY_ALERT` row
   (`CONSECUTIVE_ACCESS_DENIED_EXCEEDED`) and the anomaly feed on the Admin Console lights up with a
   red *SECURITY ANOMALY: BRUTE-FORCE / IDOR ENUMERATION* card.

```sql
SELECT action, status, details FROM audit_logs
WHERE action IN ('ACCESS_DENIED','SECURITY_ALERT') ORDER BY timestamp DESC LIMIT 10;
```

### 3.2 IDOR enumeration

Sign in as `bob@corp.test` and request a document he has no grant for — from the UI this is the
**Search** tab, or directly:

```powershell
$token = (Invoke-RestMethod -Method Post -Uri http://localhost:8088/api/auth/login `
    -ContentType 'application/json' `
    -Body '{"email":"bob@corp.test","password":"<bob-password>"}').token
Invoke-WebRequest -Uri "http://localhost:8088/api/documents/<alice-doc-id>/download" `
    -Headers @{ Authorization = "Bearer $token" }
```

Expected: `403 Forbidden` with an `ACCESS_DENIED` row (user, IP, document id) and, after three
attempts, another `SECURITY_ALERT`. No document metadata is ever returned.

---

## 4. Administrator operations

Sign in as `admin@corp.test` — the Admin Console is the landing tab.

### 4.1 Emergency Kill Switch

1. Type an incident reason of at least 5 characters, e.g. `Suspected credential stuffing`.
2. **Engage Lockdown**. Expected: chip flips to `LOCKED DOWN`, the red banner appears, and the
   detail block shows state / reason / actor / timestamp.
3. In a second browser profile signed in as `bob`, reload any tab: every API call returns
   `503 Service Unavailable` with code `SYSTEM_LOCKDOWN`. The stored reason is **not** leaked.
4. Back as admin press **Lift Lockdown** → traffic resumes immediately.

Audit: `SYSTEM_LOCKDOWN_TRIGGERED` then `SYSTEM_LOCKDOWN_LIFTED` (rendered in rose / emerald).

### 4.2 Break-Glass emergency access

1. Copy the id of a document `admin` does not own (hover the row's Share button, or read it from the
   audit trail).
2. In **Break-Glass Emergency Access** enter the document id and a justification of at least 10
   characters, e.g. `Legal hold — regulator request 2026-114`.
3. **Declare Access**. Expected: an amber result block shows document, owner, **Evidence Row** id and
   declared-at, plus a **Stream With FaceID** button.
4. Expected audit row: `BREAK_GLASS_ACCESS` (amber, bold) with `mode=EMERGENCY_BREAK_GLASS`, the
   reason, and a `pre_state` document snapshot.
5. Press **Stream With FaceID** and pass the gate. Expected: the download completes **and** a
   separate `READ` row is written. The declaration is evidence, not authorization — it neither
   widens rights nor replaces the biometric gate, and burn-after-reading accounting still applies.

Validation: a justification shorter than 10 characters is rejected client-side *and* server-side
(`@Size(min = 10)`).

### 4.3 Action Replay JSON diff

1. In the audit table click **Replay** on the `BREAK_GLASS_ACCESS` row (or any `EDIT` / `GRANT`).
2. Expected: pre-state and post-state JSON side by side, an event-details block, and a per-field
   change table listing `field | before | after`.
3. For a declaration, `pre_state` carries the document snapshot in scope at the moment of the
   emergency; `post_state` is empty because a declaration mutates nothing.

---

## 5. Expected end state

| Check | Expected |
| :--- | :--- |
| `SELECT COUNT(*) FROM users` | 3 (1 admin + 2 members) |
| `biometric_templates` | 3 — one per account, one face each |
| `SELECT COUNT(*) FROM audit_logs` | `UPLOAD`, `READ`, `GRANT`, `ACCESS_DENIED`, `SECURITY_ALERT`, `SYSTEM_LOCKDOWN_*`, `BREAK_GLASS_ACCESS` rows |
| `system_settings` | no `SYSTEM_LOCKDOWN` key after lifting |
| Audit table | WORM: `UPDATE` / `DELETE` on `audit_logs` still fails with SQLSTATE `45000` |

```sql
-- WORM guard must still be armed after the reset: triggers fire per row, so target a real id
SET @id = (SELECT id FROM audit_logs LIMIT 1);
UPDATE audit_logs SET details = details WHERE id = @id;
-- ERROR 1644 (45000): TrustVault Security Violation:
--   Audit logs are strictly append-only and cannot be updated.

DELETE FROM audit_logs WHERE id = @id;
-- ERROR 1644 (45000): TrustVault Security Violation:
--   Audit logs are strictly append-only and cannot be deleted.
```

---

## Troubleshooting

| Symptom | Cause / fix |
| :--- | :--- |
| Login works but every call is `503 SYSTEM_LOCKDOWN` | A previous lockdown survived in `system_settings`, or the JVM cached it. Run `DELETE FROM system_settings WHERE setting_key = 'SYSTEM_LOCKDOWN';` and restart. |
| `admin@`, `owner@`, `viewer@` reappear after a reset | `trustvault.bootstrap.seed-default-users=true` is set somewhere. Remove it and restart. |
| Share dropdown says "No registered identity matches this search" | No other **ACTIVE** account matches the term; the caller and existing grantees are filtered out by design. |
| Face gate always fails liveness | Improve lighting and turn the head a little further — a static photo cannot produce frame-to-frame variance, which is the point. |
| Break-glass returns `500` mentioning the `action` enum | Migration v7 was not applied. Re-run step 0.2. |
| Tailwind classes look unstyled after a UI edit | `npm run build` was not re-run; the CSS is compiled, not CDN-loaded. |

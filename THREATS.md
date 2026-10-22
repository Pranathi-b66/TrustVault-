# TrustVault Threat Model & Zero-Trust Security Architecture

## 1. Executive Summary
**TrustVault** is an enterprise-grade Zero-Trust Secure Document Sharing Platform architected to operate under the assumption that the network perimeter is already compromised. TrustVault combines **FIDO2 / WebAuthn Biometric Passkeys**, **Contextual Access Control Lists (ACL)**, **Burn-After-Reading Ephemeral Links**, **Instant Employee Offboarding Kill-Switches**, and **Cryptographically Enforced WORM (Write Once, Read Many) Compliance** to eliminate single points of failure.

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category | Attack Vector & Scenario | Impact Level | Architectural Mitigation & Verification |
| :--- | :--- | :--- | :--- |
| **Spoofing Identity** | Attacker steals user password or intercepts bearer tokens via phishing or MITM. | **CRITICAL** | • **FIDO2 / WebAuthn Passkeys**: Bound to hardware authenticators using public key cryptography (ES256/RS256).<br>• Biometric prompt required prior to streaming file bytes (`/api/documents/{id}/download`).<br>• Short-lived JWT tokens signed with HMAC-SHA256. |
| **Tampering with Data** | Insider adversary or rogue DBA attempts to modify compliance audit entries to conceal unauthorized exfiltration. | **CRITICAL** | • **MySQL WORM Triggers**: Immutable database triggers (`trg_audit_logs_no_update` and `trg_audit_logs_no_delete`) raising `SIGNAL SQLSTATE '45000'`.<br>• Hibernate `spring.jpa.hibernate.ddl-auto=validate` to preserve triggers.<br>• `@Immutable` JPA entity definition. |
| **Repudiation** | User denies having uploaded, accessed, granted, or deleted a sensitive asset. | **HIGH** | • **Denormalized Historical Snapshot**: Every audit log captures user UUID, email snapshot, client IP (`X-Forwarded-For`), action enum, timestamp with microsecond precision (`timestamp(6)`), and structured JSON event metadata.<br>• Historical logs remain preserved even if user accounts are purged (`ON DELETE SET NULL`). |
| **Information Disclosure (IDOR)** | Attacker enumerates UUIDs or sequential IDs to access User A's private confidential documents. | **CRITICAL** | • **Contextual Zero-Trust ACL**: Every document request validates explicit ownership or explicit grant row in `document_permissions`.<br>• Unauthorized requests immediately abort with `403 Forbidden` and log `ACCESS_DENIED`.<br>• No universal directory or folder browsing. |
| **Denial of Service (DoS)** | Attacker uploads multi-gigabyte files or sends rapid enumeration bursts. | **HIGH** | • Strict 20MB multipart file size restriction.<br>• MIME type whitelist validation.<br>• Path traversal and filename sanitization (`StringUtils.cleanPath`, regex replacement).<br>• Security anomaly detection automatically flagging bursts. |
| **Elevation of Privilege** | Normal VIEWER attempts to invoke administrative endpoints or grant permissions to third parties. | **CRITICAL** | • Spring Method Security (`@PreAuthorize("hasRole('ADMIN')")`).<br>• Granular resource ownership enforcement: Only the authoritative `owner_id` can grant or revoke document permissions. |

---

## 3. Deep-Dive Security Mitigations

### 3.1. Insecure Direct Object Reference (IDOR) Protection
Traditional CRUD applications frequently check authentication without checking contextual ownership. In TrustVault:
1. When a user requests `GET /api/documents/{id}` or `GET /api/documents/{id}/download`, `PermissionService.evaluateAndConsumeAccess(...)` is triggered.
2. If `document.owner.id == user.id`: Access granted as `OWNER`.
3. If not owner, query `document_permissions` for `(document_id, user_id)`.
4. If no grant exists, an `AccessDeniedException` is thrown immediately, logging `ACCESS_DENIED` with source IP and user identity. The response is strictly `403 Forbidden`.

### 3.2. Burn-After-Reading Ephemeral Security
To prevent long-term data exposure:
- **View Caps (`max_views`)**: When a viewer consumes the document (e.g., download), `views_count` is incremented. Once `views_count >= max_views`, the server auto-revokes the permission row and returns `403 Forbidden` on subsequent requests.
- **Temporal Expiry (`expires_at`)**: If `Instant.now().isAfter(expiresAt)`, the link is automatically pruned, blocking all further access with `403 Forbidden`.

### 3.3. Instant Employee Offboarding (Kill-Switch)
When an employee departs or is suspected of credential leakage:
- Admin triggers `PUT /api/admin/users/{id}/deactivate`, flipping status to `INACTIVE`.
- `UserAccountStatusFilter` sits directly in the Spring Security filter chain.
- On every single request, the user's live status is re-evaluated against the persistence tier.
- If `INACTIVE`, the request is terminated with `403 Forbidden`, the security context is flushed, and `ACCOUNT_INACTIVE_ACCESS_ATTEMPT` is recorded in the audit trail.

### 3.4. Security Anomaly Detection (Brute-Force & IDOR Enumeration)
- An in-memory concurrent sliding window and database query monitor consecutive `ACCESS_DENIED` events per user and IP address.
- If **3 consecutive failures** occur within a **5-minute sliding window**, the system automatically elevates the threat level and inserts a high-priority `SECURITY_ALERT` into `audit_logs`.
- Alerts are streamed directly to the Admin Security Dashboard with flashing alert indicators.

### 3.5. Biometric Passkey Gated Download
- To prevent stolen laptop or shoulder-surfing downloads, file streaming requires a fresh WebAuthn passkey assertion (`navigator.credentials.get()`).
- The server validates the cryptographic assertion and issues a scoped, 120-second token bound to that specific document ID. File bytes are only streamed if this passkey assertion is valid.

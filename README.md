# TrustVault — Zero-Trust Secure Document Sharing Platform

TrustVault is a production-ready, security-first document management and sharing platform built with **Java Spring Boot 3**, **MySQL 8.0**, and **Tailwind CSS**. It implements zero-trust architecture, webcam-based FaceID verification (face-api.js descriptors), immutable WORM audit trails, burn-after-reading links, IDOR prevention, and real-time security anomaly detection.

---

## 🔒 Key Enterprise Security Features

1. **Zero-Trust Contextual Permissions & IDOR Defense:**
   - 3 Baseline roles: `ADMIN`, `OWNER`, and `VIEWER`.
   - Contextual ownership: document uploaders automatically become the authoritative `Owner`.
   - Granular ACL (`READ` or `EDIT`) granted strictly per-document in `document_permissions`.
   - Complete prevention of Insecure Direct Object References (IDOR): unauthenticated or unauthorized users trying to view, download, edit, or delete any document immediately receive `403 Forbidden` with full audit logging.
   - Universal folder visibility is prohibited.

2. **Webcam FaceID Verification (face-api.js descriptors, no WebAuthn / passkeys):**
   - **Enrollment at Sign-Up:** the camera modal captures a 128-value facial descriptor (`tinyFaceDetector` + 68 landmarks + `FaceRecognitionNet`) and `POST /api/auth/register` creates the account plus its face binding in one transaction, so a cancelled or rejected scan never leaves a half-registered profile behind.
   - **Strict 1-to-1 Uniqueness:** `biometric_templates.face_descriptor` is bound to `user_id` and `email`, its canonical hash is unique, and every enrollment is cross-checked with the euclidean matcher, so a face already bound to another account is rejected with `400 Bad Request` (`FACE_ALREADY_REGISTERED` — "Face already registered to another account.").
   - **Explicit Capture Only:** the modal opens the webcam only when invoked, overlays an oval alignment guide, and scans only when the user presses **Scan Face**. Script-dispatched events are ignored, so an autofilled form or a cached OS credential can never produce a scan on its own.
   - **Action-Time Gate:** `GET /api/documents/{id}/download` and `PUT /api/documents/{id}` require a fresh descriptor that matches *that user's* stored embedding (similarity ≥ 0.40, i.e. euclidean distance ≤ 0.60); a mismatch returns `403 Forbidden` and writes `ACCESS_DENIED` plus `SECURITY_ALERT` rows.

3. **Instant Employee Offboarding (Fast-Kill Switch):**
   - Endpoint `PUT /api/admin/users/{id}/deactivate` flips user status to `INACTIVE`.
   - `UserAccountStatusFilter` intercepts every request: deactivated users are immediately killed (`403 Forbidden`), while historical audit logs remain preserved (`ON DELETE SET NULL`).

4. **Burn-After-Reading Links:**
   - Ephemeral sharing with optional `max_views` and `expires_at` limits.
   - Once view count is reached or time expires, access is automatically blocked (`403 Forbidden`) and permissions are revoked.

5. **Security Anomaly Detection (Brute-Force & Enumeration):**
   - Monitors consecutive `ACCESS_DENIED` violations per user and IP.
   - If 3 consecutive failures occur within 5 minutes, a high-priority `SECURITY_ALERT` is logged and surfaced on the Admin Security Dashboard.

6. **Immutable WORM Compliance Audit Trail:**
   - Append-only compliance log in `audit_logs`.
   - Backed by MySQL `BEFORE UPDATE` and `BEFORE DELETE` triggers that raise `SIGNAL SQLSTATE '45000'`.
   - Hibernate runs in `spring.jpa.hibernate.ddl-auto=validate` to protect custom database triggers.

---

## 🛠️ Technology Stack

- **Backend:** Java 21 / 24, Spring Boot 3.3.5, Spring Security 6, Spring Data JPA, JJWT 0.12.6, Jackson, AES-256-GCM descriptor sealing.
- **Database:** MySQL 8.0 (`trustvault` schema with custom WORM triggers).
- **Frontend:** Vanilla HTML5, Vanilla JavaScript (ES6+), face-api.js 1.7.15 from jsDelivr (TinyFaceDetector + FaceLandmark68Net + FaceRecognitionNet), locally compiled Tailwind CSS, FontAwesome icons.
- **Testing:** JUnit 5, Spring Boot Test, MockMvc, AssertJ.

---

## 🚀 Pre-Seeded Identities (Default Logins)

The system automatically initializes default passwords on first startup if empty. Navigate to `http://localhost:8088`:

| Email | Default Password | Role | Description |
| :--- | :--- | :--- | :--- |
| `admin@trustvault.internal` | `Admin@123` | **ADMIN** | Security Administrator (User offboarding, WORM audit inspector, anomaly alerts) |
| `owner@trustvault.internal` | `Owner@123` | **OWNER** | Alice (Uploads assets, grants ACLs, configures Burn-After-Reading) |
| `viewer@trustvault.internal` | `Viewer@123` | **VIEWER** | Bob (Consumes shared assets after a live webcam face scan) |

---

## 🧪 Automated Integration Tests

Execute the comprehensive test suite verifying IDOR protection, face uniqueness and action gating, WORM immutability, burn links, and anomaly detection:

```powershell
mvn test
```

### Verified Test Cases:
1. `IdorProtectionIntegrationTest`:
   - User B cannot read User A's private document metadata (`403 Forbidden`).
   - User B cannot download User A's private document (`403 Forbidden`).
   - User B cannot update User A's private document (`403 Forbidden`).
   - User B cannot delete User A's private document (`403 Forbidden`).
   - User A cannot download without a face scan (`403 Forbidden`).
   - User A with a verified face token successfully downloads file (`200 OK`).
2. `FaceUniquenessIntegrationTest`:
   - A byte-identical descriptor cannot be enrolled by a second account (`400`, `detectedBy=exact-hash`).
   - A noisy re-scan of an already-claimed face is caught by the euclidean matcher (`400`, `detectedBy=face-match`).
   - Sign-up binds the account and its face atomically; a claimed face aborts registration and creates no user row.
   - Download/edit without proof is rejected; a non-matching capture is audited as `ACCESS_DENIED` + `SECURITY_ALERT` and counted by the anomaly detector.
   - Repeated mismatches trip `CONSECUTIVE_ACCESS_DENIED_EXCEEDED`, and face tokens are bound to one document and one action.
3. `AuditLogImmutabilityTest`:
   - Direct SQL `UPDATE` on `audit_logs` is rejected by trigger with SQLSTATE `45000`.
   - Direct SQL `DELETE` on `audit_logs` is rejected by trigger with SQLSTATE `45000`.
4. `BurnAfterReadingTest`:
   - Single-use link consumes view on first read; second read returns `403 Forbidden`.
   - Expired link returns `403 Forbidden`.
5. `InstantOffboardingTest`:
   - Deactivated user immediately loses access (`403 Forbidden`).
   - Event logged as `ACCOUNT_INACTIVE_ACCESS_ATTEMPT`.
6. `SecurityAnomalyDetectionTest`:
   - 3 consecutive `ACCESS_DENIED` events trigger automatic `SECURITY_ALERT` insertion.

---

## 🏃 Running the Application

1. Ensure MySQL Server is running on port 3306 with the `trustvault` schema:
   ```properties
   spring.datasource.url=jdbc:mysql://localhost:3306/trustvault?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC
   spring.datasource.username=root
   spring.datasource.password=2006hlkp
   spring.jpa.hibernate.ddl-auto=validate
   ```

2. Start the Spring Boot application:
   ```powershell
   npm install
   npm run build
   mvn spring-boot:run
   ```

3. Open your browser and navigate to:
   ```
   http://localhost:8088
   ```

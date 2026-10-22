# TrustVault — Zero-Trust Secure Document Sharing Platform

TrustVault is a production-ready, security-first document management and sharing platform built with **Java Spring Boot 3**, **MySQL 8.0**, and **Tailwind CSS**. It implements zero-trust architecture, WebAuthn/FIDO2 biometric passkeys, immutable WORM audit trails, burn-after-reading links, IDOR prevention, and real-time security anomaly detection.

---

## 🔒 Key Enterprise Security Features

1. **Zero-Trust Contextual Permissions & IDOR Defense:**
   - 3 Baseline roles: `ADMIN`, `OWNER`, and `VIEWER`.
   - Contextual ownership: document uploaders automatically become the authoritative `Owner`.
   - Granular ACL (`READ` or `EDIT`) granted strictly per-document in `document_permissions`.
   - Complete prevention of Insecure Direct Object References (IDOR): unauthenticated or unauthorized users trying to view, download, edit, or delete any document immediately receive `403 Forbidden` with full audit logging.
   - Universal folder visibility is prohibited.

2. **Working WebAuthn Biometric Passkeys (FIDO2):**
   - **Registration:** `/api/auth/webauthn/register-challenge` & `/register-verify` store public keys in `user_credentials` via `navigator.credentials.create()`.
   - **Login:** `/api/auth/webauthn/login-challenge` & `/login-verify` authenticate via `navigator.credentials.get()`.
   - **Biometric Download Gate:** The secure download endpoint (`GET /api/documents/{id}/download`) **strictly requires a verified biometric passkey prompt** before streaming file bytes.

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

- **Backend:** Java 21 / 24, Spring Boot 3.3.5, Spring Security 6, Spring Data JPA, JJWT 0.12.6, Jackson CBOR, Bouncy Castle.
- **Database:** MySQL 8.0 (`trustvault` schema with custom WORM triggers).
- **Frontend:** Vanilla HTML5, Vanilla JavaScript (ES6+), locally compiled Tailwind CSS, FontAwesome icons.
- **Testing:** JUnit 5, Spring Boot Test, MockMvc, AssertJ.

---

## 🚀 Pre-Seeded Identities (Default Logins)

The system automatically initializes default passwords on first startup if empty. Navigate to `http://localhost:8088`:

| Email | Default Password | Role | Description |
| :--- | :--- | :--- | :--- |
| `admin@trustvault.internal` | `Admin@123` | **ADMIN** | Security Administrator (User offboarding, WORM audit inspector, anomaly alerts) |
| `owner@trustvault.internal` | `Owner@123` | **OWNER** | Alice (Uploads assets, grants ACLs, configures Burn-After-Reading) |
| `viewer@trustvault.internal` | `Viewer@123` | **VIEWER** | Bob (Consumes shared assets via biometric passkey download) |

---

## 🧪 Automated Integration Tests

Execute the comprehensive test suite verifying IDOR protection, WORM immutability, burn links, and anomaly detection:

```powershell
mvn test
```

### Verified Test Cases:
1. `IdorProtectionIntegrationTest`:
   - User B cannot read User A's private document metadata (`403 Forbidden`).
   - User B cannot download User A's private document (`403 Forbidden`).
   - User B cannot update User A's private document (`403 Forbidden`).
   - User B cannot delete User A's private document (`403 Forbidden`).
   - User A cannot download without biometric passkey assertion (`403 Forbidden`).
   - User A with verified passkey token successfully downloads file (`200 OK`).
2. `AuditLogImmutabilityTest`:
   - Direct SQL `UPDATE` on `audit_logs` is rejected by trigger with SQLSTATE `45000`.
   - Direct SQL `DELETE` on `audit_logs` is rejected by trigger with SQLSTATE `45000`.
3. `BurnAfterReadingTest`:
   - Single-use link consumes view on first read; second read returns `403 Forbidden`.
   - Expired link returns `403 Forbidden`.
4. `InstantOffboardingTest`:
   - Deactivated user immediately loses access (`403 Forbidden`).
   - Event logged as `ACCOUNT_INACTIVE_ACCESS_ATTEMPT`.
5. `SecurityAnomalyDetectionTest`:
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

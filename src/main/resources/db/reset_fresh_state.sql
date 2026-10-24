-- =============================================================================
-- TrustVault: full data reset (fresh-install state, schema untouched)
--
-- Purges every user-owned row: accounts, credential rows, face enrollments, documents,
-- ACL grants, the biometric challenge ledger and the whole audit trail. The schema, the
-- indexes and the WORM triggers are deliberately left in place - only data is removed.
--
-- Why TRUNCATE and not DELETE:
--   audit_logs carries two BEFORE UPDATE / BEFORE DELETE triggers that SIGNAL SQLSTATE
--   '45000'. TRUNCATE is DDL and never fires row triggers, so the append-only guard does
--   not have to be dropped (and risk being forgotten) just to clear the table.
--
-- Why FOREIGN_KEY_CHECKS = 0:
--   users is the parent of every other table. Disabling the check lets the child tables
--   and then the parent be truncated without a specific ordering constraint, and it is
--   restored immediately afterwards. Child-first ordering is still respected below so the
--   script also works with the checks left on.
--
-- Run:
--   mysql -u root -p trustvault < src/main/resources/db/reset_fresh_state.sql
-- =============================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- 1. Security trail and forensic state (append-only table, DDL truncate bypasses the triggers).
TRUNCATE TABLE audit_logs;

-- 2. Replay-protection ledger and biometric templates.
TRUNCATE TABLE biometric_challenges;
TRUNCATE TABLE biometric_templates;

-- 3. ACL grants, then the documents they point at.
TRUNCATE TABLE document_permissions;
TRUNCATE TABLE documents;

-- 4. Credential rows (legacy WebAuthn table, retained for schema compatibility).
TRUNCATE TABLE user_credentials;

-- 5. Accounts last: every foreign key above points here.
TRUNCATE TABLE users;

-- 6. Key/value store: removing SYSTEM_LOCKDOWN leaves the platform OPERATIONAL.
--    A running JVM caches the flag, so restart the application after a lockdown was active.
DELETE FROM system_settings;

SET FOREIGN_KEY_CHECKS = 1;

-- -----------------------------------------------------------------------------
-- Verification: every counter must read 0.
-- -----------------------------------------------------------------------------
SELECT 'users'                AS table_name, COUNT(*) AS rows_left FROM users
UNION ALL SELECT 'documents',            COUNT(*) FROM documents
UNION ALL SELECT 'document_permissions', COUNT(*) FROM document_permissions
UNION ALL SELECT 'biometric_templates',  COUNT(*) FROM biometric_templates
UNION ALL SELECT 'biometric_challenges', COUNT(*) FROM biometric_challenges
UNION ALL SELECT 'user_credentials',     COUNT(*) FROM user_credentials
UNION ALL SELECT 'audit_logs',           COUNT(*) FROM audit_logs
UNION ALL SELECT 'system_settings',      COUNT(*) FROM system_settings;

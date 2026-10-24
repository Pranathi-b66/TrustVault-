-- =============================================================================
-- TrustVault migration v7: Break-Glass emergency access audit action
--
-- Adds a dedicated WORM action for an administrator's declared emergency access so the
-- forensic trail distinguishes it from a routine READ or a SECURITY_ALERT anomaly. The
-- audit_logs.action column is a MySQL ENUM, so the new label must be appended to the
-- definition; MODIFY is idempotent and preserves the WORM triggers (they reference the
-- table, not this column list).
--
-- Run:
--   mysql -u root -p trustvault < src/main/resources/db/migration_v7_break_glass_audit.sql
-- =============================================================================

ALTER TABLE audit_logs
    MODIFY COLUMN action ENUM(
        'UPLOAD',
        'READ',
        'EDIT',
        'DELETE',
        'GRANT',
        'REVOKE',
        'ACCESS_DENIED',
        'ACCOUNT_DEACTIVATED',
        'ACCOUNT_INACTIVE_ACCESS_ATTEMPT',
        'SECURITY_ALERT',
        'SYSTEM_LOCKDOWN_TRIGGERED',
        'SYSTEM_LOCKDOWN_LIFTED',
        'ROLE_CHANGED',
        'BREAK_GLASS_ACCESS'
    ) NOT NULL;

-- Verification: the last enum label must be BREAK_GLASS_ACCESS.
SELECT COLUMN_TYPE
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'audit_logs'
  AND COLUMN_NAME = 'action';

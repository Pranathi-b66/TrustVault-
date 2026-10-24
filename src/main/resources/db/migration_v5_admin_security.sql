-- =============================================================================
-- TrustVault migration v5: Emergency Global Kill Switch + Action Replay forensics
--
-- Adds:
--   * audit_logs.pre_state / audit_logs.post_state - JSON resource snapshots taken
--     immediately before and after every administrative mutation, so a mutation can
--     be replayed field-by-field from the immutable WORM trail.
--   * three new audit actions used by the lockdown and user-administration surfaces.
--   * system_settings - small durable key/value store backing the global
--     SYSTEM_LOCKDOWN flag (the request path reads it from an in-memory cache).
--
-- Run once before deploying this release:
--   mysql -u root -p trustvault -e "source src/main/resources/db/migration_v5_admin_security.sql"
--
-- `spring.jpa.hibernate.ddl-auto=validate` verifies every column below at boot.
-- The BEFORE UPDATE / BEFORE DELETE triggers on audit_logs are untouched: ALTER TABLE
-- is DDL and never fires row triggers, and the table stays strictly append-only.
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
        'ROLE_CHANGED'
    ) NOT NULL,
    ADD COLUMN pre_state JSON NULL AFTER details,
    ADD COLUMN post_state JSON NULL AFTER pre_state;

CREATE TABLE IF NOT EXISTS system_settings (
    setting_key VARCHAR(64) NOT NULL,
    setting_value VARCHAR(2048) NOT NULL,
    updated_by VARCHAR(255) NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_system_settings PRIMARY KEY (setting_key)
);

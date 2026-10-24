-- =============================================================================
-- TrustVault: complete data purge -> pristine, first-boot state (schema untouched)
--
-- Removes every user-owned row: identities, face enrollments, documents, ACL grants,
-- biometric challenges, the whole WORM audit trail, the anomaly backlog and the
-- system_settings key/value store (SYSTEM_LOCKDOWN included).
--
-- The schema, indexes, ENUM definitions and the WORM triggers are deliberately left in
-- place - only data is removed. Re-running this script is safe and idempotent.
--
-- Why TRUNCATE and not DELETE:
--   audit_logs carries BEFORE UPDATE / BEFORE DELETE triggers that SIGNAL SQLSTATE '45000'.
--   TRUNCATE is DDL and never fires row triggers, so the append-only guard does not have to
--   be dropped (and risk being forgotten) just to clear the table. TRUNCATE also resets the
--   storage statistics, which is exactly the pristine baseline requested here.
--
-- Why FOREIGN_KEY_CHECKS = 0:
--   users is the parent of every other table, and audit_logs.user_id is ON DELETE SET NULL.
--   Disabling the check lets children and then the parent be truncated without an ordering
--   constraint, and it is restored immediately afterwards. Child-first ordering is still
--   respected below so the script also works with the checks left on.
--
-- Tables named in the reset request that this schema does not have:
--   * shared_permissions      -> this build stores ACL grants in document_permissions
--   * pending_admin_actions   -> admin mutations are applied synchronously (no staging table)
--   * user_risk_scores        -> anomaly counters live in AnomalyDetectionService (in-memory)
--                                and are backed by audit_logs; both are cleared below, so a
--                                JVM restart is required to drop the in-memory counters too.
--   The optional-table block still truncates them if a future/legacy schema has them.
--
-- Run (application may stay up; restart it afterwards):
--   mysql -u root -p trustvault < src/main/resources/db/reset_fresh_state.sql
-- =============================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- -----------------------------------------------------------------------------
-- 1. Security trail and forensic state
--    (append-only table: DDL truncate bypasses the WORM triggers)
-- -----------------------------------------------------------------------------
TRUNCATE TABLE audit_logs;

-- -----------------------------------------------------------------------------
-- 2. Replay-protection ledger and biometric templates
-- -----------------------------------------------------------------------------
TRUNCATE TABLE biometric_challenges;
TRUNCATE TABLE biometric_templates;

-- -----------------------------------------------------------------------------
-- 3. ACL grants, then the documents they point at
-- -----------------------------------------------------------------------------
TRUNCATE TABLE document_permissions;
TRUNCATE TABLE documents;

-- -----------------------------------------------------------------------------
-- 4. Legacy credential rows (WebAuthn table retained for schema compatibility)
-- -----------------------------------------------------------------------------
TRUNCATE TABLE user_credentials;

-- -----------------------------------------------------------------------------
-- 5. Accounts last: every foreign key above points here
-- -----------------------------------------------------------------------------
TRUNCATE TABLE users;

-- -----------------------------------------------------------------------------
-- 6. Key/value store: removing SYSTEM_LOCKDOWN returns the platform to OPERATIONAL.
--    A running JVM caches the flag, so restart the application when a lockdown was active.
-- -----------------------------------------------------------------------------
DELETE FROM system_settings;

-- -----------------------------------------------------------------------------
-- 7. Optional / legacy tables: truncated only when the schema actually contains them,
--    so the script stays portable across revisions without failing on a missing table.
-- -----------------------------------------------------------------------------
SET @optional_table = 'shared_permissions';
SET @optional_sql = (SELECT IF(COUNT(*) > 0,
        CONCAT('TRUNCATE TABLE `', @optional_table, '`'), 'DO 0')
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = @optional_table);
PREPARE optional_stmt FROM @optional_sql;
EXECUTE optional_stmt;
DEALLOCATE PREPARE optional_stmt;

SET @optional_table = 'pending_admin_actions';
SET @optional_sql = (SELECT IF(COUNT(*) > 0,
        CONCAT('TRUNCATE TABLE `', @optional_table, '`'), 'DO 0')
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = @optional_table);
PREPARE optional_stmt FROM @optional_sql;
EXECUTE optional_stmt;
DEALLOCATE PREPARE optional_stmt;

SET @optional_table = 'user_risk_scores';
SET @optional_sql = (SELECT IF(COUNT(*) > 0,
        CONCAT('TRUNCATE TABLE `', @optional_table, '`'), 'DO 0')
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = @optional_table);
PREPARE optional_stmt FROM @optional_sql;
EXECUTE optional_stmt;
DEALLOCATE PREPARE optional_stmt;

SET FOREIGN_KEY_CHECKS = 1;

-- -----------------------------------------------------------------------------
-- 8. Primary-key sequences.
--    Every table in this schema uses a UUID VARCHAR(36) primary key, so there is no
--    AUTO_INCREMENT counter to rewind today. The procedure below reads information_schema
--    and rewinds every counter that does exist (now, or after a future migration) to 1, so
--    a fresh install always starts its identities at the first value. A prepared statement
--    carries exactly one statement, so this has to be a cursor loop - a GROUP_CONCAT of
--    several ALTERs would fail the moment a second table gained a counter.
--
--    DELIMITER is a mysql-client directive: run this file with the CLI (or Workbench),
--    not through a driver that only forwards single statements.
-- -----------------------------------------------------------------------------
DROP PROCEDURE IF EXISTS tv_reset_auto_increment;

DELIMITER $$
CREATE PROCEDURE tv_reset_auto_increment()
BEGIN
    DECLARE finished INT DEFAULT 0;
    DECLARE target VARCHAR(64);
    DECLARE counter_cursor CURSOR FOR
        SELECT TABLE_NAME
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE()
          AND AUTO_INCREMENT IS NOT NULL;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET finished = 1;

    OPEN counter_cursor;
    sequence_loop: LOOP
        FETCH counter_cursor INTO target;
        IF finished = 1 THEN
            LEAVE sequence_loop;
        END IF;

        SET @sequence_sql = CONCAT('ALTER TABLE `', target, '` AUTO_INCREMENT = 1');
        PREPARE sequence_stmt FROM @sequence_sql;
        EXECUTE sequence_stmt;
        DEALLOCATE PREPARE sequence_stmt;
    END LOOP;
    CLOSE counter_cursor;
END$$
DELIMITER ;

CALL tv_reset_auto_increment();
DROP PROCEDURE tv_reset_auto_increment;

-- -----------------------------------------------------------------------------
-- 9. Verification: every counter must read 0.
-- -----------------------------------------------------------------------------
SELECT 'users'                AS table_name, COUNT(*) AS rows_left FROM users
UNION ALL SELECT 'documents',            COUNT(*) FROM documents
UNION ALL SELECT 'document_permissions', COUNT(*) FROM document_permissions
UNION ALL SELECT 'biometric_templates',  COUNT(*) FROM biometric_templates
UNION ALL SELECT 'biometric_challenges', COUNT(*) FROM biometric_challenges
UNION ALL SELECT 'user_credentials',     COUNT(*) FROM user_credentials
UNION ALL SELECT 'audit_logs',           COUNT(*) FROM audit_logs
UNION ALL SELECT 'system_settings',      COUNT(*) FROM system_settings;

-- =============================================================================
-- TrustVault migration v6: timestamped single-use FaceID challenges
--
-- Adds:
--   * biometric_challenges - the single-use ledger behind POST /api/auth/biometric/challenge.
--     A facial descriptor is a durable credential, so POST /verify-face must be bound to a
--     nonce that (a) is signed and timestamped, (b) is tied to one user + document + action,
--     (c) expires after at most 30 seconds and (d) can be redeemed exactly once.
--
--     Only the SHA-256 digest of the issued token is stored, so the table itself cannot be
--     turned into a supply of valid challenges.
--
-- Run once before deploying this release:
--   mysql -u root -p trustvault -e "source src/main/resources/db/migration_v6_biometric_challenges.sql"
--
-- `spring.jpa.hibernate.ddl-auto=validate` verifies every column below at boot.
-- =============================================================================

CREATE TABLE IF NOT EXISTS biometric_challenges (
    id          VARCHAR(36)  NOT NULL,
    user_id     VARCHAR(36)  NOT NULL,
    document_id VARCHAR(36)  NOT NULL,
    action      VARCHAR(16)  NOT NULL,
    token_hash  VARCHAR(64)  NOT NULL,
    issued_at   TIMESTAMP(6) NOT NULL,
    expires_at  TIMESTAMP(6) NOT NULL,
    consumed_at TIMESTAMP(6) NULL,
    issued_ip   VARCHAR(64)  NULL,
    consumed_ip VARCHAR(64)  NULL,
    CONSTRAINT pk_biometric_challenges PRIMARY KEY (id),
    CONSTRAINT uq_biometric_challenges_token UNIQUE (token_hash),
    KEY idx_biometric_challenges_user_expiry (user_id, expires_at),
    CONSTRAINT fk_biometric_challenges_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- =============================================================================
-- TrustVault migration: retire the WebAuthn / FIDO2 credential store (v3)
--
-- WebAuthn passkeys were replaced by the direct minutiae fingerprint engine in
-- `biometric_templates`. The old `user_credentials` table only held FIDO2 public
-- keys, credential IDs and signature counters; no entity, repository or endpoint
-- reads it any more.
--
-- Take a backup first, then run once:
--   mysql -u root -p trustvault < src/main/resources/db/migration_v3_remove_webauthn.sql
--
-- This is irreversible. It is a no-op on schemas where the table was never created.
-- =============================================================================

DROP TABLE IF EXISTS user_credentials;

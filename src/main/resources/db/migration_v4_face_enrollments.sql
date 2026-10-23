-- =============================================================================
-- TrustVault migration v4: exclusive webcam face descriptors
--
-- Replaces the retired minutiae fingerprint columns with the facial embedding
-- produced by face-api.js (128 values, AES-256-GCM sealed at rest).
--
-- Run once against the TrustVault schema before deploying the FaceID engine:
--   mysql -u root -p trustvault < src/main/resources/db/migration_v4_face_enrollments.sql
--
-- `spring.jpa.hibernate.ddl-auto=validate` verifies the columns below at boot.
-- Fingerprint templates cannot be converted into facial embeddings, so existing
-- enrollments are dropped and every identity must re-enroll its face.
-- =============================================================================

DROP TABLE IF EXISTS biometric_templates;

CREATE TABLE biometric_templates (
    id VARCHAR(36) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    email VARCHAR(255) NOT NULL,
    face_descriptor TEXT NOT NULL,
    face_hash VARCHAR(64) NOT NULL,
    algorithm_version VARCHAR(32) NOT NULL DEFAULT 'TV-FACE-1',
    embedding_size INT NOT NULL DEFAULT 128,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT pk_biometric_templates PRIMARY KEY (id),
    CONSTRAINT uk_biometric_templates_user_id UNIQUE (user_id),
    CONSTRAINT uk_biometric_templates_email UNIQUE (email),
    CONSTRAINT uk_biometric_templates_face_hash UNIQUE (face_hash),
    CONSTRAINT fk_biometric_templates_user
        FOREIGN KEY (user_id) REFERENCES users (id)
);

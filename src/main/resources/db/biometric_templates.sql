-- TrustVault facial enrollment schema (current shape).
-- Applied automatically only in test/local environments where ddl-auto is not "validate".
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

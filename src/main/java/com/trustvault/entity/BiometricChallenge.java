package com.trustvault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * One outstanding (or consumed) timestamped challenge for the webcam FaceID flow.
 *
 * <p>Only the SHA-256 digest of the issued token is stored: a database leak therefore cannot be
 * turned into a valid challenge. The row is the single-use ledger that makes replay detection
 * work - the token signature proves it was minted here, and {@code consumed_at} proves it has
 * not been spent yet.</p>
 */
@Entity
@Table(name = "biometric_challenges")
public class BiometricChallenge {

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @Column(name = "user_id", length = 36, nullable = false)
    private String userId;

    @Column(name = "document_id", length = 36, nullable = false)
    private String documentId;

    @Column(name = "action", length = 16, nullable = false)
    private String action;

    /** SHA-256 (hex) of the signed token handed to the browser. */
    @Column(name = "token_hash", length = 64, nullable = false)
    private String tokenHash;

    @Column(name = "issued_at", nullable = false, updatable = false)
    private Instant issuedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    /** {@code null} until the challenge is redeemed; a second redemption is a replay. */
    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "issued_ip", length = 64)
    private String issuedIp;

    @Column(name = "consumed_ip", length = 64)
    private String consumedIp;

    public BiometricChallenge() {
    }

    public BiometricChallenge(String id, String userId, String documentId, String action, String tokenHash,
                              Instant issuedAt, Instant expiresAt, String issuedIp) {
        this.id = id;
        this.userId = userId;
        this.documentId = documentId;
        this.action = action;
        this.tokenHash = tokenHash;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.issuedIp = issuedIp;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getDocumentId() {
        return documentId;
    }

    public void setDocumentId(String documentId) {
        this.documentId = documentId;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public void setTokenHash(String tokenHash) {
        this.tokenHash = tokenHash;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Instant getConsumedAt() {
        return consumedAt;
    }

    public void setConsumedAt(Instant consumedAt) {
        this.consumedAt = consumedAt;
    }

    public String getIssuedIp() {
        return issuedIp;
    }

    public void setIssuedIp(String issuedIp) {
        this.issuedIp = issuedIp;
    }

    public String getConsumedIp() {
        return consumedIp;
    }

    public void setConsumedIp(String consumedIp) {
        this.consumedIp = consumedIp;
    }
}

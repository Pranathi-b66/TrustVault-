package com.trustvault.dto;

import java.time.Instant;

/**
 * Timestamped challenge handed to the browser before a face capture. It must be echoed back in
 * the same {@code verify-face} call that carries the descriptor; the server rejects anything
 * older than the TTL or already redeemed.
 */
public class BiometricChallengeResponse {

    private String challengeToken;
    private String documentId;
    private String action;
    private Instant issuedAt;
    private Instant expiresAt;
    private long expiresInSeconds;

    public String getChallengeToken() {
        return challengeToken;
    }

    public void setChallengeToken(String challengeToken) {
        this.challengeToken = challengeToken;
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

    public long getExpiresInSeconds() {
        return expiresInSeconds;
    }

    public void setExpiresInSeconds(long expiresInSeconds) {
        this.expiresInSeconds = expiresInSeconds;
    }
}

package com.trustvault.dto;

import java.time.Instant;

/**
 * Facial enrollment state of the authenticated identity, used by the UI to decide whether the
 * "Enroll Face" or the "Verify with face" prompt should be shown.
 */
public class FaceStatusResponse {

    private boolean enrolled;
    private String email;
    private String algorithm;
    private Integer embeddingSize;
    private Instant enrolledAt;
    private Instant updatedAt;

    public boolean isEnrolled() {
        return enrolled;
    }

    public void setEnrolled(boolean enrolled) {
        this.enrolled = enrolled;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Integer getEmbeddingSize() {
        return embeddingSize;
    }

    public void setEmbeddingSize(Integer embeddingSize) {
        this.embeddingSize = embeddingSize;
    }

    public Instant getEnrolledAt() {
        return enrolledAt;
    }

    public void setEnrolledAt(Instant enrolledAt) {
        this.enrolledAt = enrolledAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}

package com.trustvault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Action-time face proof: the embedding captured from the webcam immediately before a
 * DOWNLOAD or EDIT, together with the timestamped challenge that proves the capture is fresh.
 *
 * <p>{@code challengeToken} is intentionally not {@code @NotBlank}: a missing challenge must be
 * rejected by the verification service so the attempt is written to the audit trail as
 * {@code FACE_CHALLENGE_REQUIRED}, rather than short-circuiting as a generic 400 validation
 * error.</p>
 */
public class FaceVerificationRequest {

    @NotBlank
    @Size(max = 36)
    private String documentId;

    @NotBlank
    @Size(max = 16)
    private String action;

    @NotNull
    @Size(min = 16, max = 1024)
    private List<Double> descriptor;

    /** Signed, single-use challenge minted by {@code POST /api/auth/biometric/challenge}. */
    @Size(max = 2048)
    private String challengeToken;

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

    public List<Double> getDescriptor() {
        return descriptor;
    }

    public void setDescriptor(List<Double> descriptor) {
        this.descriptor = descriptor;
    }

    public String getChallengeToken() {
        return challengeToken;
    }

    public void setChallengeToken(String challengeToken) {
        this.challengeToken = challengeToken;
    }
}

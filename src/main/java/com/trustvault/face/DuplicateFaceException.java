package com.trustvault.face;

/**
 * Raised when a face being enrolled already belongs to another TrustVault identity. Mapped to
 * {@code 400 Bad Request} so the client can surface a deterministic duplicate error.
 */
public class DuplicateFaceException extends RuntimeException {

    public static final String CODE = "FACE_ALREADY_REGISTERED";
    public static final String MESSAGE = "Face already registered to another account.";

    private final String conflictingEmail;
    private final String detectedBy;

    public DuplicateFaceException(String message, String conflictingEmail, String detectedBy) {
        super(message);
        this.conflictingEmail = conflictingEmail;
        this.detectedBy = detectedBy;
    }

    public String getConflictingEmail() {
        return conflictingEmail;
    }

    /** {@code exact-hash} for byte-identical replays, {@code face-match} for live re-captures. */
    public String getDetectedBy() {
        return detectedBy;
    }
}

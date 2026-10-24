package com.trustvault.face;

/**
 * Raised when an action-time face check cannot be satisfied. Mapped to {@code 403 Forbidden}
 * after the ACCESS_DENIED / SECURITY_ALERT audit trail has been written.
 */
public class FaceVerificationException extends RuntimeException {

    public static final String NOT_ENROLLED = "FACE_NOT_ENROLLED";
    public static final String MISMATCH = "FACE_MISMATCH";
    public static final String PROOF_REQUIRED = "FACE_PROOF_REQUIRED";

    /** Replay protection: the timestamped challenge was absent, stale, forged or already spent. */
    public static final String CHALLENGE_REQUIRED = "FACE_CHALLENGE_REQUIRED";
    public static final String CHALLENGE_EXPIRED = "FACE_CHALLENGE_EXPIRED";
    public static final String CHALLENGE_REUSED = "FACE_CHALLENGE_REUSED";
    public static final String CHALLENGE_MISMATCH = "FACE_CHALLENGE_MISMATCH";

    private final String code;
    private final double score;
    private final int anomalyCount;

    public FaceVerificationException(String code, String message, double score, int anomalyCount) {
        super(message);
        this.code = code;
        this.score = score;
        this.anomalyCount = anomalyCount;
    }

    public String getCode() {
        return code;
    }

    public double getScore() {
        return score;
    }

    public int getAnomalyCount() {
        return anomalyCount;
    }
}

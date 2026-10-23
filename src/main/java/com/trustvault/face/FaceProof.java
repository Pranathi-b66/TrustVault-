package com.trustvault.face;

/**
 * Whatever the caller presented to prove a live face for a sensitive document action.
 *
 * <ul>
 *   <li>{@code actionToken} - a short-lived JWT minted by a successful
 *       {@code POST /api/auth/biometric/verify-face};</li>
 *   <li>{@code faceDescriptor} - a freshly captured embedding (JSON array) verified inline by the
 *       download/edit endpoint itself.</li>
 * </ul>
 */
public record FaceProof(String actionToken, String faceDescriptor) {

    public static FaceProof of(String actionToken, String faceDescriptor) {
        return new FaceProof(trimToNull(actionToken), trimToNull(faceDescriptor));
    }

    public static FaceProof empty() {
        return new FaceProof(null, null);
    }

    public boolean isEmpty() {
        return actionToken == null && faceDescriptor == null;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}

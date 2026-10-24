package com.trustvault.service;

import com.trustvault.entity.User;
import com.trustvault.face.FaceProof;
import com.trustvault.face.FaceVerificationException;
import com.trustvault.security.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import org.springframework.stereotype.Service;

/**
 * The single choke point every sensitive document action must pass through.
 *
 * <p>The gate accepts exactly two forms of proof and nothing else:</p>
 * <ol>
 *   <li>a short-lived action token bound to {@code userId + documentId + action}; or</li>
 *   <li>a freshly captured face descriptor that is matched server-side against the
 *       caller's own enrollment.</li>
 * </ol>
 *
 * <p>There is deliberately no development bypass: an unproven request is denied, logged as
 * {@code ACCESS_DENIED} + {@code SECURITY_ALERT}, and counted by the anomaly detector.</p>
 */
@Service
public class FaceGateService {

    private static final String ACTION_SCOPE = "FACE_ACTION_VERIFIED";

    private final FaceEnrollmentService faceEnrollmentService;
    private final JwtTokenProvider jwtTokenProvider;

    public FaceGateService(FaceEnrollmentService faceEnrollmentService,
                           JwtTokenProvider jwtTokenProvider) {
        this.faceEnrollmentService = faceEnrollmentService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /**
     * @throws FaceVerificationException (403) when the proof is missing, expired, bound to a
     *         different action/document/account, or does not match the enrolled face.
     */
    public void enforce(User user, String documentId, String action,
                        FaceProof proof, String clientIp) {
        String normalisedAction = FaceEnrollmentService.normaliseAction(action);
        FaceProof presented = proof != null ? proof : FaceProof.empty();

        if (presented.actionToken() != null) {
            if (isTokenValidFor(presented.actionToken(), user, documentId, normalisedAction)) {
                return;
            }
            faceEnrollmentService.denyAccess(user, documentId, normalisedAction, clientIp,
                    FaceVerificationException.PROOF_REQUIRED,
                    "Face token is invalid, expired, or not bound to this document and action.",
                    0d);
        }

        if (presented.faceDescriptor() != null) {
            // Matches against this user's enrollment only; throws 403 + audit on mismatch, and
            // rejects the request outright when the timestamped challenge is missing, older than
            // 30 seconds or has already been redeemed.
            faceEnrollmentService.verifyForAction(
                    user, documentId, normalisedAction, presented.faceDescriptor(),
                    presented.challengeToken(), clientIp);
            return;
        }

        faceEnrollmentService.denyAccess(user, documentId, normalisedAction, clientIp,
                FaceVerificationException.PROOF_REQUIRED,
                "Face verification is required before this " + normalisedAction + " action.",
                0d);
    }

    private boolean isTokenValidFor(String token, User user, String documentId, String action) {
        if (!jwtTokenProvider.validateToken(token)) {
            return false;
        }
        try {
            Claims claims = jwtTokenProvider.getClaimsFromToken(token);
            String scope = claims.get("scope", String.class);
            String tokenDocumentId = claims.get("documentId", String.class);
            String tokenAction = claims.get("action", String.class);
            String tokenUserId = claims.get("userId", String.class);

            return ACTION_SCOPE.equals(scope)
                    && documentId.equals(tokenDocumentId)
                    && action.equalsIgnoreCase(tokenAction)
                    && user.getId().equals(tokenUserId);
        } catch (RuntimeException e) {
            return false;
        }
    }
}

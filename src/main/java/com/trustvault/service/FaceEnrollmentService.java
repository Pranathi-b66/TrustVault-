package com.trustvault.service;

import com.trustvault.dto.FaceRegistrationRequest;
import com.trustvault.dto.FaceStatusResponse;
import com.trustvault.dto.FaceVerificationResponse;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditStatus;
import com.trustvault.entity.FaceEnrollment;
import com.trustvault.entity.User;
import com.trustvault.face.DuplicateFaceException;
import com.trustvault.face.FaceDescriptor;
import com.trustvault.face.FaceDescriptorCipher;
import com.trustvault.face.FaceMatcher;
import com.trustvault.face.FaceVerificationException;
import com.trustvault.repository.FaceEnrollmentRepository;
import com.trustvault.security.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Owns the exclusive facial enrollment of every TrustVault identity.
 *
 * <p>Enrollment rules:</p>
 * <ol>
 *   <li>the capture must be a complete embedding of the expected dimension ({@link FaceDescriptor});</li>
 *   <li>its canonical hash must not already be bound to another account (<b>exact replay</b>);</li>
 *   <li>it must not <i>match</i> an embedding owned by another account (<b>same face, new capture</b>);</li>
 *   <li>the account must not already hold a different face (1-to-1 binding).</li>
 * </ol>
 *
 * <p>Action-time matching compares the live descriptor against <b>only that user's</b> stored
 * template. A mismatch writes {@code ACCESS_DENIED} and {@code SECURITY_ALERT} rows and feeds
 * the anomaly detector before the request is rejected with 403.</p>
 */
@Service
public class FaceEnrollmentService {

    private static final Logger log = LoggerFactory.getLogger(FaceEnrollmentService.class);

    public static final String ACTION_DOWNLOAD = "DOWNLOAD";
    public static final String ACTION_EDIT = "EDIT";

    private static final Set<String> SUPPORTED_ACTIONS = Set.of(ACTION_DOWNLOAD, ACTION_EDIT);

    private final FaceEnrollmentRepository faceEnrollmentRepository;
    private final FaceMatcher faceMatcher;
    private final FaceDescriptorCipher descriptorCipher;
    private final AuditLogService auditLogService;
    private final AnomalyDetectionService anomalyDetectionService;
    private final JwtTokenProvider jwtTokenProvider;
    private final BiometricChallengeService biometricChallengeService;

    /** Similarity required to accept a live capture; also used to detect a duplicate enrollment. */
    @Value("${trustvault.face.match-threshold:0.40}")
    private double matchThreshold;

    /**
     * Hard ceiling for identity matching: the euclidean distance between the live probe and the
     * enrolled template must be {@code <= 0.60}. The property can only tighten this value; the
     * constant is never relaxed at runtime.
     *
     * <p>0.60 is the operating point of the browser model, not a round number: FaceRecognitionNet
     * places two captures of one face 0.4-0.6 apart, so anything below 0.5 rejects genuine users
     * (measured live at 0.513 and 0.587). It is also the distance the duplicate-enrollment scan
     * already treats as one identity (similarity 0.40), so the two rules now agree instead of
     * calling two captures the same person on enrollment and different people on verification.</p>
     */
    public static final double MAX_VERIFY_DISTANCE = 0.60d;

    @Value("${trustvault.face.verify-max-distance:0.60}")
    private double configuredVerifyMaxDistance;

    /** Upper bound on enrollments inspected during the duplicate scan. */
    @Value("${trustvault.face.max-candidates:5000}")
    private int maxCandidates;

    /** Dimension of the embedding produced by the browser model. */
    @Value("${trustvault.face.descriptor-size:128}")
    private int descriptorSize;

    public FaceEnrollmentService(FaceEnrollmentRepository faceEnrollmentRepository,
                                 FaceMatcher faceMatcher,
                                 FaceDescriptorCipher descriptorCipher,
                                 AuditLogService auditLogService,
                                 AnomalyDetectionService anomalyDetectionService,
                                 JwtTokenProvider jwtTokenProvider,
                                 BiometricChallengeService biometricChallengeService) {
        this.faceEnrollmentRepository = faceEnrollmentRepository;
        this.faceMatcher = faceMatcher;
        this.descriptorCipher = descriptorCipher;
        this.auditLogService = auditLogService;
        this.anomalyDetectionService = anomalyDetectionService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.biometricChallengeService = biometricChallengeService;
    }

    // =====================================================================
    // 1. ENROLLMENT (registration-time binding)
    // =====================================================================

    @Transactional
    public FaceEnrollment register(User user, FaceRegistrationRequest request, String clientIp) {
        if (user == null) {
            throw new IllegalArgumentException("An authenticated account is required to enroll a face.");
        }

        String email = request.getEmail() == null ? "" : request.getEmail().trim().toLowerCase(Locale.ROOT);
        if (!email.equals(user.getEmail().trim().toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("Email must match the authenticated account.");
        }

        // The descriptor is the evidence: it must be a complete embedding of the model's
        // dimension, its canonical hash must be unclaimed, and it is bound to this account alone.
        FaceDescriptor descriptor = FaceDescriptor.of(request.getDescriptor(), descriptorSize);

        var ownEnrollment = faceEnrollmentRepository.findByUserId(user.getId());
        if (ownEnrollment.isPresent() && matchesOwnEnrollment(ownEnrollment.get(), descriptor)) {
            // Re-capturing the face that is already bound is idempotent rather than an error.
            return ownEnrollment.get();
        }

        // Fast path: byte-identical replay of an embedding owned by somebody else.
        FaceEnrollment exactConflict = faceEnrollmentRepository
                .findByFaceHash(descriptor.canonicalHash())
                .filter(stored -> !stored.getUser().getId().equals(user.getId()))
                .orElse(null);
        if (exactConflict != null) {
            rejectDuplicate(user, user.getEmail(), exactConflict, "exact-hash", clientIp);
        }

        // Slow path: a new capture of the same face, with a fresh embedding.
        FaceEnrollment matchConflict = findConflictingEnrollment(user.getId(), descriptor);
        if (matchConflict != null) {
            rejectDuplicate(user, user.getEmail(), matchConflict, "face-match", clientIp);
        }

        if (ownEnrollment.isPresent()) {
            throw new IllegalArgumentException(
                    "This account is already bound to a face. Revoke the existing enrollment before scanning a different face.");
        }

        FaceEnrollment enrollment = new FaceEnrollment(
                UUID.randomUUID().toString(),
                user,
                email,
                descriptor.canonicalHash(),
                descriptorCipher.seal(descriptor.canonicalForm()),
                FaceDescriptor.ALGORITHM,
                descriptor.size());

        try {
            FaceEnrollment saved = faceEnrollmentRepository.saveAndFlush(enrollment);

            Map<String, Object> details = new HashMap<>();
            details.put("event", "FACE_ENROLLED");
            details.put("algorithm", FaceDescriptor.ALGORITHM);
            details.put("embeddingSize", descriptor.size());
            details.put("deviceLabel", request.getDeviceLabel() != null ? request.getDeviceLabel() : "unspecified");
            // Joins the caller's transaction: during sign-up the account row is not committed yet,
            // so the enrollment record must commit atomically with it.
            auditLogService.logEventInTransaction(user, user.getEmail(), AuditAction.UPLOAD, null, clientIp,
                    AuditStatus.SUCCESS, details);

            return saved;
        } catch (DataIntegrityViolationException e) {
            // Concurrent enrollment won the race against the pre-checks: the unique keys hold the line.
            Map<String, Object> details = new HashMap<>();
            details.put("event", "DUPLICATE_FACE_ENROLLMENT_BLOCKED");
            details.put("detectedBy", "unique-constraint");
            details.put("userEmail", user.getEmail());
            // No entity reference: the surrounding transaction is rolling back, so the account row
            // may never exist. The alert still has to be persisted, and an email-only row can be
            // written without waiting on a foreign-key lock.
            auditLogService.logEvent(null, user.getEmail(), AuditAction.SECURITY_ALERT, null, clientIp,
                    AuditStatus.FAILURE, details);
            throw new DuplicateFaceException(DuplicateFaceException.MESSAGE, null, "unique-constraint");
        }
    }

    /**
     * Convenience overload for test fixtures and in-process callers that already hold the
     * embedding. HTTP callers go through {@link #register(User, FaceRegistrationRequest, String)}.
     */
    @Transactional
    public FaceEnrollment enroll(User user, List<Double> descriptor, String clientIp) {
        FaceRegistrationRequest request = new FaceRegistrationRequest();
        request.setEmail(user.getEmail());
        request.setDescriptor(descriptor);
        request.setDeviceLabel("api");
        return register(user, request, clientIp);
    }

    /**
     * Sign-up pre-flight: validates the capture and rejects a face already bound to another
     * identity <b>without persisting anything</b>. Account creation can therefore abort cleanly,
     * so a duplicate biometric never leaves a half-registered user behind.
     *
     * @param applicantEmail email attempting to sign up; the account may not exist yet
     */
    @Transactional
    public void assertFaceClaimable(List<Double> rawDescriptor, String applicantEmail, String clientIp) {
        FaceDescriptor descriptor = FaceDescriptor.of(rawDescriptor, descriptorSize);

        FaceEnrollment exactConflict = faceEnrollmentRepository
                .findByFaceHash(descriptor.canonicalHash())
                .orElse(null);
        if (exactConflict != null) {
            rejectDuplicate(null, applicantEmail, exactConflict, "exact-hash", clientIp);
        }

        FaceEnrollment matchConflict = findConflictingEnrollment(null, descriptor);
        if (matchConflict != null) {
            rejectDuplicate(null, applicantEmail, matchConflict, "face-match", clientIp);
        }
    }

    /** True when the incoming capture is the same face already bound to this account. */
    private boolean matchesOwnEnrollment(FaceEnrollment enrollment, FaceDescriptor candidate) {
        if (enrollment.getFaceHash().equals(candidate.canonicalHash())) {
            return true;
        }
        if (enrollment.getDescriptorPayload() == null) {
            return false;
        }
        try {
            FaceDescriptor stored = FaceDescriptor.parse(
                    descriptorCipher.open(enrollment.getDescriptorPayload()), descriptorSize);
            return faceMatcher.similarity(candidate, stored) >= matchThreshold;
        } catch (RuntimeException e) {
            log.warn("Unable to compare the live capture with enrollment {}: {}", enrollment.getId(), e.getMessage());
            return false;
        }
    }

    /**
     * Returns the enrollment of another account whose face <em>matches</em> the candidate
     * capture, or {@code null} when the face is unclaimed. The exact-hash case is handled by the
     * caller before this scan runs.
     *
     * @param userId account to exclude from the scan, or {@code null} during sign-up when no
     *               account exists yet
     */
    private FaceEnrollment findConflictingEnrollment(String userId, FaceDescriptor candidate) {
        List<FaceEnrollment> enrolled = faceEnrollmentRepository.findAll();
        int inspected = 0;
        for (FaceEnrollment stored : enrolled) {
            if (inspected++ >= maxCandidates) {
                log.warn("Duplicate face scan capped at {} enrollments; remaining rows were not compared.",
                        maxCandidates);
                break;
            }
            if (stored.getUser().getId().equals(userId) || stored.getDescriptorPayload() == null) {
                continue;
            }
            FaceDescriptor storedDescriptor;
            try {
                storedDescriptor = FaceDescriptor.parse(
                        descriptorCipher.open(stored.getDescriptorPayload()), descriptorSize);
            } catch (RuntimeException e) {
                log.warn("Skipping unreadable face enrollment {} during duplicate scan: {}",
                        stored.getId(), e.getMessage());
                continue;
            }
            if (faceMatcher.similarity(candidate, storedDescriptor) >= matchThreshold) {
                return stored;
            }
        }
        return null;
    }

    private void rejectDuplicate(User user, String actingEmail, FaceEnrollment conflict,
                                 String detectedBy, String clientIp) {
        String conflictingEmail = maskEmail(conflict.getEmail());

        Map<String, Object> details = new HashMap<>();
        details.put("event", "DUPLICATE_FACE_ENROLLMENT_BLOCKED");
        details.put("conflictingAccount", conflictingEmail);
        details.put("detectedBy", detectedBy);
        details.put("reason", "Face already bound to another TrustVault identity");
        auditLogService.logEvent(user, actingEmail, AuditAction.SECURITY_ALERT, null, clientIp,
                AuditStatus.FAILURE, details);

        throw new DuplicateFaceException(DuplicateFaceException.MESSAGE, conflictingEmail, detectedBy);
    }

    // =====================================================================
    // 2. ACTION-TIME VERIFICATION (download / edit)
    // =====================================================================

    @Transactional
    public FaceVerificationResponse verifyForAction(User user,
                                                    String documentId,
                                                    String requestedAction,
                                                    List<Double> descriptor,
                                                    String challengeToken,
                                                    String clientIp) {
        FaceDescriptor probe = FaceDescriptor.of(descriptor, descriptorSize);
        return verify(user, documentId, requestedAction, probe, challengeToken, clientIp);
    }

    /** Inline-proof entry point: the descriptor arrives as a JSON array (header/query value). */
    @Transactional
    public FaceVerificationResponse verifyForAction(User user,
                                                    String documentId,
                                                    String requestedAction,
                                                    String descriptorJson,
                                                    String challengeToken,
                                                    String clientIp) {
        FaceDescriptor probe = FaceDescriptor.parse(descriptorJson, descriptorSize);
        return verify(user, documentId, requestedAction, probe, challengeToken, clientIp);
    }

    private FaceVerificationResponse verify(User user,
                                            String documentId,
                                            String requestedAction,
                                            FaceDescriptor probe,
                                            String challengeToken,
                                            String clientIp) {
        String action = normaliseAction(requestedAction);

        // 0. Replay protection. The descriptor is a durable credential, not a nonce: a recorded
        //    verify-face body would stay valid indefinitely. The challenge is timestamped, bound to
        //    user+document+action and burned on first use, so a captured body is worthless on
        //    replay. This runs before any template work.
        BiometricChallengeService.ChallengeDecision challenge =
                biometricChallengeService.consume(user, documentId, action, challengeToken, clientIp);
        if (!challenge.valid()) {
            deny(user, documentId, action, clientIp, challenge.code(), challenge.message(), 0d,
                    "FACE_CHALLENGE_REJECTED");
        }

        FaceEnrollment enrollment = faceEnrollmentRepository.findByUserId(user.getId())
                .orElse(null);

        if (enrollment == null || enrollment.getDescriptorPayload() == null) {
            Map<String, Object> details = new HashMap<>();
            details.put("event", "FACE_NOT_ENROLLED");
            details.put("action", action);
            details.put("reason", "Account has no face enrollment to match against");
            auditLogService.logEvent(user, user.getEmail(), AuditAction.ACCESS_DENIED, documentId, clientIp,
                    AuditStatus.FAILURE, details);
            auditLogService.logEvent(user, user.getEmail(), AuditAction.SECURITY_ALERT, documentId, clientIp,
                    AuditStatus.FAILURE, details);

            throw new FaceVerificationException(
                    FaceVerificationException.NOT_ENROLLED,
                    "No face is enrolled for this account. Enroll your face before accessing protected documents.",
                    0d,
                    anomalyDetectionService.currentFailureCount(clientIp, user.getEmail()));
        }

        FaceDescriptor reference;
        try {
            reference = FaceDescriptor.parse(
                    descriptorCipher.open(enrollment.getDescriptorPayload()), descriptorSize);
        } catch (RuntimeException e) {
            log.error("Stored face enrollment for {} cannot be opened", maskEmail(user.getEmail()), e);
            throw new FaceVerificationException(
                    FaceVerificationException.NOT_ENROLLED,
                    "The enrolled face descriptor is unreadable. Re-enroll to continue.",
                    0d,
                    anomalyDetectionService.currentFailureCount(clientIp, user.getEmail()));
        }

        // Identity decision on the raw euclidean distance against the account's own template:
        // accept only d <= 0.60, the model's own intra-person operating range. The liveness pass
        // and the single-use challenge are what make this ceiling safe; a tighter distance only
        // locks genuine users out of their own documents.
        double rawDistance = faceMatcher.distance(probe, reference);
        double distance = round(rawDistance);
        double maxDistance = getVerifyMaxDistance();
        double similarity = round(faceMatcher.similarity(probe, reference));

        if (rawDistance > maxDistance) {
            Map<String, Object> details = new HashMap<>();
            details.put("event", "FACE_MATCH_FAILED");
            details.put("action", action);
            details.put("targetDocumentId", documentId);
            details.put("matchDistance", distance);
            details.put("distanceThreshold", maxDistance);
            details.put("matchScore", similarity);
            details.put("userEmail", user.getEmail());
            auditLogService.logEvent(user, user.getEmail(), AuditAction.ACCESS_DENIED, documentId, clientIp,
                    AuditStatus.FAILURE, details);
            auditLogService.logEvent(user, user.getEmail(), AuditAction.SECURITY_ALERT, documentId, clientIp,
                    AuditStatus.FAILURE, details);

            throw new FaceVerificationException(
                    FaceVerificationException.MISMATCH,
                    "Face does not match the descriptor enrolled for this account (distance "
                            + String.format(Locale.ROOT, "%.3f", distance) + " > " + maxDistance
                            + "). " + action + " blocked.",
                    distance,
                    anomalyDetectionService.currentFailureCount(clientIp, user.getEmail()));
        }

        String faceToken = jwtTokenProvider.generateFaceActionToken(
                user.getId(), user.getEmail(), documentId, action);

        Map<String, Object> details = new HashMap<>();
        details.put("event", "FACE_ACTION_VERIFIED");
        details.put("action", action);
        details.put("matchDistance", distance);
        details.put("distanceThreshold", maxDistance);
        details.put("matchScore", similarity);
        details.put("algorithm", enrollment.getAlgorithmVersion());
        details.put("challengeId", challenge.challengeId());
        auditLogService.logEvent(user, user.getEmail(), AuditAction.READ, documentId, clientIp,
                AuditStatus.SUCCESS, details);

        FaceVerificationResponse response = new FaceVerificationResponse();
        response.setVerified(true);
        response.setAction(action);
        response.setDocumentId(documentId);
        response.setScore(similarity);
        response.setDistance(distance);
        response.setThreshold(maxDistance);
        response.setMetric("EUCLIDEAN_DISTANCE");
        response.setFaceToken(faceToken);
        response.setExpiresInSeconds(120L);
        response.setAlgorithm(enrollment.getAlgorithmVersion());
        response.setVerifiedAt(Instant.now());
        return response;
    }

    /** Effective identity threshold: configuration can tighten 0.60 but never loosen it. */
    public double getVerifyMaxDistance() {
        double configured = configuredVerifyMaxDistance > 0 ? configuredVerifyMaxDistance : MAX_VERIFY_DISTANCE;
        return Math.max(0.05d, Math.min(configured, MAX_VERIFY_DISTANCE));
    }

    // =====================================================================
    // 3. STATE & LIFECYCLE
    // =====================================================================

    @Transactional(readOnly = true)
    public FaceStatusResponse getStatus(User user) {
        FaceStatusResponse response = new FaceStatusResponse();
        response.setEmail(user.getEmail());
        var enrollment = faceEnrollmentRepository.findByUserId(user.getId());
        if (enrollment.isEmpty()) {
            response.setEnrolled(false);
            response.setAlgorithm(FaceDescriptor.ALGORITHM);
            return response;
        }
        FaceEnrollment face = enrollment.get();
        response.setEnrolled(face.getDescriptorPayload() != null);
        response.setAlgorithm(face.getAlgorithmVersion());
        response.setEmbeddingSize(face.getEmbeddingSize());
        response.setEnrolledAt(face.getCreatedAt());
        response.setUpdatedAt(face.getUpdatedAt());
        return response;
    }

    @Transactional
    public void revoke(User user, String clientIp) {
        var enrollment = faceEnrollmentRepository.findByUserId(user.getId());
        if (enrollment.isEmpty()) {
            throw new IllegalArgumentException("No face enrollment exists for this account.");
        }
        faceEnrollmentRepository.delete(enrollment.get());
        faceEnrollmentRepository.flush();

        Map<String, Object> details = new HashMap<>();
        details.put("event", "FACE_ENROLLMENT_REVOKED");
        auditLogService.logEvent(user, user.getEmail(), AuditAction.REVOKE, null, clientIp,
                AuditStatus.SUCCESS, details);
    }

    public double getMatchThreshold() {
        return matchThreshold;
    }

    // =====================================================================
    // 4. HELPERS
    // =====================================================================

    public static String normaliseAction(String requestedAction) {
        String action = requestedAction == null ? ACTION_DOWNLOAD : requestedAction.trim().toUpperCase(Locale.ROOT);
        if (!SUPPORTED_ACTIONS.contains(action)) {
            throw new IllegalArgumentException(
                    "Unsupported biometric action '" + requestedAction + "'. Expected DOWNLOAD or EDIT.");
        }
        return action;
    }

    /**
     * Writes the full denial trail (ACCESS_DENIED + SECURITY_ALERT) and throws the 403 mapped
     * exception. Exposed so the document gate can reject requests that carry no usable proof.
     */
    public void denyAccess(User user, String documentId, String action, String clientIp,
                           String code, String reason, double score) {
        deny(user, documentId, action, clientIp, code, reason, score, "FACE_PROOF_MISSING");
    }

    /**
     * Single denial path: one audit event pair, one exception, one anomaly count - whatever the
     * reason (missing proof, rejected challenge, failed match).
     */
    private void deny(User user, String documentId, String action, String clientIp,
                      String code, String reason, double score, String event) {
        Map<String, Object> details = new HashMap<>();
        details.put("event", event);
        details.put("verificationCode", code);
        details.put("action", action);
        details.put("targetDocumentId", documentId);
        details.put("reason", reason);
        details.put("matchScore", round(score));
        details.put("distanceThreshold", getVerifyMaxDistance());
        details.put("userEmail", user != null ? user.getEmail() : "unknown");

        String email = user != null ? user.getEmail() : "unknown";
        auditLogService.logEvent(user, email, AuditAction.ACCESS_DENIED, documentId, clientIp,
                AuditStatus.FAILURE, details);
        // A nonce that simply aged out is a timing artifact, not an attack: the client now mints
        // the challenge after the capture and submits it immediately, so only clock skew beyond
        // the skew allowance or a stalled tab can expire one. The refusal is still audited, but
        // SECURITY_ALERT is reserved for what really indicates replay: a spent, re-bound or
        // mismatched token.
        if (!FaceVerificationException.CHALLENGE_EXPIRED.equals(code)) {
            auditLogService.logEvent(user, email, AuditAction.SECURITY_ALERT, documentId, clientIp,
                    AuditStatus.FAILURE, details);
        }

        throw new FaceVerificationException(code, reason,
                round(score), anomalyDetectionService.currentFailureCount(clientIp, email));
    }

    private static double round(double value) {
        return Math.round(value * 1000d) / 1000d;
    }

    /** Keeps the audit trail informative without exposing a full address to the caller. */
    static String maskEmail(String email) {
        if (email == null || email.isBlank()) {
            return "unknown";
        }
        int at = email.indexOf('@');
        if (at <= 1) {
            return "***" + (at >= 0 ? email.substring(at) : "");
        }
        return email.charAt(0) + "***" + email.substring(at);
    }
}

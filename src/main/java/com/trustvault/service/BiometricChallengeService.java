package com.trustvault.service;

import com.trustvault.dto.BiometricChallengeResponse;
import com.trustvault.entity.BiometricChallenge;
import com.trustvault.entity.User;
import com.trustvault.face.FaceVerificationException;
import com.trustvault.repository.BiometricChallengeRepository;
import com.trustvault.security.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Issues and redeems the timestamped challenges that protect {@code POST /verify-face} against
 * replay.
 *
 * <p>A face descriptor is not a nonce: a captured request body stays valid for as long as the
 * template keeps matching the user's face. The challenge closes that window by making every
 * verification single-use and time-boxed:</p>
 *
 * <ol>
 *   <li>{@link #issue} mints a signed token bound to {@code user + document + action} with a
 *       TTL that can only be configured <em>shorter</em> than 30 seconds, and records its SHA-256
 *       digest in {@code biometric_challenges};</li>
 *   <li>{@link #consume} re-validates the signature, the binding, the age and the ledger row, then
 *       flips {@code consumed_at} with a single conditional {@code UPDATE}.</li>
 * </ol>
 *
 * <p>Consumption runs in its own transaction: the challenge stays burned even when the face match
 * that follows fails and rolls the surrounding business transaction back.</p>
 */
@Service
public class BiometricChallengeService {

    private static final Logger log = LoggerFactory.getLogger(BiometricChallengeService.class);

    /** Published policy ceiling; configuration can shorten the window but never extend it. */
    public static final long MAX_TTL_SECONDS = 30L;

    private static final String SCOPE = "BIOMETRIC_CHALLENGE";

    private final BiometricChallengeRepository challengeRepository;
    private final JwtTokenProvider jwtTokenProvider;

    @Value("${trustvault.face.challenge-ttl-seconds:30}")
    private long configuredTtlSeconds;

    /** Tolerance for clock drift between the minting and the redeeming node. */
    @Value("${trustvault.face.challenge-clock-skew-seconds:5}")
    private long clockSkewSeconds;

    public BiometricChallengeService(BiometricChallengeRepository challengeRepository,
                                     JwtTokenProvider jwtTokenProvider) {
        this.challengeRepository = challengeRepository;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /** Outcome of a redemption attempt; a rejection never throws so the caller can audit it. */
    public record ChallengeDecision(boolean valid, String code, String message,
                                    String challengeId, Instant issuedAt, Instant expiresAt) {

        public static ChallengeDecision accepted(String challengeId, Instant issuedAt, Instant expiresAt) {
            return new ChallengeDecision(true, null, null, challengeId, issuedAt, expiresAt);
        }

        public static ChallengeDecision rejected(String code, String message) {
            return new ChallengeDecision(false, code, message, null, null, null);
        }
    }

    // =====================================================================
    // 1. ISSUANCE
    // =====================================================================

    @Transactional
    public BiometricChallengeResponse issue(User user, String documentId, String normalisedAction, String clientIp) {
        Instant issuedAt = Instant.now();
        long ttl = effectiveTtlSeconds();
        Instant expiresAt = issuedAt.plusSeconds(ttl);

        // Keep the ledger bounded without a scheduler: only this account's long-expired rows go.
        challengeRepository.deleteStaleForUser(user.getId(), issuedAt.minusSeconds(300));

        String challengeId = UUID.randomUUID().toString();
        String token = jwtTokenProvider.generateBiometricChallengeToken(
                user.getId(), user.getEmail(), challengeId, documentId, normalisedAction, ttl);

        challengeRepository.save(new BiometricChallenge(
                challengeId, user.getId(), documentId, normalisedAction, sha256(token), issuedAt, expiresAt, clientIp));

        BiometricChallengeResponse response = new BiometricChallengeResponse();
        response.setChallengeToken(token);
        response.setDocumentId(documentId);
        response.setAction(normalisedAction);
        response.setIssuedAt(issuedAt);
        response.setExpiresAt(expiresAt);
        response.setExpiresInSeconds(ttl);
        return response;
    }

    // =====================================================================
    // 2. REDEMPTION (single use, 30 s maximum age)
    // =====================================================================

    /**
     * Validates and burns the challenge. Own transaction: the burn survives a later rollback of
     * the face-verification transaction, so a failed match cannot be retried with the same nonce.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ChallengeDecision consume(User user, String documentId, String normalisedAction,
                                     String challengeToken, String clientIp) {
        if (challengeToken == null || challengeToken.isBlank()) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_REQUIRED,
                    "A FaceID challenge is required. Request one from /api/auth/biometric/challenge "
                            + "before scanning and submit it with the descriptor.");
        }

        Claims claims;
        try {
            claims = jwtTokenProvider.getClaimsFromToken(challengeToken);
        } catch (ExpiredJwtException e) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_EXPIRED,
                    "This FaceID challenge has expired. Request a new one and scan again.");
        } catch (RuntimeException e) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_MISMATCH,
                    "The FaceID challenge signature is not valid.");
        }

        if (!SCOPE.equals(claims.get("scope", String.class))) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_MISMATCH,
                    "The presented token is not a FaceID challenge.");
        }

        String challengeId = claims.get("challengeId", String.class);
        String tokenUserId = claims.get("userId", String.class);
        String tokenDocumentId = claims.get("documentId", String.class);
        String tokenAction = claims.get("action", String.class);
        if (challengeId == null || tokenUserId == null || tokenDocumentId == null || tokenAction == null) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_MISMATCH,
                    "The FaceID challenge is missing its binding claims.");
        }

        Instant now = Instant.now();
        Date issuedDate = claims.getIssuedAt();
        Instant issuedAt = issuedDate != null ? issuedDate.toInstant() : null;

        // A token stamped in the future beyond the tolerated drift did not come from this clock.
        if (issuedAt != null && issuedAt.isAfter(now.plusSeconds(clockSkewSeconds))) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_MISMATCH,
                    "The FaceID challenge timestamp is not valid.");
        }

        if (!user.getId().equals(tokenUserId)
                || !documentId.equals(tokenDocumentId)
                || !normalisedAction.equalsIgnoreCase(tokenAction)) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_MISMATCH,
                    "The FaceID challenge was issued for a different account, document or action.");
        }

        // Defence in depth: enforce the 30 s policy even if a token somehow claims a longer life.
        if (issuedAt != null
                && Duration.between(issuedAt, now).getSeconds() > effectiveTtlSeconds() + clockSkewSeconds) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_EXPIRED,
                    "This FaceID challenge is older than the permitted 30 second window.");
        }

        BiometricChallenge stored = challengeRepository.findById(challengeId).orElse(null);
        if (stored == null) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_REUSED,
                    "This FaceID challenge is unknown or has already been retired. Request a new one.");
        }
        if (!stored.getUserId().equals(user.getId())) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_MISMATCH,
                    "The FaceID challenge belongs to another account.");
        }
        if (!stored.getTokenHash().equals(sha256(challengeToken))) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_MISMATCH,
                    "The FaceID challenge does not match the one that was issued.");
        }
        if (stored.getConsumedAt() != null) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_REUSED,
                    "This FaceID challenge has already been used. Request a new one and scan again.");
        }
        if (now.isAfter(stored.getExpiresAt())) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_EXPIRED,
                    "This FaceID challenge has expired. Request a new one and scan again.");
        }

        // Atomic redemption: the loser of a concurrent replay updates zero rows.
        if (challengeRepository.markConsumed(challengeId, now, clientIp) != 1) {
            return ChallengeDecision.rejected(FaceVerificationException.CHALLENGE_REUSED,
                    "This FaceID challenge has already been used. Request a new one and scan again.");
        }

        log.info("FaceID challenge {} redeemed for {} ({} on {})",
                challengeId, stored.getUserId(), normalisedAction, documentId);
        return ChallengeDecision.accepted(challengeId, stored.getIssuedAt(), stored.getExpiresAt());
    }

    public long getChallengeTtlSeconds() {
        return effectiveTtlSeconds();
    }

    private long effectiveTtlSeconds() {
        return Math.max(1L, Math.min(configuredTtlSeconds, MAX_TTL_SECONDS));
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable in this JVM.", e);
        }
    }
}

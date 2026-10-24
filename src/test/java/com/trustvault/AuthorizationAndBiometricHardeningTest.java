package com.trustvault;

import com.trustvault.dto.DocumentResponse;
import com.trustvault.dto.FaceVerificationResponse;
import com.trustvault.dto.GrantPermissionRequest;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.PermissionLevel;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import com.trustvault.face.FaceVerificationException;
import com.trustvault.repository.AuditLogRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.JwtTokenProvider;
import com.trustvault.service.BiometricChallengeService;
import com.trustvault.service.DocumentService;
import com.trustvault.service.FaceEnrollmentService;
import com.trustvault.service.PermissionService;
import com.trustvault.support.FaceFixtures;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Regression suite for the four hardening corrections, each of which is only meaningful if the
 * <em>old</em> behaviour would have let the attack through:
 *
 * <ol>
 *   <li><b>Real-time ACL</b> - the caller's JWT stays valid across a revocation, so a download
 *       or edit that succeeds after the grant is gone proves the decision came from a cached
 *       claim instead of {@code shared_permissions};</li>
 *   <li><b>Liveness + quality</b> - asserted in the JavaScript layer; the server contract it
 *       feeds is the strict distance rule covered here;</li>
 *   <li><b>Distance ceiling</b> - a capture 0.45 away is still the enrolled person (the model
 *       puts one face's own frames 0.4-0.6 apart) while 0.75 is a different identity, so the
 *       0.60 ceiling accepts the first and rejects the second;</li>
 *   <li><b>Timestamped challenges</b> - a captured {@code verify-face} body must become useless
 *       the moment its challenge is spent, expired or re-bound.</li>
 * </ol>
 */
@SpringBootTest
@AutoConfigureMockMvc
public class AuthorizationAndBiometricHardeningTest {

    private static final String OWNER_EMAIL = "hardening.owner@internal.test";
    private static final String RECIPIENT_EMAIL = "hardening.recipient@internal.test";
    private static final String ADMIN_EMAIL = "hardening.admin@internal.test";
    private static final String DISTANCE_EMAIL = "hardening.distance@internal.test";
    private static final String CLIENT_IP = "10.10.0.5";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private DocumentService documentService;

    @Autowired
    private PermissionService permissionService;

    @Autowired
    private FaceEnrollmentService faceEnrollmentService;

    @Autowired
    private BiometricChallengeService biometricChallengeService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private User owner;
    private User recipient;
    private User admin;
    private User distanceUser;
    private String ownerToken;
    private String recipientToken;
    private String adminToken;

    @BeforeEach
    void setUp() {
        owner = upsert(OWNER_EMAIL, "Hardening Owner", Role.OWNER);
        recipient = upsert(RECIPIENT_EMAIL, "Hardening Recipient", Role.VIEWER);
        admin = upsert(ADMIN_EMAIL, "Hardening Administrator", Role.ADMIN);
        distanceUser = upsert(DISTANCE_EMAIL, "Distance Boundary", Role.VIEWER);

        ownerToken = bearerFor(owner);
        recipientToken = bearerFor(recipient);
        adminToken = bearerFor(admin);

        // Deterministic fixtures keep the 1-to-1 binding idempotent across repeated suite runs.
        enroll(owner);
        enroll(recipient);
        enroll(admin);
        enroll(distanceUser);
    }

    // =====================================================================
    // 1. REAL-TIME MIDDLEWARE PERMISSION CHECK (IDOR)
    // =====================================================================

    @Test
    @DisplayName("Live ACL: a grant revoked after login is rejected on the very next download")
    void revokedGrantIsRejectedOnTheNextDownload() throws Exception {
        String documentId = upload("Hardening Revoked Grant");
        permissionService.grantPermission(documentId, owner, grant(recipient, PermissionLevel.READ), CLIENT_IP);

        // The recipient's JWT is minted once and never refreshed: it stays cryptographically
        // valid for the whole scenario, which is exactly the window this correction closes.
        mockMvc.perform(get(downloadUri(documentId))
                        .header("Authorization", "Bearer " + recipientToken)
                        .header("X-Face-Token", mintActionToken(recipient, documentId, FaceEnrollmentService.ACTION_DOWNLOAD)))
                .andExpect(status().isOk());

        permissionService.revokePermission(documentId, recipient.getId(), owner, CLIENT_IP);

        // A fresh face proof is minted after the revocation, so the rejection cannot be blamed
        // on an expired action token: only the live ACL lookup can stop this request.
        mockMvc.perform(get(downloadUri(documentId))
                        .header("Authorization", "Bearer " + recipientToken)
                        .header("X-Face-Token", mintActionToken(recipient, documentId, FaceEnrollmentService.ACTION_DOWNLOAD)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value(containsString("Re-request access")));
    }

    @Test
    @DisplayName("Live ACL: an EDIT grant downgraded to READ is rejected on the very next update")
    void editGrantDowngradedToReadIsRejectedOnTheNextUpdate() throws Exception {
        String documentId = upload("Hardening Downgraded Grant");
        permissionService.grantPermission(documentId, owner, grant(recipient, PermissionLevel.EDIT), CLIENT_IP);

        mockMvc.perform(put("/api/documents/" + documentId)
                        .header("Authorization", "Bearer " + recipientToken)
                        .header("X-Face-Token", mintActionToken(recipient, documentId, FaceEnrollmentService.ACTION_EDIT))
                        .contentType("application/json")
                        .content("{\"title\":\"Edited By Recipient\",\"category\":\"Hardening\"}"))
                .andExpect(status().isOk());

        // Downgrade only the ACL row; the recipient's token and face enrollment are untouched.
        permissionService.grantPermission(documentId, owner, grant(recipient, PermissionLevel.READ), CLIENT_IP);

        mockMvc.perform(put("/api/documents/" + documentId)
                        .header("Authorization", "Bearer " + recipientToken)
                        .header("X-Face-Token", mintActionToken(recipient, documentId, FaceEnrollmentService.ACTION_EDIT))
                        .contentType("application/json")
                        .content("{\"title\":\"Escalated Edit\",\"category\":\"Hardening\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value(containsString("does not authorise EDIT")));
    }

    @Test
    @DisplayName("Live ACL: the guard runs before the face gate and is written to the audit trail")
    void nonOwnerWithoutProofIsDeniedByTheLiveGuardFirst() throws Exception {
        String documentId = upload("Hardening Guard Order");

        // No face proof at all. If the face gate ran first this would surface as
        // FACE_PROOF_REQUIRED; the ACL guard must answer before the biometric check.
        mockMvc.perform(get(downloadUri(documentId))
                        .header("Authorization", "Bearer " + recipientToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value(containsString("shared_permissions")));

        assertTrue(auditLogRepository.findByActionOrderByTimestampDesc(AuditAction.ACCESS_DENIED).stream()
                        .anyMatch(entry -> documentId.equals(entry.getDocumentId())
                                && recipient.getEmail().equalsIgnoreCase(entry.getUserEmail())
                                && entry.getDetails() != null
                                && entry.getDetails().contains("PER_TRANSACTION_DATABASE")),
                "The per-transaction ACL rejection must be recorded as ACCESS_DENIED");
    }

    @Test
    @DisplayName("Live ACL: an administrator passes the guard on a document they do not own")
    void administratorBypassesTheAclWithALiveCheck() throws Exception {
        String documentId = upload("Hardening Admin Override");

        mockMvc.perform(get(downloadUri(documentId))
                        .header("Authorization", "Bearer " + adminToken)
                        .header("X-Face-Token", mintActionToken(admin, documentId, FaceEnrollmentService.ACTION_DOWNLOAD)))
                .andExpect(status().isOk());
    }

    // =====================================================================
    // 3. STRICT EUCLIDEAN THRESHOLD
    // =====================================================================

    @Test
    @DisplayName("Identity: distance 0.45 is accepted while 0.75 is rejected, and 0.60 is the ceiling")
    void distanceAboveTheStrictCeilingIsRejected() {
        String documentId = upload("Hardening Distance Boundary");

        FaceVerificationResponse accepted = faceEnrollmentService.verifyForAction(
                distanceUser, documentId, FaceEnrollmentService.ACTION_DOWNLOAD,
                FaceFixtures.atDistance(distanceUser.getEmail(), 0.45),
                challengeFor(distanceUser, documentId, FaceEnrollmentService.ACTION_DOWNLOAD), CLIENT_IP);

        assertTrue(accepted.isVerified());
        assertEquals(0.60, accepted.getThreshold(), 1e-9, "The published ceiling must be exactly 0.60");
        assertEquals("EUCLIDEAN_DISTANCE", accepted.getMetric());
        assertEquals(0.45, accepted.getDistance(), 0.02, "The reported distance must reflect the probe");

        // 0.75 is beyond the model's intra-person range: this is what an impostor looks like, and
        // it must be refused even though the capture passed liveness and held a fresh challenge.
        FaceVerificationException rejected = assertThrows(FaceVerificationException.class, () ->
                faceEnrollmentService.verifyForAction(
                        distanceUser, documentId, FaceEnrollmentService.ACTION_DOWNLOAD,
                        FaceFixtures.atDistance(distanceUser.getEmail(), 0.75),
                        challengeFor(distanceUser, documentId, FaceEnrollmentService.ACTION_DOWNLOAD), CLIENT_IP));

        assertEquals(FaceVerificationException.MISMATCH, rejected.getCode());
        assertEquals(0.75, rejected.getScore(), 0.02, "The rejection must report the measured distance");
    }

    // =====================================================================
    // 4. TIMESTAMPED CRYPTOGRAPHIC CHALLENGES
    // =====================================================================

    @Test
    @DisplayName("Replay: a verification without a challenge is rejected before any matching")
    void verificationWithoutAChallengeIsRejected() throws Exception {
        String documentId = upload("Hardening Challenge Required");

        mockMvc.perform(post("/api/auth/biometric/verify-face")
                        .header("Authorization", "Bearer " + ownerToken)
                        .contentType("application/json")
                        .content(verifyBody(documentId, FaceEnrollmentService.ACTION_DOWNLOAD,
                                FaceFixtures.rescan(owner.getEmail()), null)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FACE_CHALLENGE_REQUIRED"));
    }

    @Test
    @DisplayName("Replay: a challenge can be redeemed exactly once")
    void challengeCannotBeRedeemedTwice() throws Exception {
        String documentId = upload("Hardening Challenge Reuse");
        String challenge = challengeFor(owner, documentId, FaceEnrollmentService.ACTION_DOWNLOAD);
        String body = verifyBody(documentId, FaceEnrollmentService.ACTION_DOWNLOAD,
                FaceFixtures.rescan(owner.getEmail()), challenge);

        mockMvc.perform(post("/api/auth/biometric/verify-face")
                        .header("Authorization", "Bearer " + ownerToken)
                        .contentType("application/json")
                        .content(body))
                .andExpect(status().isOk());

        // Byte-identical replay: the descriptor still matches, only the nonce is spent.
        mockMvc.perform(post("/api/auth/biometric/verify-face")
                        .header("Authorization", "Bearer " + ownerToken)
                        .contentType("application/json")
                        .content(body))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FACE_CHALLENGE_REUSED"));
    }

    @Test
    @DisplayName("Replay: a challenge issued for DOWNLOAD cannot authorise an EDIT")
    void challengeIsBoundToTheRequestedAction() throws Exception {
        String documentId = upload("Hardening Challenge Binding");
        String downloadChallenge = challengeFor(owner, documentId, FaceEnrollmentService.ACTION_DOWNLOAD);

        mockMvc.perform(post("/api/auth/biometric/verify-face")
                        .header("Authorization", "Bearer " + ownerToken)
                        .contentType("application/json")
                        .content(verifyBody(documentId, FaceEnrollmentService.ACTION_EDIT,
                                FaceFixtures.rescan(owner.getEmail()), downloadChallenge)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FACE_CHALLENGE_MISMATCH"));
    }

    @Test
    @DisplayName("Replay: a challenge older than the 30 second window is rejected")
    void expiredChallengeIsRejected() throws Exception {
        String documentId = upload("Hardening Challenge Expiry");

        // Minted with a negative TTL, i.e. the same signed token a replay would present after
        // the window closed. The signature is valid, only the timestamp is not.
        String expired = jwtTokenProvider.generateBiometricChallengeToken(
                owner.getId(), owner.getEmail(), UUID.randomUUID().toString(),
                documentId, FaceEnrollmentService.ACTION_DOWNLOAD, -5L);

        mockMvc.perform(post("/api/auth/biometric/verify-face")
                        .header("Authorization", "Bearer " + ownerToken)
                        .contentType("application/json")
                        .content(verifyBody(documentId, FaceEnrollmentService.ACTION_DOWNLOAD,
                                FaceFixtures.rescan(owner.getEmail()), expired)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FACE_CHALLENGE_EXPIRED"));
    }

    @Test
    @DisplayName("Replay: the configured challenge lifetime can never exceed 30 seconds")
    void challengeTtlNeverExceedsThirtySeconds() {
        assertTrue(biometricChallengeService.getChallengeTtlSeconds() <= BiometricChallengeService.MAX_TTL_SECONDS,
                "The challenge TTL must stay within the published 30 second ceiling");
        assertEquals(30L, BiometricChallengeService.MAX_TTL_SECONDS);
    }

    @Test
    @DisplayName("Replay: a failed match still burns the challenge it redeemed")
    void failedMatchStillBurnsTheChallenge() {
        String documentId = upload("Hardening Challenge Burn");
        String challenge = challengeFor(owner, documentId, FaceEnrollmentService.ACTION_DOWNLOAD);

        // The intruder burns the nonce on a failed match...
        FaceVerificationException mismatch = assertThrows(FaceVerificationException.class, () ->
                faceEnrollmentService.verifyForAction(
                        owner, documentId, FaceEnrollmentService.ACTION_DOWNLOAD,
                        FaceFixtures.differentFace("hardening-intruder"), challenge, CLIENT_IP));
        assertEquals(FaceVerificationException.MISMATCH, mismatch.getCode());

        // ...so the genuine capture cannot reuse it, even though the match would now succeed.
        FaceVerificationException replay = assertThrows(FaceVerificationException.class, () ->
                faceEnrollmentService.verifyForAction(
                        owner, documentId, FaceEnrollmentService.ACTION_DOWNLOAD,
                        FaceFixtures.rescan(owner.getEmail()), challenge, CLIENT_IP));
        assertEquals(FaceVerificationException.CHALLENGE_REUSED, replay.getCode());
    }

    // =====================================================================
    // helpers
    // =====================================================================

    private User upsert(String email, String fullName, Role role) {
        User user = userRepository.findByEmail(email).orElseGet(() ->
                userRepository.save(new User(UUID.randomUUID().toString(), email, "hash", fullName, role, UserStatus.ACTIVE)));

        boolean dirty = false;
        if (user.getRole() != role) {
            user.setRole(role);
            dirty = true;
        }
        if (user.getStatus() != UserStatus.ACTIVE) {
            user.setStatus(UserStatus.ACTIVE);
            dirty = true;
        }
        return dirty ? userRepository.save(user) : user;
    }

    /** Re-binding the deterministic fixture is idempotent, so the suite is re-runnable. */
    private void enroll(User user) {
        faceEnrollmentService.enroll(user, FaceFixtures.descriptor(user.getEmail()), CLIENT_IP);
    }

    private String bearerFor(User user) {
        return jwtTokenProvider.generateTokenFromUser(user.getId(), user.getEmail(), user.getRole().name());
    }

    private String upload(String title) {
        MockMultipartFile file = new MockMultipartFile(
                "file", "hardening_probe.txt", "text/plain", "Hardening payload".getBytes());
        DocumentResponse document = documentService.uploadDocument(title, "Hardening", file, owner, CLIENT_IP);
        return document.getId();
    }

    private static String downloadUri(String documentId) {
        return "/api/documents/" + documentId + "/download";
    }

    private static GrantPermissionRequest grant(User user, PermissionLevel level) {
        return new GrantPermissionRequest(user.getEmail(), level, null, null);
    }

    /** Issues a single-use FaceID challenge bound to this user, document and action. */
    private String challengeFor(User user, String documentId, String action) {
        return biometricChallengeService.issue(user, documentId, action, CLIENT_IP).getChallengeToken();
    }

    /** Runs a realistic re-scan through the matcher and returns the action token it mints. */
    private String mintActionToken(User user, String documentId, String action) {
        FaceVerificationResponse response = faceEnrollmentService.verifyForAction(
                user, documentId, action, FaceFixtures.rescan(user.getEmail()),
                challengeFor(user, documentId, action), CLIENT_IP);
        assertTrue(response.isVerified(), "Face verification should have succeeded for " + user.getEmail());
        return response.getFaceToken();
    }

    private static String verifyBody(String documentId, String action, List<Double> descriptor, String challengeToken) {
        StringBuilder body = new StringBuilder()
                .append("{\"documentId\":\"").append(documentId).append("\",")
                .append("\"action\":\"").append(action).append("\",")
                .append("\"descriptor\":").append(FaceFixtures.json(descriptor));
        if (challengeToken != null) {
            body.append(",\"challengeToken\":\"").append(challengeToken).append('"');
        }
        return body.append('}').toString();
    }
}

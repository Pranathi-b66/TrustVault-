package com.trustvault;

import com.trustvault.dto.DocumentResponse;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.FaceEnrollment;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import com.trustvault.face.FaceVerificationException;
import com.trustvault.repository.AuditLogRepository;
import com.trustvault.repository.FaceEnrollmentRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.JwtTokenProvider;
import com.trustvault.service.DocumentService;
import com.trustvault.service.FaceEnrollmentService;
import com.trustvault.support.FaceFixtures;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies the strict 1-to-1 contract between a TrustVault account and a webcam facial
 * descriptor, plus the action-time verification trail required for download and edit.
 */
@SpringBootTest
@AutoConfigureMockMvc
public class FaceUniquenessIntegrationTest {

    private static final String PRIMARY_EMAIL = "face.unique.primary@internal.test";
    private static final String SECOND_EMAIL = "face.unique.second@internal.test";
    private static final String SHARED_FACE = "shared-enrollment-face";
    private static final String ANOMALY_ORIGIN_IP = "10.0.0.77";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private FaceEnrollmentRepository faceEnrollmentRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private FaceEnrollmentService faceEnrollmentService;

    @Autowired
    private DocumentService documentService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private User primary;
    private User second;
    private String primaryToken;
    private String secondToken;

    @BeforeEach
    void setUp() {
        primary = upsertUser(PRIMARY_EMAIL, "FaceID Primary", Role.OWNER);
        second = upsertUser(SECOND_EMAIL, "FaceID Second", Role.VIEWER);

        // Every run starts from an unbound state so the uniqueness assertions stay meaningful
        // even though the integration database is reused between runs.
        resetEnrollment(primary);
        resetEnrollment(second);

        primaryToken = jwtTokenProvider.generateTokenFromUser(primary.getId(), primary.getEmail(), primary.getRole().name());
        secondToken = jwtTokenProvider.generateTokenFromUser(second.getId(), second.getEmail(), second.getRole().name());
    }

    @Test
    @DisplayName("Uniqueness: an identical face descriptor cannot be enrolled by a second account (400)")
    void identicalDescriptorIsRejectedForSecondAccount() throws Exception {
        List<Double> capture = FaceFixtures.descriptor(SHARED_FACE);

        mockMvc.perform(post("/api/auth/biometric/register-face")
                        .header("Authorization", "Bearer " + primaryToken)
                        .contentType("application/json")
                        .content(registerFaceBody(PRIMARY_EMAIL, capture)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(PRIMARY_EMAIL));

        mockMvc.perform(post("/api/auth/biometric/register-face")
                        .header("Authorization", "Bearer " + secondToken)
                        .contentType("application/json")
                        .content(registerFaceBody(SECOND_EMAIL, capture)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("FACE_ALREADY_REGISTERED"))
                .andExpect(jsonPath("$.detectedBy").value("exact-hash"))
                .andExpect(jsonPath("$.message").value("Face already registered to another account."));

        assertTrue(faceEnrollmentRepository.findByUserId(second.getId()).isEmpty(),
                "The rejected enrollment must not leave a face descriptor behind");
    }

    @Test
    @DisplayName("Uniqueness: a noisy re-scan of an already enrolled face is also rejected (400)")
    void rescanOfEnrolledFaceIsRejectedForSecondAccount() throws Exception {
        mockMvc.perform(post("/api/auth/biometric/register-face")
                        .header("Authorization", "Bearer " + primaryToken)
                        .contentType("application/json")
                        .content(registerFaceBody(PRIMARY_EMAIL, FaceFixtures.descriptor(SHARED_FACE))))
                .andExpect(status().isOk());

        // Different bytes, same person: only the euclidean matcher can catch this.
        mockMvc.perform(post("/api/auth/biometric/register-face")
                        .header("Authorization", "Bearer " + secondToken)
                        .contentType("application/json")
                        .content(registerFaceBody(SECOND_EMAIL, FaceFixtures.rescan(SHARED_FACE))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("FACE_ALREADY_REGISTERED"))
                .andExpect(jsonPath("$.detectedBy").value("face-match"));

        assertTrue(faceEnrollmentRepository.findByUserId(second.getId()).isEmpty());
    }

    @Test
    @DisplayName("Uniqueness: a bound account keeps its original face (no silent re-binding)")
    void boundAccountCannotEnrollADifferentFace() throws Exception {
        mockMvc.perform(post("/api/auth/biometric/register-face")
                        .header("Authorization", "Bearer " + primaryToken)
                        .contentType("application/json")
                        .content(registerFaceBody(PRIMARY_EMAIL, FaceFixtures.descriptor(SHARED_FACE))))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/biometric/register-face")
                        .header("Authorization", "Bearer " + primaryToken)
                        .contentType("application/json")
                        .content(registerFaceBody(PRIMARY_EMAIL, FaceFixtures.differentFace("a-different-person"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("already bound")));
    }

    @Test
    @DisplayName("Uniqueness: re-scanning the same face for the same account is idempotent")
    void reEnrollingOwnFaceIsIdempotent() throws Exception {
        String firstId = registerFaceExpectingOk(primaryToken, PRIMARY_EMAIL, FaceFixtures.descriptor(SHARED_FACE));

        String secondId = registerFaceExpectingOk(primaryToken, PRIMARY_EMAIL, FaceFixtures.rescan(SHARED_FACE));

        assertEquals(firstId, secondId, "A re-scan of the bound face must reuse the existing enrollment");
        assertEquals(1, faceEnrollmentRepository.findAll().stream()
                .filter(enrollment -> enrollment.getUser().getId().equals(primary.getId()))
                .count(), "1-to-1 binding must never produce a second row for the same account");
    }

    @Test
    @DisplayName("Uniqueness: a genuinely different face enrolls without collision")
    void differentFaceIsAcceptedForSecondAccount() throws Exception {
        registerFaceExpectingOk(primaryToken, PRIMARY_EMAIL, FaceFixtures.descriptor(PRIMARY_EMAIL));
        registerFaceExpectingOk(secondToken, SECOND_EMAIL, FaceFixtures.descriptor(SECOND_EMAIL));

        assertTrue(faceEnrollmentRepository.findByUserId(primary.getId()).isPresent());
        assertTrue(faceEnrollmentRepository.findByUserId(second.getId()).isPresent());
    }

    @Test
    @DisplayName("Action-time verification: a matching scan mints a face token for that user only")
    void matchingScanMintsFaceToken() throws Exception {
        registerFaceExpectingOk(primaryToken, PRIMARY_EMAIL, FaceFixtures.descriptor(PRIMARY_EMAIL));
        String documentId = uploadOwnedDocument(primary);

        mockMvc.perform(post("/api/auth/biometric/verify-face")
                        .header("Authorization", "Bearer " + primaryToken)
                        .contentType("application/json")
                        .content(verifyBody(documentId, "DOWNLOAD", FaceFixtures.rescan(PRIMARY_EMAIL))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verified").value(true))
                .andExpect(jsonPath("$.action").value("DOWNLOAD"))
                .andExpect(jsonPath("$.score").isNumber())
                .andExpect(jsonPath("$.threshold").value(0.4))
                .andExpect(jsonPath("$.faceToken").isNotEmpty());
    }

    @Test
    @DisplayName("Action-time verification: a non-matching scan returns 403 with ACCESS_DENIED + SECURITY_ALERT")
    void nonMatchingScanIsAuditedAndRejected() throws Exception {
        registerFaceExpectingOk(primaryToken, PRIMARY_EMAIL, FaceFixtures.descriptor(PRIMARY_EMAIL));
        String documentId = uploadOwnedDocument(primary);

        long deniedBefore = countAudit(AuditAction.ACCESS_DENIED, PRIMARY_EMAIL);
        long alertsBefore = countAudit(AuditAction.SECURITY_ALERT, PRIMARY_EMAIL);

        mockMvc.perform(post("/api/auth/biometric/verify-face")
                        .header("Authorization", "Bearer " + primaryToken)
                        .contentType("application/json")
                        .content(verifyBody(documentId, "EDIT", FaceFixtures.differentFace(SECOND_EMAIL))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FACE_MISMATCH"))
                .andExpect(jsonPath("$.anomalyCount").isNumber());

        assertEquals(deniedBefore + 1, countAudit(AuditAction.ACCESS_DENIED, PRIMARY_EMAIL),
                "A failed match must append exactly one ACCESS_DENIED row");
        // At least one SECURITY_ALERT is written per mismatch; a second one is appended when the
        // anomaly detector escalates the attempt.
        assertTrue(countAudit(AuditAction.SECURITY_ALERT, PRIMARY_EMAIL) >= alertsBefore + 1,
                "A failed match must append a SECURITY_ALERT row");
    }

    @Test
    @DisplayName("Anomaly detection: consecutive mismatches increment the counter and escalate to an alert")
    void consecutiveMismatchesTripTheAnomalyDetector() throws Exception {
        registerFaceExpectingOk(secondToken, SECOND_EMAIL, FaceFixtures.descriptor(SECOND_EMAIL));
        String documentId = uploadOwnedDocument(primary);
        List<Double> wrongFace = FaceFixtures.differentFace(PRIMARY_EMAIL);

        // A dedicated origin keeps this counter isolated from the other test methods.
        List<Integer> observedCounts = new ArrayList<>();
        for (int attempt = 0; attempt < 3; attempt++) {
            FaceVerificationException failure = assertThrows(FaceVerificationException.class,
                    () -> faceEnrollmentService.verifyForAction(second, documentId,
                            FaceEnrollmentService.ACTION_DOWNLOAD, wrongFace, ANOMALY_ORIGIN_IP));
            assertEquals(FaceVerificationException.MISMATCH, failure.getCode());
            observedCounts.add(failure.getAnomalyCount());
        }

        assertEquals(1, observedCounts.get(0), "The first failed match must register as one anomaly");
        assertEquals(2, observedCounts.get(1), "The anomaly counter must increment on every failed match");
        assertTrue(auditLogRepository.findByActionOrderByTimestampDesc(AuditAction.SECURITY_ALERT).stream()
                        .anyMatch(entry -> entry.getDetails() != null
                                && entry.getDetails().contains("CONSECUTIVE_ACCESS_DENIED_EXCEEDED")),
                "Reaching the failure threshold must escalate to a CONSECUTIVE_ACCESS_DENIED_EXCEEDED alert");
    }

    @Test
    @DisplayName("Action-time verification: an unsupported action is rejected before any face work")
    void unsupportedActionIsRejected() throws Exception {
        registerFaceExpectingOk(primaryToken, PRIMARY_EMAIL, FaceFixtures.descriptor(PRIMARY_EMAIL));
        String documentId = uploadOwnedDocument(primary);

        mockMvc.perform(post("/api/auth/biometric/verify-face")
                        .header("Authorization", "Bearer " + primaryToken)
                        .contentType("application/json")
                        .content(verifyBody(documentId, "DELETE", FaceFixtures.rescan(PRIMARY_EMAIL))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Lifecycle: revoking an enrollment blocks protected actions until re-enrollment")
    void revokedEnrollmentBlocksProtectedActions() throws Exception {
        registerFaceExpectingOk(primaryToken, PRIMARY_EMAIL, FaceFixtures.descriptor(PRIMARY_EMAIL));
        String documentId = uploadOwnedDocument(primary);

        mockMvc.perform(delete("/api/auth/biometric/face")
                        .header("Authorization", "Bearer " + primaryToken))
                .andExpect(status().isOk());

        assertTrue(faceEnrollmentRepository.findByUserId(primary.getId()).isEmpty());

        mockMvc.perform(post("/api/auth/biometric/verify-face")
                        .header("Authorization", "Bearer " + primaryToken)
                        .contentType("application/json")
                        .content(verifyBody(documentId, "DOWNLOAD", FaceFixtures.rescan(PRIMARY_EMAIL))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FACE_NOT_ENROLLED"));

        mockMvc.perform(get("/api/documents/" + documentId + "/download")
                        .header("Authorization", "Bearer " + primaryToken)
                        .header("X-Face-Descriptor", FaceFixtures.json(FaceFixtures.rescan(PRIMARY_EMAIL))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FACE_NOT_ENROLLED"));
    }

    @Test
    @DisplayName("Status endpoint reports the facial enrollment state of the caller")
    void statusReflectsEnrollmentState() throws Exception {
        mockMvc.perform(get("/api/auth/biometric/face-status")
                        .header("Authorization", "Bearer " + primaryToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enrolled").value(false));

        registerFaceExpectingOk(primaryToken, PRIMARY_EMAIL, FaceFixtures.descriptor(PRIMARY_EMAIL));

        mockMvc.perform(get("/api/auth/biometric/face-status")
                        .header("Authorization", "Bearer " + primaryToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enrolled").value(true))
                .andExpect(jsonPath("$.algorithm").value(FaceFixtures.ALGORITHM))
                .andExpect(jsonPath("$.embeddingSize").value(FaceFixtures.DIMENSION));
    }

    @Test
    @DisplayName("Sign-up: the account and its exclusive face descriptor are created together")
    void signUpBindsFaceAtomically() throws Exception {
        String email = "face.signup.atomic@internal.test";
        clearUser(email);

        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(signUpBody(email, FaceFixtures.descriptor(email))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.faceEnrolled").value(true));

        User created = userRepository.findByEmail(email).orElseThrow();
        assertTrue(faceEnrollmentRepository.findByUserId(created.getId()).isPresent(),
                "Sign-up must persist the face binding alongside the profile");
    }

    @Test
    @DisplayName("Sign-up: a face already bound to another account is rejected with 400 and creates no user")
    void signUpRejectsAlreadyClaimedFace() throws Exception {
        String firstEmail = "face.signup.first@internal.test";
        String cloneEmail = "face.signup.clone@internal.test";
        clearUser(firstEmail);
        clearUser(cloneEmail);

        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(signUpBody(firstEmail, FaceFixtures.descriptor(firstEmail))))
                .andExpect(status().isOk());

        // The second identity presents the very same face.
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(signUpBody(cloneEmail, FaceFixtures.descriptor(firstEmail))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("FACE_ALREADY_REGISTERED"))
                .andExpect(jsonPath("$.message").value("Face already registered to another account."));

        assertTrue(userRepository.findByEmail(cloneEmail).isEmpty(),
                "A duplicate face must abort sign-up before the profile row is written");
    }

    @Test
    @DisplayName("Sign-up: a noisy re-scan of a claimed face is rejected with 400")
    void signUpRejectsRescanOfClaimedFace() throws Exception {
        String firstEmail = "face.signup.rescan.owner@internal.test";
        String cloneEmail = "face.signup.rescan.clone@internal.test";
        clearUser(firstEmail);
        clearUser(cloneEmail);

        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(signUpBody(firstEmail, FaceFixtures.descriptor(firstEmail))))
                .andExpect(status().isOk());

        // Same person, new embedding: only the similarity matcher can catch this.
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(signUpBody(cloneEmail, FaceFixtures.rescan(firstEmail))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("FACE_ALREADY_REGISTERED"))
                .andExpect(jsonPath("$.detectedBy").value("face-match"));

        assertTrue(userRepository.findByEmail(cloneEmail).isEmpty());
    }

    @Test
    @DisplayName("Sign-up: a missing face capture is rejected with 400")
    void signUpRequiresFaceCapture() throws Exception {
        String email = "face.signup.missing@internal.test";
        clearUser(email);

        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content("{\"email\":\"" + email + "\",\"password\":\"FaceId#2026\","
                                + "\"fullName\":\"No Face\",\"role\":\"VIEWER\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("face scan is required")));

        assertTrue(userRepository.findByEmail(email).isEmpty());
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private User upsertUser(String email, String fullName, Role role) {
        User user = userRepository.findByEmail(email).orElseGet(() ->
                userRepository.save(new User(UUID.randomUUID().toString(), email, "hash", fullName, role, UserStatus.ACTIVE)));
        if (user.getStatus() != UserStatus.ACTIVE) {
            user.setStatus(UserStatus.ACTIVE);
            user = userRepository.save(user);
        }
        return user;
    }

    private void resetEnrollment(User user) {
        FaceEnrollment enrollment = faceEnrollmentRepository.findByUserId(user.getId()).orElse(null);
        if (enrollment != null) {
            faceEnrollmentRepository.delete(enrollment);
            faceEnrollmentRepository.flush();
        }
    }

    /** Removes a sign-up test identity so the scenario can be replayed against the same DB. */
    private void clearUser(String email) {
        userRepository.findByEmail(email).ifPresent(existing -> {
            resetEnrollment(existing);
            userRepository.delete(existing);
            userRepository.flush();
        });
    }

    private String registerFaceExpectingOk(String bearer, String email, List<Double> descriptor) throws Exception {
        String body = mockMvc.perform(post("/api/auth/biometric/register-face")
                        .header("Authorization", "Bearer " + bearer)
                        .contentType("application/json")
                        .content(registerFaceBody(email, descriptor)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return com.jayway.jsonpath.JsonPath.read(body, "$.id");
    }

    private String uploadOwnedDocument(User owner) {
        MockMultipartFile file = new MockMultipartFile(
                "file", "face_gate_probe.txt", "text/plain", "Protected payload".getBytes());
        DocumentResponse document = documentService.uploadDocument(
                "FaceID Gate Probe", "Confidential", file, owner, "10.0.0.9");
        return document.getId();
    }

    private long countAudit(AuditAction action, String email) {
        return auditLogRepository.findByActionOrderByTimestampDesc(action).stream()
                .filter(entry -> email.equalsIgnoreCase(entry.getUserEmail()))
                .count();
    }

    private static String registerFaceBody(String email, List<Double> descriptor) {
        return "{\"email\":\"" + email + "\",\"descriptor\":" + FaceFixtures.json(descriptor)
                + ",\"deviceLabel\":\"integration-test\"}";
    }

    /** Full sign-up payload: profile + the mandatory webcam face capture. */
    private static String signUpBody(String email, List<Double> descriptor) {
        return "{\"email\":\"" + email + "\",\"password\":\"FaceId#2026\","
                + "\"fullName\":\"FaceID Signup\",\"role\":\"VIEWER\","
                + "\"faceDescriptor\":" + FaceFixtures.json(descriptor)
                + ",\"deviceLabel\":\"integration-test\"}";
    }

    private static String verifyBody(String documentId, String action, List<Double> descriptor) {
        return "{\"documentId\":\"" + documentId + "\",\"action\":\"" + action
                + "\",\"descriptor\":" + FaceFixtures.json(descriptor) + "}";
    }
}

package com.trustvault;

import com.trustvault.dto.DocumentResponse;
import com.trustvault.dto.FaceVerificationResponse;
import com.trustvault.dto.GrantPermissionRequest;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.PermissionLevel;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import com.trustvault.repository.AuditLogRepository;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.JwtTokenProvider;
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

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class IdorProtectionIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private DocumentRepository documentRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private DocumentService documentService;

    @Autowired
    private PermissionService permissionService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private FaceEnrollmentService faceEnrollmentService;

    private User userA;
    private User userB;
    private String tokenA;
    private String tokenB;
    private DocumentResponse docA;

    @BeforeEach
    void setUp() {
        // User A (Document Owner)
        userA = userRepository.findByEmail("alice.owner@internal.test").orElseGet(() -> {
            User u = new User(UUID.randomUUID().toString(), "alice.owner@internal.test", "hash", "Alice Owner", Role.OWNER, UserStatus.ACTIVE);
            return userRepository.save(u);
        });
        // Ensure userA is always ACTIVE (guard against cross-test DB pollution)
        if (userA.getStatus() != UserStatus.ACTIVE) {
            userA.setStatus(UserStatus.ACTIVE);
            userA = userRepository.save(userA);
        }

        // User B (Attacker / Unauthorized User)
        userB = userRepository.findByEmail("bob.attacker@internal.test").orElseGet(() -> {
            User u = new User(UUID.randomUUID().toString(), "bob.attacker@internal.test", "hash", "Bob Attacker", Role.VIEWER, UserStatus.ACTIVE);
            return userRepository.save(u);
        });
        // Ensure userB is always ACTIVE
        if (userB.getStatus() != UserStatus.ACTIVE) {
            userB.setStatus(UserStatus.ACTIVE);
            userB = userRepository.save(userB);
        }

        tokenA = jwtTokenProvider.generateTokenFromUser(userA.getId(), userA.getEmail(), userA.getRole().name());
        tokenB = jwtTokenProvider.generateTokenFromUser(userB.getId(), userB.getEmail(), userB.getRole().name());

        // Bind an exclusive face descriptor to each identity. Both enrollments are deterministic
        // and therefore idempotent across repeated runs against the same database.
        faceEnrollmentService.enroll(userA, FaceFixtures.descriptor(userA.getEmail()), "10.0.0.1");
        faceEnrollmentService.enroll(userB, FaceFixtures.descriptor(userB.getEmail()), "10.0.0.2");

        MockMultipartFile file = new MockMultipartFile(
                "file", "confidential_q4_financials.pdf", "application/pdf", "Confidential Financial Data".getBytes()
        );
        docA = documentService.uploadDocument("Confidential Q4 Financials", "Financial", file, userA, "10.0.0.1");
    }

    /**
     * Runs a realistic re-scan through the similarity matcher and returns the short-lived action
     * token it mints. This is the only way to satisfy the face gate now that no bypass exists.
     */
    private String mintActionToken(User user, String documentId, String action) {
        FaceVerificationResponse response = faceEnrollmentService.verifyForAction(
                user, documentId, action, FaceFixtures.rescan(user.getEmail()), "10.0.0.1");
        assertTrue(response.isVerified(), "Face verification should have succeeded for " + user.getEmail());
        return response.getFaceToken();
    }

    @Test
    @DisplayName("IDOR Prevention: User B cannot read User A's private document metadata")
    void userBCannotReadUserADocument() throws Exception {
        mockMvc.perform(get("/api/documents/" + docA.getId())
                        .header("Authorization", "Bearer " + tokenB))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Granted document appears in the recipient's shared documents")
    void grantedDocumentAppearsInRecipientSharedList() throws Exception {
        permissionService.grantPermission(
                docA.getId(),
                userA,
                new GrantPermissionRequest(userB.getEmail().toUpperCase(), PermissionLevel.READ, null, null),
                "10.0.0.1"
        );

        mockMvc.perform(get("/api/documents/shared")
                        .header("Authorization", "Bearer " + tokenB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '" + docA.getId() + "')].title").value("Confidential Q4 Financials"));
    }

    @Test
    @DisplayName("IDOR Prevention: User B cannot download User A's private document even with a valid face proof")
    void userBCannotDownloadUserADocument() throws Exception {
        // The face factor is fully satisfied here, so the rejection must come from the
        // authorization layer (no ownership, no ACL grant) rather than from the face gate.
        String faceProof = mintActionToken(userB, docA.getId(), FaceEnrollmentService.ACTION_DOWNLOAD);

        mockMvc.perform(get("/api/documents/" + docA.getId() + "/download")
                        .header("Authorization", "Bearer " + tokenB)
                        .header("X-Face-Token", faceProof))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("IDOR Prevention: User B cannot update User A's private document even with a valid face proof")
    void userBCannotUpdateUserADocument() throws Exception {
        String faceProof = mintActionToken(userB, docA.getId(), FaceEnrollmentService.ACTION_EDIT);

        mockMvc.perform(put("/api/documents/" + docA.getId())
                        .header("Authorization", "Bearer " + tokenB)
                        .header("X-Face-Token", faceProof)
                        .contentType("application/json")
                        .content("{\"title\":\"Hacked Title\",\"category\":\"Compromised\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("IDOR Prevention: User B cannot delete User A's private document")
    void userBCannotDeleteUserADocument() throws Exception {
        mockMvc.perform(delete("/api/documents/" + docA.getId())
                        .header("Authorization", "Bearer " + tokenB))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("IDOR Prevention: Unauthorized download attempt without a face proof is rejected with 403")
    void userACannotDownloadWithoutFaceProof() throws Exception {
        // Even the owner cannot download without a verified face proof
        mockMvc.perform(get("/api/documents/" + docA.getId() + "/download")
                        .header("Authorization", "Bearer " + tokenA))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FACE_PROOF_REQUIRED"));
    }

    @Test
    @DisplayName("Authorized Owner with a face-issued token can download document")
    void userACanDownloadWithFaceVerification() throws Exception {
        String faceProof = mintActionToken(userA, docA.getId(), FaceEnrollmentService.ACTION_DOWNLOAD);

        mockMvc.perform(get("/api/documents/" + docA.getId() + "/download")
                        .header("Authorization", "Bearer " + tokenA)
                        .header("X-Face-Token", faceProof))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Owner can download by submitting a live face descriptor instead of a token")
    void userACanDownloadWithInlineFaceDescriptor() throws Exception {
        mockMvc.perform(get("/api/documents/" + docA.getId() + "/download")
                        .header("Authorization", "Bearer " + tokenA)
                        .header("X-Face-Descriptor", FaceFixtures.json(FaceFixtures.rescan(userA.getEmail()))))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("A face capture from a different person is rejected with 403 and audited")
    void userACannotDownloadWithWrongFace() throws Exception {
        long deniedBefore = auditLogRepository.findByActionOrderByTimestampDesc(AuditAction.ACCESS_DENIED).size();
        long alertsBefore = auditLogRepository.findByActionOrderByTimestampDesc(AuditAction.SECURITY_ALERT).size();

        mockMvc.perform(get("/api/documents/" + docA.getId() + "/download")
                        .header("Authorization", "Bearer " + tokenA)
                        .header("X-Face-Descriptor", FaceFixtures.json(FaceFixtures.differentFace("an-unrelated-person"))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FACE_MISMATCH"));

        assertTrue(auditLogRepository.findByActionOrderByTimestampDesc(AuditAction.ACCESS_DENIED).size() > deniedBefore,
                "A failed face match must write an ACCESS_DENIED audit row");
        assertTrue(auditLogRepository.findByActionOrderByTimestampDesc(AuditAction.SECURITY_ALERT).size() > alertsBefore,
                "A failed face match must write a SECURITY_ALERT audit row");
    }

    @Test
    @DisplayName("FaceID Gate: Owner cannot update document without a face proof")
    void userACannotUpdateWithoutFaceProof() throws Exception {
        mockMvc.perform(put("/api/documents/" + docA.getId())
                        .header("Authorization", "Bearer " + tokenA)
                        .contentType("application/json")
                        .content("{\"title\":\"Tampered Title\",\"category\":\"Financial\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("FaceID Gate: Owner with a face-issued token can update document")
    void userACanUpdateWithFaceVerification() throws Exception {
        String faceProof = mintActionToken(userA, docA.getId(), FaceEnrollmentService.ACTION_EDIT);

        mockMvc.perform(put("/api/documents/" + docA.getId())
                        .header("Authorization", "Bearer " + tokenA)
                        .header("X-Face-Token", faceProof)
                        .contentType("application/json")
                        .content("{\"title\":\"Verified New Title\",\"category\":\"Financial\"}"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("FaceID Gate: a DOWNLOAD token cannot be replayed for an EDIT action")
    void downloadTokenCannotBeReplayedForEdit() throws Exception {
        String downloadOnlyProof = mintActionToken(userA, docA.getId(), FaceEnrollmentService.ACTION_DOWNLOAD);

        mockMvc.perform(put("/api/documents/" + docA.getId())
                        .header("Authorization", "Bearer " + tokenA)
                        .header("X-Face-Token", downloadOnlyProof)
                        .contentType("application/json")
                        .content("{\"title\":\"Cross-Action Replay\",\"category\":\"Financial\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FACE_PROOF_REQUIRED"));
    }
}

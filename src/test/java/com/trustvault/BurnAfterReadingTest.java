package com.trustvault;

import com.trustvault.dto.DocumentResponse;
import com.trustvault.dto.FaceVerificationResponse;
import com.trustvault.dto.GrantPermissionRequest;
import com.trustvault.entity.PermissionLevel;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class BurnAfterReadingTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private DocumentService documentService;

    @Autowired
    private PermissionService permissionService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private FaceEnrollmentService faceEnrollmentService;

    @Autowired
    private BiometricChallengeService biometricChallengeService;

    private User owner;
    private User recipient;
    private String recipientToken;

    @BeforeEach
    void setUp() {
        owner = userRepository.findByEmail("burn.owner@internal.test").orElseGet(() -> {
            User u = new User(UUID.randomUUID().toString(), "burn.owner@internal.test", "hash", "Burn Owner", Role.OWNER, UserStatus.ACTIVE);
            return userRepository.save(u);
        });

        recipient = userRepository.findByEmail("burn.recipient@internal.test").orElseGet(() -> {
            User u = new User(UUID.randomUUID().toString(), "burn.recipient@internal.test", "hash", "Burn Recipient", Role.VIEWER, UserStatus.ACTIVE);
            return userRepository.save(u);
        });

        recipientToken = jwtTokenProvider.generateTokenFromUser(recipient.getId(), recipient.getEmail(), recipient.getRole().name());

        // The recipient must hold an exclusive face enrollment before any download is allowed.
        // The fixture is deterministic, so re-running the suite keeps the same 1-to-1 binding.
        faceEnrollmentService.enroll(recipient, FaceFixtures.descriptor(recipient.getEmail()), "127.0.0.1");
    }

    /** Mints a short-lived DOWNLOAD authorisation by re-scanning the given user's enrolled face. */
    private String mintDownloadToken(User user, String documentId) {
        // Each verification redeems its own timestamped challenge, as the browser does.
        String challenge = biometricChallengeService.issue(
                user, documentId, FaceEnrollmentService.ACTION_DOWNLOAD, "127.0.0.1").getChallengeToken();
        FaceVerificationResponse response = faceEnrollmentService.verifyForAction(
                user, documentId, FaceEnrollmentService.ACTION_DOWNLOAD,
                FaceFixtures.rescan(user.getEmail()), challenge, "127.0.0.1");
        return response.getFaceToken();
    }

    @Test
    @DisplayName("Burn-After-Reading: Max views limit (1 view) burns document access on second attempt")
    void testMaxViewsBurnLink() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "burn_test.txt", "text/plain", "Top Secret Payload".getBytes());
        DocumentResponse doc = documentService.uploadDocument("Burn After 1 View Doc", "Confidential", file, owner, "127.0.0.1");

        GrantPermissionRequest grant = new GrantPermissionRequest(recipient.getEmail(), PermissionLevel.READ, 1, null);
        permissionService.grantPermission(doc.getId(), owner, grant, "127.0.0.1");

        // 1st download attempt: succeeds (consumes the 1 permitted view)
        mockMvc.perform(get("/api/documents/" + doc.getId() + "/download")
                        .header("Authorization", "Bearer " + recipientToken)
                        .header("X-Face-Token", mintDownloadToken(recipient, doc.getId())))
                .andExpect(status().isOk());

        // 2nd download attempt: the scan still verifies, but the view budget is burned, so the
        // rejection must come from the burn-after-reading rule rather than the face gate.
        mockMvc.perform(get("/api/documents/" + doc.getId() + "/download")
                        .header("Authorization", "Bearer " + recipientToken)
                        .header("X-Face-Token", mintDownloadToken(recipient, doc.getId())))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Burn-After-Reading: an ADMIN's own share still burns, while the admin override survives")
    void adminShareStillBurns() throws Exception {
        User admin = userRepository.findByEmail("burn.admin@internal.test").orElseGet(() -> userRepository.save(
                new User(UUID.randomUUID().toString(), "burn.admin@internal.test", "hash", "Burn Admin",
                        Role.ADMIN, UserStatus.ACTIVE)));
        faceEnrollmentService.enroll(admin, FaceFixtures.descriptor(admin.getEmail()), "127.0.0.1");
        String adminToken = jwtTokenProvider.generateTokenFromUser(
                admin.getId(), admin.getEmail(), admin.getRole().name());

        MockMultipartFile file = new MockMultipartFile("file", "admin_burn.txt", "text/plain", "Admin Burn".getBytes());
        DocumentResponse doc = documentService.uploadDocument("Admin Burn Doc", "Confidential", file, owner, "127.0.0.1");

        GrantPermissionRequest grant = new GrantPermissionRequest(admin.getEmail(), PermissionLevel.READ, 1, null);
        permissionService.grantPermission(doc.getId(), owner, grant, "127.0.0.1");

        mockMvc.perform(get("/api/documents/" + doc.getId() + "/download")
                        .header("Authorization", "Bearer " + adminToken)
                        .header("X-Face-Token", mintDownloadToken(admin, doc.getId())))
                .andExpect(status().isOk());

        // The single permitted view is spent: the grant row is gone even though the caller is an
        // ADMIN. This is the regression: the early ADMIN return used to skip the counter entirely.
        assertTrue(permissionService.getDocumentPermissions(doc.getId(), owner, "127.0.0.1").isEmpty(),
                "A burn-after-reading grant held by an ADMIN must still be consumed");

        // The override itself is untouched, so an administrator can still act after the share burns.
        mockMvc.perform(get("/api/documents/" + doc.getId() + "/download")
                        .header("Authorization", "Bearer " + adminToken)
                        .header("X-Face-Token", mintDownloadToken(admin, doc.getId())))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Burn-After-Reading: Expired link returns 403 Forbidden")
    void testExpiredPermissionLink() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "expire_test.txt", "text/plain", "Time Bound Data".getBytes());
        DocumentResponse doc = documentService.uploadDocument("Time Expiring Doc", "Legal", file, owner, "127.0.0.1");

        // Expired in past
        Instant pastExpiry = Instant.now().minus(10, ChronoUnit.MINUTES);
        GrantPermissionRequest grant = new GrantPermissionRequest(recipient.getEmail(), PermissionLevel.READ, 10, pastExpiry);
        permissionService.grantPermission(doc.getId(), owner, grant, "127.0.0.1");

        // Attempting to read expired link must return 403 Forbidden
        mockMvc.perform(get("/api/documents/" + doc.getId())
                        .header("Authorization", "Bearer " + recipientToken))
                .andExpect(status().isForbidden());
    }
}

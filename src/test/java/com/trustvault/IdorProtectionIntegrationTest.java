package com.trustvault;

import com.trustvault.dto.DocumentResponse;
import com.trustvault.dto.GrantPermissionRequest;
import com.trustvault.entity.PermissionLevel;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import com.trustvault.repository.AuditLogRepository;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.JwtTokenProvider;
import com.trustvault.service.DocumentService;
import com.trustvault.service.PermissionService;
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

        MockMultipartFile file = new MockMultipartFile(
                "file", "confidential_q4_financials.pdf", "application/pdf", "Confidential Financial Data".getBytes()
        );
        docA = documentService.uploadDocument("Confidential Q4 Financials", "Financial", file, userA, "10.0.0.1");
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
    @DisplayName("IDOR Prevention: User B cannot download User A's private document")
    void userBCannotDownloadUserADocument() throws Exception {
        mockMvc.perform(get("/api/documents/" + docA.getId() + "/download")
                        .header("Authorization", "Bearer " + tokenB)
                        .header("X-Passkey-Token", "mock-passkey"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("IDOR Prevention: User B cannot update User A's private document")
    void userBCannotUpdateUserADocument() throws Exception {
        mockMvc.perform(put("/api/documents/" + docA.getId())
                        .header("Authorization", "Bearer " + tokenB)
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
    @DisplayName("IDOR Prevention: Unauthorized download attempt without valid passkey is rejected with 403")
    void userACannotDownloadWithoutPasskeyVerification() throws Exception {
        // Even the owner cannot download without verified biometric passkey token
        mockMvc.perform(get("/api/documents/" + docA.getId() + "/download")
                        .header("Authorization", "Bearer " + tokenA))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Authorized Owner with verified passkey token can download document")
    void userACanDownloadWithPasskeyVerification() throws Exception {
        mockMvc.perform(get("/api/documents/" + docA.getId() + "/download")
                        .header("Authorization", "Bearer " + tokenA)
                        .header("X-Passkey-Token", "mock-passkey"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Biometric Gate: Owner cannot update document without valid biometric passkey verification")
    void userACannotUpdateWithoutPasskeyVerification() throws Exception {
        mockMvc.perform(put("/api/documents/" + docA.getId())
                        .header("Authorization", "Bearer " + tokenA)
                        .contentType("application/json")
                        .content("{\"title\":\"Tampered Title\",\"category\":\"Financial\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Biometric Gate: Owner with verified passkey token can update document")
    void userACanUpdateWithPasskeyVerification() throws Exception {
        mockMvc.perform(put("/api/documents/" + docA.getId())
                        .header("Authorization", "Bearer " + tokenA)
                        .header("X-Passkey-Token", "mock-passkey")
                        .contentType("application/json")
                        .content("{\"title\":\"Verified New Title\",\"category\":\"Financial\"}"))
                .andExpect(status().isOk());
    }
}

package com.trustvault;

import com.trustvault.dto.DocumentResponse;
import com.trustvault.dto.GrantPermissionRequest;
import com.trustvault.entity.PermissionLevel;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

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
                        .header("X-Passkey-Token", "mock-passkey"))
                .andExpect(status().isOk());

        // 2nd download attempt: burned! Must return 403 Forbidden
        mockMvc.perform(get("/api/documents/" + doc.getId() + "/download")
                        .header("Authorization", "Bearer " + recipientToken)
                        .header("X-Passkey-Token", "mock-passkey"))
                .andExpect(status().isForbidden());
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

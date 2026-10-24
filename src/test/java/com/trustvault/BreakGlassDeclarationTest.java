package com.trustvault;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustvault.dto.DocumentResponse;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditLog;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import com.trustvault.repository.AuditLogRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.JwtTokenProvider;
import com.trustvault.service.DocumentService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.Optional;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Coverage for Break-Glass emergency access.
 *
 * <p>The declaration is deliberately <em>evidence, not authorization</em>: it timestamps intent on
 * the WORM trail before an administrator opens a document, but it must not widen rights, must not
 * replace the live face gate, and must stay restricted to administrators.</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
public class BreakGlassDeclarationTest {

    private static final String CLIENT_IP = "10.9.9.9";
    private static final String REASON = "Legal hold - regulator request 2026-114";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private DocumentService documentService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private User admin;
    private User owner;
    private String adminToken;
    private String ownerToken;
    private String documentId;

    @BeforeEach
    void setUp() {
        admin = upsert("breakglass.admin@internal.test", "Break-Glass Administrator", Role.ADMIN);
        owner = upsert("breakglass.owner@internal.test", "Break-Glass Owner", Role.OWNER);

        adminToken = jwtTokenProvider.generateTokenFromUser(admin.getId(), admin.getEmail(), admin.getRole().name());
        ownerToken = jwtTokenProvider.generateTokenFromUser(owner.getId(), owner.getEmail(), owner.getRole().name());

        MockMultipartFile file = new MockMultipartFile(
                "file", "breakglass_probe.txt", "text/plain", "Break-glass payload".getBytes());
        DocumentResponse document = documentService.uploadDocument(
                "Break-Glass Evidence Probe", "LEGAL", file, owner, CLIENT_IP);
        documentId = document.getId();
    }

    @Test
    @DisplayName("An administrator declaration is written to the WORM trail with a document snapshot")
    void declarationWritesImmutableEvidence() throws Exception {
        String body = declare(adminToken, documentId, REASON)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.documentId").value(documentId))
                .andExpect(jsonPath("$.title").value("Break-Glass Evidence Probe"))
                .andExpect(jsonPath("$.ownerEmail").value(owner.getEmail()))
                .andExpect(jsonPath("$.requiresLiveFace").value(true))
                .andReturn().getResponse().getContentAsString();

        String auditLogId = objectMapper.readTree(body).path("auditLogId").asText();

        Optional<AuditLog> stored = auditLogRepository.findById(auditLogId);
        assertTrue(stored.isPresent(), "Expected the declaration to persist an audit row");

        AuditLog evidence = stored.get();
        assertEquals(AuditAction.BREAK_GLASS_ACCESS, evidence.getAction());
        assertEquals(admin.getEmail(), evidence.getUserEmail());
        assertEquals(documentId, evidence.getDocumentId());
        assertEquals(CLIENT_IP, evidence.getIpAddress());

        assertNotNull(evidence.getDetails(), "Expected the declaration details to be serialised");
        assertTrue(evidence.getDetails().contains("EMERGENCY_BREAK_GLASS"),
                "Expected the mode marker in " + evidence.getDetails());
        assertTrue(evidence.getDetails().contains(REASON),
                "Expected the justification to be preserved verbatim");

        assertNotNull(evidence.getPreState(), "Expected a document snapshot for the forensic inspector");
        assertTrue(evidence.getPreState().contains("Break-Glass Evidence Probe"),
                "Expected the snapshot to describe the document in scope");
        assertNull(evidence.getPostState(), "A declaration mutates nothing, so post_state stays empty");
    }

    @Test
    @DisplayName("A declaration does not replace the live face gate")
    void declarationDoesNotAuthoriseTheRead() throws Exception {
        declare(adminToken, documentId, REASON).andExpect(status().isOk());

        // The administrator now holds the evidence row, but no face proof: the download must fail.
        mockMvc.perform(get("/api/documents/" + documentId + "/download")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Only administrators may declare break-glass access")
    void nonAdministratorCannotDeclare() throws Exception {
        declare(ownerToken, documentId, REASON)
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("A justification shorter than ten characters is rejected before anything is written")
    void shortJustificationIsRejected() throws Exception {
        declare(adminToken, documentId, "too short")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("An unknown document id returns 404 and writes no evidence row")
    void unknownDocumentIsRejected() throws Exception {
        String unknownId = UUID.randomUUID().toString();

        declare(adminToken, unknownId, REASON)
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value(containsString("Document not found")));

        assertFalse(auditLogRepository.findAll().stream()
                        .anyMatch(log -> AuditAction.BREAK_GLASS_ACCESS == log.getAction()
                                && unknownId.equals(log.getDocumentId())),
                "No evidence row may be written for a document that does not exist");
    }

    private ResultActions declare(String token, String targetDocumentId, String reason)
            throws Exception {
        String payload = "{\"documentId\":\"" + targetDocumentId + "\",\"reason\":\"" + reason + "\"}";
        return mockMvc.perform(post("/api/admin/break-glass")
                .header("Authorization", "Bearer " + token)
                // The incident workstation reaches the API through the proxy, so the forwarded
                // address - not the socket peer - is what the evidence row must record.
                .header("X-Forwarded-For", CLIENT_IP)
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload));
    }

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
}

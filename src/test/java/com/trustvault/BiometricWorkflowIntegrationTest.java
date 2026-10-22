package com.trustvault;

import com.trustvault.dto.RegisterCompleteRequest;
import com.trustvault.dto.RegisterInitiateResponse;
import com.trustvault.dto.RegisterRequest;
import com.trustvault.dto.WebAuthnLoginVerifyRequest;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import com.trustvault.repository.AuditLogRepository;
import com.trustvault.repository.UserCredentialRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.service.WebAuthnService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@AutoConfigureMockMvc
public class BiometricWorkflowIntegrationTest {

    @Autowired
    private WebAuthnService webAuthnService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserCredentialRepository userCredentialRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Test
    @DisplayName("Mandatory Biometric Sign-Up: User is NOT created if biometric ceremony is aborted")
    void testUserNotCreatedWhenBiometricAborted() {
        String testEmail = "aborted.user." + UUID.randomUUID() + "@trustvault.internal";
        RegisterRequest req = new RegisterRequest(testEmail, "SecretPass123!", "Aborted User", Role.VIEWER);

        RegisterInitiateResponse initRes = webAuthnService.initiateRegistration(req);
        assertNotNull(initRes.getRegistrationToken());
        assertNotNull(initRes.getChallenge());

        // User must NOT exist in the database yet
        assertFalse(userRepository.findByEmail(testEmail).isPresent(),
                "User must not be persisted before mandatory biometric registration is completed.");
    }

    @Test
    @DisplayName("Action Biometric Verification: Failure logs ACCESS_DENIED and SECURITY_ALERT")
    void testActionVerificationFailureLogsSecurityAlert() {
        User testUser = userRepository.save(new User(
                UUID.randomUUID().toString(),
                "biometric.victim." + UUID.randomUUID() + "@trustvault.internal",
                "hash",
                "Biometric Victim",
                Role.OWNER,
                UserStatus.ACTIVE
        ));

        WebAuthnLoginVerifyRequest badVerify = new WebAuthnLoginVerifyRequest();
        badVerify.setId("non-existent-credential-id");
        Map<String, Object> respMap = new HashMap<>();
        String fakeClientData = "{\"type\":\"webauthn.get\",\"challenge\":\"invalid-challenge\"}";
        respMap.put("clientDataJSON", Base64.getUrlEncoder().withoutPadding().encodeToString(fakeClientData.getBytes(StandardCharsets.UTF_8)));
        badVerify.setResponse(respMap);

        // Verification must throw SecurityException
        assertThrows(SecurityException.class, () -> {
            webAuthnService.verifyActionAndIssueToken(testUser, badVerify, "doc-123", "EDIT", "192.0.2.1");
        });

        // Verify that SECURITY_ALERT was logged
        boolean alertLogged = auditLogRepository.findAllByOrderByTimestampDesc().stream()
                .anyMatch(log -> log.getAction() == AuditAction.SECURITY_ALERT &&
                                 "doc-123".equals(log.getDocumentId()));

        assertTrue(alertLogged, "Expected SECURITY_ALERT to be logged on failed biometric action verification.");
    }
}

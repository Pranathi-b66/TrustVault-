package com.trustvault;

import com.trustvault.entity.AuditAction;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import com.trustvault.repository.AuditLogRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class SecurityAnomalyDetectionTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private User attacker;
    private String attackerToken;

    @BeforeEach
    void setUp() {
        attacker = userRepository.findByEmail("recon.attacker@internal.test").orElseGet(() -> {
            User u = new User(UUID.randomUUID().toString(), "recon.attacker@internal.test", "hash", "Recon Attacker", Role.VIEWER, UserStatus.ACTIVE);
            return userRepository.save(u);
        });

        attackerToken = jwtTokenProvider.generateTokenFromUser(attacker.getId(), attacker.getEmail(), attacker.getRole().name());
    }

    @Test
    @DisplayName("Security Anomaly Detection: 3 consecutive ACCESS_DENIED triggers automatic SECURITY_ALERT")
    void testAnomalyDetectionTriggersAlert() throws Exception {
        String testIp = "198.51.100.99";

        // Perform 3 consecutive IDOR enumeration attempts
        for (int i = 1; i <= 3; i++) {
            mockMvc.perform(get("/api/documents/non-existent-doc-id-" + i)
                            .header("Authorization", "Bearer " + attackerToken)
                            .header("X-Forwarded-For", testIp))
                    .andExpect(status().isForbidden());
        }

        // Verify that SECURITY_ALERT was inserted into audit_logs
        boolean alertFound = auditLogRepository.findAllByOrderByTimestampDesc().stream()
                .anyMatch(log -> log.getAction() == AuditAction.SECURITY_ALERT);

        assertTrue(alertFound, "Expected SECURITY_ALERT to be logged after 3 consecutive ACCESS_DENIED events");
    }
}

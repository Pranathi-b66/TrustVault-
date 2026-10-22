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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class InstantOffboardingTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private User admin;
    private User employee;
    private String adminToken;
    private String employeeToken;

    @BeforeEach
    void setUp() {
        admin = userRepository.findByEmail("admin.sec@internal.test").orElseGet(() -> {
            User u = new User(UUID.randomUUID().toString(), "admin.sec@internal.test", "hash", "Admin Sec", Role.ADMIN, UserStatus.ACTIVE);
            return userRepository.save(u);
        });

        employee = userRepository.findByEmail("disgruntled.employee@internal.test").orElseGet(() -> {
            User u = new User(UUID.randomUUID().toString(), "disgruntled.employee@internal.test", "hash", "Disgruntled Employee", Role.OWNER, UserStatus.ACTIVE);
            return userRepository.save(u);
        });

        // Ensure employee is active before test
        employee.setStatus(UserStatus.ACTIVE);
        userRepository.save(employee);

        adminToken = jwtTokenProvider.generateTokenFromUser(admin.getId(), admin.getEmail(), admin.getRole().name());
        employeeToken = jwtTokenProvider.generateTokenFromUser(employee.getId(), employee.getEmail(), employee.getRole().name());
    }

    @Test
    @DisplayName("Instant Offboarding: Deactivating user immediately cuts access with 403 and logs event")
    void testInstantOffboardingKillSwitch() throws Exception {
        // 1. Employee is initially active and can access endpoints
        mockMvc.perform(get("/api/documents/owned")
                        .header("Authorization", "Bearer " + employeeToken))
                .andExpect(status().isOk());

        // 2. Admin triggers instant offboarding
        mockMvc.perform(put("/api/admin/users/" + employee.getId() + "/deactivate")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());

        // 3. Employee immediately receives 403 Forbidden even with valid unexpired JWT token
        mockMvc.perform(get("/api/documents/owned")
                        .header("Authorization", "Bearer " + employeeToken))
                .andExpect(status().isForbidden());

        // 4. Verify audit log captured the attempt
        boolean hasInactiveAccessAttempt = auditLogRepository.findAllByOrderByTimestampDesc().stream()
                .anyMatch(log -> log.getAction() == AuditAction.ACCOUNT_INACTIVE_ACCESS_ATTEMPT &&
                                 employee.getEmail().equals(log.getUserEmail()));
        assertTrue(hasInactiveAccessAttempt, "Expected ACCOUNT_INACTIVE_ACCESS_ATTEMPT in audit_logs");
    }
}

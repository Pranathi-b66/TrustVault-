package com.trustvault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditLog;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import com.trustvault.repository.AuditLogRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.JwtTokenProvider;
import com.trustvault.service.SystemLockdownService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end coverage for the two admin security features:
 *
 * <ol>
 *   <li>Emergency Global Kill Switch - freezes every non-admin surface and every document
 *       operation with {@code 503}, keeps the admin console alive, and writes a high-priority
 *       {@code SYSTEM_LOCKDOWN_TRIGGERED} audit event with actor and reason.</li>
 *   <li>Action Replay - administrative mutations persist before/after snapshots that the
 *       {@code /api/admin/audit/{id}/diff} endpoint turns into a field-level delta.</li>
 * </ol>
 */
@SpringBootTest
@AutoConfigureMockMvc
public class SystemLockdownAndAuditReplayTest {

    private static final String LOCKDOWN_REASON = "Suspected credential compromise in finance unit";
    private static final String LOCKDOWN_MESSAGE = "System is under administrative security lockdown";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private SystemLockdownService systemLockdownService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private User admin;
    private User employee;
    private String adminToken;
    private String employeeToken;

    @BeforeEach
    void setUp() {
        // The flag is durable: never inherit an enabled lockdown from a previous run.
        systemLockdownService.apply(false, "Test baseline: lockdown cleared", "junit");

        admin = userRepository.findByEmail("admin.lockdown@internal.test").orElseGet(() -> {
            User u = new User(UUID.randomUUID().toString(), "admin.lockdown@internal.test", "hash",
                    "Lockdown Admin", Role.ADMIN, UserStatus.ACTIVE);
            return userRepository.save(u);
        });

        employee = userRepository.findByEmail("lockdown.employee@internal.test").orElseGet(() -> {
            User u = new User(UUID.randomUUID().toString(), "lockdown.employee@internal.test", "hash",
                    "Lockdown Employee", Role.OWNER, UserStatus.ACTIVE);
            return userRepository.save(u);
        });

        admin.setRole(Role.ADMIN);
        admin.setStatus(UserStatus.ACTIVE);
        userRepository.save(admin);

        employee.setRole(Role.OWNER);
        employee.setStatus(UserStatus.ACTIVE);
        userRepository.save(employee);

        adminToken = tokenFor(admin);
        employeeToken = tokenFor(employee);
    }

    @AfterEach
    void tearDown() {
        // A leaked lockdown flag would fail every later test in the same JVM.
        systemLockdownService.apply(false, "Test teardown: lockdown cleared", "junit");
    }

    @Test
    @DisplayName("Kill switch: 503 for non-admins and all document traffic, admin console stays reachable")
    void lockdownFreezesPerimeterButKeepsAdminConsole() throws Exception {
        // Baseline: the employee can reach their own vault and the admin console rejects them (403).
        mockMvc.perform(get("/api/documents/owned").header("Authorization", bearer(employeeToken)))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/admin/stats").header("Authorization", bearer(employeeToken)))
                .andExpect(status().isForbidden());

        Set<String> knownTriggers = auditIds(AuditAction.SYSTEM_LOCKDOWN_TRIGGERED);

        // Engage the lockdown.
        mockMvc.perform(post("/api/admin/system/lockdown")
                        .header("Authorization", bearer(adminToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":true,\"reason\":\"" + LOCKDOWN_REASON + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.state").value("LOCKED_DOWN"))
                .andExpect(jsonPath("$.reason").value(LOCKDOWN_REASON));

        // Non-admin traffic is frozen with the fixed public message.
        MvcResult employeeDenied = mockMvc.perform(get("/api/documents/owned")
                        .header("Authorization", bearer(employeeToken)))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("SYSTEM_LOCKDOWN"))
                .andExpect(jsonPath("$.message").value(LOCKDOWN_MESSAGE))
                .andReturn();

        String deniedBody = employeeDenied.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertFalse(deniedBody.contains(LOCKDOWN_REASON),
                "The incident reason must never leak to a caller that is not an administrator");

        mockMvc.perform(get("/api/admin/stats").header("Authorization", bearer(employeeToken)))
                .andExpect(status().isServiceUnavailable());

        // Administrators keep the incident console...
        mockMvc.perform(get("/api/admin/stats").header("Authorization", bearer(adminToken)))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/admin/system/lockdown").header("Authorization", bearer(adminToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.triggeredBy").value(admin.getEmail()));

        // ...but document operations are frozen for everyone, admins included, so evidence is immutable.
        mockMvc.perform(get("/api/documents/owned").header("Authorization", bearer(adminToken)))
                .andExpect(status().isServiceUnavailable());

        // High-priority audit event with timestamp, admin identity and reason.
        AuditLog triggered = newAuditSince(AuditAction.SYSTEM_LOCKDOWN_TRIGGERED, knownTriggers);
        assertNotNull(triggered, "Expected a SYSTEM_LOCKDOWN_TRIGGERED audit row");
        assertNotNull(triggered.getTimestamp(), "Expected the lockdown event to carry a timestamp");
        assertNotNull(triggered.getPreState(), "Expected a pre_state snapshot on the lockdown event");
        assertNotNull(triggered.getPostState(), "Expected a post_state snapshot on the lockdown event");
        assertTrue(triggered.getDetails().contains(admin.getId()), "Expected the admin user id in the audit details");
        assertTrue(triggered.getDetails().contains(LOCKDOWN_REASON), "Expected the incident reason in the audit details");

        // Lifting the lockdown restores traffic and appends the matching audit event.
        Set<String> knownLifts = auditIds(AuditAction.SYSTEM_LOCKDOWN_LIFTED);

        mockMvc.perform(post("/api/admin/system/lockdown")
                        .header("Authorization", bearer(adminToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false,\"reason\":\"Containment verified; credentials rotated\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));

        mockMvc.perform(get("/api/documents/owned").header("Authorization", bearer(employeeToken)))
                .andExpect(status().isOk());

        assertNotNull(newAuditSince(AuditAction.SYSTEM_LOCKDOWN_LIFTED, knownLifts),
                "Expected a SYSTEM_LOCKDOWN_LIFTED audit row");
    }

    @Test
    @DisplayName("Kill switch: engaging without a reason is rejected with 400")
    void lockdownRequiresReason() throws Exception {
        mockMvc.perform(post("/api/admin/system/lockdown")
                        .header("Authorization", bearer(adminToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":true}"))
                .andExpect(status().isBadRequest());

        assertFalse(systemLockdownService.isLockdownEnabled(),
                "A rejected request must never flip the flag");
    }

    @Test
    @DisplayName("Action Replay: deactivation diff exposes the ACTIVE -> INACTIVE status transition")
    void replayDiffExposesUserStatusTransition() throws Exception {
        Set<String> knownDeactivations = auditIds(AuditAction.ACCOUNT_DEACTIVATED);

        mockMvc.perform(put("/api/admin/users/" + employee.getId() + "/deactivate")
                        .header("Authorization", bearer(adminToken)))
                .andExpect(status().isOk());

        AuditLog deactivated = newAuditSince(AuditAction.ACCOUNT_DEACTIVATED, knownDeactivations);
        assertNotNull(deactivated, "Expected an ACCOUNT_DEACTIVATED audit row");

        JsonNode diff = fetchDiff(deactivated.getId());

        assertTrue(diff.path("hasSnapshot").asBoolean(), "Expected before/after snapshots");
        assertEquals("USER", diff.path("resourceType").asText());
        assertEquals(admin.getEmail(), diff.path("actorEmail").asText());
        assertEquals(admin.getId(), diff.path("actorUserId").asText());

        JsonNode statusChange = findChange(diff.path("changes"), "status");
        assertNotNull(statusChange, "Expected a field-level delta for 'status'");
        assertEquals("ACTIVE", statusChange.path("before").asText());
        assertEquals("INACTIVE", statusChange.path("after").asText());
        assertEquals("MODIFIED", statusChange.path("changeType").asText());

        assertEquals("ACTIVE", diff.path("preState").path("status").asText());
        assertEquals("INACTIVE", diff.path("postState").path("status").asText());
        assertEquals(1, diff.path("summary").path("modified").asInt());

        // The WORM list endpoint must not serialize the actor's credentials.
        MvcResult listResult = mockMvc.perform(get("/api/admin/audit-logs")
                        .header("Authorization", bearer(adminToken)))
                .andExpect(status().isOk())
                .andReturn();
        String auditPayload = listResult.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertFalse(auditPayload.contains("passwordHash"),
                "Audit payload must not expose actor credentials");
    }

    @Test
    @DisplayName("Action Replay: role change diff exposes the OWNER -> VIEWER privilege transition")
    void replayDiffExposesRoleChange() throws Exception {
        Set<String> knownRoleChanges = auditIds(AuditAction.ROLE_CHANGED);

        mockMvc.perform(put("/api/admin/users/" + employee.getId() + "/role")
                        .header("Authorization", bearer(adminToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role\":\"VIEWER\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("VIEWER"));

        AuditLog roleChanged = newAuditSince(AuditAction.ROLE_CHANGED, knownRoleChanges);
        assertNotNull(roleChanged, "Expected a ROLE_CHANGED audit row");

        JsonNode diff = fetchDiff(roleChanged.getId());
        JsonNode roleChange = findChange(diff.path("changes"), "role");

        assertNotNull(roleChange, "Expected a field-level delta for 'role'");
        assertEquals("OWNER", roleChange.path("before").asText());
        assertEquals("VIEWER", roleChange.path("after").asText());
        assertEquals("MODIFIED", roleChange.path("changeType").asText());
        assertEquals("USER", diff.path("resourceType").asText());
    }

    @Test
    @DisplayName("Action Replay: non-admins cannot read the forensic diff")
    void replayDiffRequiresAdministrator() throws Exception {
        AuditLog anyLog = auditLogRepository.findAllByOrderByTimestampDesc().stream()
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Test requires at least one audit row"));

        mockMvc.perform(get("/api/admin/audit/" + anyLog.getId() + "/diff")
                        .header("Authorization", bearer(employeeToken)))
                .andExpect(status().isForbidden());
    }

    private JsonNode fetchDiff(String auditId) throws Exception {
        MvcResult result = mockMvc.perform(get("/api/admin/audit/" + auditId + "/diff")
                        .header("Authorization", bearer(adminToken)))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private JsonNode findChange(JsonNode changes, String field) {
        for (JsonNode change : changes) {
            if (field.equals(change.path("field").asText())) {
                return change;
            }
        }
        return null;
    }

    private Set<String> auditIds(AuditAction action) {
        Set<String> ids = new HashSet<>();
        for (AuditLog log : auditLogRepository.findAllByOrderByTimestampDesc()) {
            if (log.getAction() == action) {
                ids.add(log.getId());
            }
        }
        return ids;
    }

    private AuditLog newAuditSince(AuditAction action, Set<String> knownIds) {
        return auditLogRepository.findAllByOrderByTimestampDesc().stream()
                .filter(log -> log.getAction() == action)
                .filter(log -> !knownIds.contains(log.getId()))
                .findFirst()
                .orElse(null);
    }

    private String tokenFor(User user) {
        return jwtTokenProvider.generateTokenFromUser(user.getId(), user.getEmail(), user.getRole().name());
    }

    private String bearer(String token) {
        return "Bearer " + token;
    }
}

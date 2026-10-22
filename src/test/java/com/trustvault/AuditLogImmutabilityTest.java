package com.trustvault;

import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditLog;
import com.trustvault.entity.AuditStatus;
import com.trustvault.service.AuditLogService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
public class AuditLogImmutabilityTest {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    @DisplayName("WORM Compliance: MySQL trigger blocks UPDATE on audit_logs with SQLSTATE 45000")
    void testAuditLogUpdateIsBlockedByTrigger() {
        AuditLog saved = auditLogService.logEvent(
                null,
                "auditor@trustvault.internal",
                AuditAction.READ,
                null,
                "127.0.0.1",
                AuditStatus.SUCCESS,
                Collections.singletonMap("note", "Initial Immutable Audit")
        );

        // Direct SQL update attempt must fail due to trigger trg_audit_logs_no_update
        Exception exception = assertThrows(Exception.class, () -> {
            jdbcTemplate.update("UPDATE audit_logs SET user_email = 'tampered@evil.com' WHERE id = ?", saved.getId());
        });

        String message = exception.getMessage();
        assertTrue(message.contains("TrustVault Security Violation") || message.contains("45000"),
                "Expected trigger violation error but got: " + message);
    }

    @Test
    @DisplayName("WORM Compliance: MySQL trigger blocks DELETE on audit_logs with SQLSTATE 45000")
    void testAuditLogDeleteIsBlockedByTrigger() {
        AuditLog saved = auditLogService.logEvent(
                null,
                "auditor@trustvault.internal",
                AuditAction.DELETE,
                null,
                "127.0.0.1",
                AuditStatus.SUCCESS,
                Collections.singletonMap("note", "Delete audit test")
        );

        // Direct SQL delete attempt must fail due to trigger trg_audit_logs_no_delete
        Exception exception = assertThrows(Exception.class, () -> {
            jdbcTemplate.update("DELETE FROM audit_logs WHERE id = ?", saved.getId());
        });

        String message = exception.getMessage();
        assertTrue(message.contains("TrustVault Security Violation") || message.contains("45000"),
                "Expected trigger violation error but got: " + message);
    }
}

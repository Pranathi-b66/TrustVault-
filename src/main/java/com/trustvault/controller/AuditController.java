package com.trustvault.controller;

import com.trustvault.entity.AuditLog;
import com.trustvault.service.AuditLogService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/admin/audit-logs")
@PreAuthorize("hasRole('ADMIN')")
public class AuditController {

    private final AuditLogService auditLogService;

    public AuditController(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @GetMapping
    public ResponseEntity<List<AuditLog>> getAuditLogs() {
        return ResponseEntity.ok(auditLogService.getRecentLogs());
    }

    @GetMapping("/alerts")
    public ResponseEntity<List<AuditLog>> getSecurityAlerts() {
        return ResponseEntity.ok(auditLogService.getSecurityAlerts());
    }
}

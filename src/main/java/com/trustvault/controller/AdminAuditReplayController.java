package com.trustvault.controller;

import com.trustvault.dto.AuditDiffResponse;
import com.trustvault.entity.AuditLog;
import com.trustvault.service.AuditDiffService;
import com.trustvault.service.AuditLogService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.NoSuchElementException;

/**
 * Action Replay forensic endpoint.
 *
 * <p>Returns the structured delta between the {@code pre_state} and {@code post_state} snapshots
 * of a single immutable audit entry. ADMIN only; snapshots never contain credentials or biometric
 * material.</p>
 */
@RestController
@RequestMapping("/api/admin/audit")
@PreAuthorize("hasRole('ADMIN')")
public class AdminAuditReplayController {

    private final AuditLogService auditLogService;
    private final AuditDiffService auditDiffService;

    public AdminAuditReplayController(AuditLogService auditLogService,
                                      AuditDiffService auditDiffService) {
        this.auditLogService = auditLogService;
        this.auditDiffService = auditDiffService;
    }

    @GetMapping("/{id}/diff")
    public ResponseEntity<AuditDiffResponse> getAuditDiff(@PathVariable("id") String id) {
        AuditLog auditLog = auditLogService.getLog(id)
                .orElseThrow(() -> new NoSuchElementException("Audit entry not found: " + id));
        return ResponseEntity.ok(auditDiffService.buildDiff(auditLog));
    }
}

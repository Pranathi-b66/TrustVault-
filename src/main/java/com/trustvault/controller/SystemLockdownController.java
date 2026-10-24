package com.trustvault.controller;

import com.trustvault.dto.LockdownRequest;
import com.trustvault.dto.LockdownStatusResponse;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditStatus;
import com.trustvault.entity.User;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.UserPrincipal;
import com.trustvault.service.AuditLogService;
import com.trustvault.service.AuditSnapshotService;
import com.trustvault.service.SystemLockdownService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Emergency Global Kill Switch control surface.
 *
 * <p>Engaging the switch flips the platform-wide {@code SYSTEM_LOCKDOWN} flag and writes a
 * high-priority {@code SYSTEM_LOCKDOWN_TRIGGERED} row (actor id, email, reason, timestamp and
 * before/after snapshots) to the immutable audit trail. Lifting it writes the matching
 * {@code SYSTEM_LOCKDOWN_LIFTED} row.</p>
 */
@RestController
@RequestMapping("/api/admin/system")
@PreAuthorize("hasRole('ADMIN')")
public class SystemLockdownController {

    private static final Logger log = LoggerFactory.getLogger(SystemLockdownController.class);

    private final SystemLockdownService systemLockdownService;
    private final AuditLogService auditLogService;
    private final AuditSnapshotService auditSnapshotService;
    private final UserRepository userRepository;

    public SystemLockdownController(SystemLockdownService systemLockdownService,
                                    AuditLogService auditLogService,
                                    AuditSnapshotService auditSnapshotService,
                                    UserRepository userRepository) {
        this.systemLockdownService = systemLockdownService;
        this.auditLogService = auditLogService;
        this.auditSnapshotService = auditSnapshotService;
        this.userRepository = userRepository;
    }

    @PostMapping("/lockdown")
    public ResponseEntity<LockdownStatusResponse> setLockdown(
            @Valid @RequestBody LockdownRequest request,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest httpRequest) {

        boolean enabled = Boolean.TRUE.equals(request.getEnabled());
        String reason = request.getReason() != null ? request.getReason().trim() : null;

        if (enabled && (reason == null || reason.length() < 5)) {
            throw new IllegalArgumentException("A lockdown reason of at least 5 characters is required.");
        }

        SystemLockdownService.LockdownStatus previous = systemLockdownService.getStatus();
        SystemLockdownService.LockdownStatus next =
                systemLockdownService.apply(enabled, reason, principal.getEmail());

        recordLockdownEvent(previous, next, principal, httpRequest);

        return ResponseEntity.ok(LockdownStatusResponse.from(next));
    }

    @GetMapping("/lockdown")
    public ResponseEntity<LockdownStatusResponse> getLockdownStatus() {
        return ResponseEntity.ok(LockdownStatusResponse.from(systemLockdownService.getStatus()));
    }

    /**
     * The flag is already enforcing containment when this runs. An audit persistence failure is
     * therefore logged at ERROR level but never turns the control action into a 5xx: a retry by
     * the operator would only repeat an already-applied state change.
     */
    private void recordLockdownEvent(SystemLockdownService.LockdownStatus previous,
                                     SystemLockdownService.LockdownStatus next,
                                     UserPrincipal principal,
                                     HttpServletRequest httpRequest) {
        try {
            User admin = userRepository.findById(principal.getId()).orElse(null);
            AuditAction action = next.enabled()
                    ? AuditAction.SYSTEM_LOCKDOWN_TRIGGERED
                    : AuditAction.SYSTEM_LOCKDOWN_LIFTED;

            Map<String, Object> details = new LinkedHashMap<>();
            details.put("reason", next.reason());
            details.put("adminUserId", principal.getId());
            details.put("adminEmail", principal.getEmail());
            details.put("lockdownEnabled", next.enabled());
            details.put("previousState", previous.enabled() ? "LOCKED_DOWN" : "OPERATIONAL");
            details.put("newState", next.enabled() ? "LOCKED_DOWN" : "OPERATIONAL");
            details.put("triggeredAt", Instant.now().toString());

            auditLogService.logEvent(
                    admin,
                    principal.getEmail(),
                    action,
                    null,
                    getClientIp(httpRequest),
                    AuditStatus.SUCCESS,
                    details,
                    auditSnapshotService.lockdownSnapshot(previous),
                    auditSnapshotService.lockdownSnapshot(next)
            );
        } catch (Exception auditError) {
            log.error("Lockdown state changed (enabled={}) but the forensic audit row could not be written.",
                    next.enabled(), auditError);
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }
}

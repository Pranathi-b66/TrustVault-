package com.trustvault.controller;

import com.trustvault.dto.UserResponse;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditStatus;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import com.trustvault.repository.AuditLogRepository;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.UserPrincipal;
import com.trustvault.service.AuditLogService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserRepository userRepository;
    private final DocumentRepository documentRepository;
    private final AuditLogRepository auditLogRepository;
    private final AuditLogService auditLogService;

    public AdminController(UserRepository userRepository,
                           DocumentRepository documentRepository,
                           AuditLogRepository auditLogRepository,
                           AuditLogService auditLogService) {
        this.userRepository = userRepository;
        this.documentRepository = documentRepository;
        this.auditLogRepository = auditLogRepository;
        this.auditLogService = auditLogService;
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    @GetMapping("/users")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        List<User> users = userRepository.findAllByOrderByCreatedAtDesc();
        List<UserResponse> list = new ArrayList<>();
        for (User u : users) {
            list.add(new UserResponse(u.getId(), u.getEmail(), u.getFullName(), u.getRole(), u.getStatus(), u.getCreatedAt()));
        }
        return ResponseEntity.ok(list);
    }

    @PutMapping("/users/{id}/deactivate")
    public ResponseEntity<UserResponse> deactivateUser(
            @PathVariable("id") String id,
            @AuthenticationPrincipal UserPrincipal adminPrincipal,
            HttpServletRequest request) {

        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + id));

        user.setStatus(UserStatus.INACTIVE);
        User saved = userRepository.save(user);

        User admin = userRepository.findById(adminPrincipal.getId()).orElse(null);
        Map<String, Object> details = new HashMap<>();
        details.put("action", "INSTANT_OFFBOARDING_TRIGGERED");
        details.put("targetUserEmail", user.getEmail());
        details.put("targetUserId", user.getId());

        auditLogService.logEvent(admin, adminPrincipal.getEmail(), AuditAction.ACCOUNT_DEACTIVATED, null, getClientIp(request), AuditStatus.SUCCESS, details);

        return ResponseEntity.ok(new UserResponse(saved.getId(), saved.getEmail(), saved.getFullName(), saved.getRole(), saved.getStatus(), saved.getCreatedAt()));
    }

    @PutMapping("/users/{id}/activate")
    public ResponseEntity<UserResponse> activateUser(
            @PathVariable("id") String id,
            @AuthenticationPrincipal UserPrincipal adminPrincipal,
            HttpServletRequest request) {

        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + id));

        user.setStatus(UserStatus.ACTIVE);
        User saved = userRepository.save(user);

        User admin = userRepository.findById(adminPrincipal.getId()).orElse(null);
        Map<String, Object> details = new HashMap<>();
        details.put("action", "ACCOUNT_ACTIVATED");
        details.put("targetUserEmail", user.getEmail());

        auditLogService.logEvent(admin, adminPrincipal.getEmail(), AuditAction.EDIT, null, getClientIp(request), AuditStatus.SUCCESS, details);

        return ResponseEntity.ok(new UserResponse(saved.getId(), saved.getEmail(), saved.getFullName(), saved.getRole(), saved.getStatus(), saved.getCreatedAt()));
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getAdminStats() {
        Map<String, Object> stats = new HashMap<>();
        long totalUsers = userRepository.count();
        long totalDocs = documentRepository.count();
        long totalAuditLogs = auditLogRepository.count();
        long securityAlertsCount = auditLogRepository.findByActionOrderByTimestampDesc(AuditAction.SECURITY_ALERT).size();

        stats.put("totalUsers", totalUsers);
        stats.put("totalDocuments", totalDocs);
        stats.put("totalAuditLogs", totalAuditLogs);
        stats.put("securityAlertsCount", securityAlertsCount);

        return ResponseEntity.ok(stats);
    }
}

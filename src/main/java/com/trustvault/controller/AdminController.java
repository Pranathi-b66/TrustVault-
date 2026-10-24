package com.trustvault.controller;

import com.trustvault.dto.RoleUpdateRequest;
import com.trustvault.dto.UserResponse;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.User;
import com.trustvault.repository.AuditLogRepository;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.UserPrincipal;
import com.trustvault.service.AdminUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
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
    private final AdminUserService adminUserService;

    public AdminController(UserRepository userRepository,
                           DocumentRepository documentRepository,
                           AuditLogRepository auditLogRepository,
                           AdminUserService adminUserService) {
        this.userRepository = userRepository;
        this.documentRepository = documentRepository;
        this.auditLogRepository = auditLogRepository;
        this.adminUserService = adminUserService;
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    private UserResponse toResponse(User user) {
        return new UserResponse(user.getId(), user.getEmail(), user.getFullName(),
                user.getRole(), user.getStatus(), user.getCreatedAt());
    }

    @GetMapping("/users")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        List<User> users = userRepository.findAllByOrderByCreatedAtDesc();
        List<UserResponse> list = new ArrayList<>();
        for (User u : users) {
            list.add(toResponse(u));
        }
        return ResponseEntity.ok(list);
    }

    @PutMapping("/users/{id}/deactivate")
    public ResponseEntity<UserResponse> deactivateUser(
            @PathVariable("id") String id,
            @AuthenticationPrincipal UserPrincipal adminPrincipal,
            HttpServletRequest request) {

        User saved = adminUserService.deactivateUser(id, adminPrincipal.getId(), getClientIp(request));
        return ResponseEntity.ok(toResponse(saved));
    }

    @PutMapping("/users/{id}/activate")
    public ResponseEntity<UserResponse> activateUser(
            @PathVariable("id") String id,
            @AuthenticationPrincipal UserPrincipal adminPrincipal,
            HttpServletRequest request) {

        User saved = adminUserService.activateUser(id, adminPrincipal.getId(), getClientIp(request));
        return ResponseEntity.ok(toResponse(saved));
    }

    /**
     * Role changes are captured with before/after snapshots so the Action Replay inspector can
     * show exactly which identity moved between which privilege tier.
     */
    @PutMapping("/users/{id}/role")
    public ResponseEntity<UserResponse> changeRole(
            @PathVariable("id") String id,
            @Valid @RequestBody RoleUpdateRequest request,
            @AuthenticationPrincipal UserPrincipal adminPrincipal,
            HttpServletRequest httpRequest) {

        User saved = adminUserService.changeRole(id, adminPrincipal.getId(), request.getRole(),
                getClientIp(httpRequest));
        return ResponseEntity.ok(toResponse(saved));
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

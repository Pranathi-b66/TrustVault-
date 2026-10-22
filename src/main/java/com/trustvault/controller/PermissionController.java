package com.trustvault.controller;

import com.trustvault.dto.GrantPermissionRequest;
import com.trustvault.dto.PermissionResponse;
import com.trustvault.entity.User;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.UserPrincipal;
import com.trustvault.service.PermissionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/api/documents/{id}/permissions")
public class PermissionController {

    private final PermissionService permissionService;
    private final UserRepository userRepository;

    public PermissionController(PermissionService permissionService, UserRepository userRepository) {
        this.permissionService = permissionService;
        this.userRepository = userRepository;
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    @PostMapping
    public ResponseEntity<PermissionResponse> grantPermission(
            @PathVariable("id") String documentId,
            @RequestBody GrantPermissionRequest request,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest httpRequest) {

        User granter = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        PermissionResponse resp = permissionService.grantPermission(documentId, granter, request, getClientIp(httpRequest));
        return ResponseEntity.ok(resp);
    }

    @GetMapping
    public ResponseEntity<List<PermissionResponse>> getPermissions(
            @PathVariable("id") String documentId,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest httpRequest) {

        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return ResponseEntity.ok(permissionService.getDocumentPermissions(documentId, user, getClientIp(httpRequest)));
    }

    @DeleteMapping("/{userId}")
    public ResponseEntity<?> revokePermission(
            @PathVariable("id") String documentId,
            @PathVariable("userId") String targetUserId,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest httpRequest) {

        User requester = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        permissionService.revokePermission(documentId, targetUserId, requester, getClientIp(httpRequest));
        return ResponseEntity.ok(Collections.singletonMap("message", "Permission revoked successfully."));
    }
}

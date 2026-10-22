package com.trustvault.service;

import com.trustvault.dto.GrantPermissionRequest;
import com.trustvault.dto.PermissionResponse;
import com.trustvault.entity.*;
import com.trustvault.repository.DocumentPermissionRepository;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.UserRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

@Service
public class PermissionService {

    private final DocumentPermissionRepository permissionRepository;
    private final DocumentRepository documentRepository;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;

    public PermissionService(DocumentPermissionRepository permissionRepository,
                             DocumentRepository documentRepository,
                             UserRepository userRepository,
                             AuditLogService auditLogService) {
        this.permissionRepository = permissionRepository;
        this.documentRepository = documentRepository;
        this.userRepository = userRepository;
        this.auditLogService = auditLogService;
    }

    /**
     * Determines the effective permission of a user on a document: "OWNER", "EDIT", "READ", or null.
     * Enforces Burn-After-Reading limits and expiration.
     */
    @Transactional
    public String evaluateAndConsumeAccess(Document document, User user, boolean isReadOperation, String clientIp) {
        if (user == null || document == null) {
            throw new AccessDeniedException("Unauthorized: missing user or document context.");
        }

        // 1. Owner always has full access
        if (document.getOwner().getId().equals(user.getId())) {
            return "OWNER";
        }

        // 2. Check document permissions
        Optional<DocumentPermission> permOpt = permissionRepository.findByDocumentIdAndUserId(document.getId(), user.getId());
        if (permOpt.isEmpty()) {
            Map<String, Object> details = new HashMap<>();
            details.put("reason", "IDOR Prevention: User has no explicit ACL grant for document");
            details.put("attemptedDocOwner", document.getOwner().getEmail());
            auditLogService.logEvent(user, user.getEmail(), AuditAction.ACCESS_DENIED, document.getId(), clientIp, AuditStatus.FAILURE, details);
            throw new AccessDeniedException("Access Denied: You do not have permission to access this document.");
        }

        DocumentPermission permission = permOpt.get();

        // 3. Check time-based expiration
        if (permission.getExpiresAt() != null && Instant.now().isAfter(permission.getExpiresAt())) {
            permissionRepository.delete(permission);
            Map<String, Object> details = new HashMap<>();
            details.put("reason", "Burn-After-Reading: Permission expired at " + permission.getExpiresAt());
            auditLogService.logEvent(user, user.getEmail(), AuditAction.REVOKE, document.getId(), clientIp, AuditStatus.SUCCESS, details);
            auditLogService.logEvent(user, user.getEmail(), AuditAction.ACCESS_DENIED, document.getId(), clientIp, AuditStatus.FAILURE, details);
            throw new AccessDeniedException("Access Denied: This link has expired.");
        }

        // 4. Check max views (Burn-After-Reading)
        if (permission.getMaxViews() != null && permission.getViewsCount() >= permission.getMaxViews()) {
            permissionRepository.delete(permission);
            Map<String, Object> details = new HashMap<>();
            details.put("reason", "Burn-After-Reading: Max view count exceeded (" + permission.getMaxViews() + ")");
            auditLogService.logEvent(user, user.getEmail(), AuditAction.REVOKE, document.getId(), clientIp, AuditStatus.SUCCESS, details);
            auditLogService.logEvent(user, user.getEmail(), AuditAction.ACCESS_DENIED, document.getId(), clientIp, AuditStatus.FAILURE, details);
            throw new AccessDeniedException("Access Denied: Burn-after-reading view limit reached.");
        }

        // 5. If this is a read operation, increment view counter
        if (isReadOperation) {
            permission.setViewsCount(permission.getViewsCount() + 1);
            if (permission.getMaxViews() != null && permission.getViewsCount() >= permission.getMaxViews()) {
                // Auto-delete / revoke on burning final view
                permissionRepository.delete(permission);
                Map<String, Object> details = new HashMap<>();
                details.put("reason", "Burn-After-Reading: Document consumed final permitted view, permission burned.");
                auditLogService.logEvent(user, user.getEmail(), AuditAction.REVOKE, document.getId(), clientIp, AuditStatus.SUCCESS, details);
            } else {
                permissionRepository.save(permission);
            }
        }

        return permission.getPermissionLevel().name();
    }

    @Transactional
    public PermissionResponse grantPermission(String documentId, User granter, GrantPermissionRequest request, String clientIp) {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new IllegalArgumentException("Document not found: " + documentId));

        // Only the Owner can grant permissions
        if (!document.getOwner().getId().equals(granter.getId())) {
            Map<String, Object> details = new HashMap<>();
            details.put("reason", "Only document owner can grant permissions");
            auditLogService.logEvent(granter, granter.getEmail(), AuditAction.ACCESS_DENIED, documentId, clientIp, AuditStatus.FAILURE, details);
            throw new AccessDeniedException("Only the owner can grant access to this document.");
        }

        String recipientEmail = request.getUserEmail() != null ? request.getUserEmail().trim() : "";
        User recipient = userRepository.findByEmailIgnoreCase(recipientEmail)
                .orElseThrow(() -> new IllegalArgumentException("Target user not found: " + request.getUserEmail()));

        if (recipient.getId().equals(granter.getId())) {
            throw new IllegalArgumentException("Cannot grant permissions to yourself (already owner).");
        }

        // Find existing or create new
        DocumentPermission permission = permissionRepository.findByDocumentIdAndUserId(documentId, recipient.getId())
                .orElse(new DocumentPermission());

        if (permission.getId() == null) {
            permission.setId(UUID.randomUUID().toString());
            permission.setDocument(document);
            permission.setUser(recipient);
            permission.setViewsCount(0);
        }

        permission.setPermissionLevel(request.getPermissionLevel() != null ? request.getPermissionLevel() : PermissionLevel.READ);
        permission.setMaxViews(request.getMaxViews());
        permission.setExpiresAt(request.getExpiresAt());
        permission.setGrantedBy(granter);

        DocumentPermission saved = permissionRepository.save(permission);

        Map<String, Object> details = new HashMap<>();
        details.put("recipient", recipient.getEmail());
        details.put("permissionLevel", saved.getPermissionLevel().name());
        details.put("maxViews", saved.getMaxViews());
        details.put("expiresAt", saved.getExpiresAt() != null ? saved.getExpiresAt().toString() : null);
        auditLogService.logEvent(granter, granter.getEmail(), AuditAction.GRANT, documentId, clientIp, AuditStatus.SUCCESS, details);

        return toPermissionResponse(saved);
    }

    @Transactional
    public void revokePermission(String documentId, String targetUserId, User requester, String clientIp) {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new IllegalArgumentException("Document not found: " + documentId));

        // Only Owner can revoke permissions
        if (!document.getOwner().getId().equals(requester.getId())) {
            Map<String, Object> details = new HashMap<>();
            details.put("reason", "Only document owner can revoke permissions");
            auditLogService.logEvent(requester, requester.getEmail(), AuditAction.ACCESS_DENIED, documentId, clientIp, AuditStatus.FAILURE, details);
            throw new AccessDeniedException("Only the document owner can revoke permissions.");
        }

        Optional<DocumentPermission> permOpt = permissionRepository.findByDocumentIdAndUserId(documentId, targetUserId);
        if (permOpt.isPresent()) {
            DocumentPermission perm = permOpt.get();
            permissionRepository.delete(perm);

            Map<String, Object> details = new HashMap<>();
            details.put("revokedUser", perm.getUser().getEmail());
            auditLogService.logEvent(requester, requester.getEmail(), AuditAction.REVOKE, documentId, clientIp, AuditStatus.SUCCESS, details);
        }
    }

    @Transactional(readOnly = true)
    public List<PermissionResponse> getDocumentPermissions(String documentId, User requester, String clientIp) {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new IllegalArgumentException("Document not found: " + documentId));

        if (!document.getOwner().getId().equals(requester.getId()) && requester.getRole() != Role.ADMIN) {
            Map<String, Object> details = new HashMap<>();
            details.put("reason", "Unauthorized attempt to view ACL table of document");
            auditLogService.logEvent(requester, requester.getEmail(), AuditAction.ACCESS_DENIED, documentId, clientIp, AuditStatus.FAILURE, details);
            throw new AccessDeniedException("Unauthorized to inspect document permissions.");
        }

        List<DocumentPermission> perms = permissionRepository.findByDocumentId(documentId);
        List<PermissionResponse> list = new ArrayList<>();
        for (DocumentPermission p : perms) {
            list.add(toPermissionResponse(p));
        }
        return list;
    }

    public PermissionResponse toPermissionResponse(DocumentPermission p) {
        PermissionResponse resp = new PermissionResponse();
        resp.setId(p.getId());
        resp.setDocumentId(p.getDocument().getId());
        resp.setUserId(p.getUser().getId());
        resp.setUserEmail(p.getUser().getEmail());
        resp.setUserFullName(p.getUser().getFullName());
        resp.setPermissionLevel(p.getPermissionLevel());
        resp.setMaxViews(p.getMaxViews());
        resp.setViewsCount(p.getViewsCount());
        resp.setExpiresAt(p.getExpiresAt());
        resp.setGrantedByEmail(p.getGrantedBy() != null ? p.getGrantedBy().getEmail() : null);
        resp.setGrantedAt(p.getGrantedAt());
        return resp;
    }
}

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
    private final AuditSnapshotService auditSnapshotService;

    public PermissionService(DocumentPermissionRepository permissionRepository,
                             DocumentRepository documentRepository,
                             UserRepository userRepository,
                             AuditLogService auditLogService,
                             AuditSnapshotService auditSnapshotService) {
        this.permissionRepository = permissionRepository;
        this.documentRepository = documentRepository;
        this.userRepository = userRepository;
        this.auditLogService = auditLogService;
        this.auditSnapshotService = auditSnapshotService;
    }

    /**
     * Determines the effective permission of a user on a document: "OWNER", "EDIT", "READ", or null.
     * Enforces Burn-After-Reading limits and expiration.
     *
     * <p>Resolution is identity-neutral for the two vault roles: {@code OWNER} and {@code VIEWER}
     * are evaluated by exactly the same rules, so a viewer who owns a document governs it and an
     * owner who receives a grant consumes it like anyone else. Only the document's owner, an
     * active ACL grant and an administrator override produce access.</p>
     *
     * <p>An {@code ADMIN} keeps an unconditional override, but an <b>explicit</b> grant held by that
     * administrator still governs its own budget: a burn-after-reading link handed to an admin has
     * to burn like any other, otherwise the recipient's share is silently unlimited and the owner's
     * "views left" counter never moves.</p>
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

        Optional<DocumentPermission> grantOpt =
                permissionRepository.findByDocumentIdAndUserId(document.getId(), user.getId());

        // 2. Administrators hold an override that is independent of the document ACL. Without this
        //    branch the real-time guard below would reject every admin action, and the only way to
        //    keep the console usable would be to trust the role cached in the caller's token.
        //    The override does not extend to the accounting of their own share, though: a grant
        //    they were explicitly given is consumed exactly as it would be for a viewer.
        if (user.getRole() != null && user.getRole().isAdministrator()) {
            grantOpt.ifPresent(grant -> {
                if (grant.getExpiresAt() != null && Instant.now().isAfter(grant.getExpiresAt())) {
                    burnGrant(document, user, grant, clientIp,
                            "Burn-After-Reading: Permission expired at " + grant.getExpiresAt());
                } else if (isReadOperation) {
                    consumeOneView(document, user, grant, clientIp);
                }
            });
            return "ADMIN";
        }

        // 3. Check document permissions
        if (grantOpt.isEmpty()) {
            Map<String, Object> details = new HashMap<>();
            details.put("reason", "IDOR Prevention: User has no explicit ACL grant for document");
            details.put("attemptedDocOwner", document.getOwner().getEmail());
            auditLogService.logEvent(user, user.getEmail(), AuditAction.ACCESS_DENIED, document.getId(), clientIp, AuditStatus.FAILURE, details);
            throw new AccessDeniedException("Access Denied: You do not have permission to access this document.");
        }

        DocumentPermission permission = grantOpt.get();

        // 4. Check time-based expiration
        if (permission.getExpiresAt() != null && Instant.now().isAfter(permission.getExpiresAt())) {
            String reason = "Burn-After-Reading: Permission expired at " + permission.getExpiresAt();
            burnGrant(document, user, permission, clientIp, reason);
            Map<String, Object> details = new HashMap<>();
            details.put("reason", reason);
            auditLogService.logEvent(user, user.getEmail(), AuditAction.ACCESS_DENIED, document.getId(), clientIp, AuditStatus.FAILURE, details);
            throw new AccessDeniedException("Access Denied: This link has expired.");
        }

        // 5. Check max views (Burn-After-Reading)
        if (permission.getMaxViews() != null && permission.getViewsCount() >= permission.getMaxViews()) {
            String reason = "Burn-After-Reading: Max view count exceeded (" + permission.getMaxViews() + ")";
            burnGrant(document, user, permission, clientIp, reason);
            Map<String, Object> details = new HashMap<>();
            details.put("reason", reason);
            auditLogService.logEvent(user, user.getEmail(), AuditAction.ACCESS_DENIED, document.getId(), clientIp, AuditStatus.FAILURE, details);
            throw new AccessDeniedException("Access Denied: Burn-after-reading view limit reached.");
        }

        // 6. If this is a read operation, increment view counter
        if (isReadOperation) {
            consumeOneView(document, user, permission, clientIp);
        }

        return permission.getPermissionLevel().name();
    }

    /**
     * Records one permitted view and finalises the grant when the budget is spent. Unlimited
     * grants keep a plain counter so the owner's dashboard can still show how often a document
     * was opened.
     */
    private void consumeOneView(Document document, User user, DocumentPermission permission, String clientIp) {
        permission.setViewsCount(permission.getViewsCount() + 1);
        if (permission.getMaxViews() != null && permission.getViewsCount() >= permission.getMaxViews()) {
            burnGrant(document, user, permission, clientIp,
                    "Burn-After-Reading: Document consumed final permitted view, permission burned.");
        } else {
            permissionRepository.save(permission);
        }
    }

    /** Deletes a grant and writes the REVOKE row carrying its last known policy state. */
    private void burnGrant(Document document, User user, DocumentPermission permission, String clientIp, String reason) {
        Map<String, Object> burnedState = auditSnapshotService.permissionSnapshot(permission);
        permissionRepository.delete(permission);
        Map<String, Object> details = new HashMap<>();
        details.put("reason", reason);
        auditLogService.logEvent(user, user.getEmail(), AuditAction.REVOKE, document.getId(), clientIp,
                AuditStatus.SUCCESS, details, burnedState, null);
    }

    /**
     * Authoritative, per-transaction authorization gate for the two highest-risk document
     * operations: byte streaming ({@code GET /{id}/download}) and mutation ({@code PUT /{id}}).
     *
     * <p>A JWT proves <em>who</em> is calling; it never proves what that identity may still
     * touch. The token is minted at login and can outlive a revocation by hours, so this method
     * ignores every cached claim and answers the question from the database on every single
     * transaction:</p>
     *
     * <ol>
     *   <li>re-read the caller's account so a demotion/deactivation applies immediately;</li>
     *   <li>owner of the document?</li>
     *   <li>{@code ADMIN}?</li>
     *   <li>an <b>active</b> (unexpired, unburned) {@code shared_permissions} row at the required
     *       level?</li>
     * </ol>
     *
     * <p>Any other outcome is a {@code 403} raised <b>before</b> a byte is read from disk or a
     * field is mutated, and it is written to the immutable trail as {@code ACCESS_DENIED}.</p>
     *
     * @param required minimum level that satisfies the operation ({@code READ} for streaming,
     *                 {@code EDIT} for mutation)
     * @return the effective role: {@code OWNER}, {@code ADMIN}, {@code EDIT} or {@code READ}
     * @throws AccessDeniedException (403) when no live grant exists
     */
    @Transactional
    public String requireLiveAccess(Document document, User user, PermissionLevel required, String clientIp) {
        if (document == null || user == null) {
            throw new AccessDeniedException("Unauthorized: missing user or document context.");
        }

        PermissionLevel requiredLevel = required != null ? required : PermissionLevel.READ;

        // 1. Real-time identity check. The role on the caller's object was resolved when their
        //    token was presented; re-reading the row is what makes a role change immediate.
        User liveUser = userRepository.findById(user.getId()).orElse(null);
        if (liveUser == null) {
            throw denyLiveAccess(user.getEmail(), document, requiredLevel, clientIp,
                    "Account no longer exists");
        }

        // 2. Owner: unconditional.
        if (document.getOwner().getId().equals(liveUser.getId())) {
            return "OWNER";
        }

        // 3. ADMIN override, based on the role stored in the database right now.
        if (liveUser.getRole() != null && liveUser.getRole().isAdministrator()) {
            return "ADMIN";
        }

        // 4. Live ACL lookup. Expired grants and exhausted burn-after-reading budgets do not
        //    match this query, so a revoked recipient is denied on their very next request.
        Optional<DocumentPermission> active = permissionRepository
                .findActiveByDocumentIdAndUserId(document.getId(), liveUser.getId(), Instant.now());

        if (active.isEmpty()) {
            throw denyLiveAccess(liveUser.getEmail(), document, requiredLevel, clientIp,
                    describeMissingGrant(document.getId(), liveUser.getId()));
        }

        DocumentPermission permission = active.get();
        String granted = permission.getPermissionLevel() != null
                ? permission.getPermissionLevel().name()
                : PermissionLevel.READ.name();

        if (requiredLevel == PermissionLevel.EDIT && !PermissionLevel.EDIT.name().equals(granted)) {
            throw denyLiveAccess(liveUser.getEmail(), document, requiredLevel, clientIp,
                    "Live grant is " + granted + ", which does not authorise " + requiredLevel.name());
        }

        return granted;
    }

    /** Explains <em>why</em> no active grant was found, without leaking the owner's identity. */
    private String describeMissingGrant(String documentId, String userId) {
        Optional<DocumentPermission> stale = permissionRepository.findByDocumentIdAndUserId(documentId, userId);
        if (stale.isEmpty()) {
            return "No shared_permissions grant exists for this account";
        }
        DocumentPermission revoked = stale.get();
        if (revoked.getExpiresAt() != null && Instant.now().isAfter(revoked.getExpiresAt())) {
            return "Grant revoked: the shared link expired at " + revoked.getExpiresAt();
        }
        if (revoked.getMaxViews() != null && revoked.getViewsCount() >= revoked.getMaxViews()) {
            return "Grant revoked: the burn-after-reading view budget (" + revoked.getMaxViews()
                    + ") is exhausted";
        }
        return "Grant revoked: no active shared_permissions row remains";
    }

    /**
     * Writes the denial to the immutable trail (its own transaction, so the row survives the
     * caller's rollback) and returns the 403 to throw.
     */
    private AccessDeniedException denyLiveAccess(String userEmail, Document document, PermissionLevel required,
                                                 String clientIp, String reason) {
        Map<String, Object> details = new HashMap<>();
        details.put("reason", "Real-time ACL check failed before the operation was processed");
        details.put("detail", reason);
        details.put("requiredPermission", required.name());
        details.put("targetDocumentId", document.getId());
        details.put("checkMode", "PER_TRANSACTION_DATABASE");
        auditLogService.logEvent(null, userEmail, AuditAction.ACCESS_DENIED, document.getId(), clientIp,
                AuditStatus.FAILURE, details);

        return new AccessDeniedException(
                "Access Denied: " + reason + ". Re-request access from the document owner.");
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

        // Snapshot the policy before the mutation so the grant/update can be replayed field by field.
        Map<String, Object> preState = permission.getId() != null
                ? auditSnapshotService.permissionSnapshot(permission)
                : null;

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
        Map<String, Object> postState = auditSnapshotService.permissionSnapshot(saved);

        Map<String, Object> details = new HashMap<>();
        details.put("recipient", recipient.getEmail());
        details.put("permissionLevel", saved.getPermissionLevel().name());
        details.put("maxViews", saved.getMaxViews());
        details.put("expiresAt", saved.getExpiresAt() != null ? saved.getExpiresAt().toString() : null);
        details.put("policyAction", preState == null ? "CREATE" : "UPDATE");
        auditLogService.logEvent(granter, granter.getEmail(), AuditAction.GRANT, documentId, clientIp, AuditStatus.SUCCESS, details, preState, postState);

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
            Map<String, Object> preState = auditSnapshotService.permissionSnapshot(perm);
            permissionRepository.delete(perm);

            Map<String, Object> details = new HashMap<>();
            details.put("revokedUser", perm.getUser().getEmail());
            details.put("revokedPermissionLevel",
                    perm.getPermissionLevel() != null ? perm.getPermissionLevel().name() : null);
            auditLogService.logEvent(requester, requester.getEmail(), AuditAction.REVOKE, documentId, clientIp, AuditStatus.SUCCESS, details, preState, null);
        }
    }

    @Transactional(readOnly = true)
    public List<PermissionResponse> getDocumentPermissions(String documentId, User requester, String clientIp) {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new IllegalArgumentException("Document not found: " + documentId));

        if (!document.getOwner().getId().equals(requester.getId())
                && (requester.getRole() == null || !requester.getRole().isAdministrator())) {
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

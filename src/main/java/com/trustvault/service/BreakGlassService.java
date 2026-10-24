package com.trustvault.service;

import com.trustvault.dto.BreakGlassRequest;
import com.trustvault.dto.BreakGlassResponse;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditLog;
import com.trustvault.entity.AuditStatus;
import com.trustvault.entity.Document;
import com.trustvault.entity.User;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.UserRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * Break-Glass emergency access.
 *
 * <p>An administrator already holds an ACL override in {@link PermissionService}; what an incident
 * review needs on top of that is <em>intent</em>. This service records the declaration - who, which
 * document, and why - as an immutable {@code BREAK_GLASS_ACCESS} row before the document is opened,
 * so the emergency read can never be mistaken for routine browsing.</p>
 *
 * <p>The declaration is evidence, not authorization: it neither widens the administrator's rights
 * nor replaces the live face gate. The subsequent download still passes {@code requireLiveAccess},
 * {@code FaceGateService} and the burn-after-reading accounting, and is written to the trail as its
 * own {@code READ} row.</p>
 */
@Service
public class BreakGlassService {

    private final UserRepository userRepository;
    private final DocumentRepository documentRepository;
    private final AuditLogService auditLogService;
    private final AuditSnapshotService auditSnapshotService;

    public BreakGlassService(UserRepository userRepository,
                             DocumentRepository documentRepository,
                             AuditLogService auditLogService,
                             AuditSnapshotService auditSnapshotService) {
        this.userRepository = userRepository;
        this.documentRepository = documentRepository;
        this.auditLogService = auditLogService;
        this.auditSnapshotService = auditSnapshotService;
    }

    /**
     * Declares an emergency access event and returns the metadata needed to continue it.
     *
     * @throws AccessDeniedException   when the caller is not an administrator
     * @throws NoSuchElementException  when the document id does not exist (404)
     */
    @Transactional
    public BreakGlassResponse declare(BreakGlassRequest request, String adminUserId, String clientIp) {
        User admin = userRepository.findById(adminUserId)
                .orElseThrow(() -> new NoSuchElementException("Administrator not found: " + adminUserId));

        // Defence in depth: the route is already ROLE_ADMIN, but the check is repeated against the
        // live database row so a role change applied seconds ago cannot be bypassed by an old token.
        if (admin.getRole() == null || !admin.getRole().isAdministrator()) {
            throw new AccessDeniedException("Break-glass access is restricted to administrators.");
        }

        Document document = documentRepository.findById(request.getDocumentId())
                .orElseThrow(() -> new NoSuchElementException(
                        "Document not found: " + request.getDocumentId()));

        String reason = request.getReason() == null ? "" : request.getReason().trim();
        Instant declaredAt = Instant.now();

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("mode", "EMERGENCY_BREAK_GLASS");
        details.put("reason", reason);
        details.put("documentTitle", document.getTitle());
        details.put("documentCategory", document.getCategory());
        details.put("ownerEmail", document.getOwner() != null ? document.getOwner().getEmail() : null);
        details.put("scope", "READ_AND_DOWNLOAD");
        details.put("requiresLiveFace", true);
        details.put("declaredAt", declaredAt.toString());

        // The document snapshot is captured as pre_state so the forensic inspector can show exactly
        // which resource was in scope at the moment the emergency was declared.
        AuditLog evidence = auditLogService.logEvent(admin, admin.getEmail(), AuditAction.BREAK_GLASS_ACCESS,
                document.getId(), clientIp, AuditStatus.SUCCESS, details,
                auditSnapshotService.documentSnapshot(document), null);

        BreakGlassResponse response = new BreakGlassResponse();
        response.setDocumentId(document.getId());
        response.setTitle(document.getTitle());
        response.setCategory(document.getCategory());
        response.setOwnerEmail(document.getOwner() != null ? document.getOwner().getEmail() : null);
        response.setReason(reason);
        response.setDeclaredAt(declaredAt);
        response.setAuditLogId(evidence.getId());
        response.setRequiresLiveFace(true);
        response.setNextStep("Run the FaceID stream for this document. The declaration is on the "
                + "immutable trail; the read is audited separately.");
        return response;
    }
}

package com.trustvault.service;

import com.trustvault.face.FaceProof;
import com.trustvault.dto.DocumentResponse;
import com.trustvault.entity.*;
import com.trustvault.repository.DocumentPermissionRepository;
import com.trustvault.repository.DocumentRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.Instant;
import java.util.*;

@Service
public class DocumentService {

    private final DocumentRepository documentRepository;
    private final DocumentPermissionRepository permissionRepository;
    private final FileStorageService fileStorageService;
    private final PermissionService permissionService;
    private final AuditLogService auditLogService;
    private final FaceGateService faceGateService;
    private final AuditSnapshotService auditSnapshotService;

    public DocumentService(DocumentRepository documentRepository,
                           DocumentPermissionRepository permissionRepository,
                           FileStorageService fileStorageService,
                           PermissionService permissionService,
                           AuditLogService auditLogService,
                           FaceGateService faceGateService,
                           AuditSnapshotService auditSnapshotService) {
        this.documentRepository = documentRepository;
        this.permissionRepository = permissionRepository;
        this.fileStorageService = fileStorageService;
        this.permissionService = permissionService;
        this.auditLogService = auditLogService;
        this.faceGateService = faceGateService;
        this.auditSnapshotService = auditSnapshotService;
    }

    @Transactional
    public DocumentResponse uploadDocument(String title, String category, MultipartFile file, User user, String clientIp) {
        if (title == null || title.isBlank()) {
            title = file.getOriginalFilename();
        }
        if (category == null || category.isBlank()) {
            category = "General";
        }

        String storedPath = fileStorageService.storeFile(file);

        Document document = new Document();
        document.setId(UUID.randomUUID().toString());
        document.setTitle(title.trim());
        document.setFilePath(storedPath);
        document.setFileSizeBytes(file.getSize());
        document.setMimeType(file.getContentType() != null ? file.getContentType() : "application/octet-stream");
        document.setCategory(category.trim());
        document.setOwner(user);

        Document saved = documentRepository.save(document);

        Map<String, Object> details = new HashMap<>();
        details.put("title", saved.getTitle());
        details.put("sizeBytes", saved.getFileSizeBytes());
        details.put("mimeType", saved.getMimeType());
        details.put("category", saved.getCategory());
        auditLogService.logEvent(user, user.getEmail(), AuditAction.UPLOAD, saved.getId(), clientIp, AuditStatus.SUCCESS, details, null, auditSnapshotService.documentSnapshot(saved));

        return toDocumentResponse(saved, "OWNER", null);
    }

    @Transactional
    public DocumentResponse getDocument(String documentId, User user, String clientIp) {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> {
                    Map<String, Object> details = new HashMap<>();
                    details.put("reason", "IDOR Protection: Document not found");
                    auditLogService.logEvent(user, user != null ? user.getEmail() : "anonymous", AuditAction.ACCESS_DENIED, documentId, clientIp, AuditStatus.FAILURE, details);
                    return new AccessDeniedException("Access Denied: Document not found or unauthorized.");
                });

        String effectiveRole = permissionService.evaluateAndConsumeAccess(document, user, false, clientIp);

        Optional<DocumentPermission> permOpt = permissionRepository.findByDocumentIdAndUserId(documentId, user.getId());

        Map<String, Object> details = new HashMap<>();
        details.put("title", document.getTitle());
        details.put("effectiveRole", effectiveRole);
        auditLogService.logEvent(user, user.getEmail(), AuditAction.READ, document.getId(), clientIp, AuditStatus.SUCCESS, details);

        return toDocumentResponse(document, effectiveRole, permOpt.orElse(null));
    }

    public static class DownloadPayload {
        private final byte[] bytes;
        private final String filename;
        private final String mimeType;

        public DownloadPayload(byte[] bytes, String filename, String mimeType) {
            this.bytes = bytes;
            this.filename = filename;
            this.mimeType = mimeType;
        }

        public byte[] getBytes() { return bytes; }
        public String getFilename() { return filename; }
        public String getMimeType() { return mimeType; }
    }

    @Transactional
    public DownloadPayload downloadDocument(String documentId, FaceProof proof, User user, String clientIp) {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> {
                    Map<String, Object> details = new HashMap<>();
                    details.put("reason", "IDOR Protection: Document not found for download");
                    auditLogService.logEvent(user, user != null ? user.getEmail() : "anonymous", AuditAction.ACCESS_DENIED, documentId, clientIp, AuditStatus.FAILURE, details);
                    return new AccessDeniedException("Access Denied: Document not found or unauthorized.");
                });

        // 1. Real-time authorization, executed before anything else. A JWT claim is only evidence
        //    of identity: this per-transaction query is the authority on whether the caller may
        //    still touch the document. A revoked grant is rejected here, before the face gate runs
        //    and before a single byte is read from disk.
        permissionService.requireLiveAccess(document, user, PermissionLevel.READ, clientIp);

        // 2. Action-time face gate. Runs before a burn-after-reading view is consumed so a
        //    failed match never costs the recipient one of their permitted views.
        faceGateService.enforce(user, documentId, FaceEnrollmentService.ACTION_DOWNLOAD, proof, clientIp);

        // 3. Evaluate user permission & Burn-After-Reading consumption
        permissionService.evaluateAndConsumeAccess(document, user, true, clientIp);

        byte[] fileBytes = fileStorageService.loadFileBytes(document.getFilePath());

        Map<String, Object> details = new HashMap<>();
        details.put("action", "DOWNLOAD_STREAMED");
        details.put("title", document.getTitle());
        details.put("sizeBytes", document.getFileSizeBytes());
        auditLogService.logEvent(user, user.getEmail(), AuditAction.READ, document.getId(), clientIp, AuditStatus.SUCCESS, details);

        return new DownloadPayload(fileBytes, document.getTitle(), document.getMimeType());
    }

    @Transactional
    public DocumentResponse updateDocument(String documentId, String newTitle, String newCategory, FaceProof proof, User user, String clientIp) {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new AccessDeniedException("Access Denied: Document not found."));

        // Real-time authorization before any field is mutated: owner, live ADMIN, or an active
        // EDIT grant. READ-only recipients are rejected here with 403 and an ACCESS_DENIED row.
        String effectiveRole = permissionService.requireLiveAccess(document, user, PermissionLevel.EDIT, clientIp);
        if (!"OWNER".equals(effectiveRole) && !"EDIT".equals(effectiveRole) && !"ADMIN".equals(effectiveRole)) {
            Map<String, Object> details = new HashMap<>();
            details.put("reason", "User attempted to update document without EDIT/OWNER permission");
            auditLogService.logEvent(user, user.getEmail(), AuditAction.ACCESS_DENIED, documentId, clientIp, AuditStatus.FAILURE, details);
            throw new AccessDeniedException("Access Denied: You do not have permission to edit this document.");
        }

        // Action-time face gate for the sensitive EDIT action.
        faceGateService.enforce(user, documentId, FaceEnrollmentService.ACTION_EDIT, proof, clientIp);

        Map<String, Object> preState = auditSnapshotService.documentSnapshot(document);

        if (newTitle != null && !newTitle.isBlank()) {
            document.setTitle(newTitle.trim());
        }
        if (newCategory != null && !newCategory.isBlank()) {
            document.setCategory(newCategory.trim());
        }

        Document saved = documentRepository.save(document);

        Map<String, Object> details = new HashMap<>();
        details.put("updatedTitle", saved.getTitle());
        details.put("updatedCategory", saved.getCategory());
        auditLogService.logEvent(user, user.getEmail(), AuditAction.EDIT, documentId, clientIp, AuditStatus.SUCCESS, details, preState, auditSnapshotService.documentSnapshot(saved));

        return toDocumentResponse(saved, effectiveRole, null);
    }

    @Transactional
    public void deleteDocument(String documentId, User user, String clientIp) {
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> new AccessDeniedException("Access Denied: Document not found."));

        // Only Owner or Admin can delete
        if (!document.getOwner().getId().equals(user.getId()) && user.getRole() != Role.ADMIN) {
            Map<String, Object> details = new HashMap<>();
            details.put("reason", "IDOR Protection: Non-owner tried to delete document");
            auditLogService.logEvent(user, user.getEmail(), AuditAction.ACCESS_DENIED, documentId, clientIp, AuditStatus.FAILURE, details);
            throw new AccessDeniedException("Access Denied: Only the document owner can delete this document.");
        }

        fileStorageService.deleteFile(document.getFilePath());
        Map<String, Object> preState = auditSnapshotService.documentSnapshot(document);
        documentRepository.delete(document);

        Map<String, Object> details = new HashMap<>();
        details.put("deletedTitle", document.getTitle());
        details.put("deletedCategory", document.getCategory());
        auditLogService.logEvent(user, user.getEmail(), AuditAction.DELETE, documentId, clientIp, AuditStatus.SUCCESS, details, preState, null);
    }

    @Transactional(readOnly = true)
    public List<DocumentResponse> searchAndFilterDocuments(String title, String category, String ownerEmail,
                                                           Instant startDate, Instant endDate, User currentUser) {
        List<Document> allMatches = documentRepository.searchDocuments(
                (title != null && !title.isBlank()) ? title : null,
                (category != null && !category.isBlank()) ? category : null,
                (ownerEmail != null && !ownerEmail.isBlank()) ? ownerEmail : null,
                startDate,
                endDate
        );

        List<DocumentResponse> results = new ArrayList<>();
        Map<String, DocumentPermission> userPermsMap = new HashMap<>();
        List<DocumentPermission> userPerms = permissionRepository.findAllByRecipientId(currentUser.getId());
        for (DocumentPermission p : userPerms) {
            userPermsMap.put(p.getDocument().getId(), p);
        }

        for (Document doc : allMatches) {
            if (doc.getOwner().getId().equals(currentUser.getId())) {
                results.add(toDocumentResponse(doc, "OWNER", null));
            } else if (userPermsMap.containsKey(doc.getId())) {
                DocumentPermission p = userPermsMap.get(doc.getId());
                // Filter out already expired or burned-out permissions from visibility
                if (p.getExpiresAt() != null && Instant.now().isAfter(p.getExpiresAt())) {
                    continue;
                }
                if (p.getMaxViews() != null && p.getViewsCount() >= p.getMaxViews()) {
                    continue;
                }
                results.add(toDocumentResponse(doc, p.getPermissionLevel().name(), p));
            } else if (currentUser.getRole() == Role.ADMIN) {
                results.add(toDocumentResponse(doc, "ADMIN_VIEW", null));
            }
            // All other non-authorized documents are strictly excluded (No universal visibility)
        }

        return results;
    }

    @Transactional(readOnly = true)
    public List<DocumentResponse> getMyOwnedDocuments(User user) {
        List<Document> docs = documentRepository.findByOwnerId(user.getId());
        List<DocumentResponse> list = new ArrayList<>();
        for (Document d : docs) {
            list.add(toDocumentResponse(d, "OWNER", null));
        }
        return list;
    }

    @Transactional(readOnly = true)
    public List<DocumentResponse> getSharedWithMeDocuments(User user) {
        List<DocumentPermission> perms = permissionRepository.findAllByRecipientId(user.getId());
        List<DocumentResponse> list = new ArrayList<>();
        for (DocumentPermission p : perms) {
            if (p.getExpiresAt() != null && Instant.now().isAfter(p.getExpiresAt())) {
                continue;
            }
            if (p.getMaxViews() != null && p.getViewsCount() >= p.getMaxViews()) {
                continue;
            }
            list.add(toDocumentResponse(p.getDocument(), p.getPermissionLevel().name(), p));
        }
        return list;
    }

    private DocumentResponse toDocumentResponse(Document d, String effectiveRole, DocumentPermission p) {
        DocumentResponse resp = new DocumentResponse();
        resp.setId(d.getId());
        resp.setTitle(d.getTitle());
        resp.setFileSizeBytes(d.getFileSizeBytes());
        resp.setMimeType(d.getMimeType());
        resp.setCategory(d.getCategory());
        resp.setOwnerId(d.getOwner().getId());
        resp.setOwnerEmail(d.getOwner().getEmail());
        resp.setOwnerFullName(d.getOwner().getFullName());
        resp.setCreatedAt(d.getCreatedAt());
        resp.setUpdatedAt(d.getUpdatedAt());
        resp.setEffectivePermission(effectiveRole);

        if (p != null) {
            resp.setViewsCount(p.getViewsCount());
            resp.setMaxViews(p.getMaxViews());
            resp.setExpiresAt(p.getExpiresAt());
        }
        return resp;
    }
}

package com.trustvault.dto;

import java.time.Instant;

/**
 * Result of a declared break-glass event.
 *
 * <p>It carries what the administrator needs to continue the emergency read - the document
 * metadata and the id of the immutable evidence row - plus an explicit statement that the live
 * face gate still applies. A declaration never substitutes for biometric proof.</p>
 */
public class BreakGlassResponse {

    private String documentId;
    private String title;
    private String category;
    private String ownerEmail;
    private String reason;
    private Instant declaredAt;
    private String auditLogId;
    private boolean requiresLiveFace;
    private String nextStep;

    public String getDocumentId() {
        return documentId;
    }

    public void setDocumentId(String documentId) {
        this.documentId = documentId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getOwnerEmail() {
        return ownerEmail;
    }

    public void setOwnerEmail(String ownerEmail) {
        this.ownerEmail = ownerEmail;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public Instant getDeclaredAt() {
        return declaredAt;
    }

    public void setDeclaredAt(Instant declaredAt) {
        this.declaredAt = declaredAt;
    }

    public String getAuditLogId() {
        return auditLogId;
    }

    public void setAuditLogId(String auditLogId) {
        this.auditLogId = auditLogId;
    }

    public boolean isRequiresLiveFace() {
        return requiresLiveFace;
    }

    public void setRequiresLiveFace(boolean requiresLiveFace) {
        this.requiresLiveFace = requiresLiveFace;
    }

    public String getNextStep() {
        return nextStep;
    }

    public void setNextStep(String nextStep) {
        this.nextStep = nextStep;
    }
}

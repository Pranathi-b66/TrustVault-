package com.trustvault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Payload for {@code POST /api/admin/break-glass}.
 *
 * <p>A break-glass event is an administrator declaring, on the record, why they are about to open
 * a document they neither own nor hold a grant for. The reason is mandatory and is stored verbatim
 * on the {@code BREAK_GLASS_ACCESS} audit row, so an incident review can tell an emergency read
 * apart from routine administration.</p>
 */
public class BreakGlassRequest {

    @NotBlank(message = "documentId is required")
    private String documentId;

    @NotBlank(message = "a justification is required for emergency access")
    @Size(min = 10, max = 500, message = "reason must be between 10 and 500 characters")
    private String reason;

    public String getDocumentId() {
        return documentId;
    }

    public void setDocumentId(String documentId) {
        this.documentId = documentId;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }
}

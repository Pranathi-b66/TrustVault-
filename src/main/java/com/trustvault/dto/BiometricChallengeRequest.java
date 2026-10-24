package com.trustvault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request for a fresh FaceID challenge nonce, issued immediately before the webcam modal opens.
 * The challenge is bound to the caller, the document and the action it authorises.
 */
public class BiometricChallengeRequest {

    @NotBlank
    @Size(max = 36)
    private String documentId;

    @NotBlank
    @Size(max = 16)
    private String action;

    public String getDocumentId() {
        return documentId;
    }

    public void setDocumentId(String documentId) {
        this.documentId = documentId;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }
}

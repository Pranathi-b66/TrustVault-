package com.trustvault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Action-time face proof: the embedding captured from the webcam immediately before a
 * DOWNLOAD or EDIT.
 */
public class FaceVerificationRequest {

    @NotBlank
    @Size(max = 36)
    private String documentId;

    @NotBlank
    @Size(max = 16)
    private String action;

    @NotNull
    @Size(min = 16, max = 1024)
    private List<Double> descriptor;

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

    public List<Double> getDescriptor() {
        return descriptor;
    }

    public void setDescriptor(List<Double> descriptor) {
        this.descriptor = descriptor;
    }
}

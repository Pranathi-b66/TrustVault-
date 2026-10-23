package com.trustvault.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Enrollment payload: the TrustVault profile being bound to a live facial embedding.
 *
 * <p>{@code descriptor} is the 128-value vector produced by the browser's face-recognition
 * model. The server validates its dimension and range, seals it at rest, and rejects a face
 * already bound to another identity.</p>
 */
public class FaceRegistrationRequest {

    @NotBlank
    @Email
    @Size(max = 255)
    private String email;

    @NotNull
    @Size(min = 16, max = 1024)
    private List<Double> descriptor;

    @Size(max = 120)
    private String deviceLabel;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public List<Double> getDescriptor() {
        return descriptor;
    }

    public void setDescriptor(List<Double> descriptor) {
        this.descriptor = descriptor;
    }

    public String getDeviceLabel() {
        return deviceLabel;
    }

    public void setDeviceLabel(String deviceLabel) {
        this.deviceLabel = deviceLabel;
    }
}

package com.trustvault.dto;

import com.trustvault.entity.Role;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Sign-up payload. The webcam face capture is mandatory: the account and its exclusive
 * face descriptor are created together, so neither can exist without the other.
 */
public class RegisterRequest {
    private String email;
    private String password;
    private String fullName;
    private Role role;

    /** Live facial embedding (128 values) captured by the browser's face-recognition model. */
    @Size(min = 16, max = 1024)
    private List<Double> faceDescriptor;

    /** Free-form camera label kept for the enrollment audit trail. */
    @Size(max = 120)
    private String deviceLabel;

    public RegisterRequest() {}

    public RegisterRequest(String email, String password, String fullName, Role role) {
        this.email = email;
        this.password = password;
        this.fullName = fullName;
        this.role = role;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public List<Double> getFaceDescriptor() {
        return faceDescriptor;
    }

    public void setFaceDescriptor(List<Double> faceDescriptor) {
        this.faceDescriptor = faceDescriptor;
    }

    public String getDeviceLabel() {
        return deviceLabel;
    }

    public void setDeviceLabel(String deviceLabel) {
        this.deviceLabel = deviceLabel;
    }
}

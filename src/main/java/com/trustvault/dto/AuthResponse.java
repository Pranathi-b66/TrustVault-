package com.trustvault.dto;

import com.trustvault.entity.Role;
import com.trustvault.entity.UserStatus;

public class AuthResponse {
    private String token;
    private String userId;
    private String email;
    private String fullName;
    private Role role;
    private UserStatus status;

    public AuthResponse() {}

    public AuthResponse(String token, String userId, String email, String fullName, Role role, UserStatus status) {
        this.token = token;
        this.userId = userId;
        this.email = email;
        this.fullName = fullName;
        this.role = role;
        this.status = status;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
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

    public UserStatus getStatus() {
        return status;
    }

    public void setStatus(UserStatus status) {
        this.status = status;
    }
}

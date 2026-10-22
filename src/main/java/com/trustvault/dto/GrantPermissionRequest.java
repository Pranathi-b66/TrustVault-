package com.trustvault.dto;

import com.trustvault.entity.PermissionLevel;

import java.time.Instant;

public class GrantPermissionRequest {
    private String userEmail;
    private PermissionLevel permissionLevel;
    private Integer maxViews;
    private Instant expiresAt;

    public GrantPermissionRequest() {}

    public GrantPermissionRequest(String userEmail, PermissionLevel permissionLevel, Integer maxViews, Instant expiresAt) {
        this.userEmail = userEmail;
        this.permissionLevel = permissionLevel;
        this.maxViews = maxViews;
        this.expiresAt = expiresAt;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public PermissionLevel getPermissionLevel() {
        return permissionLevel;
    }

    public void setPermissionLevel(PermissionLevel permissionLevel) {
        this.permissionLevel = permissionLevel;
    }

    public Integer getMaxViews() {
        return maxViews;
    }

    public void setMaxViews(Integer maxViews) {
        this.maxViews = maxViews;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }
}

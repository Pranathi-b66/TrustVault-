package com.trustvault.dto;

import com.trustvault.entity.Role;
import jakarta.validation.constraints.NotNull;

/**
 * Payload for {@code PUT /api/admin/users/{id}/role}.
 */
public class RoleUpdateRequest {

    @NotNull(message = "role is required")
    private Role role;

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }
}

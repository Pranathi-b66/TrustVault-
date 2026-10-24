package com.trustvault.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Payload for {@code POST /api/admin/system/lockdown}.
 * A reason is mandatory when engaging the lockdown and is stored on the
 * {@code SYSTEM_LOCKDOWN_TRIGGERED} audit row.
 */
public class LockdownRequest {

    @NotNull(message = "enabled flag is required")
    private Boolean enabled;

    @Size(max = 500, message = "reason must not exceed 500 characters")
    private String reason;

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }
}

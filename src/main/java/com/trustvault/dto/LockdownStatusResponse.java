package com.trustvault.dto;

import com.trustvault.service.SystemLockdownService;

import java.time.Instant;

/**
 * Administrative view of the global kill switch. Only reachable by ADMINS; this is the object
 * that carries the incident reason that the public 503 body deliberately omits.
 */
public class LockdownStatusResponse {

    private boolean enabled;
    private String state;
    private String reason;
    private String triggeredBy;
    private Instant triggeredAt;

    public LockdownStatusResponse() {
    }

    public LockdownStatusResponse(boolean enabled, String state, String reason,
                                  String triggeredBy, Instant triggeredAt) {
        this.enabled = enabled;
        this.state = state;
        this.reason = reason;
        this.triggeredBy = triggeredBy;
        this.triggeredAt = triggeredAt;
    }

    public static LockdownStatusResponse from(SystemLockdownService.LockdownStatus status) {
        return new LockdownStatusResponse(
                status.enabled(),
                status.enabled() ? "LOCKED_DOWN" : "OPERATIONAL",
                status.reason(),
                status.triggeredBy(),
                status.triggeredAt()
        );
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getTriggeredBy() {
        return triggeredBy;
    }

    public void setTriggeredBy(String triggeredBy) {
        this.triggeredBy = triggeredBy;
    }

    public Instant getTriggeredAt() {
        return triggeredAt;
    }

    public void setTriggeredAt(Instant triggeredAt) {
        this.triggeredAt = triggeredAt;
    }
}

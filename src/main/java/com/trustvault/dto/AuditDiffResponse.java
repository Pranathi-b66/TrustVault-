package com.trustvault.dto;

import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditStatus;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Structured "Action Replay" payload: the audit envelope, the raw before/after snapshots and the
 * field-level delta that the admin console renders in the forensic inspector.
 */
public class AuditDiffResponse {

    private String auditId;
    private AuditAction action;
    private AuditStatus status;
    private String actorEmail;
    private String actorUserId;
    private String ipAddress;
    private Instant timestamp;
    private String resourceType;
    private String resourceId;
    private String details;

    private boolean hasSnapshot;
    private Map<String, Object> preState;
    private Map<String, Object> postState;
    private List<AuditDiffEntry> changes;
    private Map<String, Integer> summary;

    public AuditDiffResponse() {
    }

    public String getAuditId() {
        return auditId;
    }

    public void setAuditId(String auditId) {
        this.auditId = auditId;
    }

    public AuditAction getAction() {
        return action;
    }

    public void setAction(AuditAction action) {
        this.action = action;
    }

    public AuditStatus getStatus() {
        return status;
    }

    public void setStatus(AuditStatus status) {
        this.status = status;
    }

    public String getActorEmail() {
        return actorEmail;
    }

    public void setActorEmail(String actorEmail) {
        this.actorEmail = actorEmail;
    }

    public String getActorUserId() {
        return actorUserId;
    }

    public void setActorUserId(String actorUserId) {
        this.actorUserId = actorUserId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public String getResourceType() {
        return resourceType;
    }

    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public boolean isHasSnapshot() {
        return hasSnapshot;
    }

    public void setHasSnapshot(boolean hasSnapshot) {
        this.hasSnapshot = hasSnapshot;
    }

    public Map<String, Object> getPreState() {
        return preState;
    }

    public void setPreState(Map<String, Object> preState) {
        this.preState = preState;
    }

    public Map<String, Object> getPostState() {
        return postState;
    }

    public void setPostState(Map<String, Object> postState) {
        this.postState = postState;
    }

    public List<AuditDiffEntry> getChanges() {
        return changes;
    }

    public void setChanges(List<AuditDiffEntry> changes) {
        this.changes = changes;
    }

    public Map<String, Integer> getSummary() {
        return summary;
    }

    public void setSummary(Map<String, Integer> summary) {
        this.summary = summary;
    }
}

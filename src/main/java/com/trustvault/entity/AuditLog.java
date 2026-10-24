package com.trustvault.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import org.hibernate.annotations.Immutable;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;

@Entity
@Table(name = "audit_logs")
@Immutable
public class AuditLog {

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    /**
     * Actor association, loaded only where server-side code needs the id (for example the replay
     * DTO). It is deliberately excluded from JSON: the audit trail is served straight from this
     * entity, and serializing the association would leak the actor's password hash and trigger a
     * per-row lazy load. Consumers use {@code userEmail}, which is denormalized on the row.
     */
    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "user_email", length = 255, nullable = false)
    private String userEmail;

    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false)
    private AuditAction action;

    @Column(name = "document_id", length = 36)
    private String documentId;

    @Column(name = "ip_address", length = 45, nullable = false)
    private String ipAddress;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private AuditStatus status;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "details", columnDefinition = "json")
    private String details;

    /**
     * Forensic snapshot of the resource immediately before an administrative mutation.
     * Serialized JSON; never contains credentials, password hashes or biometric data.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "pre_state", columnDefinition = "json")
    private String preState;

    /**
     * Forensic snapshot of the resource immediately after the mutation. {@code null} when the
     * mutation destroyed the resource (deletion) or when the action is not state-bearing.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "post_state", columnDefinition = "json")
    private String postState;

    @Column(name = "timestamp", nullable = false, updatable = false)
    private Instant timestamp;

    public AuditLog() {
    }

    public AuditLog(String id, User user, String userEmail, AuditAction action, String documentId,
                    String ipAddress, AuditStatus status, String details, Instant timestamp) {
        this(id, user, userEmail, action, documentId, ipAddress, status, details, null, null, timestamp);
    }

    public AuditLog(String id, User user, String userEmail, AuditAction action, String documentId,
                    String ipAddress, AuditStatus status, String details, String preState, String postState,
                    Instant timestamp) {
        this.id = id;
        this.user = user;
        this.userEmail = userEmail;
        this.action = action;
        this.documentId = documentId;
        this.ipAddress = ipAddress;
        this.status = status;
        this.details = details;
        this.preState = preState;
        this.postState = postState;
        this.timestamp = timestamp != null ? timestamp : Instant.now();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public AuditAction getAction() {
        return action;
    }

    public void setAction(AuditAction action) {
        this.action = action;
    }

    public String getDocumentId() {
        return documentId;
    }

    public void setDocumentId(String documentId) {
        this.documentId = documentId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public AuditStatus getStatus() {
        return status;
    }

    public void setStatus(AuditStatus status) {
        this.status = status;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public String getPreState() {
        return preState;
    }

    public void setPreState(String preState) {
        this.preState = preState;
    }

    public String getPostState() {
        return postState;
    }

    public void setPostState(String postState) {
        this.postState = postState;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }
}

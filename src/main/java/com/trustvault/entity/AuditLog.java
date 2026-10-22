package com.trustvault.entity;

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

    @Column(name = "timestamp", nullable = false, updatable = false)
    private Instant timestamp;

    public AuditLog() {
    }

    public AuditLog(String id, User user, String userEmail, AuditAction action, String documentId,
                    String ipAddress, AuditStatus status, String details, Instant timestamp) {
        this.id = id;
        this.user = user;
        this.userEmail = userEmail;
        this.action = action;
        this.documentId = documentId;
        this.ipAddress = ipAddress;
        this.status = status;
        this.details = details;
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

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }
}

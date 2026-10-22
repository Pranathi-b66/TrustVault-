package com.trustvault.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

@Entity
@Table(name = "document_permissions", uniqueConstraints = {
    @UniqueConstraint(name = "uq_doc_user", columnNames = {"document_id", "user_id"})
})
public class DocumentPermission {

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "document_id", nullable = false)
    private Document document;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "permission_level", nullable = false)
    private PermissionLevel permissionLevel;

    @Column(name = "max_views")
    private Integer maxViews;

    @Column(name = "views_count", nullable = false)
    private Integer viewsCount = 0;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "granted_by")
    private User grantedBy;

    @CreationTimestamp
    @Column(name = "granted_at", nullable = false, updatable = false)
    private Instant grantedAt;

    public DocumentPermission() {
    }

    public DocumentPermission(String id, Document document, User user, PermissionLevel permissionLevel,
                              Integer maxViews, Integer viewsCount, Instant expiresAt, User grantedBy) {
        this.id = id;
        this.document = document;
        this.user = user;
        this.permissionLevel = permissionLevel;
        this.maxViews = maxViews;
        this.viewsCount = viewsCount != null ? viewsCount : 0;
        this.expiresAt = expiresAt;
        this.grantedBy = grantedBy;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Document getDocument() {
        return document;
    }

    public void setDocument(Document document) {
        this.document = document;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
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

    public Integer getViewsCount() {
        return viewsCount;
    }

    public void setViewsCount(Integer viewsCount) {
        this.viewsCount = viewsCount;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public User getGrantedBy() {
        return grantedBy;
    }

    public void setGrantedBy(User grantedBy) {
        this.grantedBy = grantedBy;
    }

    public Instant getGrantedAt() {
        return grantedAt;
    }

    public void setGrantedAt(Instant grantedAt) {
        this.grantedAt = grantedAt;
    }
}

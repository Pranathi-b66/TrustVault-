package com.trustvault.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

@Entity
@Table(name = "user_credentials")
public class UserCredential {

    @Id
    @Column(name = "credential_id", length = 255, nullable = false)
    private String credentialId;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Lob
    @Column(name = "public_key", nullable = false, columnDefinition = "text")
    private String publicKey;

    @Column(name = "sign_count", nullable = false)
    private Long signCount = 0L;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public UserCredential() {
    }

    public UserCredential(String credentialId, User user, String publicKey, Long signCount) {
        this.credentialId = credentialId;
        this.user = user;
        this.publicKey = publicKey;
        this.signCount = signCount != null ? signCount : 0L;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public Long getSignCount() {
        return signCount;
    }

    public void setSignCount(Long signCount) {
        this.signCount = signCount;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}

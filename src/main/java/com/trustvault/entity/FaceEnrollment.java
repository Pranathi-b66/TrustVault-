package com.trustvault.entity;

import com.trustvault.face.FaceDescriptor;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;

/**
 * Exclusive facial enrollment for a single TrustVault identity.
 *
 * <p>The table enforces the 1-to-1 contract at the storage layer:</p>
 * <ul>
 *   <li>{@code uk_biometric_templates_user_id} - one enrollment per account,</li>
 *   <li>{@code uk_biometric_templates_email} - one enrollment per email address,</li>
 *   <li>{@code uk_biometric_templates_face_hash} - one account per face.</li>
 * </ul>
 *
 * <p>{@code descriptorPayload} holds the AES-GCM sealed embedding; {@code faceHash} is the
 * SHA-256 of its canonical projection and is used both as a fast duplicate index and as a
 * DB-level guard against concurrent double enrollment.</p>
 */
@Entity
@Table(
        name = "biometric_templates",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_biometric_templates_user_id", columnNames = "user_id"),
                @UniqueConstraint(name = "uk_biometric_templates_email", columnNames = "email"),
                @UniqueConstraint(name = "uk_biometric_templates_face_hash", columnNames = "face_hash")
        }
)
public class FaceEnrollment {

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Column(name = "email", length = 255, nullable = false)
    private String email;

    @Column(name = "face_hash", length = 64, nullable = false, unique = true)
    private String faceHash;

    @Lob
    @Column(name = "face_descriptor", columnDefinition = "text", nullable = false)
    private String descriptorPayload;

    @Column(name = "algorithm_version", length = 32, nullable = false)
    private String algorithmVersion = FaceDescriptor.ALGORITHM;

    @Column(name = "embedding_size", nullable = false)
    private Integer embeddingSize = FaceDescriptor.DEFAULT_SIZE;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected FaceEnrollment() {
    }

    public FaceEnrollment(String id, User user, String email, String faceHash) {
        this(id, user, email, faceHash, null, FaceDescriptor.ALGORITHM, FaceDescriptor.DEFAULT_SIZE);
    }

    public FaceEnrollment(String id, User user, String email, String faceHash,
                          String descriptorPayload, String algorithmVersion, int embeddingSize) {
        this.id = id;
        this.user = user;
        this.email = email;
        this.faceHash = faceHash;
        this.descriptorPayload = descriptorPayload;
        this.algorithmVersion = algorithmVersion != null ? algorithmVersion : FaceDescriptor.ALGORITHM;
        this.embeddingSize = embeddingSize;
    }

    public String getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public String getEmail() {
        return email;
    }

    public String getFaceHash() {
        return faceHash;
    }

    public String getDescriptorPayload() {
        return descriptorPayload;
    }

    public void setDescriptorPayload(String descriptorPayload) {
        this.descriptorPayload = descriptorPayload;
    }

    public String getAlgorithmVersion() {
        return algorithmVersion;
    }

    public void setAlgorithmVersion(String algorithmVersion) {
        this.algorithmVersion = algorithmVersion;
    }

    public Integer getEmbeddingSize() {
        return embeddingSize;
    }

    public void setEmbeddingSize(Integer embeddingSize) {
        this.embeddingSize = embeddingSize;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}

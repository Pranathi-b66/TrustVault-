package com.trustvault.service;

import com.trustvault.entity.Document;
import com.trustvault.entity.DocumentPermission;
import com.trustvault.entity.User;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the forensic resource snapshots persisted in {@code audit_logs.pre_state} and
 * {@code audit_logs.post_state}.
 *
 * <p>Snapshots are deliberately explicit rather than reflective: they must never leak a password
 * hash, a face descriptor, a file-system path or a JWT. Only fields an investigator needs to
 * reconstruct an administrative decision are captured.</p>
 */
@Service
public class AuditSnapshotService {

    public Map<String, Object> userSnapshot(User user) {
        if (user == null) {
            return null;
        }
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("id", user.getId());
        snapshot.put("email", user.getEmail());
        snapshot.put("fullName", user.getFullName());
        snapshot.put("role", user.getRole() != null ? user.getRole().name() : null);
        snapshot.put("status", user.getStatus() != null ? user.getStatus().name() : null);
        snapshot.put("createdAt", asString(user.getCreatedAt()));
        return snapshot;
    }

    public Map<String, Object> documentSnapshot(Document document) {
        if (document == null) {
            return null;
        }
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("id", document.getId());
        snapshot.put("title", document.getTitle());
        snapshot.put("category", document.getCategory());
        snapshot.put("mimeType", document.getMimeType());
        snapshot.put("fileSizeBytes", document.getFileSizeBytes());
        snapshot.put("ownerId", document.getOwner() != null ? document.getOwner().getId() : null);
        snapshot.put("ownerEmail", document.getOwner() != null ? document.getOwner().getEmail() : null);
        snapshot.put("createdAt", asString(document.getCreatedAt()));
        snapshot.put("updatedAt", asString(document.getUpdatedAt()));
        return snapshot;
    }

    public Map<String, Object> permissionSnapshot(DocumentPermission permission) {
        if (permission == null) {
            return null;
        }
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("id", permission.getId());
        snapshot.put("documentId", permission.getDocument() != null ? permission.getDocument().getId() : null);
        snapshot.put("userId", permission.getUser() != null ? permission.getUser().getId() : null);
        snapshot.put("userEmail", permission.getUser() != null ? permission.getUser().getEmail() : null);
        snapshot.put("permissionLevel",
                permission.getPermissionLevel() != null ? permission.getPermissionLevel().name() : null);
        snapshot.put("maxViews", permission.getMaxViews());
        snapshot.put("viewsCount", permission.getViewsCount());
        snapshot.put("expiresAt", asString(permission.getExpiresAt()));
        snapshot.put("grantedByEmail",
                permission.getGrantedBy() != null ? permission.getGrantedBy().getEmail() : null);
        snapshot.put("grantedAt", asString(permission.getGrantedAt()));
        return snapshot;
    }

    public Map<String, Object> lockdownSnapshot(SystemLockdownService.LockdownStatus status) {
        if (status == null) {
            return null;
        }
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("lockdownEnabled", status.enabled());
        snapshot.put("reason", status.reason());
        snapshot.put("triggeredBy", status.triggeredBy());
        snapshot.put("triggeredAt", asString(status.triggeredAt()));
        return snapshot;
    }

    private String asString(Instant instant) {
        return instant != null ? instant.toString() : null;
    }
}

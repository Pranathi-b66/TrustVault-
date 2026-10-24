package com.trustvault.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustvault.dto.AuditDiffEntry;
import com.trustvault.dto.AuditDiffResponse;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Computes the structured delta that powers the "Inspect Action Replay" admin modal.
 *
 * <p>Snapshots are flattened to dotted field paths (for example {@code owner.email}) so nested
 * objects produce readable, individual diff rows instead of one opaque blob. Only fields that
 * actually changed are returned; the summary keeps counts for added / removed / modified /
 * unchanged so the console can render headline chips.</p>
 */
@Service
public class AuditDiffService {

    private static final Logger log = LoggerFactory.getLogger(AuditDiffService.class);
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {
    };

    private final ObjectMapper objectMapper;

    public AuditDiffService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public AuditDiffResponse buildDiff(AuditLog auditLog) {
        Map<String, Object> preState = parseSnapshot(auditLog.getPreState());
        Map<String, Object> postState = parseSnapshot(auditLog.getPostState());

        Map<String, Object> flatPre = new LinkedHashMap<>();
        Map<String, Object> flatPost = new LinkedHashMap<>();
        flatten("", preState, flatPre);
        flatten("", postState, flatPost);

        LinkedHashSet<String> fields = new LinkedHashSet<>();
        fields.addAll(flatPre.keySet());
        fields.addAll(flatPost.keySet());

        List<AuditDiffEntry> changes = new ArrayList<>();
        int added = 0;
        int removed = 0;
        int modified = 0;
        int unchanged = 0;

        for (String field : fields) {
            boolean inPre = flatPre.containsKey(field);
            boolean inPost = flatPost.containsKey(field);
            Object before = flatPre.get(field);
            Object after = flatPost.get(field);

            if (!inPre) {
                added++;
                changes.add(new AuditDiffEntry(field, null, after, "ADDED"));
            } else if (!inPost) {
                removed++;
                changes.add(new AuditDiffEntry(field, before, null, "REMOVED"));
            } else if (!Objects.equals(before, after)) {
                modified++;
                changes.add(new AuditDiffEntry(field, before, after, "MODIFIED"));
            } else {
                unchanged++;
            }
        }

        Map<String, Integer> summary = new LinkedHashMap<>();
        summary.put("modified", modified);
        summary.put("added", added);
        summary.put("removed", removed);
        summary.put("unchanged", unchanged);
        summary.put("total", changedCount(added, removed, modified));

        AuditDiffResponse response = new AuditDiffResponse();
        response.setAuditId(auditLog.getId());
        response.setAction(auditLog.getAction());
        response.setStatus(auditLog.getStatus());
        response.setActorEmail(auditLog.getUserEmail());
        response.setActorUserId(auditLog.getUser() != null ? auditLog.getUser().getId() : null);
        response.setIpAddress(auditLog.getIpAddress());
        response.setTimestamp(auditLog.getTimestamp());
        response.setDetails(auditLog.getDetails());
        response.setResourceType(resolveResourceType(auditLog.getAction()));
        response.setResourceId(resolveResourceId(auditLog, preState, postState));
        response.setHasSnapshot(auditLog.getPreState() != null || auditLog.getPostState() != null);
        response.setPreState(preState);
        response.setPostState(postState);
        response.setChanges(changes);
        response.setSummary(summary);
        return response;
    }

    private int changedCount(int added, int removed, int modified) {
        return added + removed + modified;
    }

    private Map<String, Object> parseSnapshot(String json) {
        if (json == null || json.isBlank()) {
            return new LinkedHashMap<>();
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(json, MAP_TYPE);
            return parsed != null ? parsed : new LinkedHashMap<>();
        } catch (Exception parseError) {
            log.warn("Unable to parse audit state snapshot for replay: {}", parseError.getMessage());
            return new LinkedHashMap<>();
        }
    }

    private void flatten(String prefix, Map<String, Object> source, Map<String, Object> target) {
        if (source == null) {
            return;
        }
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            String field = prefix.isEmpty() ? String.valueOf(entry.getKey()) : prefix + "." + entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Map<?, ?> nested) {
                Map<String, Object> normalized = new LinkedHashMap<>();
                nested.forEach((key, nestedValue) -> normalized.put(String.valueOf(key), nestedValue));
                flatten(field, normalized, target);
            } else {
                target.put(field, value);
            }
        }
    }

    private String resolveResourceId(AuditLog auditLog, Map<String, Object> preState, Map<String, Object> postState) {
        if (auditLog.getDocumentId() != null) {
            return auditLog.getDocumentId();
        }
        Object id = preState.get("id");
        if (id == null) {
            id = postState.get("id");
        }
        return id != null ? String.valueOf(id) : null;
    }

    private String resolveResourceType(AuditAction action) {
        if (action == null) {
            return "UNKNOWN";
        }
        return switch (action) {
            case SYSTEM_LOCKDOWN_TRIGGERED, SYSTEM_LOCKDOWN_LIFTED -> "SYSTEM";
            case ROLE_CHANGED, ACCOUNT_DEACTIVATED, ACCOUNT_INACTIVE_ACCESS_ATTEMPT -> "USER";
            case GRANT, REVOKE -> "DOCUMENT_PERMISSION";
            case SECURITY_ALERT -> "SECURITY";
            default -> "DOCUMENT";
        };
    }
}

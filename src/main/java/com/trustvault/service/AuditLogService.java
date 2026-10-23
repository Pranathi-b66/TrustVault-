package com.trustvault.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditLog;
import com.trustvault.entity.AuditStatus;
import com.trustvault.entity.User;
import com.trustvault.repository.AuditLogRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;
    private final AnomalyDetectionService anomalyDetectionService;
    private final ObjectMapper objectMapper;

    public AuditLogService(AuditLogRepository auditLogRepository,
                           AnomalyDetectionService anomalyDetectionService,
                           ObjectMapper objectMapper) {
        this.auditLogRepository = auditLogRepository;
        this.anomalyDetectionService = anomalyDetectionService;
        this.objectMapper = objectMapper;
    }

    /**
     * Writes the row in its own transaction so a denial is preserved even when the business
     * transaction rolls back.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuditLog logEvent(User user, String userEmail, AuditAction action, String documentId,
                             String ipAddress, AuditStatus status, Map<String, Object> detailsMap) {
        return persistEvent(user, userEmail, action, documentId, ipAddress, status, detailsMap);
    }

    /**
     * Writes the row on the caller's connection, so it commits and rolls back together with the
     * change it describes. Required for sign-up: the account row is still uncommitted there, and a
     * {@link Propagation#REQUIRES_NEW} insert would have to take a foreign-key lock on that parent
     * row and stall against its own caller until the InnoDB lock-wait timeout expires.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public AuditLog logEventInTransaction(User user, String userEmail, AuditAction action, String documentId,
                                          String ipAddress, AuditStatus status, Map<String, Object> detailsMap) {
        return persistEvent(user, userEmail, action, documentId, ipAddress, status, detailsMap);
    }

    private AuditLog persistEvent(User user, String userEmail, AuditAction action, String documentId,
                                  String ipAddress, AuditStatus status, Map<String, Object> detailsMap) {
        String jsonDetails = null;
        if (detailsMap != null && !detailsMap.isEmpty()) {
            try {
                jsonDetails = objectMapper.writeValueAsString(detailsMap);
            } catch (JsonProcessingException e) {
                jsonDetails = "{}";
            }
        }

        String effectiveEmail = (user != null) ? user.getEmail() : (userEmail != null ? userEmail : "anonymous");
        String effectiveIp = (ipAddress != null && !ipAddress.isBlank()) ? ipAddress : "127.0.0.1";

        AuditLog log = new AuditLog(
                UUID.randomUUID().toString(),
                user,
                effectiveEmail,
                action,
                documentId,
                effectiveIp,
                status,
                jsonDetails,
                Instant.now()
        );

        AuditLog saved = auditLogRepository.save(log);

        if (action == AuditAction.ACCESS_DENIED) {
            anomalyDetectionService.recordAccessDenied(effectiveIp, effectiveEmail, documentId);
        } else if (status == AuditStatus.SUCCESS) {
            anomalyDetectionService.recordSuccess(effectiveIp, effectiveEmail);
        }

        return saved;
    }

    @Transactional(readOnly = true)
    public List<AuditLog> getRecentLogs() {
        return auditLogRepository.findTop100ByOrderByTimestampDesc();
    }

    @Transactional(readOnly = true)
    public List<AuditLog> getAllLogs() {
        return auditLogRepository.findAllByOrderByTimestampDesc();
    }

    @Transactional(readOnly = true)
    public List<AuditLog> getSecurityAlerts() {
        return auditLogRepository.findByActionOrderByTimestampDesc(AuditAction.SECURITY_ALERT);
    }
}

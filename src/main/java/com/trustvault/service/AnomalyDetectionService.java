package com.trustvault.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditLog;
import com.trustvault.entity.AuditStatus;
import com.trustvault.repository.AuditLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class AnomalyDetectionService {

    private static final Logger log = LoggerFactory.getLogger(AnomalyDetectionService.class);
    private static final int THRESHOLD = 3;
    private static final Duration WINDOW = Duration.ofMinutes(5);

    private final AuditLogRepository auditLogRepository;
    private final AuditLogService auditLogService;
    private final ObjectMapper objectMapper;

    // Tracking for consecutive failures
    private final ConcurrentHashMap<String, FailureTracker> ipFailures = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, FailureTracker> userFailures = new ConcurrentHashMap<>();

    public AnomalyDetectionService(AuditLogRepository auditLogRepository,
                                  @Lazy AuditLogService auditLogService,
                                  ObjectMapper objectMapper) {
        this.auditLogRepository = auditLogRepository;
        this.auditLogService = auditLogService;
        this.objectMapper = objectMapper;
    }

    private static class FailureTracker {
        final AtomicInteger count = new AtomicInteger(0);
        volatile Instant firstFailureTime = Instant.now();
        volatile Instant lastFailureTime = Instant.now();

        void recordFailure() {
            Instant now = Instant.now();
            if (Duration.between(firstFailureTime, now).compareTo(WINDOW) > 0) {
                count.set(1);
                firstFailureTime = now;
            } else {
                count.incrementAndGet();
            }
            lastFailureTime = now;
        }

        void reset() {
            count.set(0);
            firstFailureTime = Instant.now();
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordAccessDenied(String ipAddress, String userEmail, String documentId) {
        boolean alertTriggered = false;
        String triggerSource = "";

        if (ipAddress != null && !ipAddress.isBlank()) {
            FailureTracker tracker = ipFailures.computeIfAbsent(ipAddress, k -> new FailureTracker());
            tracker.recordFailure();
            if (tracker.count.get() >= THRESHOLD) {
                alertTriggered = true;
                triggerSource = "IP: " + ipAddress;
                tracker.reset();
            }
        }

        if (!alertTriggered && userEmail != null && !userEmail.isBlank() && !"anonymous".equalsIgnoreCase(userEmail)) {
            FailureTracker tracker = userFailures.computeIfAbsent(userEmail, k -> new FailureTracker());
            tracker.recordFailure();
            if (tracker.count.get() >= THRESHOLD) {
                alertTriggered = true;
                triggerSource = "User: " + userEmail;
                tracker.reset();
            }
        }

        // Also check DB count for distributed/clustered resilience
        if (!alertTriggered) {
            Instant fiveMinutesAgo = Instant.now().minus(WINDOW);
            long ipCount = ipAddress != null ? auditLogRepository.countRecentAccessDeniedByIp(ipAddress, AuditAction.ACCESS_DENIED, AuditStatus.FAILURE, fiveMinutesAgo) : 0;
            long userCount = (userEmail != null && !userEmail.isBlank() && !"anonymous".equalsIgnoreCase(userEmail))
                    ? auditLogRepository.countRecentAccessDeniedByUserEmail(userEmail, AuditAction.ACCESS_DENIED, AuditStatus.FAILURE, fiveMinutesAgo) : 0;

            if (ipCount >= THRESHOLD || userCount >= THRESHOLD) {
                alertTriggered = true;
                triggerSource = ipCount >= THRESHOLD ? ("DB IP: " + ipAddress) : ("DB User: " + userEmail);
            }
        }

        if (alertTriggered) {
            log.warn("SECURITY_ALERT triggered! Anomaly detected from {}", triggerSource);
            Map<String, Object> details = new HashMap<>();
            details.put("alert", "CONSECUTIVE_ACCESS_DENIED_EXCEEDED");
            details.put("threshold", THRESHOLD);
            details.put("windowMinutes", 5);
            details.put("triggerSource", triggerSource);
            details.put("targetDocumentId", documentId);
            details.put("timestamp", Instant.now().toString());

            String jsonDetails;
            try {
                jsonDetails = objectMapper.writeValueAsString(details);
            } catch (JsonProcessingException e) {
                jsonDetails = "{\"alert\":\"CONSECUTIVE_ACCESS_DENIED_EXCEEDED\"}";
            }

            AuditLog alertLog = new AuditLog(
                    UUID.randomUUID().toString(),
                    null,
                    userEmail != null ? userEmail : "SYSTEM_ANOMALY_DETECTOR",
                    AuditAction.SECURITY_ALERT,
                    documentId,
                    ipAddress != null ? ipAddress : "0.0.0.0",
                    AuditStatus.FAILURE,
                    jsonDetails,
                    Instant.now()
            );
            auditLogRepository.save(alertLog);
        }
    }

    public void recordSuccess(String ipAddress, String userEmail) {
        if (ipAddress != null) {
            FailureTracker tracker = ipFailures.get(ipAddress);
            if (tracker != null) tracker.reset();
        }
        if (userEmail != null) {
            FailureTracker tracker = userFailures.get(userEmail);
            if (tracker != null) tracker.reset();
        }
    }
}

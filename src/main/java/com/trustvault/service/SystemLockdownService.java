package com.trustvault.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustvault.entity.SystemSetting;
import com.trustvault.repository.SystemSettingRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;

/**
 * Single source of truth for the Emergency Global Kill Switch.
 *
 * <p>The flag is persisted in {@code system_settings} so a restart cannot silently lift an active
 * lockdown, but the request path only reads the volatile in-memory copy: every HTTP request is
 * checked by {@code SystemLockdownFilter} and must not pay a database round-trip for it.</p>
 *
 * <p>State is applied to memory <em>before</em> it is persisted. If the database write fails the
 * lockdown still engages: availability of the kill switch itself must never depend on the very
 * infrastructure that is potentially under attack.</p>
 */
@Service
public class SystemLockdownService {

    private static final Logger log = LoggerFactory.getLogger(SystemLockdownService.class);
    private static final String SETTING_KEY = "SYSTEM_LOCKDOWN";

    private final SystemSettingRepository systemSettingRepository;
    private final ObjectMapper objectMapper;

    private volatile LockdownStatus current = LockdownStatus.disabled();

    public SystemLockdownService(SystemSettingRepository systemSettingRepository, ObjectMapper objectMapper) {
        this.systemSettingRepository = systemSettingRepository;
        this.objectMapper = objectMapper;
    }

    public record LockdownStatus(boolean enabled, String reason, String triggeredBy, Instant triggeredAt) {

        public static LockdownStatus disabled() {
            return new LockdownStatus(false, null, null, null);
        }
    }

    @PostConstruct
    void restorePersistedState() {
        try {
            systemSettingRepository.findById(SETTING_KEY).ifPresent(setting -> {
                try {
                    LockdownStatus restored = objectMapper.readValue(setting.getValue(), LockdownStatus.class);
                    current = restored != null ? restored : LockdownStatus.disabled();
                    if (current.enabled()) {
                        log.warn("TrustVault restarted with an ACTIVE administrative lockdown (reason: {}).",
                                current.reason());
                    }
                } catch (Exception parseError) {
                    log.error("Unable to parse persisted lockdown state; defaulting to UNLOCKED.", parseError);
                }
            });
        } catch (Exception loadError) {
            // The table is guaranteed by ddl-auto=validate; a read failure here must not stop boot.
            log.error("Unable to restore persisted lockdown state; defaulting to UNLOCKED.", loadError);
        }
    }

    public boolean isLockdownEnabled() {
        return current.enabled();
    }

    public LockdownStatus getStatus() {
        return current;
    }

    /**
     * Applies the flag and writes the forensic state transition to {@code system_settings}.
     * Concurrent toggles are serialized by the method monitor; the volatile field keeps the
     * hot request path wait-free.
     *
     * <p>No surrounding transaction is used on purpose: the repository's own short transactions
     * mean a persistence failure cannot mark a wider unit of work rollback-only, so the catch
     * below can safely keep the in-memory kill switch engaged.</p>
     */
    public synchronized LockdownStatus apply(boolean enabled, String reason, String adminEmail) {
        LockdownStatus next = enabled
                ? new LockdownStatus(true, normalizeReason(reason), adminEmail, Instant.now())
                : new LockdownStatus(false, normalizeReason(reason), adminEmail, Instant.now());

        LockdownStatus previous = current;
        current = next;

        try {
            SystemSetting setting = systemSettingRepository.findById(SETTING_KEY)
                    .orElseGet(() -> new SystemSetting(SETTING_KEY, "{}", adminEmail));
            setting.setValue(objectMapper.writeValueAsString(next));
            setting.setUpdatedBy(adminEmail);
            systemSettingRepository.save(setting);
        } catch (Exception persistError) {
            // Never fail the kill switch on persistence problems: the in-memory flag is already
            // enforcing containment, and an operator can re-apply the state after recovery.
            log.error("Lockdown state changed to enabled={} but could not be persisted.", enabled, persistError);
        }

        if (previous.enabled() != next.enabled()) {
            log.warn("TrustVault administrative lockdown transition: {} -> {} (operator: {}, reason: {})",
                    previous.enabled(), next.enabled(), adminEmail, next.reason());
        }

        return next;
    }

    private String normalizeReason(String reason) {
        if (reason == null || reason.isBlank()) {
            return "No reason supplied by the administrator.";
        }
        String trimmed = reason.trim();
        return trimmed.length() > 500 ? trimmed.substring(0, 500) : trimmed;
    }
}

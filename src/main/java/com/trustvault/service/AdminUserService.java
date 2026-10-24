package com.trustvault.service;

import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditStatus;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import com.trustvault.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Administrative identity mutations.
 *
 * <p>Every mutation captures the target's full (non-secret) snapshot before and after the change
 * and writes it onto the same database transaction as the mutation itself, so the WORM trail can
 * never contain an audit row for a change that rolled back - nor a change without its evidence.</p>
 */
@Service
public class AdminUserService {

    private final UserRepository userRepository;
    private final AuditLogService auditLogService;
    private final AuditSnapshotService auditSnapshotService;

    public AdminUserService(UserRepository userRepository,
                            AuditLogService auditLogService,
                            AuditSnapshotService auditSnapshotService) {
        this.userRepository = userRepository;
        this.auditLogService = auditLogService;
        this.auditSnapshotService = auditSnapshotService;
    }

    @Transactional
    public User deactivateUser(String targetUserId, String adminUserId, String clientIp) {
        User admin = requireAdmin(adminUserId);
        User target = requireUser(targetUserId);

        if (target.getId().equals(admin.getId())) {
            throw new IllegalStateException("Administrators cannot deactivate their own account; "
                    + "ask another administrator to perform the offboarding.");
        }

        Map<String, Object> preState = auditSnapshotService.userSnapshot(target);

        target.setStatus(UserStatus.INACTIVE);
        User saved = userRepository.save(target);

        Map<String, Object> postState = auditSnapshotService.userSnapshot(saved);

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("action", "INSTANT_OFFBOARDING_TRIGGERED");
        details.put("targetUserEmail", target.getEmail());
        details.put("targetUserId", target.getId());
        details.put("previousStatus", UserStatus.ACTIVE.name());
        details.put("newStatus", UserStatus.INACTIVE.name());

        auditLogService.logEventInTransaction(admin, admin.getEmail(), AuditAction.ACCOUNT_DEACTIVATED,
                null, clientIp, AuditStatus.SUCCESS, details, preState, postState);

        return saved;
    }

    @Transactional
    public User activateUser(String targetUserId, String adminUserId, String clientIp) {
        User admin = requireAdmin(adminUserId);
        User target = requireUser(targetUserId);

        Map<String, Object> preState = auditSnapshotService.userSnapshot(target);

        target.setStatus(UserStatus.ACTIVE);
        User saved = userRepository.save(target);

        Map<String, Object> postState = auditSnapshotService.userSnapshot(saved);

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("action", "ACCOUNT_ACTIVATED");
        details.put("targetUserEmail", target.getEmail());
        details.put("targetUserId", target.getId());
        details.put("previousStatus", preState.get("status"));
        details.put("newStatus", UserStatus.ACTIVE.name());

        auditLogService.logEventInTransaction(admin, admin.getEmail(), AuditAction.EDIT,
                null, clientIp, AuditStatus.SUCCESS, details, preState, postState);

        return saved;
    }

    @Transactional
    public User changeRole(String targetUserId, String adminUserId, Role newRole, String clientIp) {
        if (newRole == null) {
            throw new IllegalArgumentException("A target role is required.");
        }

        User admin = requireAdmin(adminUserId);
        User target = requireUser(targetUserId);

        if (target.getId().equals(admin.getId())) {
            throw new IllegalStateException("Administrators cannot change their own role; "
                    + "ask another administrator to perform the change.");
        }

        Role previousRole = target.getRole();
        if (previousRole == newRole) {
            return target;
        }

        boolean removingActiveAdmin = previousRole == Role.ADMIN
                && target.getStatus() == UserStatus.ACTIVE
                && newRole != Role.ADMIN
                && userRepository.countByRoleAndStatus(Role.ADMIN, UserStatus.ACTIVE) <= 1;
        if (removingActiveAdmin) {
            throw new IllegalStateException("Cannot demote the last active administrator; "
                    + "promote another identity first.");
        }

        Map<String, Object> preState = auditSnapshotService.userSnapshot(target);

        target.setRole(newRole);
        User saved = userRepository.save(target);

        Map<String, Object> postState = auditSnapshotService.userSnapshot(saved);

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("action", "ROLE_CHANGED");
        details.put("targetUserEmail", target.getEmail());
        details.put("targetUserId", target.getId());
        details.put("previousRole", previousRole != null ? previousRole.name() : null);
        details.put("newRole", newRole.name());

        auditLogService.logEventInTransaction(admin, admin.getEmail(), AuditAction.ROLE_CHANGED,
                null, clientIp, AuditStatus.SUCCESS, details, preState, postState);

        return saved;
    }

    private User requireUser(String userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));
    }

    private User requireAdmin(String adminUserId) {
        User admin = userRepository.findById(adminUserId)
                .orElseThrow(() -> new IllegalArgumentException("Administrator not found: " + adminUserId));
        if (admin.getRole() != Role.ADMIN) {
            throw new IllegalStateException("Administrative privileges are required for this operation.");
        }
        return admin;
    }
}

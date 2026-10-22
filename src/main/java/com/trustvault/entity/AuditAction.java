package com.trustvault.entity;

public enum AuditAction {
    UPLOAD,
    READ,
    EDIT,
    DELETE,
    GRANT,
    REVOKE,
    ACCESS_DENIED,
    ACCOUNT_DEACTIVATED,
    ACCOUNT_INACTIVE_ACCESS_ATTEMPT,
    SECURITY_ALERT
}

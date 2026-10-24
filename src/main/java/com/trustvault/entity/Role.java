package com.trustvault.entity;

/**
 * Platform identity classes.
 *
 * <p>{@code OWNER} and {@code VIEWER} are deliberately <b>not</b> privilege tiers. They share one
 * vault baseline: an authenticated workspace with upload, search, read/download and the ability to
 * manage documents they own. What differs between two identities is never their label but their
 * <em>position</em> relative to a document - owner of the row, holder of a live ACL grant, or
 * neither - which {@code PermissionService} resolves per transaction from the database.</p>
 *
 * <p>{@code ADMIN} is the only genuine separation: it carries the security console, the kill
 * switch, immutable-trail access and an ACL override. Nothing in the document workspace may treat
 * an administrator as a superior reader.</p>
 */
public enum Role {
    ADMIN,
    OWNER,
    VIEWER;

    /** True only for the security-operations identity. Never used to gate document reading. */
    public boolean isAdministrator() {
        return this == ADMIN;
    }
}

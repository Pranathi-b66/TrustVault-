package com.trustvault.dto;

/**
 * One field-level delta between the pre-state and post-state snapshots of an audited mutation.
 *
 * <p>{@code changeType} is one of {@code ADDED}, {@code REMOVED} or {@code MODIFIED}. Unchanged
 * fields are deliberately excluded so the replay view shows exactly what the administrator did.</p>
 */
public class AuditDiffEntry {

    private String field;
    private Object before;
    private Object after;
    private String changeType;

    public AuditDiffEntry() {
    }

    public AuditDiffEntry(String field, Object before, Object after, String changeType) {
        this.field = field;
        this.before = before;
        this.after = after;
        this.changeType = changeType;
    }

    public String getField() {
        return field;
    }

    public void setField(String field) {
        this.field = field;
    }

    public Object getBefore() {
        return before;
    }

    public void setBefore(Object before) {
        this.before = before;
    }

    public Object getAfter() {
        return after;
    }

    public void setAfter(Object after) {
        this.after = after;
    }

    public String getChangeType() {
        return changeType;
    }

    public void setChangeType(String changeType) {
        this.changeType = changeType;
    }
}

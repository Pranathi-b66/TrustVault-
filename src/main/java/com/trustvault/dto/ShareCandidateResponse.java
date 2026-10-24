package com.trustvault.dto;

/**
 * One selectable recipient for the document-sharing modal.
 *
 * <p>Deliberately narrow: the directory exists so an owner can address a share without typing an
 * exact address, so only the three fields needed to render a suggestion are exposed. Status is
 * never echoed - the endpoint only ever returns {@code ACTIVE} identities - and no identifier of
 * a document or of the caller is included.</p>
 */
public class ShareCandidateResponse {

    private String id;
    private String email;
    private String fullName;
    private String role;

    public ShareCandidateResponse() {}

    public ShareCandidateResponse(String id, String email, String fullName, String role) {
        this.id = id;
        this.email = email;
        this.fullName = fullName;
        this.role = role;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}

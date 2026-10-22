package com.trustvault.dto;

import java.util.Map;

public class RegisterCompleteRequest {
    private String registrationToken;
    private String id;
    private String rawId;
    private String type;
    private Map<String, Object> response;

    public RegisterCompleteRequest() {}

    public String getRegistrationToken() {
        return registrationToken;
    }

    public void setRegistrationToken(String registrationToken) {
        this.registrationToken = registrationToken;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRawId() {
        return rawId;
    }

    public void setRawId(String rawId) {
        this.rawId = rawId;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Map<String, Object> getResponse() {
        return response;
    }

    public void setResponse(Map<String, Object> response) {
        this.response = response;
    }
}

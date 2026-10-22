package com.trustvault.dto;

import java.util.List;
import java.util.Map;

public class WebAuthnLoginChallengeResponse {
    private String challenge;
    private Long timeout;
    private String rpId;
    private List<Map<String, Object>> allowCredentials;

    public WebAuthnLoginChallengeResponse() {}

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public Long getTimeout() {
        return timeout;
    }

    public void setTimeout(Long timeout) {
        this.timeout = timeout;
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }

    public List<Map<String, Object>> getAllowCredentials() {
        return allowCredentials;
    }

    public void setAllowCredentials(List<Map<String, Object>> allowCredentials) {
        this.allowCredentials = allowCredentials;
    }
}

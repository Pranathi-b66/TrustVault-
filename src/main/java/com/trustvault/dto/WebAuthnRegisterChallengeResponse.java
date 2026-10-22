package com.trustvault.dto;

import java.util.List;
import java.util.Map;

public class WebAuthnRegisterChallengeResponse {
    private String challenge;
    private Map<String, String> rp;
    private Map<String, String> user;
    private List<Map<String, Object>> pubKeyCredParams;
    private Long timeout;
    private String attestation;
    private Map<String, Object> authenticatorSelection;

    public WebAuthnRegisterChallengeResponse() {}

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public Map<String, String> getRp() {
        return rp;
    }

    public void setRp(Map<String, String> rp) {
        this.rp = rp;
    }

    public Map<String, String> getUser() {
        return user;
    }

    public void setUser(Map<String, String> user) {
        this.user = user;
    }

    public List<Map<String, Object>> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public void setPubKeyCredParams(List<Map<String, Object>> pubKeyCredParams) {
        this.pubKeyCredParams = pubKeyCredParams;
    }

    public Long getTimeout() {
        return timeout;
    }

    public void setTimeout(Long timeout) {
        this.timeout = timeout;
    }

    public String getAttestation() {
        return attestation;
    }

    public void setAttestation(String attestation) {
        this.attestation = attestation;
    }

    public Map<String, Object> getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public void setAuthenticatorSelection(Map<String, Object> authenticatorSelection) {
        this.authenticatorSelection = authenticatorSelection;
    }
}

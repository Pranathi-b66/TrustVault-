package com.trustvault.controller;

import com.trustvault.dto.*;
import com.trustvault.entity.User;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.UserPrincipal;
import com.trustvault.service.WebAuthnService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/api/auth/webauthn")
public class WebAuthnController {

    private final WebAuthnService webAuthnService;
    private final UserRepository userRepository;

    public WebAuthnController(WebAuthnService webAuthnService, UserRepository userRepository) {
        this.webAuthnService = webAuthnService;
        this.userRepository = userRepository;
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    @PostMapping("/register-challenge")
    public ResponseEntity<WebAuthnRegisterChallengeResponse> registerChallenge(@AuthenticationPrincipal UserPrincipal principal) {
        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return ResponseEntity.ok(webAuthnService.createRegisterChallenge(user));
    }

    @PostMapping("/register-verify")
    public ResponseEntity<?> registerVerify(@AuthenticationPrincipal UserPrincipal principal,
                                            @RequestBody WebAuthnRegisterVerifyRequest request) {
        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        webAuthnService.verifyAndSaveRegistration(user, request);
        return ResponseEntity.ok(Collections.singletonMap("message", "WebAuthn biometric passkey successfully registered."));
    }

    @PostMapping("/login-challenge")
    public ResponseEntity<WebAuthnLoginChallengeResponse> loginChallenge(@RequestBody(required = false) Map<String, String> body) {
        String email = body != null ? body.get("email") : null;
        return ResponseEntity.ok(webAuthnService.createLoginChallenge(email));
    }

    @PostMapping("/login-verify")
    public ResponseEntity<?> loginVerify(@RequestBody WebAuthnLoginVerifyRequest request) {
        String token = webAuthnService.verifyLoginAndIssueToken(request);
        return ResponseEntity.ok(Collections.singletonMap("token", token));
    }

    // Biometric Action Challenge (DOWNLOAD or EDIT)
    @PostMapping("/action-challenge")
    public ResponseEntity<WebAuthnLoginChallengeResponse> actionChallenge(
            @RequestParam("docId") String docId,
            @RequestParam(value = "action", defaultValue = "DOWNLOAD") String action,
            @AuthenticationPrincipal UserPrincipal principal) {
        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return ResponseEntity.ok(webAuthnService.createActionPasskeyChallenge(user, docId, action));
    }

    // Biometric Action Verification (DOWNLOAD or EDIT)
    @PostMapping("/action-verify")
    public ResponseEntity<?> actionVerify(
            @RequestParam("docId") String docId,
            @RequestParam(value = "action", defaultValue = "DOWNLOAD") String action,
            @AuthenticationPrincipal UserPrincipal principal,
            @RequestBody WebAuthnLoginVerifyRequest request,
            HttpServletRequest httpRequest) {
        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        String actionToken = webAuthnService.verifyActionAndIssueToken(user, request, docId, action, getClientIp(httpRequest));
        return ResponseEntity.ok(Collections.singletonMap("passkeyToken", actionToken));
    }

    // Backwards-compatible download endpoints
    @PostMapping("/download-challenge")
    public ResponseEntity<WebAuthnLoginChallengeResponse> downloadChallenge(
            @RequestParam("docId") String docId,
            @AuthenticationPrincipal UserPrincipal principal) {
        return actionChallenge(docId, "DOWNLOAD", principal);
    }

    @PostMapping("/download-verify")
    public ResponseEntity<?> downloadVerify(
            @RequestParam("docId") String docId,
            @AuthenticationPrincipal UserPrincipal principal,
            @RequestBody WebAuthnLoginVerifyRequest request,
            HttpServletRequest httpRequest) {
        return actionVerify(docId, "DOWNLOAD", principal, request, httpRequest);
    }
}

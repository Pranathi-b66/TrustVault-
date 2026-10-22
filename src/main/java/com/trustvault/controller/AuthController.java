package com.trustvault.controller;

import com.trustvault.dto.*;
import com.trustvault.entity.User;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.UserPrincipal;
import com.trustvault.service.AuthService;
import com.trustvault.service.WebAuthnService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final WebAuthnService webAuthnService;
    private final UserRepository userRepository;

    public AuthController(AuthService authService,
                          WebAuthnService webAuthnService,
                          UserRepository userRepository) {
        this.authService = authService;
        this.webAuthnService = webAuthnService;
        this.userRepository = userRepository;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    // Step 1: Initiate profile and generate WebAuthn registration ceremony options
    @PostMapping("/register-initiate")
    public ResponseEntity<RegisterInitiateResponse> registerInitiate(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(webAuthnService.initiateRegistration(request));
    }

    // Step 2: Verify device biometric passkey attestation and finalize identity persistence
    @PostMapping("/register-complete")
    public ResponseEntity<AuthResponse> registerComplete(@RequestBody RegisterCompleteRequest request) {
        return ResponseEntity.ok(webAuthnService.completeRegistration(request));
    }

    // Direct registration (fallback)
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal UserPrincipal principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body("Unauthenticated");
        }
        User user = userRepository.findById(principal.getId()).orElse(null);
        if (user == null) {
            return ResponseEntity.status(404).body("User not found");
        }
        return ResponseEntity.ok(user);
    }
}

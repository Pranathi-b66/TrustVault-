package com.trustvault.controller;

import com.trustvault.dto.FaceRegistrationRequest;
import com.trustvault.dto.FaceStatusResponse;
import com.trustvault.dto.FaceVerificationRequest;
import com.trustvault.dto.FaceVerificationResponse;
import com.trustvault.entity.FaceEnrollment;
import com.trustvault.entity.User;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.UserPrincipal;
import com.trustvault.service.FaceEnrollmentService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Exclusive face enrollment and action-time verification endpoints.
 *
 * <ul>
 *   <li>{@code POST /register-face} - binds the authenticated profile to a live facial
 *       embedding. A face already owned by another account is rejected with {@code 400}.</li>
 *   <li>{@code POST /verify-face} - matches a fresh webcam capture against <em>this</em> user's
 *       descriptor and issues the short-lived action token consumed by download/edit.</li>
 *   <li>{@code GET /face-status} - enrollment state for the current identity.</li>
 *   <li>{@code DELETE /face} - revokes the enrollment (re-enrollment required afterwards).</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/auth/biometric")
public class FaceBiometricController {

    private final FaceEnrollmentService faceEnrollmentService;
    private final UserRepository userRepository;

    public FaceBiometricController(FaceEnrollmentService faceEnrollmentService, UserRepository userRepository) {
        this.faceEnrollmentService = faceEnrollmentService;
        this.userRepository = userRepository;
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    private User currentUser(UserPrincipal principal) {
        return userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalArgumentException("Authenticated account was not found."));
    }

    @PostMapping("/register-face")
    public ResponseEntity<Map<String, Object>> registerFace(
            @Valid @RequestBody FaceRegistrationRequest request,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest httpRequest) {

        FaceEnrollment enrollment = faceEnrollmentService.register(
                currentUser(principal), request, getClientIp(httpRequest));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", "Face descriptor registered and exclusively bound to this account.");
        body.put("id", enrollment.getId());
        body.put("email", enrollment.getEmail());
        body.put("algorithm", enrollment.getAlgorithmVersion());
        body.put("embeddingSize", enrollment.getEmbeddingSize());
        body.put("enrolledAt", enrollment.getCreatedAt() != null
                ? enrollment.getCreatedAt().toString()
                : Instant.now().toString());
        return ResponseEntity.ok(body);
    }

    @PostMapping("/verify-face")
    public ResponseEntity<FaceVerificationResponse> verifyFace(
            @Valid @RequestBody FaceVerificationRequest request,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest httpRequest) {

        FaceVerificationResponse response = faceEnrollmentService.verifyForAction(
                currentUser(principal),
                request.getDocumentId(),
                request.getAction(),
                request.getDescriptor(),
                getClientIp(httpRequest));

        return ResponseEntity.ok(response);
    }

    @GetMapping("/face-status")
    public ResponseEntity<FaceStatusResponse> status(@AuthenticationPrincipal UserPrincipal principal) {
        return ResponseEntity.ok(faceEnrollmentService.getStatus(currentUser(principal)));
    }

    @DeleteMapping("/face")
    public ResponseEntity<Map<String, String>> revoke(
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest httpRequest) {

        faceEnrollmentService.revoke(currentUser(principal), getClientIp(httpRequest));
        return ResponseEntity.ok(Collections.singletonMap(
                "message", "Face enrollment revoked. Re-enroll before accessing protected documents."));
    }
}

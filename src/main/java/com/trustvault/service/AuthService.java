package com.trustvault.service;

import com.trustvault.dto.AuthResponse;
import com.trustvault.dto.LoginRequest;
import com.trustvault.dto.RegisterRequest;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.JwtTokenProvider;
import jakarta.annotation.PostConstruct;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final FaceEnrollmentService faceEnrollmentService;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtTokenProvider jwtTokenProvider,
                       FaceEnrollmentService faceEnrollmentService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.faceEnrollmentService = faceEnrollmentService;
    }

    @PostConstruct
    @Transactional
    public void initDefaultCredentials() {
        // Ensure default seeded accounts have valid default passwords if not set
        ensureUserPassword("usr-admin-01", "admin@trustvault.internal", "Admin@123", "Security Administrator", Role.ADMIN);
        ensureUserPassword("usr-owner-01", "owner@trustvault.internal", "Owner@123", "Alice Document Owner", Role.OWNER);
        ensureUserPassword("usr-viewer-01", "viewer@trustvault.internal", "Viewer@123", "Bob Security Viewer", Role.VIEWER);
    }

    private void ensureUserPassword(String id, String email, String plainPassword, String fullName, Role role) {
        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            if (user.getPasswordHash() == null || user.getPasswordHash().isBlank()) {
                user.setPasswordHash(passwordEncoder.encode(plainPassword));
                userRepository.save(user);
            }
        } else {
            User user = new User(id, email, passwordEncoder.encode(plainPassword), fullName, role, UserStatus.ACTIVE);
            userRepository.save(user);
        }
    }

    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password."));

        if (user.getPasswordHash() == null || !passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new BadCredentialsException("Invalid email or password.");
        }

        if (user.getStatus() == UserStatus.INACTIVE) {
            throw new BadCredentialsException("Account is inactive. Contact your administrator.");
        }

        String token = jwtTokenProvider.generateTokenFromUser(user.getId(), user.getEmail(), user.getRole().name());

        AuthResponse response = new AuthResponse(
                token,
                user.getId(),
                user.getEmail(),
                user.getFullName(),
                user.getRole(),
                user.getStatus()
        );
        // Lets the client skip the enrollment prompt when the face is already bound.
        response.setFaceEnrolled(faceEnrollmentService.getStatus(user).isEnrolled());
        return response;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request, String clientIp) {
        String email = request.getEmail() == null ? "" : request.getEmail().trim();
        if (email.isEmpty()) {
            throw new IllegalArgumentException("Email is required.");
        }
        if (request.getPassword() == null || request.getPassword().isBlank()) {
            throw new IllegalArgumentException("Password is required.");
        }
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already registered: " + email);
        }
        if (request.getFaceDescriptor() == null || request.getFaceDescriptor().isEmpty()) {
            throw new IllegalArgumentException(
                    "A webcam face scan is required to create a TrustVault account.");
        }

        // The descriptor itself is the evidence: it must be a complete embedding, it must not
        // already be bound to another identity, and it is stored exclusively against this account
        // in the same transaction.

        // Reject an already-claimed face BEFORE the profile row is created, so a duplicate
        // biometric enrolment leaves no orphaned account behind.
        faceEnrollmentService.assertFaceClaimable(request.getFaceDescriptor(), email, clientIp);

        Role assignedRole = request.getRole() != null ? request.getRole() : Role.VIEWER;

        User user = new User(
                UUID.randomUUID().toString(),
                email,
                passwordEncoder.encode(request.getPassword()),
                request.getFullName(),
                assignedRole,
                UserStatus.ACTIVE
        );

        User saved = userRepository.saveAndFlush(user);

        // Same transaction: if the face cannot be bound, the account is rolled back with it.
        faceEnrollmentService.enroll(saved, request.getFaceDescriptor(), clientIp);

        String token = jwtTokenProvider.generateTokenFromUser(saved.getId(), saved.getEmail(), saved.getRole().name());

        AuthResponse response = new AuthResponse(
                token,
                saved.getId(),
                saved.getEmail(),
                saved.getFullName(),
                saved.getRole(),
                saved.getStatus()
        );
        response.setFaceEnrolled(true);
        return response;
    }
}

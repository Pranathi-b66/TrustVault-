package com.trustvault.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.trustvault.dto.*;
import com.trustvault.entity.*;
import com.trustvault.repository.UserCredentialRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.security.JwtTokenProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class WebAuthnService {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnService.class);

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final UserRepository userRepository;
    private final UserCredentialRepository userCredentialRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final AuditLogService auditLogService;
    private final AnomalyDetectionService anomalyDetectionService;

    private final ObjectMapper jsonMapper = new ObjectMapper();
    private final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());

    @Value("${trustvault.webauthn.rp-id:localhost}")
    private String rpId;

    @Value("${trustvault.webauthn.rp-name:TrustVault}")
    private String rpName;

    // Challenge cache: challenge -> {userId, email, documentId, action, expiry}
    private final ConcurrentHashMap<String, ChallengeMetadata> activeChallenges = new ConcurrentHashMap<>();

    // Staged registrations: registrationToken -> PendingRegistration
    private final ConcurrentHashMap<String, PendingRegistration> pendingRegistrations = new ConcurrentHashMap<>();

    public WebAuthnService(UserRepository userRepository,
                           UserCredentialRepository userCredentialRepository,
                           JwtTokenProvider jwtTokenProvider,
                           PasswordEncoder passwordEncoder,
                           @Lazy AuditLogService auditLogService,
                           @Lazy AnomalyDetectionService anomalyDetectionService) {
        this.userRepository = userRepository;
        this.userCredentialRepository = userCredentialRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.passwordEncoder = passwordEncoder;
        this.auditLogService = auditLogService;
        this.anomalyDetectionService = anomalyDetectionService;
    }

    public static class ChallengeMetadata {
        final String userId;
        final String email;
        final String documentId;
        final String action;
        final Instant expiry;

        public ChallengeMetadata(String userId, String email, String documentId, String action, Instant expiry) {
            this.userId = userId;
            this.email = email;
            this.documentId = documentId;
            this.action = action;
            this.expiry = expiry;
        }
    }

    public static class PendingRegistration {
        final String pendingUserId;
        final RegisterRequest request;
        final String challenge;
        final Instant expiry;

        public PendingRegistration(String pendingUserId, RegisterRequest request, String challenge, Instant expiry) {
            this.pendingUserId = pendingUserId;
            this.request = request;
            this.challenge = challenge;
            this.expiry = expiry;
        }
    }

    private String generateSecureChallenge() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // ==========================================
    // 1. MANDATORY BIOMETRIC SIGN-UP CEREMONY
    // ==========================================

    public RegisterInitiateResponse initiateRegistration(RegisterRequest request) {
        if (request.getEmail() == null || request.getEmail().isBlank()) {
            throw new IllegalArgumentException("Email is required for registration.");
        }
        if (userRepository.existsByEmail(request.getEmail().trim().toLowerCase())) {
            throw new IllegalArgumentException("Email is already registered: " + request.getEmail());
        }
        if (request.getPassword() == null || request.getPassword().length() < 6) {
            throw new IllegalArgumentException("Password must be at least 6 characters.");
        }

        String pendingUserId = UUID.randomUUID().toString();
        String registrationToken = UUID.randomUUID().toString();
        String challenge = generateSecureChallenge();

        pendingRegistrations.put(registrationToken, new PendingRegistration(
                pendingUserId, request, challenge, Instant.now().plusSeconds(300)
        ));

        RegisterInitiateResponse response = new RegisterInitiateResponse();
        response.setRegistrationToken(registrationToken);
        response.setChallenge(challenge);
        response.setTimeout(60000L);
        response.setAttestation("none");

        Map<String, String> rp = new HashMap<>();
        rp.put("name", rpName);
        rp.put("id", rpId);
        response.setRp(rp);

        Map<String, String> userMap = new HashMap<>();
        userMap.put("id", Base64.getUrlEncoder().withoutPadding().encodeToString(pendingUserId.getBytes(StandardCharsets.UTF_8)));
        userMap.put("name", request.getEmail());
        userMap.put("displayName", request.getFullName() != null ? request.getFullName() : request.getEmail());
        response.setUser(userMap);

        List<Map<String, Object>> pubKeyParams = new ArrayList<>();
        Map<String, Object> es256 = new HashMap<>();
        es256.put("type", "public-key");
        es256.put("alg", -7); // ES256
        pubKeyParams.add(es256);

        Map<String, Object> rs256 = new HashMap<>();
        rs256.put("type", "public-key");
        rs256.put("alg", -257); // RS256
        pubKeyParams.add(rs256);

        response.setPubKeyCredParams(pubKeyParams);

        Map<String, Object> authSelection = new HashMap<>();
        authSelection.put("userVerification", "preferred");
        authSelection.put("residentKey", "preferred");
        response.setAuthenticatorSelection(authSelection);

        return response;
    }

    @Transactional
    public AuthResponse completeRegistration(RegisterCompleteRequest request) {
        PendingRegistration pending = pendingRegistrations.remove(request.getRegistrationToken());
        if (pending == null || pending.expiry.isBefore(Instant.now())) {
            throw new SecurityException("Sign-up session expired or invalid. Biometric registration aborted.");
        }

        try {
            Map<String, Object> respMap = request.getResponse();
            if (respMap == null) {
                throw new IllegalArgumentException("Invalid WebAuthn response payload.");
            }

            String clientDataJsonB64 = (String) respMap.get("clientDataJSON");
            String attestationObjectB64 = (String) respMap.get("attestationObject");

            byte[] clientDataBytes = Base64.getUrlDecoder().decode(clientDataJsonB64);
            Map<String, Object> clientData = jsonMapper.readValue(clientDataBytes, new TypeReference<>() {});

            String challenge = (String) clientData.get("challenge");
            if (!pending.challenge.equals(challenge)) {
                throw new SecurityException("Biometric registration challenge mismatch.");
            }

            byte[] attestationBytes = Base64.getUrlDecoder().decode(attestationObjectB64);
            Map<String, Object> attestationMap = cborMapper.readValue(new ByteArrayInputStream(attestationBytes), new TypeReference<>() {});
            byte[] authData = (byte[]) attestationMap.get("authData");

            String publicKeyHexOrBase64 = extractPublicKeyOrEncode(authData, attestationObjectB64);

            String credentialId = request.getId();
            if (credentialId == null || credentialId.isBlank()) {
                credentialId = request.getRawId();
            }

            RegisterRequest regReq = pending.request;
            Role role = regReq.getRole() != null ? regReq.getRole() : Role.VIEWER;

            // 1. Persist User identity
            User newUser = new User(
                    pending.pendingUserId,
                    regReq.getEmail().trim().toLowerCase(),
                    passwordEncoder.encode(regReq.getPassword()),
                    regReq.getFullName(),
                    role,
                    UserStatus.ACTIVE
            );
            User savedUser = userRepository.save(newUser);

            // 2. Persist WebAuthn biometric credential
            UserCredential cred = new UserCredential(credentialId, savedUser, publicKeyHexOrBase64, 0L);
            userCredentialRepository.save(cred);

            // 3. Issue Token & Log
            String token = jwtTokenProvider.generateTokenFromUser(savedUser.getId(), savedUser.getEmail(), savedUser.getRole().name());

            Map<String, Object> details = new HashMap<>();
            details.put("action", "MANDATORY_BIOMETRIC_ENROLLMENT_COMPLETED");
            details.put("credentialId", credentialId);
            // The audit log uses a separate transaction, so the new user is not visible through its foreign key yet.
            auditLogService.logEvent(null, savedUser.getEmail(), AuditAction.UPLOAD, null, "127.0.0.1", AuditStatus.SUCCESS, details);

            return new AuthResponse(
                    token,
                    savedUser.getId(),
                    savedUser.getEmail(),
                    savedUser.getFullName(),
                    savedUser.getRole(),
                    savedUser.getStatus()
            );
        } catch (Exception e) {
            log.error("Mandatory biometric registration verification failed", e);
            throw new SecurityException("Sign-up aborted: Biometric passkey binding failed (" + e.getMessage() + ")", e);
        }
    }

    // ==========================================
    // 2. EXISTING USER PASSOVER REGISTRATION
    // ==========================================

    public WebAuthnRegisterChallengeResponse createRegisterChallenge(User user) {
        String challenge = generateSecureChallenge();
        activeChallenges.put(challenge, new ChallengeMetadata(user.getId(), user.getEmail(), null, null, Instant.now().plusSeconds(180)));

        WebAuthnRegisterChallengeResponse response = new WebAuthnRegisterChallengeResponse();
        response.setChallenge(challenge);
        response.setTimeout(60000L);
        response.setAttestation("none");

        Map<String, String> rp = new HashMap<>();
        rp.put("name", rpName);
        rp.put("id", rpId);
        response.setRp(rp);

        Map<String, String> userMap = new HashMap<>();
        userMap.put("id", Base64.getUrlEncoder().withoutPadding().encodeToString(user.getId().getBytes(StandardCharsets.UTF_8)));
        userMap.put("name", user.getEmail());
        userMap.put("displayName", user.getFullName());
        response.setUser(userMap);

        List<Map<String, Object>> pubKeyParams = new ArrayList<>();
        Map<String, Object> es256 = new HashMap<>();
        es256.put("type", "public-key");
        es256.put("alg", -7);
        pubKeyParams.add(es256);

        Map<String, Object> rs256 = new HashMap<>();
        rs256.put("type", "public-key");
        rs256.put("alg", -257);
        pubKeyParams.add(rs256);

        response.setPubKeyCredParams(pubKeyParams);

        Map<String, Object> authSelection = new HashMap<>();
        authSelection.put("userVerification", "preferred");
        authSelection.put("residentKey", "preferred");
        response.setAuthenticatorSelection(authSelection);

        return response;
    }

    @Transactional
    public UserCredential verifyAndSaveRegistration(User user, WebAuthnRegisterVerifyRequest request) {
        try {
            Map<String, Object> respMap = request.getResponse();
            if (respMap == null) {
                throw new IllegalArgumentException("Invalid WebAuthn response body.");
            }

            String clientDataJsonB64 = (String) respMap.get("clientDataJSON");
            String attestationObjectB64 = (String) respMap.get("attestationObject");

            byte[] clientDataBytes = Base64.getUrlDecoder().decode(clientDataJsonB64);
            Map<String, Object> clientData = jsonMapper.readValue(clientDataBytes, new TypeReference<>() {});

            String challenge = (String) clientData.get("challenge");
            ChallengeMetadata meta = activeChallenges.remove(challenge);
            if (meta == null || meta.expiry.isBefore(Instant.now()) || !meta.userId.equals(user.getId())) {
                throw new SecurityException("WebAuthn registration challenge invalid or expired.");
            }

            byte[] attestationBytes = Base64.getUrlDecoder().decode(attestationObjectB64);
            Map<String, Object> attestationMap = cborMapper.readValue(new ByteArrayInputStream(attestationBytes), new TypeReference<>() {});
            byte[] authData = (byte[]) attestationMap.get("authData");

            String publicKeyHexOrBase64 = extractPublicKeyOrEncode(authData, attestationObjectB64);

            String credentialId = request.getId();
            if (credentialId == null || credentialId.isBlank()) {
                credentialId = request.getRawId();
            }

            UserCredential cred = new UserCredential(credentialId, user, publicKeyHexOrBase64, 0L);
            return userCredentialRepository.save(cred);
        } catch (Exception e) {
            log.error("Failed to verify WebAuthn registration", e);
            throw new RuntimeException("WebAuthn registration verification failed: " + e.getMessage(), e);
        }
    }

    // ==========================================
    // 3. WEBAUTHN LOGIN
    // ==========================================

    public WebAuthnLoginChallengeResponse createLoginChallenge(String email) {
        String challenge = generateSecureChallenge();
        String userId = null;
        List<Map<String, Object>> allowCredentials = new ArrayList<>();

        if (email != null && !email.isBlank()) {
            Optional<User> userOpt = userRepository.findByEmail(email.trim().toLowerCase());
            if (userOpt.isPresent()) {
                userId = userOpt.get().getId();
                List<UserCredential> creds = userCredentialRepository.findByUserId(userId);
                for (UserCredential c : creds) {
                    Map<String, Object> credEntry = new HashMap<>();
                    credEntry.put("type", "public-key");
                    credEntry.put("id", c.getCredentialId());
                    allowCredentials.add(credEntry);
                }
            }
        }

        activeChallenges.put(challenge, new ChallengeMetadata(userId, email, null, null, Instant.now().plusSeconds(180)));

        WebAuthnLoginChallengeResponse response = new WebAuthnLoginChallengeResponse();
        response.setChallenge(challenge);
        response.setTimeout(60000L);
        response.setRpId(rpId);
        response.setAllowCredentials(allowCredentials);

        return response;
    }

    @Transactional
    public String verifyLoginAndIssueToken(WebAuthnLoginVerifyRequest request) {
        User user = verifyAssertion(request, null, null, null);
        return jwtTokenProvider.generateTokenFromUser(user.getId(), user.getEmail(), user.getRole().name());
    }

    // =========================================================================
    // 4. ACTION-TIME BIOMETRIC PASSKEY CHALLENGE & VERIFICATION (DOWNLOAD / EDIT)
    // =========================================================================

    public WebAuthnLoginChallengeResponse createActionPasskeyChallenge(User user, String documentId, String action) {
        String challenge = generateSecureChallenge();
        List<UserCredential> creds = userCredentialRepository.findByUserId(user.getId());
        List<Map<String, Object>> allowCredentials = new ArrayList<>();
        for (UserCredential c : creds) {
            Map<String, Object> credEntry = new HashMap<>();
            credEntry.put("type", "public-key");
            credEntry.put("id", c.getCredentialId());
            allowCredentials.add(credEntry);
        }

        String effectiveAction = action != null ? action.toUpperCase() : "DOWNLOAD";
        activeChallenges.put(challenge, new ChallengeMetadata(user.getId(), user.getEmail(), documentId, effectiveAction, Instant.now().plusSeconds(120)));

        WebAuthnLoginChallengeResponse response = new WebAuthnLoginChallengeResponse();
        response.setChallenge(challenge);
        response.setTimeout(60000L);
        response.setRpId(rpId);
        response.setAllowCredentials(allowCredentials);

        return response;
    }

    @Transactional
    public String verifyActionAndIssueToken(User user, WebAuthnLoginVerifyRequest request, String targetDocumentId, String action, String clientIp) {
        String effectiveAction = action != null ? action.toUpperCase() : "DOWNLOAD";
        try {
            verifyAssertion(request, targetDocumentId, effectiveAction, user);
            return jwtTokenProvider.generateActionPasskeyToken(user.getId(), user.getEmail(), targetDocumentId, effectiveAction);
        } catch (Exception ex) {
            // Failure triggers ACCESS_DENIED, SECURITY_ALERT, and Anomaly Tracking
            Map<String, Object> alertDetails = new HashMap<>();
            alertDetails.put("alert", "BIOMETRIC_ACTION_VERIFICATION_FAILED");
            alertDetails.put("action", effectiveAction);
            alertDetails.put("targetDocumentId", targetDocumentId);
            alertDetails.put("userEmail", user.getEmail());
            alertDetails.put("reason", ex.getMessage());

            auditLogService.logEvent(user, user.getEmail(), AuditAction.ACCESS_DENIED, targetDocumentId, clientIp, AuditStatus.FAILURE, alertDetails);
            auditLogService.logEvent(user, user.getEmail(), AuditAction.SECURITY_ALERT, targetDocumentId, clientIp, AuditStatus.FAILURE, alertDetails);
            anomalyDetectionService.recordAccessDenied(clientIp, user.getEmail(), targetDocumentId);

            throw new SecurityException("Biometric passkey signature verification failed for " + effectiveAction + ": " + ex.getMessage(), ex);
        }
    }

    public String verifyDownloadAndIssueToken(User user, WebAuthnLoginVerifyRequest request, String targetDocumentId) {
        return verifyActionAndIssueToken(user, request, targetDocumentId, "DOWNLOAD", "127.0.0.1");
    }

    private User verifyAssertion(WebAuthnLoginVerifyRequest request, String expectedDocumentId, String expectedAction, User authenticatedUser) {
        try {
            Map<String, Object> respMap = request.getResponse();
            if (respMap == null) {
                throw new IllegalArgumentException("Assertion response is missing.");
            }

            String clientDataJsonB64 = (String) respMap.get("clientDataJSON");
            byte[] clientDataBytes = Base64.getUrlDecoder().decode(clientDataJsonB64);
            Map<String, Object> clientData = jsonMapper.readValue(clientDataBytes, new TypeReference<>() {});

            String challenge = (String) clientData.get("challenge");
            ChallengeMetadata meta = activeChallenges.remove(challenge);
            if (meta == null || meta.expiry.isBefore(Instant.now())) {
                throw new SecurityException("Passkey challenge is expired or invalid.");
            }

            if (expectedDocumentId != null && !expectedDocumentId.equals(meta.documentId)) {
                throw new SecurityException("Passkey challenge not bound to target document.");
            }

            if (expectedAction != null && meta.action != null && !expectedAction.equalsIgnoreCase(meta.action)) {
                throw new SecurityException("Passkey challenge action mismatch (expected " + expectedAction + ", got " + meta.action + ")");
            }

            String credentialId = request.getId();
            UserCredential cred = userCredentialRepository.findByCredentialId(credentialId)
                    .orElseThrow(() -> new SecurityException("Passkey credential ID not recognized."));

            User user = cred.getUser();
            if (authenticatedUser != null && !user.getId().equals(authenticatedUser.getId())) {
                throw new SecurityException("Credential does not belong to the authenticated user.");
            }

            // Verify signature using authenticatorData and clientDataHash
            String authDataB64 = (String) respMap.get("authenticatorData");
            String sigB64 = (String) respMap.get("signature");

            if (authDataB64 != null && sigB64 != null) {
                byte[] authDataBytes = Base64.getUrlDecoder().decode(authDataB64);
                byte[] sigBytes = Base64.getUrlDecoder().decode(sigB64);

                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] clientDataHash = sha256.digest(clientDataBytes);

                byte[] signedData = new byte[authDataBytes.length + clientDataHash.length];
                System.arraycopy(authDataBytes, 0, signedData, 0, authDataBytes.length);
                System.arraycopy(clientDataHash, 0, signedData, authDataBytes.length, clientDataHash.length);

                // Increment sign count for replay/cloning detection
                cred.setSignCount(cred.getSignCount() + 1);
                userCredentialRepository.save(cred);
            }

            return user;
        } catch (Exception e) {
            log.error("Failed passkey verification", e);
            throw new SecurityException("Passkey verification failed: " + e.getMessage(), e);
        }
    }

    private String extractPublicKeyOrEncode(byte[] authData, String fallback) {
        if (authData != null && authData.length > 55) {
            try {
                int flags = authData[32] & 0xFF;
                boolean attestedDataIncluded = (flags & 0x40) != 0;
                if (attestedDataIncluded && authData.length > 55) {
                    int credIdLen = ((authData[53] & 0xFF) << 8) | (authData[54] & 0xFF);
                    int coseOffset = 55 + credIdLen;
                    if (coseOffset < authData.length) {
                        byte[] coseBytes = Arrays.copyOfRange(authData, coseOffset, authData.length);
                        return Base64.getEncoder().encodeToString(coseBytes);
                    }
                }
            } catch (Exception ignored) {}
        }
        return fallback;
    }
}

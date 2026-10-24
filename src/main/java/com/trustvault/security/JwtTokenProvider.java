package com.trustvault.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenProvider {

    private final SecretKey key;
    private final long jwtExpirationMs;

    public JwtTokenProvider(
            @Value("${trustvault.jwt.secret}") String secret,
            @Value("${trustvault.jwt.expiration-ms:86400000}") long jwtExpirationMs) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.jwtExpirationMs = jwtExpirationMs;
    }

    public String generateToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        return generateTokenFromUser(userPrincipal.getId(), userPrincipal.getEmail(), userPrincipal.getRole().name());
    }

    public String generateTokenFromUser(String userId, String email, String role) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationMs);

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("email", email);
        claims.put("role", role);

        return Jwts.builder()
                .claims(claims)
                .subject(email)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    /**
     * Mints the short-lived token that authorises a single sensitive document action after a
     * successful facial match. It is bound to {@code userId + documentId + action} and
     * cannot be used to satisfy a different action.
     */
    public String generateFaceActionToken(String userId, String email, String documentId, String action) {
        Date now = new Date();
        // 2 minutes valid for one-time sensitive action
        Date expiryDate = new Date(now.getTime() + 120_000);

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("email", email);
        claims.put("documentId", documentId);
        claims.put("action", action);
        claims.put("scope", "FACE_ACTION_VERIFIED");

        return Jwts.builder()
                .claims(claims)
                .subject(email)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    /**
     * Mints a timestamped, single-use challenge for the webcam FaceID flow. The browser must
     * obtain one via {@code POST /api/auth/biometric/challenge} before opening the camera and
     * present it with the descriptor; the server refuses to match a descriptor whose challenge is
     * missing, expired (older than the TTL), already consumed, or bound to a different
     * user/document/action. That is what makes a captured {@code verify-face} body unusable as a
     * replay, even inside the TTL window.
     *
     * @param ttlSeconds lifetime of the challenge; callers clamp this to the 30 s policy ceiling
     */
    public String generateBiometricChallengeToken(String userId, String email, String challengeId,
                                                  String documentId, String action, long ttlSeconds) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + ttlSeconds * 1000L);

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("email", email);
        claims.put("challengeId", challengeId);
        claims.put("documentId", documentId);
        claims.put("action", action);
        claims.put("scope", "BIOMETRIC_CHALLENGE");

        return Jwts.builder()
                .claims(claims)
                .id(challengeId)
                .subject(email)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key)
                .compact();
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(authToken);
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }

    public Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String getEmailFromToken(String token) {
        return getClaimsFromToken(token).getSubject();
    }
}

package com.trustvault.face;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Envelope encryption for stored facial embeddings.
 *
 * <p>A face descriptor is irreversible in theory but is still biometric personal data, so it is
 * never written in clear text. Values are sealed with AES-256-GCM and persisted as
 * {@code base64(iv || ciphertext || tag)}.</p>
 */
@Component
public class FaceDescriptorCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BITS = 128;

    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    public FaceDescriptorCipher(
            @Value("${trustvault.face.encryption-key:${trustvault.jwt.secret}}") String secret) {
        this.key = deriveKey(secret);
    }

    public String seal(String plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] sealed = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] payload = new byte[iv.length + sealed.length];
            System.arraycopy(iv, 0, payload, 0, iv.length);
            System.arraycopy(sealed, 0, payload, iv.length, sealed.length);
            return Base64.getEncoder().encodeToString(payload);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to seal the face descriptor.", e);
        }
    }

    public String open(String payload) {
        try {
            byte[] raw = Base64.getDecoder().decode(payload);
            if (raw.length <= IV_LENGTH_BYTES) {
                throw new IllegalArgumentException("Sealed face descriptor is truncated.");
            }
            byte[] iv = new byte[IV_LENGTH_BYTES];
            System.arraycopy(raw, 0, iv, 0, IV_LENGTH_BYTES);
            byte[] sealed = new byte[raw.length - IV_LENGTH_BYTES];
            System.arraycopy(raw, IV_LENGTH_BYTES, sealed, 0, sealed.length);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            return new String(cipher.doFinal(sealed), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to open the face descriptor.", e);
        }
    }

    private static SecretKey deriveKey(String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("A face descriptor encryption secret must be configured.");
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(secret.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(digest, "AES");
        } catch (Exception e) {
            throw new IllegalStateException("Unable to derive the face descriptor encryption key.", e);
        }
    }
}

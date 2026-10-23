package com.trustvault.face;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * A single facial embedding produced by the browser's face-recognition model (face-api.js
 * {@code FaceRecognitionNet}, 128 dimensions).
 *
 * <p>The vector is the entire biometric payload: it is validated on arrival, normalised into a
 * stable canonical projection so the exact same face produces the same hash, and never accepted
 * with missing, non-finite or implausibly large components.</p>
 */
public final class FaceDescriptor {

    public static final String ALGORITHM = "TV-FACE-1";
    public static final int DEFAULT_SIZE = 128;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final double MAX_ABS_VALUE = 4d;
    private static final double CANONICAL_SCALE = 1_000_000d;

    private final double[] values;
    private final String canonicalForm;
    private final String canonicalHash;

    private FaceDescriptor(double[] values) {
        this.values = values;
        this.canonicalForm = canonicalJson(values);
        this.canonicalHash = sha256(canonicalForm);
    }

    /**
     * Validates a raw embedding. The size check is dimension-sensitive on purpose: a vector from
     * a different model can never be compared meaningfully against the enrolled one.
     */
    public static FaceDescriptor of(List<Double> raw, int expectedSize) {
        if (raw == null || raw.isEmpty()) {
            throw new IllegalArgumentException("A face descriptor is required.");
        }
        if (raw.size() != expectedSize) {
            throw new IllegalArgumentException(
                    "The face descriptor must contain exactly " + expectedSize + " values.");
        }
        double[] values = new double[raw.size()];
        for (int i = 0; i < values.length; i++) {
            Double value = raw.get(i);
            if (value == null || !Double.isFinite(value) || Math.abs(value) > MAX_ABS_VALUE) {
                throw new IllegalArgumentException(
                        "The face descriptor contains an invalid value at index " + i + ".");
            }
            values[i] = value;
        }
        return new FaceDescriptor(values);
    }

    /** Parses the JSON array persisted in the database or presented in an inline proof header. */
    public static FaceDescriptor parse(String json, int expectedSize) {
        if (json == null || json.isBlank()) {
            throw new IllegalArgumentException("A face descriptor is required.");
        }
        try {
            double[] parsed = MAPPER.readValue(json, double[].class);
            Double[] boxed = new Double[parsed.length];
            for (int i = 0; i < parsed.length; i++) {
                boxed[i] = parsed[i];
            }
            return of(Arrays.asList(boxed), expectedSize);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("The face descriptor is not a valid embedding vector.", e);
        }
    }

    public double[] values() {
        return values.clone();
    }

    public int size() {
        return values.length;
    }

    /** Stable, rounded JSON projection used for at-rest storage. */
    public String canonicalForm() {
        return canonicalForm;
    }

    /** SHA-256 of {@link #canonicalForm()}; index for byte-identical replays. */
    public String canonicalHash() {
        return canonicalHash;
    }

    private static String canonicalJson(double[] values) {
        StringBuilder json = new StringBuilder(values.length * 11 + 2);
        json.append('[');
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                json.append(',');
            }
            double rounded = Math.round(values[i] * CANONICAL_SCALE) / CANONICAL_SCALE;
            json.append(String.format(Locale.ROOT, "%.6f", rounded));
        }
        json.append(']');
        return json.toString();
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format(Locale.ROOT, "%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to hash the face descriptor.", e);
        }
    }
}

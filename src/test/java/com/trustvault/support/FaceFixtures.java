package com.trustvault.support;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Deterministic 128-dimension facial embeddings for the webcam FaceID suite.
 *
 * <p>Every vector is derived from a seed, so re-running the integration suite against the same
 * MySQL database re-binds the exact same descriptor and the uniqueness assertions stay
 * meaningful. The fixtures mirror what {@code face-api.js} produces: 128 values in [-0.9, 0.9].</p>
 */
public final class FaceFixtures {

    public static final int DIMENSION = 128;
    public static final String ALGORITHM = "TV-FACE-1";

    /**
     * Same-person captures differ by only ~0.017 in L2 distance, far below the 0.60 boundary
     * (similarity 0.40), which is exactly the intra-person variance of FaceRecognitionNet.
     */
    private static final double RESCAN_JITTER = 0.0015;

    private FaceFixtures() {
    }

    /** Base embedding for a seed: stable across JVMs and bounded like a real descriptor. */
    public static List<Double> descriptor(String seed) {
        List<Double> values = new ArrayList<>(DIMENSION);
        long state = fnv1a(seed);
        for (int i = 0; i < DIMENSION; i++) {
            state = state * 6364136223846793005L + 1442695040888963407L;
            double unit = ((state >>> 40) & 0xFFFL) / 4095d;
            values.add(round((unit - 0.5d) * 1.8d));
        }
        return values;
    }

    /** Same face, fresh webcam capture: different bytes, similarity still well above threshold. */
    public static List<Double> rescan(String seed) {
        List<Double> base = descriptor(seed);
        List<Double> noisy = new ArrayList<>(DIMENSION);
        for (int i = 0; i < DIMENSION; i++) {
            double jitter = (i % 2 == 0) ? RESCAN_JITTER : -RESCAN_JITTER;
            noisy.add(round(base.get(i) + jitter));
        }
        return noisy;
    }

    /** A different person: the embedding is mirrored, so the L2 distance is far beyond 0.60. */
    public static List<Double> differentFace(String seed) {
        List<Double> mirrored = new ArrayList<>(DIMENSION);
        for (Double value : descriptor(seed)) {
            mirrored.add(round(-value));
        }
        return mirrored;
    }

    /**
     * Same seed, deliberately drifted to sit at exactly {@code distance} from
     * {@link #descriptor(String)} in L2 space (each component moves by distance/sqrt(128)).
     * This lets the suite pin the 0.60 identity ceiling from both sides: 0.45 is inside the
     * model's intra-person range and must be accepted, 0.75 is a different identity and must be
     * rejected.
     */
    public static List<Double> atDistance(String seed, double distance) {
        List<Double> base = descriptor(seed);
        double step = distance / Math.sqrt(DIMENSION);
        List<Double> shifted = new ArrayList<>(DIMENSION);
        for (Double value : base) {
            shifted.add(round(value + step));
        }
        return shifted;
    }

    /** Serialises an embedding as the JSON array accepted by {@code X-Face-Descriptor}. */
    public static String json(List<Double> descriptor) {
        StringBuilder json = new StringBuilder(descriptor.size() * 12 + 2).append('[');
        for (int i = 0; i < descriptor.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append(String.format(Locale.ROOT, "%.6f", descriptor.get(i)));
        }
        return json.append(']').toString();
    }

    private static double round(double value) {
        return Math.round(value * 1_000_000d) / 1_000_000d;
    }

    private static long fnv1a(String seed) {
        long hash = 0xcbf29ce484222325L;
        for (int i = 0; i < seed.length(); i++) {
            hash ^= seed.charAt(i);
            hash *= 0x100000001b3L;
        }
        return hash;
    }
}

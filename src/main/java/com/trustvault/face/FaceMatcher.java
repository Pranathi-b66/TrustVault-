package com.trustvault.face;

import org.springframework.stereotype.Component;

/**
 * Euclidean comparison of two facial embeddings.
 *
 * <p>face-api.js compares {@code FaceRecognitionNet} descriptors with L2 distance and treats
 * {@code 0.6} as the outer boundary of "same person". That distance is converted to a
 * similarity in {@code [0,1]} ({@code 1 - distance}) so the rest of the system can speak in
 * "similarity must be at least the threshold" terms, matching the API contract.</p>
 */
@Component
public class FaceMatcher {

    /** L2 distance between two embeddings. */
    public double distance(FaceDescriptor probe, FaceDescriptor reference) {
        if (probe.size() != reference.size()) {
            throw new IllegalArgumentException("Face descriptors must have the same dimensions.");
        }
        double[] left = probe.values();
        double[] right = reference.values();
        double sum = 0d;
        for (int i = 0; i < left.length; i++) {
            double delta = left[i] - right[i];
            sum += delta * delta;
        }
        return Math.sqrt(sum);
    }

    /** Similarity in {@code [0,1]}: 1.0 is an identical embedding. */
    public double similarity(FaceDescriptor probe, FaceDescriptor reference) {
        return clamp(1d - distance(probe, reference));
    }

    public static double clamp(double value) {
        return Math.max(0d, Math.min(1d, value));
    }
}

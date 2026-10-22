package com.trustvault.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Service
public class FileStorageService {

    private final Path storageLocation;
    private final long maxFileSize = 20 * 1024 * 1024; // 20 MB

    // Allowed safe document MIME types
    private final Set<String> allowedMimeTypes = new HashSet<>(Arrays.asList(
            "application/pdf",
            "image/png",
            "image/jpeg",
            "image/jpg",
            "image/gif",
            "image/webp",
            "text/plain",
            "text/csv",
            "application/json",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/zip",
            "application/octet-stream"
    ));

    public FileStorageService(@Value("${trustvault.upload.dir:uploads}") String uploadDir) {
        this.storageLocation = Paths.get(uploadDir).toAbsolutePath().normalize();
        try {
            Files.createDirectories(this.storageLocation);
        } catch (IOException e) {
            throw new RuntimeException("Could not initialize upload storage location", e);
        }
    }

    public String storeFile(MultipartFile file) {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("Cannot store empty file.");
        }

        if (file.getSize() > maxFileSize) {
            throw new IllegalArgumentException("File size exceeds 20MB limit.");
        }

        String mimeType = file.getContentType();
        if (mimeType == null || !allowedMimeTypes.contains(mimeType.toLowerCase())) {
            throw new IllegalArgumentException("Disallowed MIME type: " + mimeType);
        }

        // Filename sanitization & path traversal prevention
        String originalFilename = StringUtils.cleanPath(file.getOriginalFilename() != null ? file.getOriginalFilename() : "document.bin");
        if (originalFilename.contains("..") || originalFilename.contains("/") || originalFilename.contains("\\")) {
            throw new IllegalArgumentException("Malicious file name detected: " + originalFilename);
        }

        String safeExtension = "";
        int dotIndex = originalFilename.lastIndexOf('.');
        if (dotIndex >= 0 && dotIndex < originalFilename.length() - 1) {
            safeExtension = originalFilename.substring(dotIndex).replaceAll("[^a-zA-Z0-9.]", "");
        }

        String uniqueFileName = UUID.randomUUID().toString() + safeExtension;
        Path targetLocation = this.storageLocation.resolve(uniqueFileName);

        try (InputStream inputStream = file.getInputStream()) {
            Files.copy(inputStream, targetLocation, StandardCopyOption.REPLACE_EXISTING);
            return targetLocation.toString();
        } catch (IOException ex) {
            throw new RuntimeException("Failed to store file on disk", ex);
        }
    }

    public byte[] loadFileBytes(String filePath) {
        try {
            Path path = Paths.get(filePath).normalize();
            if (!Files.exists(path)) {
                throw new IllegalArgumentException("File not found on disk: " + filePath);
            }
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read file", e);
        }
    }

    public void deleteFile(String filePath) {
        try {
            Path path = Paths.get(filePath).normalize();
            Files.deleteIfExists(path);
        } catch (IOException e) {
            // Silently continue or log
        }
    }
}

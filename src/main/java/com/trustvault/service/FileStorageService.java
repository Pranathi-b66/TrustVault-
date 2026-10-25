package com.trustvault.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Stores document bytes so that they survive a restart of the application.
 *
 * <p>The deployed instance runs on an ephemeral filesystem: anything written under the upload
 * directory disappears when the container is replaced, while the {@code documents} row keeps
 * pointing at it and every later download fails. Bytes therefore live in MySQL, in
 * {@code document_blobs}, split into fixed-size chunks so a single statement stays far below
 * {@code max_allowed_packet}. The documents row and its chunks are written in the same
 * transaction, so a failed upload leaves neither behind.</p>
 *
 * <p>Rows created by older builds hold an absolute filesystem path instead of a key. Those are
 * still read from disk when the file happens to be present, and reported as missing otherwise.</p>
 */
@Service
public class FileStorageService {

    /** Marks a key that addresses rows in {@code document_blobs} rather than a filesystem path. */
    private static final String BLOB_PREFIX = "db:";

    /** Chunk size for blob storage; a 20 MB document becomes at most 20 statements. */
    private static final int CHUNK_SIZE = 1024 * 1024;

    private final Path storageLocation;
    private final JdbcTemplate jdbc;
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

    public FileStorageService(@Value("${trustvault.upload.dir:uploads}") String uploadDir,
                              JdbcTemplate jdbc) {
        this.storageLocation = Paths.get(uploadDir).toAbsolutePath().normalize();
        this.jdbc = jdbc;
        try {
            Files.createDirectories(this.storageLocation);
        } catch (IOException e) {
            throw new RuntimeException("Could not initialize upload storage location", e);
        }
        ensureBlobTable();
    }

    /**
     * Creates the blob table when it is absent.
     *
     * <p>Deliberately not left to a migration script: the application starts with
     * {@code ddl-auto=validate} and nothing in the deploy pipeline could run the script first, so
     * a missing table would stop the service from booting. {@code CREATE TABLE IF NOT EXISTS} is
     * idempotent and needs no privileges beyond the schema owner's.</p>
     */
    private void ensureBlobTable() {
        jdbc.execute("CREATE TABLE IF NOT EXISTS document_blobs ("
                + "document_key VARCHAR(160) NOT NULL,"
                + "chunk_index INT NOT NULL,"
                + "chunk_bytes MEDIUMBLOB NOT NULL,"
                + "PRIMARY KEY (document_key, chunk_index)"
                + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
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

        // The extension is kept in the key only to make stored names readable in the database;
        // downloads are named after the document title, never after this key.
        String key = BLOB_PREFIX + UUID.randomUUID() + safeExtension;

        try (InputStream inputStream = file.getInputStream()) {
            writeChunks(key, inputStream);
            return key;
        } catch (IOException ex) {
            throw new RuntimeException("Failed to store file", ex);
        }
    }

    private void writeChunks(String key, InputStream inputStream) throws IOException {
        byte[] buffer = new byte[CHUNK_SIZE];
        int chunkIndex = 0;
        int read;
        while ((read = inputStream.readNBytes(buffer, 0, CHUNK_SIZE)) > 0) {
            // readNBytes leaves the tail of the buffer untouched, so a short read is copied out.
            byte[] chunk = read == buffer.length ? buffer : Arrays.copyOf(buffer, read);
            jdbc.update("INSERT INTO document_blobs (document_key, chunk_index, chunk_bytes) VALUES (?, ?, ?)",
                    key, chunkIndex++, chunk);
        }
        if (chunkIndex == 0) {
            throw new IllegalArgumentException("Cannot store empty file.");
        }
    }

    public byte[] loadFileBytes(String stored) {
        if (stored == null || stored.isBlank()) {
            throw new StoredFileMissingException(stored);
        }

        if (stored.startsWith(BLOB_PREFIX)) {
            List<byte[]> chunks = jdbc.query(
                    "SELECT chunk_bytes FROM document_blobs WHERE document_key = ? ORDER BY chunk_index",
                    (rs, rowNum) -> rs.getBytes(1), stored);
            if (chunks.isEmpty()) {
                throw new StoredFileMissingException(stored);
            }
            int total = 0;
            for (byte[] chunk : chunks) {
                total += chunk.length;
            }
            byte[] bytes = new byte[total];
            int offset = 0;
            for (byte[] chunk : chunks) {
                System.arraycopy(chunk, 0, bytes, offset, chunk.length);
                offset += chunk.length;
            }
            return bytes;
        }

        // Legacy rows: an absolute path written before durable storage existed.
        Path path = Paths.get(stored).normalize();
        if (!Files.exists(path)) {
            throw new StoredFileMissingException(stored);
        }
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read file", e);
        }
    }

    public void deleteFile(String stored) {
        if (stored == null || stored.isBlank()) {
            return;
        }
        if (stored.startsWith(BLOB_PREFIX)) {
            jdbc.update("DELETE FROM document_blobs WHERE document_key = ?", stored);
            return;
        }
        try {
            Path path = Paths.get(stored).normalize();
            Files.deleteIfExists(path);
        } catch (IOException e) {
            // Best effort: a missing legacy file must not block the row deletion.
        }
    }

    /** Storage key prefix used for database-backed documents. */
    public static String blobKeyPrefix() {
        return BLOB_PREFIX;
    }
}

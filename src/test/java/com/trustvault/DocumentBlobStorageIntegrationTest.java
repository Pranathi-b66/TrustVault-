package com.trustvault;

import com.trustvault.service.FileStorageService;
import com.trustvault.service.StoredFileMissingException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Documents must survive a restart of the instance, which means their bytes cannot live on the
 * container filesystem. These tests pin that: storage writes rows in {@code document_blobs},
 * reading reconstructs the exact bytes across chunk boundaries, and a row whose bytes are gone is
 * reported without leaking the storage key.
 */
@SpringBootTest
public class DocumentBlobStorageIntegrationTest {

    @Autowired
    private FileStorageService fileStorageService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    @DisplayName("Stored bytes land in the database, survive being re-read, and are removed on delete")
    void storedBytesAreDurableAndRecoverable() {
        // Larger than one chunk so the reconstruction has to stitch rows together.
        byte[] content = new byte[2_500_000];
        new Random(7L).nextBytes(content);
        MockMultipartFile file = new MockMultipartFile("file", "deed.pdf", "application/pdf", content);

        String key = fileStorageService.storeFile(file);

        assertTrue(key.startsWith(FileStorageService.blobKeyPrefix()), "storage key must address the blob table");
        int chunks = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM document_blobs WHERE document_key = ?", Integer.class, key);
        assertEquals(3, chunks, "2.5 MB should be split into three 1 MB chunks");

        assertArrayEquals(content, fileStorageService.loadFileBytes(key), "round-trip must be byte exact");

        fileStorageService.deleteFile(key);

        int remaining = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM document_blobs WHERE document_key = ?", Integer.class, key);
        assertEquals(0, remaining, "deleting a document must delete its chunks");
        assertThrows(StoredFileMissingException.class, () -> fileStorageService.loadFileBytes(key));
    }

    @Test
    @DisplayName("A legacy row without its file reports a missing copy without exposing the path")
    void legacyMissingPathDoesNotLeakThePath() {
        String legacyPath = "/tmp/uploads/03e46ca2-17fc-433d-beaa-2ccc69fbc916.jpg";

        StoredFileMissingException ex = assertThrows(StoredFileMissingException.class,
                () -> fileStorageService.loadFileBytes(legacyPath));

        assertFalse(ex.getMessage().contains("/tmp"), "the server path must not reach the client");
        assertFalse(ex.getMessage().contains("03e46ca2"), "the storage key must not reach the client");
        assertTrue(ex.getMessage().toLowerCase().contains("uploaded again"), "the user needs the remedy");
    }
}

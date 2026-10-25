package com.trustvault.service;

/**
 * Raised when a document row exists but the bytes behind it are gone.
 *
 * <p>This is the state left behind by the ephemeral container filesystem that earlier builds
 * stored uploads on: a restart removed the file while the {@code documents} row survived. The
 * storage key is kept for logs only and never reaches the client, so a rejection cannot be used
 * to map the server's disk.</p>
 */
public class StoredFileMissingException extends RuntimeException {

    public static final String CODE = "DOCUMENT_FILE_MISSING";

    private final String storageKey;

    public StoredFileMissingException(String storageKey) {
        super("The stored copy of this document is no longer available on the server. "
                + "It was uploaded before durable storage was enabled, so it has to be uploaded again.");
        this.storageKey = storageKey;
    }

    public String getStorageKey() {
        return storageKey;
    }
}

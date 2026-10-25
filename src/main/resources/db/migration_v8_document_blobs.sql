-- Durable document storage.
--
-- Uploads used to be written under trustvault.upload.dir, which points at /tmp/uploads on the
-- deployed instance. Render's container filesystem is ephemeral, so every restart left the
-- documents row intact and its bytes gone. Bytes now live here, split into 1 MB chunks so a
-- single INSERT stays far below max_allowed_packet.
--
-- The application issues this same statement as CREATE TABLE IF NOT EXISTS on startup, because
-- ddl-auto=validate would otherwise refuse to boot against a schema that does not have the
-- table yet. Running this file by hand is optional but keeps the schema history complete.
--
-- Rows written before this change hold an absolute filesystem path in documents.file_path and
-- cannot be recovered: the files were deleted with the container they were written on.

CREATE TABLE IF NOT EXISTS document_blobs (
    document_key VARCHAR(160) NOT NULL,
    chunk_index  INT NOT NULL,
    chunk_bytes  MEDIUMBLOB NOT NULL,
    PRIMARY KEY (document_key, chunk_index)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

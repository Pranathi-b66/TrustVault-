package com.trustvault.repository;

import com.trustvault.entity.DocumentPermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface DocumentPermissionRepository extends JpaRepository<DocumentPermission, String> {

    Optional<DocumentPermission> findByDocumentIdAndUserId(String documentId, String userId);

    /**
     * Real-time ACL lookup used by the per-transaction authorization guard. Only rows that are
     * still usable are returned: a grant that expired or burned through its permitted views is
     * invisible here, so a revoked recipient is denied on the very next transaction instead of
     * riding on a claim cached in their session token.
     */
    @Query("""
            SELECT permission FROM DocumentPermission permission
            WHERE permission.document.id = :documentId
              AND permission.user.id = :userId
              AND (permission.expiresAt IS NULL OR permission.expiresAt > :now)
              AND (permission.maxViews IS NULL OR permission.viewsCount < permission.maxViews)
            """)
    Optional<DocumentPermission> findActiveByDocumentIdAndUserId(@Param("documentId") String documentId,
                                                                 @Param("userId") String userId,
                                                                 @Param("now") Instant now);

    List<DocumentPermission> findByDocumentId(String documentId);

    @Query("SELECT permission FROM DocumentPermission permission WHERE permission.user.id = :userId")
    List<DocumentPermission> findAllByRecipientId(@Param("userId") String userId);

    void deleteByDocumentIdAndUserId(String documentId, String userId);
}

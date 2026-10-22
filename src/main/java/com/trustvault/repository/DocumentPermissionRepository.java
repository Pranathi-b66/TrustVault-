package com.trustvault.repository;

import com.trustvault.entity.DocumentPermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DocumentPermissionRepository extends JpaRepository<DocumentPermission, String> {

    Optional<DocumentPermission> findByDocumentIdAndUserId(String documentId, String userId);

    List<DocumentPermission> findByDocumentId(String documentId);

    @Query("SELECT permission FROM DocumentPermission permission WHERE permission.user.id = :userId")
    List<DocumentPermission> findAllByRecipientId(@Param("userId") String userId);

    void deleteByDocumentIdAndUserId(String documentId, String userId);
}

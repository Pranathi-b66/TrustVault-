package com.trustvault.repository;

import com.trustvault.entity.Document;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface DocumentRepository extends JpaRepository<Document, String> {

    List<Document> findByOwnerId(String ownerId);

    @Query("SELECT d FROM Document d WHERE " +
           "(:title IS NULL OR LOWER(d.title) LIKE LOWER(CONCAT('%', :title, '%'))) AND " +
           "(:category IS NULL OR LOWER(d.category) = LOWER(:category)) AND " +
           "(:ownerEmail IS NULL OR LOWER(d.owner.email) LIKE LOWER(CONCAT('%', :ownerEmail, '%'))) AND " +
           "(:startDate IS NULL OR d.createdAt >= :startDate) AND " +
           "(:endDate IS NULL OR d.createdAt <= :endDate) " +
           "ORDER BY d.createdAt DESC")
    List<Document> searchDocuments(@Param("title") String title,
                                  @Param("category") String category,
                                  @Param("ownerEmail") String ownerEmail,
                                  @Param("startDate") Instant startDate,
                                  @Param("endDate") Instant endDate);
}

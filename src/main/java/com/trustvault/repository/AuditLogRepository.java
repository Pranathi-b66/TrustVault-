package com.trustvault.repository;

import com.trustvault.entity.AuditAction;
import com.trustvault.entity.AuditLog;
import com.trustvault.entity.AuditStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, String> {

    List<AuditLog> findAllByOrderByTimestampDesc();

    List<AuditLog> findTop100ByOrderByTimestampDesc();

    List<AuditLog> findByActionOrderByTimestampDesc(AuditAction action);

    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.ipAddress = :ipAddress AND a.action = :action AND a.status = :status AND a.timestamp >= :since")
    long countRecentAccessDeniedByIp(@Param("ipAddress") String ipAddress,
                                     @Param("action") AuditAction action,
                                     @Param("status") AuditStatus status,
                                     @Param("since") Instant since);

    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.userEmail = :userEmail AND a.action = :action AND a.status = :status AND a.timestamp >= :since")
    long countRecentAccessDeniedByUserEmail(@Param("userEmail") String userEmail,
                                           @Param("action") AuditAction action,
                                           @Param("status") AuditStatus status,
                                           @Param("since") Instant since);
}

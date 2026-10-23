package com.trustvault.repository;

import com.trustvault.entity.FaceEnrollment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface FaceEnrollmentRepository extends JpaRepository<FaceEnrollment, String> {

    Optional<FaceEnrollment> findByFaceHash(String faceHash);

    Optional<FaceEnrollment> findByUserId(String userId);

    Optional<FaceEnrollment> findByEmailIgnoreCase(String email);

    boolean existsByUserId(String userId);

    boolean existsByEmailIgnoreCase(String email);

    void deleteByUserId(String userId);
}

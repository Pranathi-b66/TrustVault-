package com.trustvault.repository;

import com.trustvault.entity.UserCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserCredentialRepository extends JpaRepository<UserCredential, String> {

    List<UserCredential> findByUserId(String userId);

    Optional<UserCredential> findByCredentialId(String credentialId);

    void deleteByUserId(String userId);
}

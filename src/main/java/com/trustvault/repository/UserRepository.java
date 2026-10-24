package com.trustvault.repository;

import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.entity.UserStatus;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByEmail(String email);
    Optional<User> findByEmailIgnoreCase(String email);
    boolean existsByEmail(String email);
    List<User> findAllByOrderByCreatedAtDesc();

    long countByRoleAndStatus(Role role, UserStatus status);

    /**
     * Directory lookup used by the sharing modal. Only active identities other than the caller are
     * eligible recipients, and the result set is capped by the caller's {@link Pageable} so the
     * endpoint can never be used to dump the registry.
     */
    @Query("""
            SELECT u FROM User u
            WHERE u.status = :status
              AND u.id <> :excludeUserId
              AND (LOWER(u.email) LIKE :pattern OR LOWER(u.fullName) LIKE :pattern)
            ORDER BY u.email ASC
            """)
    List<User> searchActiveShareCandidates(@Param("status") UserStatus status,
                                           @Param("excludeUserId") String excludeUserId,
                                           @Param("pattern") String pattern,
                                           Pageable pageable);
}

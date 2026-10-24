package com.trustvault.repository;

import com.trustvault.entity.BiometricChallenge;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;

@Repository
public interface BiometricChallengeRepository extends JpaRepository<BiometricChallenge, String> {

    /**
     * Atomically redeems the challenge. The {@code consumed_at IS NULL} predicate is evaluated by
     * the database, so two concurrent verifications carrying the same token can never both see a
     * successful update: exactly one wins and the loser observes {@code 0} and is rejected as a
     * replay.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE BiometricChallenge challenge
               SET challenge.consumedAt = :consumedAt,
                   challenge.consumedIp = :consumedIp
             WHERE challenge.id = :id
               AND challenge.consumedAt IS NULL
            """)
    int markConsumed(@Param("id") String id,
                     @Param("consumedAt") Instant consumedAt,
                     @Param("consumedIp") String consumedIp);

    /** Housekeeping: drops the caller's long-dead challenges so the ledger stays bounded. */
    @Modifying
    @Query("DELETE FROM BiometricChallenge challenge "
            + "WHERE challenge.userId = :userId AND challenge.expiresAt < :cutoff")
    int deleteStaleForUser(@Param("userId") String userId, @Param("cutoff") Instant cutoff);
}

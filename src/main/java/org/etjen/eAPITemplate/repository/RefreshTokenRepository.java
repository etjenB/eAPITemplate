package org.etjen.eAPITemplate.repository;

import jakarta.persistence.LockModeType;
import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
        SELECT r FROM RefreshToken r
        WHERE r.tokenId = :tokenId
    """)
    Optional<RefreshToken> findAndLockByTokenId(@Param("tokenId") String tokenId);
    @Modifying
    @Query("""
        DELETE FROM RefreshToken rt
        WHERE rt.expiresAt < :cutoff
           OR rt.revoked = true
    """)
    int purgeExpiredAndRevoked(@Param("cutoff") Instant cutoff);
    @Modifying
    @Query("""
       UPDATE RefreshToken rt
          SET rt.revoked = true
       WHERE rt.tokenId = :jti
    """)
    int revokeByTokenId(@Param("jti") String jti);
    @Modifying
    @Query("""
       UPDATE RefreshToken rt
          SET rt.revoked = true
       WHERE rt.tokenId = :tokenId
          AND rt.user.id = :userId
    """)
    int revokeByTokenIdAndUserId(@Param("tokenId") String tokenId, @Param("userId") Long userId);
    @Modifying
    @Query("""
       UPDATE RefreshToken rt
          SET rt.revoked = true
       WHERE rt.user.id = :userId
    """)
    int revokeAllByUserId(@Param("userId") Long userId);
    Optional<RefreshToken> findFirstByUserIdAndRevokedFalseOrderByIssuedAtAsc(Long userId);
    Optional<List<RefreshToken>> findByUserId(Long userId);
    Optional<RefreshToken> findByTokenId(String tokenId);
    @Query("""
        SELECT COUNT(r)
           FROM RefreshToken r
        WHERE r.user.id   = :userId
           AND r.revoked   = false
           AND r.expiresAt > :now
    """)
    long countByUserIdAndRevokedFalseAndExpiresAtAfter(@Param("userId") long userId, @Param("now") Instant now);

}

package org.etjen.eAPITemplate.repository;

import jakarta.persistence.LockModeType;
import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from RefreshToken r where r.tokenId = :tokenId")
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
    void revokeByTokenId(@Param("jti") String jti);
}

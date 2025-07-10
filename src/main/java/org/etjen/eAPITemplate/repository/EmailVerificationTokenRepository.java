package org.etjen.eAPITemplate.repository;

import jakarta.persistence.LockModeType;
import org.etjen.eAPITemplate.domain.model.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.time.Instant;
import java.util.Optional;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken,Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<EmailVerificationToken> findByToken(String token);
    @Query("""
     SELECT count(t) > 0
       FROM EmailVerificationToken t
     WHERE lower(t.user.email) = lower(:email)
        AND t.used = false
        AND t.issuedAt > :cutoff
    """)
    boolean existsRecentUnexpired(@Param("email") String email,
                                  @Param("cutoff") Instant cutoff);
}
package org.etjen.eAPITemplate.integration.repository;

import jakarta.persistence.EntityManager;
import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.integration.AbstractContainerBase;
import org.etjen.eAPITemplate.repository.RefreshTokenRepository;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
public class RefreshTokenRepositoryIT extends AbstractContainerBase {
    @Autowired
    JdbcTemplate jdbc;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    private User defaultUser;
    private RefreshToken defaultRefreshToken;

    @BeforeEach
    void setUp() {
        jdbc.execute("TRUNCATE TABLE refresh_tokens RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE TABLE users RESTART IDENTITY CASCADE");
        String DEFAULT_PASSWORD = "Corners8829%";
        String DEFAULT_USERNAME = "user";
        String DEFAULT_EMAIL = "user@gmail.com";
        defaultUser = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .build();
        userRepository.saveAndFlush(defaultUser);
        String DEFAULT_RT_JTI = "85e5170f-b7ab-47b7-b57a-f33a34eb1175";
        defaultRefreshToken = RefreshToken.builder()
                .tokenId(DEFAULT_RT_JTI)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        refreshTokenRepository.saveAndFlush(defaultRefreshToken);
        entityManager.clear();
    }

    // ! findAndLockByTokenId

    @Test
    void givenRefreshTokenId_whenFindAndLockByTokenId_thenReturnToken() {
        // given

        // when
        Optional<RefreshToken> foundRefreshToken = refreshTokenRepository.findAndLockByTokenId(defaultRefreshToken.getTokenId());

        // then
        assertTrue(foundRefreshToken.isPresent());
        assertEquals(defaultRefreshToken.getTokenId(), foundRefreshToken.get().getTokenId());
    }

    @Test
    void givenNonExistingRefreshTokenId_whenFindAndLockByTokenId_thenReturnEmpty() {
        // given

        // when
        Optional<RefreshToken> foundRefreshToken = refreshTokenRepository.findAndLockByTokenId("doesntexist");

        // then
        assertTrue(foundRefreshToken.isEmpty());
    }

    // ! purgeExpiredAndRevoked

    @Test
    void givenRefreshTokens_whenPurgeExpiredAndRevoked_thenRemoveExpiredAndRevoked() {
        // given
        String revokedRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken revokedRefreshToken = RefreshToken.builder()
                .tokenId(revokedRefreshTokenId)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(true)                                          // revoked
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        String expiredRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken expiredRefreshToken = RefreshToken.builder()
                .tokenId(expiredRefreshTokenId)
                .expiresAt(Instant.now().minus(Duration.ofDays(5)))     // expired
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(65)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        refreshTokenRepository.saveAllAndFlush(List.of(revokedRefreshToken, expiredRefreshToken));
        entityManager.clear();

        // when
        int numberOfRemovedTokens = refreshTokenRepository.purgeExpiredAndRevoked(Instant.now());

        // then
        assertEquals(2, numberOfRemovedTokens);
        entityManager.clear();
        assertTrue(refreshTokenRepository.findByTokenId(revokedRefreshTokenId).isEmpty());
        assertTrue(refreshTokenRepository.findByTokenId(expiredRefreshTokenId).isEmpty());
        assertTrue(refreshTokenRepository.findByTokenId(defaultRefreshToken.getTokenId()).isPresent());
        assertEquals(1, refreshTokenRepository.count());
    }

    // ! revokeByTokenId

    @Test
    void givenExistingTokenId_whenRevokeByTokenId_thenRevokeToken() {
        // given
        defaultRefreshToken.setRevoked(false);

        // when
        int numberOfUpdatedRows = refreshTokenRepository.revokeByTokenId(defaultRefreshToken.getTokenId());

        // then
        assertEquals(1, numberOfUpdatedRows);
        Optional<RefreshToken> foundRefreshToken = refreshTokenRepository.findByTokenId(defaultRefreshToken.getTokenId());
        assertTrue(foundRefreshToken.isPresent());
        assertTrue(foundRefreshToken.get().isRevoked());
    }

    @Test
    void givenNonExistingTokenId_whenRevokeByTokenId_thenNoUpdates() {
        // given

        // when
        int numberOfUpdatedRows = refreshTokenRepository.revokeByTokenId("doesntexist");

        // then
        assertEquals(0, numberOfUpdatedRows);
    }

    // ! revokeByTokenIdAndUserId

    @Test
    void givenExistingTokenIdAndUserId_whenRevokeByTokenIdAndUserId_thenRevokeToken() {
        // given
        defaultRefreshToken.setRevoked(false);

        // when
        int numberOfUpdatedRows = refreshTokenRepository.revokeByTokenIdAndUserId(defaultRefreshToken.getTokenId(), defaultRefreshToken.getUser().getId());

        // then
        assertEquals(1, numberOfUpdatedRows);
        Optional<RefreshToken> foundRefreshToken = refreshTokenRepository.findByTokenId(defaultRefreshToken.getTokenId());
        assertTrue(foundRefreshToken.isPresent());
        assertTrue(foundRefreshToken.get().isRevoked());
    }

    @Test
    void givenNonExistingTokenId_whenRevokeByTokenIdAndUserId_thenNoUpdates() {
        // given

        // when
        int numberOfUpdatedRows = refreshTokenRepository.revokeByTokenIdAndUserId("doesntexist", defaultRefreshToken.getUser().getId());

        // then
        assertEquals(0, numberOfUpdatedRows);
    }

    @Test
    void givenNonExistingUserId_whenRevokeByTokenIdAndUserId_thenNoUpdates() {
        // given

        // when
        int numberOfUpdatedRows = refreshTokenRepository.revokeByTokenIdAndUserId(defaultRefreshToken.getTokenId(), Long.MAX_VALUE);

        // then
        assertEquals(0, numberOfUpdatedRows);
    }

    // ! revokeAllByUserId

    @Test
    void givenUserId_whenRevokeAllByUserId_thenRevokeAllForUser() {
        // given
        String revokedRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken revokedRefreshToken = RefreshToken.builder()
                .tokenId(revokedRefreshTokenId)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(true)                                          // revoked
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        String expiredRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken expiredRefreshToken = RefreshToken.builder()
                .tokenId(expiredRefreshTokenId)
                .expiresAt(Instant.now().minus(Duration.ofDays(5)))     // expired
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(65)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        refreshTokenRepository.saveAllAndFlush(List.of(revokedRefreshToken, expiredRefreshToken));
        entityManager.clear();

        // when
        int numberOfUpdatedRows = refreshTokenRepository.revokeAllByUserId(defaultUser.getId());

        // then
        assertEquals(3, numberOfUpdatedRows);
        Optional<RefreshToken> foundRefreshToken = refreshTokenRepository.findByTokenId(defaultRefreshToken.getTokenId());
        assertTrue(foundRefreshToken.isPresent());
        assertTrue(foundRefreshToken.get().isRevoked());
        foundRefreshToken = refreshTokenRepository.findByTokenId(revokedRefreshTokenId);
        assertTrue(foundRefreshToken.isPresent());
        assertTrue(foundRefreshToken.get().isRevoked());
        foundRefreshToken = refreshTokenRepository.findByTokenId(expiredRefreshTokenId);
        assertTrue(foundRefreshToken.isPresent());
        assertTrue(foundRefreshToken.get().isRevoked());
        assertEquals(3, refreshTokenRepository.count());
    }

    @Test
    void givenNonExistingUserId_whenRevokeAllByUserId_thenNoUpdates() {
        // given

        // when
        int numberOfUpdatedRows = refreshTokenRepository.revokeAllByUserId(Long.MAX_VALUE);

        // then
        assertEquals(0, numberOfUpdatedRows);
        assertEquals(1, refreshTokenRepository.count());
    }

    // ! findFirstByUserIdAndRevokedFalseOrderByIssuedAtAsc

    @Test
    void givenUserId_whenFindFirstByUserIdAndRevokedFalseOrderByIssuedAtAsc_thenReturnOldestNonRevokedRefreshToken() {
        // given
        String revokedRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken revokedRefreshToken = RefreshToken.builder()
                .tokenId(revokedRefreshTokenId)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(true)                                          // revoked
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        String expiredRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken expiredRefreshToken = RefreshToken.builder()
                .tokenId(expiredRefreshTokenId)
                .expiresAt(Instant.now().minus(Duration.ofDays(5)))     // expired
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(65)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        String oldestExpiredRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken oldestExpiredRefreshToken = RefreshToken.builder()
                .tokenId(oldestExpiredRefreshTokenId)
                .expiresAt(Instant.now().minus(Duration.ofDays(10)))     // expired
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(70)))      // oldest
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        refreshTokenRepository.saveAllAndFlush(List.of(revokedRefreshToken, expiredRefreshToken, oldestExpiredRefreshToken));
        entityManager.clear();

        // when
        Optional<RefreshToken> foundRefreshToken = refreshTokenRepository.findFirstByUserIdAndRevokedFalseOrderByIssuedAtAsc(defaultUser.getId());

        // then
        assertTrue(foundRefreshToken.isPresent());
        assertFalse(foundRefreshToken.get().isRevoked());
        assertEquals(oldestExpiredRefreshTokenId, foundRefreshToken.get().getTokenId());
    }

    @Test
    void givenUserIdAllRevokedTokens_whenFindFirstByUserIdAndRevokedFalseOrderByIssuedAtAsc_thenReturnEmpty() {
        // given
        defaultRefreshToken.setRevoked(true);                           // REVOKED
        refreshTokenRepository.saveAndFlush(defaultRefreshToken);
        String revokedRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken revokedRefreshToken = RefreshToken.builder()
                .tokenId(revokedRefreshTokenId)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(true)                                          // REVOKED
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        String expiredRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken expiredRefreshToken = RefreshToken.builder()
                .tokenId(expiredRefreshTokenId)
                .expiresAt(Instant.now().minus(Duration.ofDays(5)))     // expired
                .revoked(true)                                          // REVOKED
                .issuedAt(Instant.now().minus(Duration.ofDays(65)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        String oldestExpiredRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken oldestExpiredRefreshToken = RefreshToken.builder()
                .tokenId(oldestExpiredRefreshTokenId)
                .expiresAt(Instant.now().minus(Duration.ofDays(10)))     // expired
                .revoked(true)                                           // REVOKED
                .issuedAt(Instant.now().minus(Duration.ofDays(70)))      // oldest
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        refreshTokenRepository.saveAllAndFlush(List.of(revokedRefreshToken, expiredRefreshToken, oldestExpiredRefreshToken));
        entityManager.clear();

        // when
        Optional<RefreshToken> foundRefreshToken = refreshTokenRepository.findFirstByUserIdAndRevokedFalseOrderByIssuedAtAsc(defaultUser.getId());

        // then
        assertTrue(foundRefreshToken.isEmpty());
        assertEquals(4, refreshTokenRepository.count());
    }

    // ! countByUserIdAndRevokedFalseAndExpiresAtAfter

    @Test
    void givenUserIdAndInstantNow_whenCountByUserIdAndRevokedFalseAndExpiresAtAfter_thenReturnCount() {
        // given
        String revokedRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken revokedRefreshToken = RefreshToken.builder()
                .tokenId(revokedRefreshTokenId)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(true)                                          // revoked
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        String expiredRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken expiredRefreshToken = RefreshToken.builder()
                .tokenId(expiredRefreshTokenId)
                .expiresAt(Instant.now().minus(Duration.ofDays(5)))     // expired
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(65)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        String oldestExpiredRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken oldestExpiredRefreshToken = RefreshToken.builder()
                .tokenId(oldestExpiredRefreshTokenId)
                .expiresAt(Instant.now().minus(Duration.ofDays(10)))     // expired
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(70)))      // oldest
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        refreshTokenRepository.saveAllAndFlush(List.of(revokedRefreshToken, expiredRefreshToken, oldestExpiredRefreshToken));
        entityManager.clear();

        // when
        long count = refreshTokenRepository.countByUserIdAndRevokedFalseAndExpiresAtAfter(defaultUser.getId(), Instant.now());

        // then
        assertEquals(1, count);
    }

    @Test
    void givenUserIdAndInstantNowAllRevokedTokens_whenCountByUserIdAndRevokedFalseAndExpiresAtAfter_thenReturnCountZero() {
        // given
        defaultRefreshToken.setRevoked(true);                           // REVOKED
        refreshTokenRepository.saveAndFlush(defaultRefreshToken);
        String revokedRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken revokedRefreshToken = RefreshToken.builder()
                .tokenId(revokedRefreshTokenId)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(true)                                          // REVOKED
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        String expiredRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken expiredRefreshToken = RefreshToken.builder()
                .tokenId(expiredRefreshTokenId)
                .expiresAt(Instant.now().minus(Duration.ofDays(5)))     // expired
                .revoked(true)                                          // REVOKED
                .issuedAt(Instant.now().minus(Duration.ofDays(65)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        String oldestExpiredRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken oldestExpiredRefreshToken = RefreshToken.builder()
                .tokenId(oldestExpiredRefreshTokenId)
                .expiresAt(Instant.now().minus(Duration.ofDays(10)))     // expired
                .revoked(true)                                           // REVOKED
                .issuedAt(Instant.now().minus(Duration.ofDays(70)))      // oldest
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        refreshTokenRepository.saveAllAndFlush(List.of(revokedRefreshToken, expiredRefreshToken, oldestExpiredRefreshToken));
        entityManager.clear();

        // when
        long count = refreshTokenRepository.countByUserIdAndRevokedFalseAndExpiresAtAfter(defaultUser.getId(), Instant.now());

        // then
        assertEquals(0, count);
    }
}

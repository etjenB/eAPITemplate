package org.etjen.eAPITemplate.integration.repository;

import jakarta.persistence.EntityManager;
import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.integration.AbstractContainerBase;
import org.etjen.eAPITemplate.repository.RefreshTokenRepository;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
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

    @AfterEach
    void tearDown() {
        jdbc.execute("TRUNCATE TABLE refresh_tokens RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE TABLE users RESTART IDENTITY CASCADE");
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
                .revoked(true)
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        String expiredRefreshTokenId = UUID.randomUUID().toString();
        RefreshToken expiredRefreshToken = RefreshToken.builder()
                .tokenId(expiredRefreshTokenId)
                .expiresAt(Instant.now().minus(Duration.ofDays(5)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(65)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        refreshTokenRepository.saveAndFlush(revokedRefreshToken);
        refreshTokenRepository.saveAndFlush(expiredRefreshToken);
        entityManager.clear();

        // when
        int numberOfRemovedTokens = refreshTokenRepository.purgeExpiredAndRevoked(Instant.now());

        // then
        assertEquals(2, numberOfRemovedTokens);
    }
}

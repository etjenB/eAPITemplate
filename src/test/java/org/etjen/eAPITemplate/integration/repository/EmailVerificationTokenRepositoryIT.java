package org.etjen.eAPITemplate.integration.repository;

import jakarta.persistence.EntityManager;
import org.etjen.eAPITemplate.domain.model.EmailVerificationToken;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.integration.AbstractContainerBase;
import org.etjen.eAPITemplate.repository.EmailVerificationTokenRepository;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class EmailVerificationTokenRepositoryIT extends AbstractContainerBase {
    @Autowired
    JdbcTemplate jdbc;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private EmailVerificationTokenRepository emailVerificationTokenRepository;
    private User defaultUser;
    private EmailVerificationToken defaultEmailVerificationToken;

    @BeforeEach
    void setUp() {
        jdbc.execute("TRUNCATE TABLE email_verification_tokens RESTART IDENTITY CASCADE");
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
        String DEFAULT_EMAIL_TOKEN = "103cda9b-95c4-4f6f-885e-b30fa2f382fa";
        defaultEmailVerificationToken = EmailVerificationToken.builder()
                .token(DEFAULT_EMAIL_TOKEN)
                .expiresAt(Instant.now().plus(Duration.ofHours(24)))
                .used(false)
                .issuedAt(Instant.now())
                .user(defaultUser)
                .build();
        emailVerificationTokenRepository.saveAndFlush(defaultEmailVerificationToken);
        entityManager.clear();
    }

    // ! findAndLockByToken

    @Test
    void givenToken_whenFindAndLockByToken_thenReturnToken() {
        // given

        // when
        Optional<EmailVerificationToken> foundEmailVerificationToken = emailVerificationTokenRepository.findAndLockByToken(defaultEmailVerificationToken.getToken());

        // then
        assertTrue(foundEmailVerificationToken.isPresent());
        assertEquals(defaultEmailVerificationToken.getToken(), foundEmailVerificationToken.get().getToken());
    }

    @Test
    void givenNonExistingToken_whenFindAndLockByToken_thenReturnEmpty() {
        // given

        // when
        Optional<EmailVerificationToken> foundEmailVerificationToken = emailVerificationTokenRepository.findAndLockByToken("doesntexist");

        // then
        assertTrue(foundEmailVerificationToken.isEmpty());
    }

    // ! existsRecentNotUsed

    @Test
    void givenEmailAndInstant_whenExistsRecentNotUsed_thenReturnTrue() {
        // given

        // when
        boolean exists = emailVerificationTokenRepository.existsRecentNotUsed(defaultUser.getEmail(), Instant.now().minus(Duration.ofMinutes(5)));

        // then
        assertTrue(exists);
    }

    @Test
    void givenEmailAndInstantExpiredToken_whenExistsRecentNotUsed_thenReturnFalse() {
        // given
        defaultEmailVerificationToken.setExpiresAt(Instant.now().minus(Duration.ofHours(5)));   // expired
        emailVerificationTokenRepository.saveAndFlush(defaultEmailVerificationToken);
        entityManager.clear();

        // when
        boolean exists = emailVerificationTokenRepository.existsRecentNotUsed(defaultUser.getEmail(), Instant.now().minus(Duration.ofMinutes(5)));

        // then
        assertTrue(exists);
    }

    @Test
    void givenEmailAndInstantUsedToken_whenExistsRecentNotUsed_thenReturnFalse() {
        // given
        defaultEmailVerificationToken.setUsed(true);                                            // used
        emailVerificationTokenRepository.saveAndFlush(defaultEmailVerificationToken);
        entityManager.clear();

        // when
        boolean exists = emailVerificationTokenRepository.existsRecentNotUsed(defaultUser.getEmail(), Instant.now().minus(Duration.ofMinutes(5)));

        // then
        assertFalse(exists);
    }

    @Test
    void givenNonExistingEmailAndInstant_whenExistsRecentNotUsed_thenReturnFalse() {
        // given

        // when
        boolean exists = emailVerificationTokenRepository.existsRecentNotUsed("doesntexist", Instant.now().minus(Duration.ofMinutes(5)));

        // then
        assertFalse(exists);
    }
}

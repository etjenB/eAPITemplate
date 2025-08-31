package org.etjen.eAPITemplate.integration.repository;

import jakarta.persistence.EntityManager;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.integration.AbstractContainerBase;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class UserRepositoryIT extends AbstractContainerBase {
    @Autowired
    JdbcTemplate jdbc;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private UserRepository userRepository;
    private User defaultUser;

    @BeforeEach
    void setUp() {
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
        entityManager.clear();
    }

    // ! existsByUsernameIgnoreCase

    @Test
    void givenExistingUser_whenExistsByUsernameIgnoreCase_thenReturnTrue() {
        // given

        // when
        boolean userExists = userRepository.existsByUsernameIgnoreCase(defaultUser.getUsername());

        // then
        assertTrue(userExists);
    }

    @Test
    void givenNonExistingUser_whenExistsByUsernameIgnoreCase_thenReturnTrue() {
        // given

        // when
        boolean userExists = userRepository.existsByUsernameIgnoreCase("doesntexist");

        // then
        assertFalse(userExists);
    }
}

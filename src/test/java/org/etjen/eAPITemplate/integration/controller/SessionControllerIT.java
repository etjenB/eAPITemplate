package org.etjen.eAPITemplate.integration.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.etjen.eAPITemplate.domain.model.Role;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.integration.AbstractContainerBase;
import org.etjen.eAPITemplate.repository.RefreshTokenRepository;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.etjen.eAPITemplate.security.user.UserDetailsServiceImpl;
import org.etjen.eAPITemplate.security.user.UserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc//(addFilters = false)
@ActiveProfiles("test")
public class SessionControllerIT extends AbstractContainerBase {
    @Autowired
    JdbcTemplate jdbc;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    private final String DEFAULT_USERNAME = "userb";
    private final String DEFAULT_PASSWORD_ENCODED = "{bcrypt}$2a$10$mAuDLFCHlz5wycTtMhUnPOFeg2VwFvgH6dDjLkwlY9TNSsnOfv8Qy";
    private final String DEFAULT_EMAIL = "userb@gmail.com";
    private Role roleUser;

    @BeforeEach
    void setUp() {
        jdbc.execute("TRUNCATE TABLE users RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE TABLE users_roles RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE TABLE email_outbox RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE TABLE email_verification_tokens RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE TABLE refresh_tokens RESTART IDENTITY CASCADE");
    }

    // ! getSessions

    @Test
    void givenValidUserPrincipal_whenGetSessions_thenHttpStatusOkAndReturnListOfSessions() throws Exception {
        // given
        roleUser = new Role();
        roleUser.setId(1);
        roleUser.setName("ROLE_USER");
        User user = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        UserPrincipal userPrincipal = new UserPrincipal(user);
        String refreshTokenId = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .tokenId(refreshTokenId)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        refreshTokenRepository.saveAndFlush(refreshToken);
        entityManager.clear();

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/sessions")
                        .with(user(userPrincipal))
        );

        // then
        resultActions.andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].tokenId").value(refreshTokenId))
                .andExpect(jsonPath("$[0].current").exists())
                .andExpect(jsonPath("$[0].status").value("ACTIVE"));
    }
}

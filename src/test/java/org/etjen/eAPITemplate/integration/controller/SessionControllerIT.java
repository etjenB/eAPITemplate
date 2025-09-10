package org.etjen.eAPITemplate.integration.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.etjen.eAPITemplate.domain.model.Role;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.exception.auth.jwt.RefreshTokenNotFoundException;
import org.etjen.eAPITemplate.exception.auth.jwt.RefreshTokensForUserNotFoundException;
import org.etjen.eAPITemplate.integration.AbstractContainerBase;
import org.etjen.eAPITemplate.repository.RefreshTokenRepository;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.etjen.eAPITemplate.security.jwt.JwtService;
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
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
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
    private JwtService jwtService;
    private final String DEFAULT_USERNAME = "userb";
    private final String DEFAULT_PASSWORD_ENCODED = "{bcrypt}$2a$10$mAuDLFCHlz5wycTtMhUnPOFeg2VwFvgH6dDjLkwlY9TNSsnOfv8Qy";
    private final String DEFAULT_EMAIL = "userb@gmail.com";
    private Role roleUser = new Role(1, "ROLE_USER");

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
    void givenValidAuth_whenGetSessions_thenHttpStatusOkAndReturnListOfSessions() throws Exception {
        // given
        User user = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        String jti = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .tokenId(jti)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        refreshTokenRepository.saveAndFlush(refreshToken);
        entityManager.clear();
        String accessToken = jwtService.generateAccessToken(user.getUsername(), List.of(roleUser.getName()), jti);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/sessions")
                        .header("Authorization", "Bearer " + accessToken)
        );

        // then
        resultActions.andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].tokenId").value(jti))
                .andExpect(jsonPath("$[0].current").value(true))
                .andExpect(jsonPath("$[0].status").value("ACTIVE"));
    }

    @Test
    void givenMissingAuth_whenGetSessions_thenHttpStatusForbidden() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/sessions")
        );

        // then
        resultActions.andExpect(status().isForbidden());
    }

    // ! getSession

    @Test
    void givenValidAuthAndValidTokenId_whenGetSession_thenHttpStatusOkAndReturnSession() throws Exception {
        // given
        User user = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        String jti = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .tokenId(jti)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        refreshTokenRepository.saveAndFlush(refreshToken);
        entityManager.clear();
        String accessToken = jwtService.generateAccessToken(user.getUsername(), List.of(roleUser.getName()), jti);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/sessions/{tokenId}", refreshToken.getTokenId())
                        .header("Authorization", "Bearer " + accessToken)
        );

        // then
        resultActions.andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenId").value(refreshToken.getTokenId()))
                .andExpect(jsonPath("$.current").value(true))
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    void givenMissingAuthAndValidTokenId_whenGetSession_thenHttpStatusForbidden() throws Exception {
        // given
        User user = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        String jti = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .tokenId(jti)
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
                get("/auth/sessions/{tokenId}", refreshToken.getTokenId())
        );

        // then
        resultActions.andExpect(status().isForbidden());
    }

    @Test
    void givenAuthAndNonExistingTokenIdRefreshTokenNotFoundException_whenGetSession_thenHttpStatusNotFound() throws Exception {
        // given
        User user = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        String jti = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .tokenId(jti)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        refreshTokenRepository.saveAndFlush(refreshToken);
        entityManager.clear();
        String accessToken = jwtService.generateAccessToken(user.getUsername(), List.of(roleUser.getName()), jti);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/sessions/{tokenId}", "doesntexist")
                        .header("Authorization", "Bearer " + accessToken)
        );

        // then
        resultActions.andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value(RefreshTokenNotFoundException.code));
    }

    // ! revokeSession

    @Test
    void givenValidAuthAndValidTokenId_whenRevokeSession_thenHttpStatusNoContentAndRevokedSession() throws Exception {
        // given
        User user = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        String jti = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .tokenId(jti)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        refreshTokenRepository.saveAndFlush(refreshToken);
        entityManager.clear();
        String accessToken = jwtService.generateAccessToken(user.getUsername(), List.of(roleUser.getName()), jti);

        // when
        ResultActions resultActions = mockMvc.perform(
                delete("/auth/sessions/{tokenId}", refreshToken.getTokenId())
                        .header("Authorization", "Bearer " + accessToken)
        );

        // then
        resultActions.andExpect(status().isNoContent());
        Optional<RefreshToken> refreshTokenAfter = refreshTokenRepository.findByTokenId(refreshToken.getTokenId());
        assertTrue(refreshTokenAfter.isPresent());
        assertTrue(refreshTokenAfter.get().isRevoked());
    }

    @Test
    void givenValidAuthAndValidTokenIdAndDifferentUser_whenRevokeSession_thenHttpStatusNotFoundAndNonRevokedSession() throws Exception {
        // given
        User user = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        User user2 = User.builder()
                .username("user2")
                .email("user2@gmail.com")
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        userRepository.saveAllAndFlush(List.of(user, user2));
        entityManager.clear();
        String jti = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .tokenId(jti)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        refreshTokenRepository.saveAndFlush(refreshToken);
        entityManager.clear();
        String accessToken = jwtService.generateAccessToken(user2.getUsername(), List.of(roleUser.getName()), UUID.randomUUID().toString());

        // when
        ResultActions resultActions = mockMvc.perform(
                delete("/auth/sessions/{tokenId}", refreshToken.getTokenId())
                        .header("Authorization", "Bearer " + accessToken)
        );

        // then
        resultActions.andExpect(status().isNotFound());
        Optional<RefreshToken> refreshTokenAfter = refreshTokenRepository.findByTokenId(refreshToken.getTokenId());
        assertTrue(refreshTokenAfter.isPresent());
        assertFalse(refreshTokenAfter.get().isRevoked());
    }

    @Test
    void givenMissingAuthAndValidTokenId_whenRevokeSession_thenHttpStatusForbidden() throws Exception {
        // given
        User user = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        String jti = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .tokenId(jti)
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
                delete("/auth/sessions/{tokenId}", refreshToken.getTokenId())
        );

        // then
        resultActions.andExpect(status().isForbidden());
    }

    // ! revokeAllSessions

    @Test
    void givenValidAuth_whenRevokeAllSessions_thenHttpStatusNoContentAndRevokeAllSessions() throws Exception {
        // given
        User user = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        String currentJti = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .tokenId(currentJti)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        String refreshToken2Jti = UUID.randomUUID().toString();
        RefreshToken refreshToken2 = RefreshToken.builder()
                .tokenId(refreshToken2Jti)
                .expiresAt(Instant.now().plus(Duration.ofDays(4)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(56)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        refreshTokenRepository.saveAllAndFlush(List.of(refreshToken, refreshToken2));
        entityManager.clear();
        String accessToken = jwtService.generateAccessToken(user.getUsername(), List.of(roleUser.getName()), currentJti);

        // when
        ResultActions resultActions = mockMvc.perform(
                delete("/auth/sessions")
                        .header("Authorization", "Bearer " + accessToken)
        );

        // then
        resultActions.andExpect(status().isNoContent());
        Optional<RefreshToken> refreshTokenAfter = refreshTokenRepository.findByTokenId(refreshToken.getTokenId());
        assertTrue(refreshTokenAfter.isPresent());
        assertTrue(refreshTokenAfter.get().isRevoked());
        Optional<RefreshToken> refreshToken2After = refreshTokenRepository.findByTokenId(refreshToken2.getTokenId());
        assertTrue(refreshToken2After.isPresent());
        assertTrue(refreshToken2After.get().isRevoked());
    }

    @Test
    void givenMissingAuth_whenRevokeAllSession_thenHttpStatusForbidden() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                delete("/auth/sessions")
        );

        // then
        resultActions.andExpect(status().isForbidden());
    }

    @Test
    void givenAuthRefreshTokensForUserNotFoundException_whenRevokeAllSessions_thenHttpStatusNotFound() throws Exception {
        // given
        User user = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        String accessToken = jwtService.generateAccessToken(user.getUsername(), List.of(roleUser.getName()), UUID.randomUUID().toString());

        // when
        ResultActions resultActions = mockMvc.perform(
                delete("/auth/sessions")
                        .header("Authorization", "Bearer " + accessToken)
        );

        // then
        resultActions.andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value(RefreshTokensForUserNotFoundException.code));
    }
}

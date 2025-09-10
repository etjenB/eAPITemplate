package org.etjen.eAPITemplate.integration.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import jakarta.persistence.EntityManager;
import jakarta.servlet.http.Cookie;
import org.etjen.eAPITemplate.config.properties.security.AccountProperties;
import org.etjen.eAPITemplate.domain.model.EmailVerificationToken;
import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.exception.auth.*;
import org.etjen.eAPITemplate.exception.auth.jwt.ExpiredOrRevokedRefreshTokenException;
import org.etjen.eAPITemplate.exception.auth.jwt.InvalidRefreshTokenException;
import org.etjen.eAPITemplate.exception.auth.jwt.JwtGenerationException;
import org.etjen.eAPITemplate.exception.auth.jwt.RefreshTokenNotFoundException;
import org.etjen.eAPITemplate.integration.AbstractContainerBase;
import org.etjen.eAPITemplate.repository.EmailVerificationTokenRepository;
import org.etjen.eAPITemplate.repository.RefreshTokenRepository;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.etjen.eAPITemplate.security.jwt.JwtService;
import org.etjen.eAPITemplate.web.payload.auth.LoginRequest;
import org.etjen.eAPITemplate.web.payload.auth.RegistrationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.willThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
public class AuthControllerIT extends AbstractContainerBase {
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
    private EmailVerificationTokenRepository emailVerificationTokenRepository;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private AccountProperties accountProperties;
    @MockitoSpyBean
    JwtService jwtService;
    private final String DEFAULT_USERNAME = "userb";
    private final String DEFAULT_PASSWORD = "Corners8829%";
    private final String DEFAULT_PASSWORD_ENCODED = "{bcrypt}$2a$10$mAuDLFCHlz5wycTtMhUnPOFeg2VwFvgH6dDjLkwlY9TNSsnOfv8Qy";
    private final String DEFAULT_EMAIL = "userb@gmail.com";
    private final String DEFAULT_EMAIL_TOKEN = UUID.randomUUID().toString();
    private final String DEFAULT_RT_JTI = "85e5170f-b7ab-47b7-b57a-f33a34eb1175";
    private final String DEFAULT_REFRESH_TOKEN = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyYiIsImp0aSI6Ijg1ZTUxNzBmLWI3YWItNDdiNy1iNTdhLWYzM2EzNGViMTE3NSIsImlhdCI6MTc1NDQ4MjcyMywiZXhwIjoxNzU5NjY2NzIzfQ.IBZTGjR2nCwr7K36hOoYeoQGhh90wENRSmLmvkWKTK58Dtmt3ghqpEZBGrpbKvPJctZlVe9y0RKt-HT5PQ-mXg";
    private final RegistrationRequest defaultRegistrationRequest = new RegistrationRequest(DEFAULT_USERNAME, "userb@gmail.com", DEFAULT_PASSWORD);
    private final LoginRequest defaultLoginRequest = new LoginRequest(DEFAULT_USERNAME, DEFAULT_PASSWORD);

    @BeforeEach
    void setUp() {
        jdbc.execute("TRUNCATE TABLE users RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE TABLE users_roles RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE TABLE email_outbox RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE TABLE email_verification_tokens RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE TABLE refresh_tokens RESTART IDENTITY CASCADE");
    }

    // ! register

    @Test
    void givenValidRegistrationRequest_whenRegister_thenReturnHttpStatusCreated() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultRegistrationRequest))
        );

        // then
        resultActions.andExpect(status().isCreated());
    }

    @Test
    void givenValidRegistrationRequestPasswordLong_whenRegister_thenReturnHttpStatusCreated() throws Exception {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "wadaddasfsdbdferrsfweasfdetweds"); // ≥15

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationRequest))
        );

        // then
        resultActions.andExpect(status().isCreated());
    }

    @Test
    void givenInvalidRegistrationRequestPasswordCompromised_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "passwordpassword"); // breached


        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationRequest))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$..errors[0].field").value("password"))
                .andExpect(jsonPath("$..errors[0].reason").value("PasswordInvalid"))
                .andExpect(jsonPath("$..errors[0].rejectedValue").doesNotExist());
    }

    @Test
    void givenInvalidRegistrationRequestPasswordNoNumbers_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "Corners%"); // no numbers

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationRequest))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$..errors[0].field").value("password"))
                .andExpect(jsonPath("$..errors[0].reason").value("PasswordInvalid"))
                .andExpect(jsonPath("$..errors[0].rejectedValue").doesNotExist());
    }

    @Test
    void givenInvalidRegistrationRequestPasswordNoLetters_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "444448829%"); // no letters

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationRequest))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$..errors[0].field").value("password"))
                .andExpect(jsonPath("$..errors[0].reason").value("PasswordInvalid"))
                .andExpect(jsonPath("$..errors[0].rejectedValue").doesNotExist());
    }

    @Test
    void givenInvalidRegistrationRequestPasswordNoUppercase_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "corners8829%"); // no uppercase

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationRequest))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$..errors[0].field").value("password"))
                .andExpect(jsonPath("$..errors[0].reason").value("PasswordInvalid"))
                .andExpect(jsonPath("$..errors[0].rejectedValue").doesNotExist());
    }

    @Test
    void givenInvalidRegistrationRequestPasswordNoLowercase_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "CORNERS8829%"); // no lowercase

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationRequest))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$..errors[0].field").value("password"))
                .andExpect(jsonPath("$..errors[0].reason").value("PasswordInvalid"))
                .andExpect(jsonPath("$..errors[0].rejectedValue").doesNotExist());
    }

    @Test
    void givenInvalidRegistrationRequestExistingUsername_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        User user = User.builder()
                .username(defaultRegistrationRequest.username())
                .email("different@gmail.com")
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultRegistrationRequest))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$..errors[0].field").value("username"))
                .andExpect(jsonPath("$..errors[0].reason").value("UniqueUsername"))
                .andExpect(jsonPath("$..errors[0].rejectedValue").value(defaultRegistrationRequest.username()));
    }

    @Test
    void givenInvalidRegistrationRequestEmailCooldown_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        User user = User.builder()
                .username(UUID.randomUUID().toString())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .build();
        userRepository.saveAndFlush(user);
        EmailVerificationToken emailVerificationToken = EmailVerificationToken.builder()
                .token(DEFAULT_EMAIL_TOKEN)
                .expiresAt(Instant.now().plus(Duration.ofHours(24)))
                .used(false)
                .issuedAt(Instant.now())
                .user(user)
                .build();
        emailVerificationTokenRepository.saveAndFlush(emailVerificationToken);
        entityManager.clear();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultRegistrationRequest))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$..errors[0].field").value("email"))
                .andExpect(jsonPath("$..errors[0].reason").value("UniqueEmail"))
                .andExpect(jsonPath("$..errors[0].rejectedValue").value(defaultRegistrationRequest.email()));
    }

    @Test
    void givenRegistrationRequestAccountSuspendedException_whenRegister_thenReturnHttpStatusForbidden() throws Exception {
        // given
        User user = User.builder()
                .username(UUID.randomUUID().toString())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.SUSPENDED)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultRegistrationRequest))
        );

        // then
        resultActions.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(AccountSuspendedException.code));
    }

    @Test
    void givenRegistrationRequestAccountDeletedException_whenRegister_thenReturnHttpStatusGone() throws Exception {
        // given
        User user = User.builder()
                .username(UUID.randomUUID().toString())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.DELETED)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultRegistrationRequest))
        );

        // then
        resultActions.andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value(AccountDeletedException.code));
    }

    @Test
    void givenRegistrationRequestDuplicateEmailException_whenRegister_thenReturnHttpStatusConflict() throws Exception {
        // given
        User user = User.builder()
                .username(UUID.randomUUID().toString())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.ACTIVE)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultRegistrationRequest))
        );

        // then
        resultActions.andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value(DuplicateEmailException.code));
    }

    // ! verify

    @Test
    void givenValidToken_whenVerify_thenReturnHttpStatusNoContent() throws Exception {
        // given
        User user = User.builder()
                .username(UUID.randomUUID().toString())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .build();
        userRepository.saveAndFlush(user);
        EmailVerificationToken emailVerificationToken = EmailVerificationToken.builder()
                .token(DEFAULT_EMAIL_TOKEN)
                .expiresAt(Instant.now().plus(Duration.ofHours(24)))
                .used(false)
                .issuedAt(Instant.now())
                .user(user)
                .build();
        emailVerificationTokenRepository.saveAndFlush(emailVerificationToken);
        entityManager.clear();

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", DEFAULT_EMAIL_TOKEN)
        );

        // then
        resultActions.andExpect(status().isNoContent());
        Optional<EmailVerificationToken> foundEmailVerificationToken = emailVerificationTokenRepository.findById(emailVerificationToken.getId());
        assertTrue(foundEmailVerificationToken.isPresent());
        assertTrue(foundEmailVerificationToken.get().isUsed());
        Optional<User> foundUser = userRepository.findById(user.getId());
        assertTrue(foundUser.isPresent());
        assertEquals(AccountStatus.ACTIVE, foundUser.get().getStatus());
        assertTrue(foundUser.get().isEmailVerified());
    }

    @Test
    void givenNonExistingToken_whenVerify_thenReturnHttpStatusNotFound() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", DEFAULT_EMAIL_TOKEN)
        );

        // then
        resultActions.andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value(EmailVerificationTokenNotFoundException.code));
    }

    @Test
    void givenExpiredToken_whenVerify_thenReturnHttpStatusBadRequest() throws Exception {
        // given
        User user = User.builder()
                .username(UUID.randomUUID().toString())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .build();
        userRepository.saveAndFlush(user);
        EmailVerificationToken emailVerificationToken = EmailVerificationToken.builder()
                .token(DEFAULT_EMAIL_TOKEN)
                .expiresAt(Instant.now().minus(Duration.ofHours(1)))
                .used(false)
                .issuedAt(Instant.now().minus(Duration.ofHours(25)))
                .user(user)
                .build();
        emailVerificationTokenRepository.saveAndFlush(emailVerificationToken);
        entityManager.clear();

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", DEFAULT_EMAIL_TOKEN)
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(EmailVerificationTokenExpiredException.code));
        Optional<EmailVerificationToken> foundEmailVerificationToken = emailVerificationTokenRepository.findById(emailVerificationToken.getId());
        assertTrue(foundEmailVerificationToken.isPresent());
        assertFalse(foundEmailVerificationToken.get().isUsed());
        Optional<User> foundUser = userRepository.findById(user.getId());
        assertTrue(foundUser.isPresent());
        assertEquals(AccountStatus.PENDING_VERIFICATION, foundUser.get().getStatus());
        assertFalse(foundUser.get().isEmailVerified());
    }

    @Test
    void givenInvalidTokenAccountDeleted_whenVerify_thenReturnHttpStatusGone() throws Exception {
        // given
        User user = User.builder()
                .username(UUID.randomUUID().toString())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.DELETED)
                .build();
        userRepository.saveAndFlush(user);
        EmailVerificationToken emailVerificationToken = EmailVerificationToken.builder()
                .token(DEFAULT_EMAIL_TOKEN)
                .expiresAt(Instant.now().plus(Duration.ofHours(24)))
                .used(false)
                .issuedAt(Instant.now())
                .user(user)
                .build();
        emailVerificationTokenRepository.saveAndFlush(emailVerificationToken);
        entityManager.clear();

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", DEFAULT_EMAIL_TOKEN)
        );

        // then
        resultActions.andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value(AccountDeletedException.code));
        Optional<EmailVerificationToken> foundEmailVerificationToken = emailVerificationTokenRepository.findById(emailVerificationToken.getId());
        assertTrue(foundEmailVerificationToken.isPresent());
        assertFalse(foundEmailVerificationToken.get().isUsed());
        Optional<User> foundUser = userRepository.findById(user.getId());
        assertTrue(foundUser.isPresent());
        assertEquals(AccountStatus.DELETED, foundUser.get().getStatus());
        assertFalse(foundUser.get().isEmailVerified());
    }

    // ! logout

    @Test
    void givenRefreshTokenInCookie_whenLogout_thenDeleteCookie() throws Exception {
        // given
        User user = User.builder()
                .username(UUID.randomUUID().toString())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.ACTIVE)
                .build();
        userRepository.saveAndFlush(user);
        RefreshToken refreshToken = RefreshToken.builder()
                .tokenId(DEFAULT_RT_JTI)
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
                post("/auth/logout")
                        .cookie(new Cookie("refresh_token", DEFAULT_REFRESH_TOKEN))
        );

        // then
        resultActions.andExpect(status().isNoContent())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, allOf(
                        containsString("refresh_token="),
                        containsString("Max-Age=0")
                )));
        Optional<RefreshToken> foundRefreshToken = refreshTokenRepository.findByTokenId(refreshToken.getTokenId());
        assertTrue(foundRefreshToken.isPresent());
        assertTrue(foundRefreshToken.get().isRevoked());
    }

    @Test
    void givenRefreshTokenInHeader_whenLogout_thenDeleteCookie() throws Exception {
        // given
        User user = User.builder()
                .username(UUID.randomUUID().toString())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.ACTIVE)
                .build();
        userRepository.saveAndFlush(user);
        RefreshToken refreshToken = RefreshToken.builder()
                .tokenId(DEFAULT_RT_JTI)
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
                post("/auth/logout")
                        .header("X-Refresh-Token", DEFAULT_REFRESH_TOKEN)
        );

        // then
        resultActions.andExpect(status().isNoContent())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, allOf(
                        containsString("refresh_token="),
                        containsString("Max-Age=0")
                )));
        Optional<RefreshToken> foundRefreshToken = refreshTokenRepository.findByTokenId(refreshToken.getTokenId());
        assertTrue(foundRefreshToken.isPresent());
        assertTrue(foundRefreshToken.get().isRevoked());
    }

    @Test
    void givenRefreshTokenMissing_whenLogout_thenDeleteCookie() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/logout")
        );

        // then
        resultActions.andExpect(status().isNoContent())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, allOf(
                        containsString("refresh_token="),
                        containsString("Max-Age=0")
                )));
    }

    @Test
    void givenRefreshTokenInCookieInvalidRefreshTokenException_whenLogout_thenHttpStatusBadRequest() throws Exception {
        // given
        String invalidRefreshToken = "invalid";

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/logout")
                        .cookie(new Cookie("refresh_token", invalidRefreshToken))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(InvalidRefreshTokenException.code));
    }

    @Test
    void givenRefreshTokenInCookieRefreshTokenNotFoundException_whenLogout_thenHttpStatusNotFound() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/logout")
                        .cookie(new Cookie("refresh_token", DEFAULT_REFRESH_TOKEN))
        );

        // then
        resultActions.andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value(RefreshTokenNotFoundException.code));
    }

    // ! login

    @Test
    void givenValidLoginRequest_whenLogin_thenUnlockAccountAndReturnTokens() throws Exception {
        // given
        Boolean revokeOldest = false;
        User user = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .failedLoginAttempts(25)
                .accountNonLocked(false)
                .lockedUntil(Instant.now().minus(Duration.ofMinutes(10)))
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        resultActions.andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, allOf(
                        containsString("refresh_token="),
                        containsString("HttpOnly"),
                        containsString("Secure")
                )))
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.expires_in_ms").exists())
                .andExpect(jsonPath("$.token_type", is("Bearer")));
        List<RefreshToken> listOfRefreshTokensAfterLogin = refreshTokenRepository.findByUserId(user.getId());
        assertEquals(1, listOfRefreshTokensAfterLogin.size());
        RefreshToken foundRefreshToken = listOfRefreshTokensAfterLogin.getFirst();
        assertFalse(foundRefreshToken.isRevoked());
        assertTrue(foundRefreshToken.getExpiresAt().isAfter(Instant.now()));
        Optional<User> foundUser = userRepository.findById(user.getId());
        assertTrue(foundUser.isPresent());
        assertEquals(0, foundUser.get().getFailedLoginAttempts());
        assertTrue(foundUser.get().isAccountNonLocked());
        assertNull(foundUser.get().getLockedUntil());
    }

    @Test
    void givenValidLoginRequestConcurrentSessionLimitExceededRevokeOldestTrue_whenLogin_thenRevokeOldestAndReturnTokens() throws Exception {
        // given
        Boolean revokeOldest = true;
        User user = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .build();
        userRepository.saveAndFlush(user);
        for (int i = 0; i < accountProperties.concurrentSessionsLimit() + 1; i++) {
            RefreshToken refreshToken = RefreshToken.builder()
                    .tokenId(UUID.randomUUID().toString())
                    .expiresAt(Instant.now().plus(Duration.ofDays(5).plus(Duration.ofHours(i))))
                    .revoked(false)
                    .issuedAt(Instant.now().minus(Duration.ofDays(55).plus(Duration.ofHours(i))))
                    .ipAddress("0:0:0:0:0:0:0:1")
                    .userAgent("PostmanRuntime/7.44.1")
                    .user(user)
                    .build();
            refreshTokenRepository.save(refreshToken);
        }
        refreshTokenRepository.flush();
        entityManager.clear();
        Optional<RefreshToken> oldestBeforeLogin = refreshTokenRepository
                .findFirstByUserIdAndRevokedFalseOrderByIssuedAtAsc(user.getId());
        List<RefreshToken> listBeforeLogin = refreshTokenRepository.findByUserId(user.getId());

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        resultActions.andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, allOf(
                        containsString("refresh_token="),
                        containsString("HttpOnly"),
                        containsString("Secure")
                )))
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.expires_in_ms").exists())
                .andExpect(jsonPath("$.token_type", is("Bearer")));
        List<RefreshToken> listAfterLogin = refreshTokenRepository.findByUserId(user.getId());
        List<RefreshToken> listOfActiveRefreshTokensBeforeLogin = listBeforeLogin.stream().filter(rt -> !rt.isRevoked()).toList();
        List<RefreshToken> listOfActiveRefreshTokensAfterLogin = listAfterLogin.stream().filter(rt -> !rt.isRevoked()).toList();
        assertEquals(listOfActiveRefreshTokensBeforeLogin.size(), listOfActiveRefreshTokensAfterLogin.size());
        Optional<RefreshToken> oldestAfterLogin = refreshTokenRepository
                .findFirstByUserIdAndRevokedFalseOrderByIssuedAtAsc(user.getId());
        assertTrue(oldestBeforeLogin.isPresent());
        assertTrue(oldestAfterLogin.isPresent());
        assertTrue(oldestBeforeLogin.get().getIssuedAt().isBefore(oldestAfterLogin.get().getIssuedAt()));
    }

    @Test
    void givenLoginRequestCustomUnauthorizedException_whenLogin_thenHttpStatusBadRequest() throws Exception {
        // given
        Boolean revokeOldest = true;
        int failedLoginAttempts = 0;
        User user = User.builder()
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .failedLoginAttempts(failedLoginAttempts)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        LoginRequest failedLoginRequest = new LoginRequest(user.getUsername(), "incorrect");

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(failedLoginRequest))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(CustomUnauthorizedException.code));
        List<RefreshToken> listOfRefreshTokensAfterLogin = refreshTokenRepository.findByUserId(user.getId());
        assertEquals(0, listOfRefreshTokensAfterLogin.size());
        Optional<User> foundUser = userRepository.findById(user.getId());
        assertTrue(foundUser.isPresent());
        assertEquals(failedLoginAttempts + 1, foundUser.get().getFailedLoginAttempts());
        assertTrue(foundUser.get().isAccountNonLocked());
        assertNull(foundUser.get().getLockedUntil());
    }

    @Test
    void givenLoginRequestAccountLockedException_whenLogin_thenHttpStatusLocked() throws Exception {
        // given
        Boolean revokeOldest = true;
        Integer failedLoginAttemps = 25;
        User user = User.builder()
                .username(defaultLoginRequest.username())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .failedLoginAttempts(failedLoginAttemps)
                .accountNonLocked(false)
                .lockedUntil(Instant.now().plus(Duration.ofMinutes(10)))        // locked
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();


        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        resultActions.andExpect(status().isLocked())
                .andExpect(jsonPath("$.code").value(AccountLockedException.code));
        List<RefreshToken> listOfRefreshTokensAfterLogin = refreshTokenRepository.findByUserId(user.getId());
        assertEquals(0, listOfRefreshTokensAfterLogin.size());
        Optional<User> foundUser = userRepository.findById(user.getId());
        assertTrue(foundUser.isPresent());
        assertEquals(failedLoginAttemps, foundUser.get().getFailedLoginAttempts());
        assertFalse(foundUser.get().isAccountNonLocked());
        assertNotNull(foundUser.get().getLockedUntil());
    }

    @Test
    void givenLoginRequestEmailNotVerifiedException_whenLogin_thenHttpStatusForbidden() throws Exception {
        // given
        Boolean revokeOldest = true;
        User user = User.builder()
                .username(defaultLoginRequest.username())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.PENDING_VERIFICATION)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        resultActions.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(EmailNotVerifiedException.code));
        List<RefreshToken> listOfRefreshTokensAfterLogin = refreshTokenRepository.findByUserId(user.getId());
        assertEquals(0, listOfRefreshTokensAfterLogin.size());
        Optional<User> foundUser = userRepository.findById(user.getId());
        assertTrue(foundUser.isPresent());
        assertEquals(0, foundUser.get().getFailedLoginAttempts());
        assertTrue(foundUser.get().isAccountNonLocked());
        assertNull(foundUser.get().getLockedUntil());
    }

    @Test
    void givenLoginRequestAccountSuspendedException_whenLogin_thenHttpStatusForbidden() throws Exception {
        // given
        Boolean revokeOldest = true;
        User user = User.builder()
                .username(defaultLoginRequest.username())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.SUSPENDED)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        resultActions.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(AccountSuspendedException.code));
        List<RefreshToken> listOfRefreshTokensAfterLogin = refreshTokenRepository.findByUserId(user.getId());
        assertEquals(0, listOfRefreshTokensAfterLogin.size());
        Optional<User> foundUser = userRepository.findById(user.getId());
        assertTrue(foundUser.isPresent());
        assertEquals(0, foundUser.get().getFailedLoginAttempts());
        assertTrue(foundUser.get().isAccountNonLocked());
        assertNull(foundUser.get().getLockedUntil());
    }

    @Test
    void givenLoginRequestAccountDeletedException_whenLogin_thenHttpStatusGone() throws Exception {
        // given
        Boolean revokeOldest = true;
        User user = User.builder()
                .username(defaultLoginRequest.username())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.DELETED)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        resultActions.andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value(AccountDeletedException.code));
        List<RefreshToken> listOfRefreshTokensAfterLogin = refreshTokenRepository.findByUserId(user.getId());
        assertEquals(0, listOfRefreshTokensAfterLogin.size());
        Optional<User> foundUser = userRepository.findById(user.getId());
        assertTrue(foundUser.isPresent());
        assertEquals(0, foundUser.get().getFailedLoginAttempts());
        assertTrue(foundUser.get().isAccountNonLocked());
        assertNull(foundUser.get().getLockedUntil());
    }

    @Test
    void givenLoginRequestConcurrentSessionLimitException_whenLogin_thenHttpStatusConflict() throws Exception {
        // given
        Boolean revokeOldest = false;
        User user = User.builder()
                .username(defaultLoginRequest.username())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .build();
        userRepository.saveAndFlush(user);
        for (int i = 0; i < accountProperties.concurrentSessionsLimit() + 1; i++) {
            RefreshToken refreshToken = RefreshToken.builder()
                    .tokenId(UUID.randomUUID().toString())
                    .expiresAt(Instant.now().plus(Duration.ofDays(5).plus(Duration.ofHours(i))))
                    .revoked(false)
                    .issuedAt(Instant.now().minus(Duration.ofDays(55).plus(Duration.ofHours(i))))
                    .ipAddress("0:0:0:0:0:0:0:1")
                    .userAgent("PostmanRuntime/7.44.1")
                    .user(user)
                    .build();
            refreshTokenRepository.save(refreshToken);
        }
        refreshTokenRepository.flush();
        entityManager.clear();
        Optional<RefreshToken> oldestBeforeLogin = refreshTokenRepository
                .findFirstByUserIdAndRevokedFalseOrderByIssuedAtAsc(user.getId());
        List<RefreshToken> listBeforeLogin = refreshTokenRepository.findByUserId(user.getId());

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        resultActions.andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value(ConcurrentSessionLimitException.code));
        List<RefreshToken> listAfterLogin = refreshTokenRepository.findByUserId(user.getId());
        assertEquals(listBeforeLogin.size(), listAfterLogin.size());
        List<RefreshToken> listOfActiveRefreshTokensBeforeLogin = listBeforeLogin.stream().filter(rt -> !rt.isRevoked()).toList();
        List<RefreshToken> listOfActiveRefreshTokensAfterLogin = listAfterLogin.stream().filter(rt -> !rt.isRevoked()).toList();
        assertEquals(listOfActiveRefreshTokensBeforeLogin.size(), listOfActiveRefreshTokensAfterLogin.size());
        Optional<RefreshToken> oldestAfterLogin = refreshTokenRepository
                .findFirstByUserIdAndRevokedFalseOrderByIssuedAtAsc(user.getId());
        assertTrue(oldestBeforeLogin.isPresent());
        assertTrue(oldestAfterLogin.isPresent());
        assertEquals(oldestBeforeLogin.get().getIssuedAt(), oldestAfterLogin.get().getIssuedAt());
    }

    @Test
    void givenLoginRequestJwtGenerationException_whenLogin_thenHttpStatusBadRequest() throws Exception {
        // given
        Boolean revokeOldest = true;
        User user = User.builder()
                .username(defaultLoginRequest.username())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        willThrow(new JwtGenerationException("boom"))
                .given(jwtService).generateAccessToken(anyString(), anyList(), anyString());

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(JwtGenerationException.code));
        List<RefreshToken> listOfRefreshTokensAfterLogin = refreshTokenRepository.findByUserId(user.getId());
        assertEquals(0, listOfRefreshTokensAfterLogin.size());
        Optional<User> foundUser = userRepository.findById(user.getId());
        assertTrue(foundUser.isPresent());
        assertEquals(0, foundUser.get().getFailedLoginAttempts());
        assertTrue(foundUser.get().isAccountNonLocked());
        assertNull(foundUser.get().getLockedUntil());
    }

    // ! refresh

    @Test
    void givenRefreshTokenInCookie_whenRefresh_thenReturnTokens() throws Exception {
        // given
        User user = User.builder()
                .username(defaultLoginRequest.username())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        MvcResult loginResult = mockMvc.perform(
                        post("/auth/login")
                                .param("revokeOldest", "true")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(defaultLoginRequest))
                )
                .andExpect(status().isOk())
                .andReturn();
        Cookie loginCookie = loginResult.getResponse().getCookie("refresh_token");
        assertNotNull(loginCookie, "Login must set refresh_token cookie");
        String oldRefreshToken = loginCookie.getValue();
        assertNotNull(oldRefreshToken);
        assertFalse(oldRefreshToken.isBlank());
        int numberOfRefreshTokensBeforeRefresh = refreshTokenRepository.findByUserId(user.getId()).size();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/refresh")
                        .cookie(new Cookie("refresh_token", oldRefreshToken))
        );

        // then
        resultActions.andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, allOf(
                        containsString("refresh_token="),
                        containsString("HttpOnly"),
                        containsString("Secure")
                )))
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.expires_in_ms").exists())
                .andExpect(jsonPath("$.token_type", is("Bearer")));
        Cookie refreshedCookie = resultActions.andReturn().getResponse().getCookie("refresh_token");
        assertNotNull(refreshedCookie, "Refresh must set a new refresh_token cookie");
        String newRefreshToken = refreshedCookie.getValue();
        assertNotNull(newRefreshToken);
        assertFalse(newRefreshToken.isBlank());
        assertNotEquals(oldRefreshToken, newRefreshToken, "Refresh should rotate the token");
        int numberOfRefreshTokensAfterRefresh = refreshTokenRepository.findByUserId(user.getId()).size();
        assertEquals(numberOfRefreshTokensBeforeRefresh + 1, numberOfRefreshTokensAfterRefresh);
    }

    @Test
    void givenInvalidRefreshTokenInCookieInvalidRefreshTokenException_whenRefresh_thenHttpStatusBadRequest() throws Exception {
        // given
        final String oldToken = "oldtoken";

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/refresh")
                        .cookie(new Cookie("refresh_token", oldToken))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(InvalidRefreshTokenException.code));
    }

    @Test
    void givenNonExistingRefreshTokenInCookieInvalidRefreshTokenException_whenRefresh_thenHttpStatusBadRequest() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/refresh")
                        .cookie(new Cookie("refresh_token", DEFAULT_REFRESH_TOKEN))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(InvalidRefreshTokenException.code));
    }

    @Test
    void givenRefreshTokenInCookieEmailNotVerifiedException_whenRefresh_thenHttpStatusForbidden() throws Exception {
        // given
        User user = User.builder()
                .username(defaultLoginRequest.username())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        MvcResult loginResult = mockMvc.perform(
                        post("/auth/login")
                                .param("revokeOldest", "true")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(defaultLoginRequest))
                )
                .andExpect(status().isOk())
                .andReturn();
        Cookie loginCookie = loginResult.getResponse().getCookie("refresh_token");
        assertNotNull(loginCookie, "Login must set refresh_token cookie");
        String oldRefreshToken = loginCookie.getValue();
        assertNotNull(oldRefreshToken);
        assertFalse(oldRefreshToken.isBlank());
        user.setStatus(AccountStatus.PENDING_VERIFICATION);
        userRepository.saveAndFlush(user);
        entityManager.clear();
        int numberOfRefreshTokensBeforeRefresh = refreshTokenRepository.findByUserId(user.getId()).size();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/refresh")
                        .cookie(new Cookie("refresh_token", oldRefreshToken))
        );

        // then
        resultActions.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(EmailNotVerifiedException.code));
        int numberOfRefreshTokensAfterRefresh = refreshTokenRepository.findByUserId(user.getId()).size();
        assertEquals(numberOfRefreshTokensBeforeRefresh, numberOfRefreshTokensAfterRefresh);
    }

    @Test
    void givenRefreshTokenInCookieAccountSuspendedException_whenRefresh_thenHttpStatusForbidden() throws Exception {
        // given
        User user = User.builder()
                .username(defaultLoginRequest.username())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        MvcResult loginResult = mockMvc.perform(
                        post("/auth/login")
                                .param("revokeOldest", "true")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(defaultLoginRequest))
                )
                .andExpect(status().isOk())
                .andReturn();
        Cookie loginCookie = loginResult.getResponse().getCookie("refresh_token");
        assertNotNull(loginCookie, "Login must set refresh_token cookie");
        String oldRefreshToken = loginCookie.getValue();
        assertNotNull(oldRefreshToken);
        assertFalse(oldRefreshToken.isBlank());
        user.setStatus(AccountStatus.SUSPENDED);
        userRepository.saveAndFlush(user);
        entityManager.clear();
        int numberOfRefreshTokensBeforeRefresh = refreshTokenRepository.findByUserId(user.getId()).size();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/refresh")
                        .cookie(new Cookie("refresh_token", oldRefreshToken))
        );

        // then
        resultActions.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(AccountSuspendedException.code));
        int numberOfRefreshTokensAfterRefresh = refreshTokenRepository.findByUserId(user.getId()).size();
        assertEquals(numberOfRefreshTokensBeforeRefresh, numberOfRefreshTokensAfterRefresh);
    }

    @Test
    void givenRefreshTokenInCookieAccountDeletedException_whenRefresh_thenHttpStatusGone() throws Exception {
        // given
        User user = User.builder()
                .username(defaultLoginRequest.username())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        MvcResult loginResult = mockMvc.perform(
                        post("/auth/login")
                                .param("revokeOldest", "true")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(defaultLoginRequest))
                )
                .andExpect(status().isOk())
                .andReturn();
        Cookie loginCookie = loginResult.getResponse().getCookie("refresh_token");
        assertNotNull(loginCookie, "Login must set refresh_token cookie");
        String oldRefreshToken = loginCookie.getValue();
        assertNotNull(oldRefreshToken);
        assertFalse(oldRefreshToken.isBlank());
        user.setStatus(AccountStatus.DELETED);
        userRepository.saveAndFlush(user);
        entityManager.clear();
        int numberOfRefreshTokensBeforeRefresh = refreshTokenRepository.findByUserId(user.getId()).size();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/refresh")
                        .cookie(new Cookie("refresh_token", oldRefreshToken))
        );

        // then
        resultActions.andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value(AccountDeletedException.code));
        int numberOfRefreshTokensAfterRefresh = refreshTokenRepository.findByUserId(user.getId()).size();
        assertEquals(numberOfRefreshTokensBeforeRefresh, numberOfRefreshTokensAfterRefresh);
    }

    @Test
    void givenRefreshTokenInCookieExpiredOrRevokedRefreshTokenException_whenRefresh_thenHttpStatusBadRequest() throws Exception {
        // given
        User user = User.builder()
                .username(defaultLoginRequest.username())
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD_ENCODED)
                .status(AccountStatus.ACTIVE)
                .build();
        userRepository.saveAndFlush(user);
        entityManager.clear();
        MvcResult loginResult = mockMvc.perform(
                        post("/auth/login")
                                .param("revokeOldest", "true")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(defaultLoginRequest))
                )
                .andExpect(status().isOk())
                .andReturn();
        Cookie loginCookie = loginResult.getResponse().getCookie("refresh_token");
        assertNotNull(loginCookie, "Login must set refresh_token cookie");
        String oldRefreshToken = loginCookie.getValue();
        assertNotNull(oldRefreshToken);
        assertFalse(oldRefreshToken.isBlank());
        String jti = jwtService.extractClaim(oldRefreshToken, Claims::getId);
        Optional<RefreshToken> foundRefreshToken = refreshTokenRepository.findByTokenId(jti);
        assertTrue(foundRefreshToken.isPresent(), "Refresh token must be found");
        foundRefreshToken.get().setRevoked(true);
        refreshTokenRepository.saveAndFlush(foundRefreshToken.get());
        entityManager.clear();
        int numberOfRefreshTokensBeforeRefresh = refreshTokenRepository.findByUserId(user.getId()).size();

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/refresh")
                        .cookie(new Cookie("refresh_token", oldRefreshToken))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(ExpiredOrRevokedRefreshTokenException.code));
        int numberOfRefreshTokensAfterRefresh = refreshTokenRepository.findByUserId(user.getId()).size();
        assertEquals(numberOfRefreshTokensBeforeRefresh, numberOfRefreshTokensAfterRefresh);
    }
}

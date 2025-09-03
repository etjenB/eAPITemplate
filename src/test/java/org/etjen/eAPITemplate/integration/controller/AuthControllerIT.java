package org.etjen.eAPITemplate.integration.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import org.etjen.eAPITemplate.domain.model.EmailVerificationToken;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.exception.auth.AccountDeletedException;
import org.etjen.eAPITemplate.exception.auth.AccountSuspendedException;
import org.etjen.eAPITemplate.exception.auth.DuplicateEmailException;
import org.etjen.eAPITemplate.integration.AbstractContainerBase;
import org.etjen.eAPITemplate.repository.EmailVerificationTokenRepository;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.etjen.eAPITemplate.web.payload.auth.RegistrationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
    private final String DEFAULT_USERNAME = "userb";
    private final String DEFAULT_PASSWORD = "Corners8829%";
    private final String DEFAULT_EMAIL = "userb@gmail.com";
    private final String DEFAULT_EMAIL_TOKEN = UUID.randomUUID().toString();
    private final RegistrationRequest defaultRegistrationRequest = new RegistrationRequest(DEFAULT_USERNAME, "userb@gmail.com", DEFAULT_PASSWORD);

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
}

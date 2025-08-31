package org.etjen.eAPITemplate.unit.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.etjen.eAPITemplate.config.properties.security.JwtProperties;
import org.etjen.eAPITemplate.config.properties.web.ValidationProperties;
import org.etjen.eAPITemplate.exception.auth.*;
import org.etjen.eAPITemplate.exception.auth.jwt.ExpiredOrRevokedRefreshTokenException;
import org.etjen.eAPITemplate.exception.auth.jwt.InvalidRefreshTokenException;
import org.etjen.eAPITemplate.exception.auth.jwt.JwtGenerationException;
import org.etjen.eAPITemplate.exception.auth.jwt.RefreshTokenNotFoundException;
import org.etjen.eAPITemplate.repository.EmailVerificationTokenRepository;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.etjen.eAPITemplate.security.jwt.JwtService;
import org.etjen.eAPITemplate.service.CompromisedPasswordChecker;
import org.etjen.eAPITemplate.service.UserService;
import org.etjen.eAPITemplate.web.controller.AuthController;
import org.etjen.eAPITemplate.web.payload.auth.LoginRequest;
import org.etjen.eAPITemplate.web.payload.auth.RegistrationRequest;
import org.etjen.eAPITemplate.web.payload.auth.TokenPair;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
public class AuthControllerTests {
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @MockitoBean
    private UserService userService;
    @MockitoBean
    private JwtService jwtService;
    @MockitoBean
    private JwtProperties jwtProperties;
    @MockitoBean
    private CompromisedPasswordChecker compromisedPasswordChecker;
    @MockitoBean
    private EmailVerificationTokenRepository emailVerificationTokenRepository;
    @MockitoBean
    private ValidationProperties validationProperties;
    @MockitoBean
    private UserRepository userRepository;
    private final String DEFAULT_REFRESH_TOKEN = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyYiIsImp0aSI6Ijg1ZTUxNzBmLWI3YWItNDdiNy1iNTdhLWYzM2EzNGViMTE3NSIsImlhdCI6MTc1NDQ4MjcyMywiZXhwIjoxNzU5NjY2NzIzfQ.IBZTGjR2nCwr7K36hOoYeoQGhh90wENRSmLmvkWKTK58Dtmt3ghqpEZBGrpbKvPJctZlVe9y0RKt-HT5PQ-mXg";
    private final String DEFAULT_ACCESS_TOKEN = "eyJhbGciOiJIUzUxMiJ9.eyJyb2xlcyI6WyJST0xFX1VTRVIiXSwic3ViIjoidXNlcmIiLCJqdGkiOiI1YzYzYzdlYi01ZDFjLTRkYWYtODIwYS1kMjgwMzIwMDU1NDgiLCJpYXQiOjE3NTU0NDkwMzcsImV4cCI6MTc1NTQ1MDIzN30.xQIiKft8OKxySzrmp3vOPI81Dz9-OdtxH1EG9BftFPvLRrkWcJs6fubwWsG_o92-r5vp41qyus9RsE7YEX_a6g";
    private final String DEFAULT_USERNAME = "userb";
    private final String DEFAULT_PASSWORD = "Corners8829%";
    private final RegistrationRequest defaultRegistrationRequest = new RegistrationRequest(DEFAULT_USERNAME, "userb@gmail.com", DEFAULT_PASSWORD);
    private final LoginRequest defaultLoginRequest = new LoginRequest(DEFAULT_USERNAME, DEFAULT_PASSWORD);
    private final TokenPair defaultTokenPair = new TokenPair(DEFAULT_ACCESS_TOKEN, DEFAULT_REFRESH_TOKEN);
    private final String defaultVerifyToken = "token";

    // ! register

    @Test
    void givenValidRegistrationRequest_whenRegister_thenReturnHttpStatusCreated() throws Exception {
        // given
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(defaultRegistrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentNotUsed(eq(defaultRegistrationRequest.email()), any())).willReturn(false);
        BDDMockito.given(validationProperties.emailVerificationCooldown()).willReturn(Duration.ofMinutes(5));
        BDDMockito.given(userRepository.existsByUsernameIgnoreCase(defaultRegistrationRequest.username())).willReturn(false);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(defaultRegistrationRequest))
        );

        // then
        resultActions.andExpect(status().isCreated());
        verify(userService, only()).register(defaultRegistrationRequest);
    }

    @Test
    void givenValidRegistrationRequestPasswordLong_whenRegister_thenReturnHttpStatusCreated() throws Exception {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "veryverylongpassword"); // ≥15
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(registrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentNotUsed(eq(registrationRequest.email()), any())).willReturn(false);
        BDDMockito.given(validationProperties.emailVerificationCooldown()).willReturn(Duration.ofMinutes(5));
        BDDMockito.given(userRepository.existsByUsernameIgnoreCase(registrationRequest.username())).willReturn(false);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationRequest))
        );

        // then
        resultActions.andExpect(status().isCreated());
        verify(userService, only()).register(registrationRequest);
    }

    @Test
    void givenInvalidRegistrationRequestPasswordCompromised_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(true); // password compromised
        BDDMockito.given(compromisedPasswordChecker.check(defaultRegistrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentNotUsed(eq(defaultRegistrationRequest.email()), any())).willReturn(false);
        BDDMockito.given(validationProperties.emailVerificationCooldown()).willReturn(Duration.ofMinutes(5));
        BDDMockito.given(userRepository.existsByUsernameIgnoreCase(defaultRegistrationRequest.username())).willReturn(false);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultRegistrationRequest))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$..errors[0].field").value("password"))
                .andExpect(jsonPath("$..errors[0].reason").value("PasswordInvalid"))
                .andExpect(jsonPath("$..errors[0].rejectedValue").doesNotExist());
        verifyNoInteractions(userService);
    }

    @Test
    void givenInvalidRegistrationRequestPasswordNoNumbers_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "Corners%"); // no numbers
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(registrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentNotUsed(eq(registrationRequest.email()), any())).willReturn(false);
        BDDMockito.given(validationProperties.emailVerificationCooldown()).willReturn(Duration.ofMinutes(5));
        BDDMockito.given(userRepository.existsByUsernameIgnoreCase(registrationRequest.username())).willReturn(false);

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
        verifyNoInteractions(userService);
    }

    @Test
    void givenInvalidRegistrationRequestPasswordNoLetters_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "444448829%"); // no letters
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(registrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentNotUsed(eq(registrationRequest.email()), any())).willReturn(false);
        BDDMockito.given(validationProperties.emailVerificationCooldown()).willReturn(Duration.ofMinutes(5));
        BDDMockito.given(userRepository.existsByUsernameIgnoreCase(registrationRequest.username())).willReturn(false);

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
        verifyNoInteractions(userService);
    }

    @Test
    void givenInvalidRegistrationRequestPasswordNoUppercase_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "corners8829%"); // no uppercase
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(registrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentNotUsed(eq(registrationRequest.email()), any())).willReturn(false);
        BDDMockito.given(validationProperties.emailVerificationCooldown()).willReturn(Duration.ofMinutes(5));
        BDDMockito.given(userRepository.existsByUsernameIgnoreCase(registrationRequest.username())).willReturn(false);

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
        verifyNoInteractions(userService);
    }

    @Test
    void givenInvalidRegistrationRequestPasswordNoLowercase_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "CORNERS8829%"); // no lowercase
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(registrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentNotUsed(eq(registrationRequest.email()), any())).willReturn(false);
        BDDMockito.given(validationProperties.emailVerificationCooldown()).willReturn(Duration.ofMinutes(5));
        BDDMockito.given(userRepository.existsByUsernameIgnoreCase(registrationRequest.username())).willReturn(false);

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
        verifyNoInteractions(userService);
    }

    @Test
    void givenInvalidRegistrationRequestExistingUsername_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(defaultRegistrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentNotUsed(eq(defaultRegistrationRequest.email()), any())).willReturn(false);
        BDDMockito.given(validationProperties.emailVerificationCooldown()).willReturn(Duration.ofMinutes(5));
        BDDMockito.given(userRepository.existsByUsernameIgnoreCase(defaultRegistrationRequest.username())).willReturn(true); // username exists

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
        verifyNoInteractions(userService);
    }

    @Test
    void givenInvalidRegistrationRequestEmailCooldown_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(defaultRegistrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentNotUsed(eq(defaultRegistrationRequest.email()), any())).willReturn(true); // someone requested a token < cooldown ago
        BDDMockito.given(validationProperties.emailVerificationCooldown()).willReturn(Duration.ofMinutes(5));
        BDDMockito.given(userRepository.existsByUsernameIgnoreCase(defaultRegistrationRequest.username())).willReturn(false);

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
        verifyNoInteractions(userService);
    }

    @Test
    void givenRegistrationRequestAccountSuspendedException_whenRegister_thenReturnHttpStatusForbidden() throws Exception {
        // given
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(defaultRegistrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentNotUsed(eq(defaultRegistrationRequest.email()), any())).willReturn(false);
        BDDMockito.given(validationProperties.emailVerificationCooldown()).willReturn(Duration.ofMinutes(5));
        BDDMockito.given(userRepository.existsByUsernameIgnoreCase(defaultRegistrationRequest.username())).willReturn(false);
        BDDMockito.willThrow(AccountSuspendedException.class).given(userService).register(defaultRegistrationRequest);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultRegistrationRequest))
        );

        // then
        verify(userService, only()).register(defaultRegistrationRequest);
        resultActions.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(AccountSuspendedException.code));
    }

    @Test
    void givenRegistrationRequestAccountDeletedException_whenRegister_thenReturnHttpStatusGone() throws Exception {
        // given
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(defaultRegistrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentNotUsed(eq(defaultRegistrationRequest.email()), any())).willReturn(false);
        BDDMockito.given(validationProperties.emailVerificationCooldown()).willReturn(Duration.ofMinutes(5));
        BDDMockito.given(userRepository.existsByUsernameIgnoreCase(defaultRegistrationRequest.username())).willReturn(false);
        BDDMockito.willThrow(AccountDeletedException.class).given(userService).register(defaultRegistrationRequest);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultRegistrationRequest))
        );

        // then
        verify(userService, only()).register(defaultRegistrationRequest);
        resultActions.andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value(AccountDeletedException.code));
    }

    @Test
    void givenRegistrationRequestDuplicateEmailException_whenRegister_thenReturnHttpStatusConflict() throws Exception {
        // given
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(defaultRegistrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentNotUsed(eq(defaultRegistrationRequest.email()), any())).willReturn(false);
        BDDMockito.given(validationProperties.emailVerificationCooldown()).willReturn(Duration.ofMinutes(5));
        BDDMockito.given(userRepository.existsByUsernameIgnoreCase(defaultRegistrationRequest.username())).willReturn(false);
        BDDMockito.willThrow(DuplicateEmailException.class).given(userService).register(defaultRegistrationRequest);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultRegistrationRequest))
        );

        // then
        verify(userService, only()).register(defaultRegistrationRequest);
        resultActions.andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value(DuplicateEmailException.code));
    }
    
    // ! verify

    @Test
    void givenValidToken_whenVerify_thenReturnHttpStatusNoContent() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", defaultVerifyToken)
        );

        // then
        resultActions.andExpect(status().isNoContent());
        verify(userService, only()).verify(defaultVerifyToken);
    }

    @Test
    void givenNonExistingToken_whenVerify_thenReturnHttpStatusNotFound() throws Exception {
        // given
        BDDMockito.willThrow(EmailVerificationTokenNotFoundException.class).given(userService).verify(defaultVerifyToken);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", defaultVerifyToken)
        );

        // then
        resultActions.andExpect(status().isNotFound());
        verify(userService).verify(defaultVerifyToken);
    }

    @Test
    void givenExpiredToken_whenVerify_thenReturnHttpStatusBadRequest() throws Exception {
        // given
        BDDMockito.willThrow(EmailVerificationTokenExpiredException.class).given(userService).verify(defaultVerifyToken);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", defaultVerifyToken)
        );

        // then
        resultActions.andExpect(status().isBadRequest());
        verify(userService).verify(defaultVerifyToken);
    }

    @Test
    void givenInvalidTokenAccountDeleted_whenVerify_thenReturnHttpStatusGone() throws Exception {
        // given
        BDDMockito.willThrow(AccountDeletedException.class).given(userService).verify(defaultVerifyToken);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", defaultVerifyToken)
        );

        // then
        resultActions.andExpect(status().isGone());
        verify(userService).verify(defaultVerifyToken);
    }

    @Test
    void givenTokenEmailVerificationTokenNotFoundException_whenVerify_thenReturnHttpStatusNotFound() throws Exception {
        // given
        BDDMockito.willThrow(EmailVerificationTokenNotFoundException.class).given(userService).verify(defaultVerifyToken);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", defaultVerifyToken)
        );

        // then
        verify(userService, only()).verify(defaultVerifyToken);
        resultActions.andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value(EmailVerificationTokenNotFoundException.code));
    }

    @Test
    void givenTokenEmailVerificationTokenExpiredException_whenVerify_thenReturnHttpStatusBadRequest() throws Exception {
        // given
        BDDMockito.willThrow(EmailVerificationTokenExpiredException.class).given(userService).verify(defaultVerifyToken);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", defaultVerifyToken)
        );

        // then
        verify(userService, only()).verify(defaultVerifyToken);
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(EmailVerificationTokenExpiredException.code));
    }

    @Test
    void givenTokenAccountDeletedException_whenVerify_thenReturnHttpStatusGone() throws Exception {
        // given
        BDDMockito.willThrow(AccountDeletedException.class).given(userService).verify(defaultVerifyToken);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", defaultVerifyToken)
        );

        // then
        verify(userService, only()).verify(defaultVerifyToken);
        resultActions.andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value(AccountDeletedException.code));
    }

    // ! logout

    @Test
    void givenRefreshTokenInCookie_whenLogout_thenDeleteCookie() throws Exception {
        // given

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
        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(userService).logout(tokenCaptor.capture());
        assertEquals(DEFAULT_REFRESH_TOKEN, tokenCaptor.getValue());
    }

    @Test
    void givenRefreshTokenInHeader_whenLogout_thenDeleteCookie() throws Exception {
        // given

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
        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(userService).logout(tokenCaptor.capture());
        assertEquals(DEFAULT_REFRESH_TOKEN, tokenCaptor.getValue());
    }

    @Test
    void givenRefreshTokenMissing_whenLogout_thenNoServiceCallDeleteCookie() throws Exception {
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
        verify(userService, never()).logout(anyString());
    }

    @Test
    void givenRefreshTokenInCookieInvalidRefreshTokenException_whenLogout_thenHttpStatusBadRequest() throws Exception {
        // given
        BDDMockito.willThrow(InvalidRefreshTokenException.class).given(userService).logout(DEFAULT_REFRESH_TOKEN);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/logout")
                        .cookie(new Cookie("refresh_token", DEFAULT_REFRESH_TOKEN))
        );

        // then
        verify(userService).logout(DEFAULT_REFRESH_TOKEN);
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(InvalidRefreshTokenException.code));
    }

    @Test
    void givenRefreshTokenInCookieRefreshTokenNotFoundException_whenLogout_thenHttpStatusNotFound() throws Exception {
        // given
        BDDMockito.willThrow(RefreshTokenNotFoundException.class).given(userService).logout(DEFAULT_REFRESH_TOKEN);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/logout")
                        .cookie(new Cookie("refresh_token", DEFAULT_REFRESH_TOKEN))
        );

        // then
        verify(userService).logout(DEFAULT_REFRESH_TOKEN);
        resultActions.andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value(RefreshTokenNotFoundException.code));
    }

    // ! login

    @Test
    void givenValidLoginRequest_whenLogin_thenReturnTokens() throws Exception {
        // given
        Boolean revokeOldest = true;
        BDDMockito.given(userService.login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest)).willReturn(defaultTokenPair);
        Duration jwtExpiration = Duration.ofMinutes(20);
        BDDMockito.given(jwtProperties.expiration()).willReturn(jwtExpiration);
        Duration jwtRefreshTokenExpiration = Duration.ofDays(60);
        BDDMockito.given(jwtService.extractExpiration(defaultTokenPair.refreshToken())).willReturn(Date.from(Instant.now().plus(jwtRefreshTokenExpiration)));

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        verify(userService).login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest);
        resultActions.andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, allOf(
                        containsString("refresh_token=" + DEFAULT_REFRESH_TOKEN),
                        containsString("HttpOnly"),
                        containsString("Secure")
                )))
                .andExpect(jsonPath("$.access_token", is(defaultTokenPair.accessToken())))
                .andExpect(jsonPath("$.expires_in_ms").value((int) jwtExpiration.toMillis()))
                .andExpect(jsonPath("$.token_type", is("Bearer")));
    }

    @Test
    void givenLoginRequestCustomUnauthorizedException_whenLogin_thenHttpStatusBadRequest() throws Exception {
        // given
        Boolean revokeOldest = true;
        BDDMockito.given(userService.login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest)).willThrow(CustomUnauthorizedException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        verify(userService).login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest);
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(CustomUnauthorizedException.code));
    }

    @Test
    void givenLoginRequestAccountLockedException_whenLogin_thenHttpStatusLocked() throws Exception {
        // given
        Boolean revokeOldest = true;
        BDDMockito.given(userService.login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest)).willThrow(AccountLockedException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        verify(userService).login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest);
        resultActions.andExpect(status().isLocked())
                .andExpect(jsonPath("$.code").value(AccountLockedException.code));
    }

    @Test
    void givenLoginRequestEmailNotVerifiedException_whenLogin_thenHttpStatusForbidden() throws Exception {
        // given
        Boolean revokeOldest = true;
        BDDMockito.given(userService.login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest)).willThrow(EmailNotVerifiedException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        verify(userService).login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest);
        resultActions.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(EmailNotVerifiedException.code));
    }

    @Test
    void givenLoginRequestAccountSuspendedException_whenLogin_thenHttpStatusForbidden() throws Exception {
        // given
        Boolean revokeOldest = true;
        BDDMockito.given(userService.login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest)).willThrow(AccountSuspendedException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        verify(userService).login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest);
        resultActions.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(AccountSuspendedException.code));
    }

    @Test
    void givenLoginRequestAccountDeletedException_whenLogin_thenHttpStatusGone() throws Exception {
        // given
        Boolean revokeOldest = true;
        BDDMockito.given(userService.login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest)).willThrow(AccountDeletedException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        verify(userService).login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest);
        resultActions.andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value(AccountDeletedException.code));
    }

    @Test
    void givenLoginRequestConcurrentSessionLimitException_whenLogin_thenHttpStatusConflict() throws Exception {
        // given
        Boolean revokeOldest = true;
        BDDMockito.given(userService.login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest)).willThrow(ConcurrentSessionLimitException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        verify(userService).login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest);
        resultActions.andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value(ConcurrentSessionLimitException.code));
    }

    @Test
    void givenLoginRequestJwtGenerationException_whenLogin_thenHttpStatusBadRequest() throws Exception {
        // given
        Boolean revokeOldest = true;
        BDDMockito.given(userService.login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest)).willThrow(JwtGenerationException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(defaultLoginRequest))
        );

        // then
        verify(userService).login(defaultLoginRequest.username(), defaultLoginRequest.password(), revokeOldest);
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(JwtGenerationException.code));
    }

    // ! refresh

    @Test
    void givenRefreshTokenInCookie_whenRefresh_thenReturnTokens() throws Exception {
        // given
        final String oldToken = "oldtoken";
        BDDMockito.given(userService.refresh(oldToken)).willReturn(defaultTokenPair);
        Duration jwtExpiration = Duration.ofMinutes(20);
        BDDMockito.given(jwtProperties.expiration()).willReturn(jwtExpiration);
        Duration jwtRefreshTokenExpiration = Duration.ofDays(60);
        BDDMockito.given(jwtService.extractExpiration(defaultTokenPair.refreshToken())).willReturn(Date.from(Instant.now().plus(jwtRefreshTokenExpiration)));

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/refresh")
                        .cookie(new Cookie("refresh_token", oldToken))
        );

        // then
        verify(userService).refresh(oldToken);
        resultActions.andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, allOf(
                        containsString("refresh_token=" + DEFAULT_REFRESH_TOKEN),
                        containsString("HttpOnly"),
                        containsString("Secure")
                )))
                .andExpect(jsonPath("$.access_token", is(defaultTokenPair.accessToken())))
                .andExpect(jsonPath("$.expires_in_ms").value((int) jwtExpiration.toMillis()))
                .andExpect(jsonPath("$.token_type", is("Bearer")));
    }

    @Test
    void givenRefreshTokenInCookieInvalidRefreshTokenException_whenRefresh_thenHttpStatusBadRequest() throws Exception {
        // given
        final String oldToken = "oldtoken";
        BDDMockito.given(userService.refresh(oldToken)).willThrow(InvalidRefreshTokenException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/refresh")
                        .cookie(new Cookie("refresh_token", oldToken))
        );

        // then
        verify(userService).refresh(oldToken);
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(InvalidRefreshTokenException.code));
    }

    @Test
    void givenRefreshTokenInCookieExpiredOrRevokedRefreshTokenException_whenRefresh_thenHttpStatusBadRequest() throws Exception {
        // given
        final String oldToken = "oldtoken";
        BDDMockito.given(userService.refresh(oldToken)).willThrow(ExpiredOrRevokedRefreshTokenException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/refresh")
                        .cookie(new Cookie("refresh_token", oldToken))
        );

        // then
        verify(userService).refresh(oldToken);
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value(ExpiredOrRevokedRefreshTokenException.code));
    }

    @Test
    void givenRefreshTokenInCookieEmailNotVerifiedException_whenRefresh_thenHttpStatusForbidden() throws Exception {
        // given
        final String oldToken = "oldtoken";
        BDDMockito.given(userService.refresh(oldToken)).willThrow(EmailNotVerifiedException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/refresh")
                        .cookie(new Cookie("refresh_token", oldToken))
        );

        // then
        verify(userService).refresh(oldToken);
        resultActions.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(EmailNotVerifiedException.code));
    }

    @Test
    void givenRefreshTokenInCookieAccountSuspendedException_whenRefresh_thenHttpStatusForbidden() throws Exception {
        // given
        final String oldToken = "oldtoken";
        BDDMockito.given(userService.refresh(oldToken)).willThrow(AccountSuspendedException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/refresh")
                        .cookie(new Cookie("refresh_token", oldToken))
        );

        // then
        verify(userService).refresh(oldToken);
        resultActions.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(AccountSuspendedException.code));
    }

    @Test
    void givenRefreshTokenInCookieAccountDeletedException_whenRefresh_thenHttpStatusGone() throws Exception {
        // given
        final String oldToken = "oldtoken";
        BDDMockito.given(userService.refresh(oldToken)).willThrow(AccountDeletedException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/refresh")
                        .cookie(new Cookie("refresh_token", oldToken))
        );

        // then
        verify(userService).refresh(oldToken);
        resultActions.andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value(AccountDeletedException.code));
    }
}

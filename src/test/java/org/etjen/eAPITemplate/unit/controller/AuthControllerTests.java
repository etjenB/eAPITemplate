package org.etjen.eAPITemplate.unit.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.etjen.eAPITemplate.config.properties.security.JwtProperties;
import org.etjen.eAPITemplate.config.properties.web.ValidationProperties;
import org.etjen.eAPITemplate.exception.auth.AccountDeletedException;
import org.etjen.eAPITemplate.exception.auth.EmailVerificationTokenExpiredException;
import org.etjen.eAPITemplate.exception.auth.EmailVerificationTokenNotFoundException;
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
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
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
    private final RegistrationRequest registrationRequest = new RegistrationRequest(DEFAULT_USERNAME, "userb@gmail.com", DEFAULT_PASSWORD);
    private final LoginRequest loginRequest = new LoginRequest(DEFAULT_USERNAME, DEFAULT_PASSWORD);
    private final TokenPair tokenPair = new TokenPair(DEFAULT_ACCESS_TOKEN, DEFAULT_REFRESH_TOKEN);
    private final String verifyToken = "token";
    // ! register

    @Test
    void givenValidRegistrationRequest_whenRegister_thenReturnHttpStatusCreated() throws Exception {
        // given
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(registrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentUnexpired(eq(registrationRequest.email()), any())).willReturn(false);
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
    void givenValidRegistrationRequestPasswordLong_whenRegister_thenReturnHttpStatusCreated() throws Exception {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "veryverylongpassword"); // ≥15
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(registrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentUnexpired(eq(registrationRequest.email()), any())).willReturn(false);
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
        BDDMockito.given(compromisedPasswordChecker.check(registrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentUnexpired(eq(registrationRequest.email()), any())).willReturn(false);
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
    void givenInvalidRegistrationRequestPasswordNoNumbers_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "Corners%"); // no numbers
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(registrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentUnexpired(eq(registrationRequest.email()), any())).willReturn(false);
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
        BDDMockito.given(emailVerificationTokenRepository.existsRecentUnexpired(eq(registrationRequest.email()), any())).willReturn(false);
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
        BDDMockito.given(emailVerificationTokenRepository.existsRecentUnexpired(eq(registrationRequest.email()), any())).willReturn(false);
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
        BDDMockito.given(emailVerificationTokenRepository.existsRecentUnexpired(eq(registrationRequest.email()), any())).willReturn(false);
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
        BDDMockito.given(compromisedPasswordChecker.check(registrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentUnexpired(eq(registrationRequest.email()), any())).willReturn(false);
        BDDMockito.given(validationProperties.emailVerificationCooldown()).willReturn(Duration.ofMinutes(5));
        BDDMockito.given(userRepository.existsByUsernameIgnoreCase(registrationRequest.username())).willReturn(true); // username exists

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registrationRequest))
        );

        // then
        resultActions.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$..errors[0].field").value("username"))
                .andExpect(jsonPath("$..errors[0].reason").value("UniqueUsername"))
                .andExpect(jsonPath("$..errors[0].rejectedValue").value(registrationRequest.username()));
        verifyNoInteractions(userService);
    }

    @Test
    void givenInvalidRegistrationRequestEmailCooldown_whenRegister_thenReturnHttpStatusBadRequestAndErrors() throws Exception {
        // given
        CompromisedPasswordDecision compromisedPasswordDecision = new CompromisedPasswordDecision(false);
        BDDMockito.given(compromisedPasswordChecker.check(registrationRequest.password())).willReturn(compromisedPasswordDecision);
        BDDMockito.given(emailVerificationTokenRepository.existsRecentUnexpired(eq(registrationRequest.email()), any())).willReturn(true); // someone requested a token < cooldown ago
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
                .andExpect(jsonPath("$..errors[0].field").value("email"))
                .andExpect(jsonPath("$..errors[0].reason").value("UniqueEmail"))
                .andExpect(jsonPath("$..errors[0].rejectedValue").value(registrationRequest.email()));
        verifyNoInteractions(userService);
    }
    
    // ! verify

    @Test
    void givenValidToken_whenVerify_thenReturnHttpStatusNoContent() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", verifyToken)
        );

        // then
        resultActions.andExpect(status().isNoContent());
        verify(userService, only()).verify(verifyToken);
    }

    @Test
    void givenNonExistingToken_whenVerify_thenReturnHttpStatusNotFound() throws Exception {
        // given
        BDDMockito.willThrow(EmailVerificationTokenNotFoundException.class).given(userService).verify(verifyToken);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", verifyToken)
        );

        // then
        resultActions.andExpect(status().isNotFound());
        verify(userService).verify(verifyToken);
    }

    @Test
    void givenExpiredToken_whenVerify_thenReturnHttpStatusBadRequest() throws Exception {
        // given
        BDDMockito.willThrow(EmailVerificationTokenExpiredException.class).given(userService).verify(verifyToken);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", verifyToken)
        );

        // then
        resultActions.andExpect(status().isBadRequest());
        verify(userService).verify(verifyToken);
    }

    @Test
    void givenInvalidTokenAccountDeleted_whenVerify_thenReturnHttpStatusGone() throws Exception {
        // given
        BDDMockito.willThrow(AccountDeletedException.class).given(userService).verify(verifyToken);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/verify").param("token", verifyToken)
        );

        // then
        resultActions.andExpect(status().isGone());
        verify(userService).verify(verifyToken);
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

    // ! login

    @Test
    void givenValidLoginRequest_whenLogin_thenReturnTokens() throws Exception {
        // given
        Boolean revokeOldest = true;
        BDDMockito.given(userService.login(loginRequest.username(), loginRequest.password(), revokeOldest)).willReturn(tokenPair);
        Duration jwtExpiration = Duration.ofMinutes(20);
        BDDMockito.given(jwtProperties.expiration()).willReturn(jwtExpiration);
        Duration jwtRefreshTokenExpiration = Duration.ofDays(60);
        BDDMockito.given(jwtService.extractExpiration(tokenPair.refreshToken())).willReturn(Date.from(Instant.now().plus(jwtRefreshTokenExpiration)));

        // when
        ResultActions resultActions = mockMvc.perform(
                post("/auth/login")
                        .param("revokeOldest", String.valueOf(revokeOldest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest))
        );

        // then
        verify(userService).login(loginRequest.username(), loginRequest.password(), revokeOldest);
        resultActions.andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, allOf(
                        containsString("refresh_token=" + DEFAULT_REFRESH_TOKEN),
                        containsString("HttpOnly"),
                        containsString("Secure")
                )))
                .andExpect(jsonPath("$.access_token", is(tokenPair.accessToken())))
                .andExpect(jsonPath("$.expires_in_ms").value((int) jwtExpiration.toMillis()))
                .andExpect(jsonPath("$.token_type", is("Bearer")));
    }

    // ! refresh

    @Test
    void givenRefreshTokenInCookie_whenRefresh_thenReturnTokens() throws Exception {
        // given
        final String oldToken = "oldtoken";
        BDDMockito.given(userService.refresh(oldToken)).willReturn(tokenPair);
        Duration jwtExpiration = Duration.ofMinutes(20);
        BDDMockito.given(jwtProperties.expiration()).willReturn(jwtExpiration);
        Duration jwtRefreshTokenExpiration = Duration.ofDays(60);
        BDDMockito.given(jwtService.extractExpiration(tokenPair.refreshToken())).willReturn(Date.from(Instant.now().plus(jwtRefreshTokenExpiration)));

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
                .andExpect(jsonPath("$.access_token", is(tokenPair.accessToken())))
                .andExpect(jsonPath("$.expires_in_ms").value((int) jwtExpiration.toMillis()))
                .andExpect(jsonPath("$.token_type", is("Bearer")));
    }

}

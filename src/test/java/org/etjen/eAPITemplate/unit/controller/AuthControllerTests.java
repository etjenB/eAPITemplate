package org.etjen.eAPITemplate.unit.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.etjen.eAPITemplate.web.payload.auth.RegistrationRequest;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import java.time.Duration;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

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
    private final RegistrationRequest registrationRequest = new RegistrationRequest("userb", "userb@gmail.com", "Corners8829%");
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
        resultActions.andExpect(MockMvcResultMatchers.status().isCreated());
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
        resultActions.andExpect(MockMvcResultMatchers.status().isCreated());
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
        resultActions.andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].field").value("password"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].reason").value("PasswordInvalid"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].rejectedValue").doesNotExist());
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
        resultActions.andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].field").value("password"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].reason").value("PasswordInvalid"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].rejectedValue").doesNotExist());
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
        resultActions.andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].field").value("password"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].reason").value("PasswordInvalid"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].rejectedValue").doesNotExist());
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
        resultActions.andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].field").value("password"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].reason").value("PasswordInvalid"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].rejectedValue").doesNotExist());
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
        resultActions.andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].field").value("password"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].reason").value("PasswordInvalid"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].rejectedValue").doesNotExist());
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
        resultActions.andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].field").value("username"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].reason").value("UniqueUsername"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].rejectedValue").value(registrationRequest.username()));
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
        resultActions.andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].field").value("email"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].reason").value("UniqueEmail"))
                .andExpect(MockMvcResultMatchers.jsonPath("$..errors[0].rejectedValue").value(registrationRequest.email()));
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
        resultActions.andExpect(MockMvcResultMatchers.status().isNoContent());
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
        resultActions.andExpect(MockMvcResultMatchers.status().isNotFound());
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
        resultActions.andExpect(MockMvcResultMatchers.status().isBadRequest());
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
        resultActions.andExpect(MockMvcResultMatchers.status().isGone());
        verify(userService).verify(verifyToken);
    }

    // ! logout

}

package org.etjen.eAPITemplate.unit.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.etjen.eAPITemplate.domain.model.Role;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.exception.auth.MissingAuthenticationCredentialsException;
import org.etjen.eAPITemplate.exception.auth.jwt.RefreshTokenNotFoundException;
import org.etjen.eAPITemplate.exception.auth.jwt.RefreshTokensForUserNotFoundException;
import org.etjen.eAPITemplate.security.user.UserPrincipal;
import org.etjen.eAPITemplate.service.SessionService;
import org.etjen.eAPITemplate.web.controller.SessionController;
import org.etjen.eAPITemplate.web.payload.session.SessionDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = SessionController.class)
@AutoConfigureMockMvc
public class SessionControllerTests {
    @Autowired
    private MockMvc mockMvc;
    @MockitoBean
    private SessionService sessionService;
    private final String DEFAULT_PASSWORD = "Corners8829%";
    private final String DEFAULT_USERNAME = "user";
    private final String DEFAULT_EMAIL = "user@gmail.com";
    private final String DEFAULT_RT_JTI = "85e5170f-b7ab-47b7-b57a-f33a34eb1175";
    private User defaultUser;
    private UserPrincipal defaultUserPrincipal;
    private RefreshToken defaultRefreshToken;
    private SessionDto defaultSessionDto;
    private Role roleUser;


    @BeforeEach
    void setUp() {
        roleUser = new Role();
        roleUser.setId(1);
        roleUser.setName("ROLE_USER");
        defaultUser = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .roles(Set.of(roleUser))
                .build();
        defaultUserPrincipal = new UserPrincipal(defaultUser);
        defaultRefreshToken = RefreshToken.builder()
                .id(1L)
                .tokenId(DEFAULT_RT_JTI)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(defaultUser)
                .build();
        defaultSessionDto = SessionDto.builder()
                .tokenId(defaultRefreshToken.getTokenId())
                .issuedAt(defaultRefreshToken.getIssuedAt())
                .expiresAt(defaultRefreshToken.getExpiresAt())
                .ipAddress(defaultRefreshToken.getIpAddress())
                .userAgent(defaultRefreshToken.getUserAgent())
                .current(true)
                .status(defaultRefreshToken.isRevoked() ? SessionDto.Status.REVOKED : SessionDto.Status.ACTIVE)
                .build();
    }

    // ! getSessions

    @Test
    void givenValidUserPrincipal_whenGetSessions_thenHttpStatusOkAndReturnListOfSessions() throws Exception {
        // given
        BDDMockito.given(sessionService.list(defaultUserPrincipal.getId())).willReturn(List.of(defaultSessionDto));

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/sessions")
                        .with(user(defaultUserPrincipal))
        );

        // then
        verify(sessionService).list(defaultUserPrincipal.getId());
        resultActions.andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].tokenId").value(defaultRefreshToken.getTokenId()))
                .andExpect(jsonPath("$[0].current").value(true))
                .andExpect(jsonPath("$[0].status").value("ACTIVE"));
    }

    @Test
    void givenMissingUserPrincipal_whenGetSessions_thenHttpStatusUnauthorized() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/sessions")
        );

        // then
        verifyNoInteractions(sessionService);
        resultActions.andExpect(status().isUnauthorized());
    }

    @Test
    void givenInvalidUserPrincipalRefreshTokensForUserNotFoundException_whenGetSessions_thenHttpStatusNotFound() throws Exception {
        // given
        BDDMockito.given(sessionService.list(defaultUserPrincipal.getId())).willThrow(RefreshTokensForUserNotFoundException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/sessions")
                        .with(user(defaultUserPrincipal))
        );

        // then
        verify(sessionService).list(defaultUserPrincipal.getId());
        resultActions.andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value(RefreshTokensForUserNotFoundException.code));
    }

    @Test
    void givenInvalidUserPrincipalMissingAuthenticationCredentialsException_whenGetSessions_thenHttpStatusInternalServerError() throws Exception {
        // given
        BDDMockito.given(sessionService.list(defaultUserPrincipal.getId())).willThrow(MissingAuthenticationCredentialsException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/sessions")
                        .with(user(defaultUserPrincipal))
        );

        // then
        verify(sessionService).list(defaultUserPrincipal.getId());
        resultActions.andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.code").value(MissingAuthenticationCredentialsException.code));
    }

    // ! getSession

    @Test
    void givenValidUserPrincipalAndValidTokenId_whenGetSession_thenHttpStatusOkAndReturnSession() throws Exception {
        // given
        BDDMockito.given(sessionService.get(defaultUserPrincipal.getId(), defaultRefreshToken.getTokenId())).willReturn(defaultSessionDto);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/sessions/{tokenId}", defaultRefreshToken.getTokenId())
                        .with(user(defaultUserPrincipal))
        );

        // then
        verify(sessionService).get(defaultUserPrincipal.getId(), defaultRefreshToken.getTokenId());
        resultActions.andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenId").value(defaultRefreshToken.getTokenId()))
                .andExpect(jsonPath("$.current").value(true))
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    void givenMissingUserPrincipalAndValidTokenId_whenGetSession_thenHttpStatusUnauthorized() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/sessions/{tokenId}", defaultRefreshToken.getTokenId())
        );

        // then
        verifyNoInteractions(sessionService);
        resultActions.andExpect(status().isUnauthorized());
    }

    @Test
    void givenUserPrincipalAndNonExistingTokenIdRefreshTokenNotFoundException_whenGetSession_thenHttpStatusNotFound() throws Exception {
        // given
        BDDMockito.given(sessionService.get(defaultUserPrincipal.getId(), defaultRefreshToken.getTokenId())).willThrow(RefreshTokenNotFoundException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/sessions/{tokenId}", defaultRefreshToken.getTokenId())
                        .with(user(defaultUserPrincipal))
        );

        // then
        verify(sessionService).get(defaultUserPrincipal.getId(), defaultRefreshToken.getTokenId());
        resultActions.andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value(RefreshTokenNotFoundException.code));
    }

    @Test
    void givenInvalidUserPrincipalAndValidTokenIdMissingAuthenticationCredentialsException_whenGetSession_thenHttpStatusInternalServerError() throws Exception {
        // given
        BDDMockito.given(sessionService.get(defaultUserPrincipal.getId(), defaultRefreshToken.getTokenId())).willThrow(MissingAuthenticationCredentialsException.class);

        // when
        ResultActions resultActions = mockMvc.perform(
                get("/auth/sessions/{tokenId}", defaultRefreshToken.getTokenId())
                        .with(user(defaultUserPrincipal))
        );

        // then
        verify(sessionService).get(defaultUserPrincipal.getId(), defaultRefreshToken.getTokenId());
        resultActions.andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.code").value(MissingAuthenticationCredentialsException.code));
    }

    // ! revokeSession

    @Test
    void givenValidUserPrincipalAndValidTokenId_whenRevokeSession_thenHttpStatusNoContent() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                delete("/auth/sessions/{tokenId}", defaultRefreshToken.getTokenId())
                        .with(user(defaultUserPrincipal))
                        .with(csrf())
        );

        // then
        verify(sessionService).revoke(defaultUserPrincipal.getId(), defaultRefreshToken.getTokenId());
        resultActions.andExpect(status().isNoContent());
    }

    @Test
    void givenValidUserPrincipalAndValidTokenIdWithoutCsrf_whenRevokeSession_thenHttpStatusForbidden() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                delete("/auth/sessions/{tokenId}", defaultRefreshToken.getTokenId())
                        .with(user(defaultUserPrincipal))
        );

        // then
        verifyNoInteractions(sessionService);
        resultActions.andExpect(status().isForbidden());
    }

    @Test
    void givenMissingUserPrincipalAndValidTokenId_whenRevokeSession_thenHttpStatusUnauthorized() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                delete("/auth/sessions/{tokenId}", defaultRefreshToken.getTokenId())
                        .with(csrf())
        );

        // then
        verifyNoInteractions(sessionService);
        resultActions.andExpect(status().isUnauthorized());
    }

    @Test
    void givenValidUserPrincipalAndNonExistingTokenIdRefreshTokenNotFoundException_whenRevokeSession_thenHttpStatusNotFound() throws Exception {
        // given
        BDDMockito.willThrow(RefreshTokenNotFoundException.class).given(sessionService).revoke(defaultUserPrincipal.getId(), defaultRefreshToken.getTokenId());

        // when
        ResultActions resultActions = mockMvc.perform(
                delete("/auth/sessions/{tokenId}", defaultRefreshToken.getTokenId())
                        .with(user(defaultUserPrincipal))
                        .with(csrf())
        );

        // then
        verify(sessionService).revoke(defaultUserPrincipal.getId(), defaultRefreshToken.getTokenId());
        resultActions.andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value(RefreshTokenNotFoundException.code));
    }

    // ! revokeAllSessions

    @Test
    void givenValidUserPrincipal_whenRevokeAllSessions_thenHttpStatusNoContent() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                delete("/auth/sessions")
                        .with(user(defaultUserPrincipal))
                        .with(csrf())
        );

        // then
        verify(sessionService).revokeAll(defaultUserPrincipal.getId());
        resultActions.andExpect(status().isNoContent());
    }

    @Test
    void givenValidUserPrincipalWithoutCsrf_whenRevokeAllSessions_thenHttpStatusForbidden() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                delete("/auth/sessions")
                        .with(user(defaultUserPrincipal))
        );

        // then
        verifyNoInteractions(sessionService);
        resultActions.andExpect(status().isForbidden());
    }

    @Test
    void givenMissingUserPrincipal_whenRevokeAllSessions_thenHttpStatusUnauthorized() throws Exception {
        // given

        // when
        ResultActions resultActions = mockMvc.perform(
                delete("/auth/sessions")
                        .with(csrf())
        );

        // then
        verifyNoInteractions(sessionService);
        resultActions.andExpect(status().isUnauthorized());
    }

    @Test
    void givenInvalidUserPrincipalRefreshTokensForUserNotFoundException_whenRevokeAllSessions_thenHttpStatusNotFound() throws Exception {
        // given
        BDDMockito.willThrow(RefreshTokensForUserNotFoundException.class).given(sessionService).revokeAll(defaultUserPrincipal.getId());

        // when
        ResultActions resultActions = mockMvc.perform(
                delete("/auth/sessions")
                        .with(user(defaultUserPrincipal))
                        .with(csrf())
        );

        // then
        verify(sessionService).revokeAll(defaultUserPrincipal.getId());
        resultActions.andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value(RefreshTokensForUserNotFoundException.code));
    }
}

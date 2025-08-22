package org.etjen.eAPITemplate.unit.service;

import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.etjen.eAPITemplate.domain.model.Role;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.exception.auth.MissingAuthenticationCredentialsException;
import org.etjen.eAPITemplate.exception.auth.jwt.RefreshTokenNotFoundException;
import org.etjen.eAPITemplate.exception.auth.jwt.RefreshTokensForUserNotFoundException;
import org.etjen.eAPITemplate.repository.RefreshTokenRepository;
import org.etjen.eAPITemplate.service.custom.SessionServiceImpl;
import org.etjen.eAPITemplate.web.mapper.SessionMapper;
import org.etjen.eAPITemplate.web.payload.session.SessionDto;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class SessionServiceTests {
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private SessionMapper sessionMapper;
    @Mock
    private SecurityContext securityContext;
    @Mock
    private Authentication authentication;
    @InjectMocks
    private SessionServiceImpl sessionServiceImpl;
    private final String DEFAULT_RT_JTI = "85e5170f-b7ab-47b7-b57a-f33a34eb1175";
    private User defaultUser;
    private RefreshToken defaultRefreshToken;
    private SessionDto defaultSessionDto;

    @BeforeEach
    void setUp() {
        Role roleUser = new Role();
        roleUser.setId(1);
        roleUser.setName("ROLE_USER");
        String DEFAULT_PASSWORD = "Corners8829%";
        String DEFAULT_USERNAME = "user";
        String DEFAULT_EMAIL = "user@gmail.com";
        defaultUser = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .roles(Set.of(roleUser))
                .build();
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
        SecurityContextHolder.setContext(securityContext);
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    // ! list

    @Test
    void givenValidUserId_whenList_thenReturnListOfSessions() {
        // given
        BDDMockito.given(refreshTokenRepository.findByUserId(defaultUser.getId())).willReturn(Optional.of(List.of(defaultRefreshToken)));
        BDDMockito.given(securityContext.getAuthentication()).willReturn(authentication);
        BDDMockito.given(authentication.getCredentials()).willReturn(DEFAULT_RT_JTI);
        BDDMockito.given(sessionMapper.toDtos(List.of(defaultRefreshToken), DEFAULT_RT_JTI)).willReturn(List.of(defaultSessionDto));

        // when
        List<SessionDto> sessionDtos = sessionServiceImpl.list(defaultUser.getId());

        // then
        assertNotNull(sessionDtos);
        assertThat(sessionDtos.size()).isGreaterThan(0);
        verify(refreshTokenRepository).findByUserId(defaultUser.getId());
        verifyNoMoreInteractions(refreshTokenRepository);
        verify(securityContext).getAuthentication();
        verifyNoMoreInteractions(securityContext);
        verify(authentication).getCredentials();
        verifyNoMoreInteractions(authentication);
        verify(sessionMapper).toDtos(List.of(defaultRefreshToken), DEFAULT_RT_JTI);
        verifyNoMoreInteractions(sessionMapper);
    }

    @Test
    void givenValidUserIdNoJTIInCredentials_whenList_thenThrowMissingAuthenticationCredentialsException() {
        // given
        BDDMockito.given(refreshTokenRepository.findByUserId(defaultUser.getId())).willReturn(Optional.of(List.of(defaultRefreshToken)));
        BDDMockito.given(securityContext.getAuthentication()).willReturn(authentication);
        BDDMockito.given(authentication.getCredentials()).willReturn(null);

        // when

        // then
        assertThrowsExactly(MissingAuthenticationCredentialsException.class, () -> sessionServiceImpl.list(defaultUser.getId()));
        verify(refreshTokenRepository).findByUserId(defaultUser.getId());
        verifyNoMoreInteractions(refreshTokenRepository);
        verify(securityContext).getAuthentication();
        verifyNoMoreInteractions(securityContext);
        verify(authentication).getCredentials();
        verifyNoMoreInteractions(authentication);
        verifyNoInteractions(sessionMapper);
    }

    @Test
    void givenInvalidUserId_whenList_thenThrowRefreshTokensForUserNotFoundException() {
        // given
        BDDMockito.given(refreshTokenRepository.findByUserId(defaultUser.getId())).willReturn(Optional.empty());

        // when

        // then
        assertThrowsExactly(RefreshTokensForUserNotFoundException.class, () -> sessionServiceImpl.list(defaultUser.getId()));
        verify(refreshTokenRepository).findByUserId(defaultUser.getId());
        verifyNoMoreInteractions(refreshTokenRepository);
        verifyNoInteractions(securityContext);
        verifyNoInteractions(authentication);
        verifyNoInteractions(sessionMapper);
    }

    // ! get

    @Test
    void givenValidTokenId_whenGet_thenReturnSession() {
        // given
        BDDMockito.given(refreshTokenRepository.findByTokenId(defaultRefreshToken.getTokenId())).willReturn(Optional.of(defaultRefreshToken));
        BDDMockito.given(securityContext.getAuthentication()).willReturn(authentication);
        BDDMockito.given(authentication.getCredentials()).willReturn(DEFAULT_RT_JTI);
        BDDMockito.given(sessionMapper.toDto(defaultRefreshToken, DEFAULT_RT_JTI)).willReturn(defaultSessionDto);

        // when
        SessionDto sessionDto = sessionServiceImpl.get(defaultUser.getId(), defaultRefreshToken.getTokenId());

        // then
        assertNotNull(sessionDto);
        verify(refreshTokenRepository).findByTokenId(defaultRefreshToken.getTokenId());
        verifyNoMoreInteractions(refreshTokenRepository);
        verify(securityContext).getAuthentication();
        verifyNoMoreInteractions(securityContext);
        verify(authentication).getCredentials();
        verifyNoMoreInteractions(authentication);
        verify(sessionMapper).toDto(defaultRefreshToken, DEFAULT_RT_JTI);
        verifyNoMoreInteractions(sessionMapper);
    }

    @Test
    void givenValidTokenIdNoJTIInCredentials_whenGet_thenThrowMissingAuthenticationCredentialsException() {
        // given
        BDDMockito.given(refreshTokenRepository.findByTokenId(defaultRefreshToken.getTokenId())).willReturn(Optional.of(defaultRefreshToken));
        BDDMockito.given(securityContext.getAuthentication()).willReturn(authentication);
        BDDMockito.given(authentication.getCredentials()).willReturn(null);

        // when

        // then
        assertThrowsExactly(MissingAuthenticationCredentialsException.class, () -> sessionServiceImpl.get(defaultUser.getId(), defaultRefreshToken.getTokenId()));
        verify(refreshTokenRepository).findByTokenId(defaultRefreshToken.getTokenId());
        verifyNoMoreInteractions(refreshTokenRepository);
        verify(securityContext).getAuthentication();
        verifyNoMoreInteractions(securityContext);
        verify(authentication).getCredentials();
        verifyNoMoreInteractions(authentication);
        verifyNoInteractions(sessionMapper);
    }

    @Test
    void givenInvalidTokenId_whenGet_thenThrowRefreshTokenNotFoundException() {
        // given
        BDDMockito.given(refreshTokenRepository.findByTokenId(defaultRefreshToken.getTokenId())).willReturn(Optional.empty());

        // when

        // then
        assertThrowsExactly(RefreshTokenNotFoundException.class, () -> sessionServiceImpl.get(defaultUser.getId(), defaultRefreshToken.getTokenId()));
        verify(refreshTokenRepository).findByTokenId(defaultRefreshToken.getTokenId());
        verifyNoMoreInteractions(refreshTokenRepository);
        // we could use for example verifyNoMoreInteractions(securityContext); and it would behave the same way, the difference is only the readability of the code
        verifyNoInteractions(securityContext);
        verifyNoInteractions(authentication);
        verifyNoInteractions(sessionMapper);
    }

    // ! revoke

    @Test
    void givenValidUserIdAndTokenId_whenRevoke_thenRevoke() {
        // given
        BDDMockito.given(refreshTokenRepository.revokeByTokenIdAndUserId(defaultRefreshToken.getTokenId(), defaultUser.getId())).willReturn(1);

        // when
        sessionServiceImpl.revoke(defaultUser.getId(), defaultRefreshToken.getTokenId());

        // then
        verify(refreshTokenRepository).revokeByTokenIdAndUserId(defaultRefreshToken.getTokenId(), defaultUser.getId());
        verifyNoMoreInteractions(refreshTokenRepository);
    }

    @Test
    void givenInvalidUserIdAndTokenId_whenRevoke_thenThrowRefreshTokenNotFoundException() {
        // given
        BDDMockito.given(refreshTokenRepository.revokeByTokenIdAndUserId(defaultRefreshToken.getTokenId(), defaultUser.getId())).willReturn(0);

        // when

        // then
        assertThrowsExactly(RefreshTokenNotFoundException.class, () -> sessionServiceImpl.revoke(defaultUser.getId(), defaultRefreshToken.getTokenId()));
        verify(refreshTokenRepository).revokeByTokenIdAndUserId(defaultRefreshToken.getTokenId(), defaultUser.getId());
        verifyNoMoreInteractions(refreshTokenRepository);
    }

    // ! revokeAll

    @Test
    void givenValidUserId_whenRevokeAll_thenRevokeAll() {
        // given
        BDDMockito.given(refreshTokenRepository.revokeAllByUserId(defaultUser.getId())).willReturn(5);

        // when
        sessionServiceImpl.revokeAll(defaultUser.getId());

        // then
        verify(refreshTokenRepository).revokeAllByUserId(defaultUser.getId());
        verifyNoMoreInteractions(refreshTokenRepository);
    }

    @Test
    void givenInvalidUserId_whenRevokeAll_thenThrowRefreshTokensForUserNotFoundException() {
        // given
        BDDMockito.given(refreshTokenRepository.revokeAllByUserId(defaultUser.getId())).willReturn(0);

        // when

        // then
        assertThrowsExactly(RefreshTokensForUserNotFoundException.class, () -> sessionServiceImpl.revokeAll(defaultUser.getId()));
        verify(refreshTokenRepository).revokeAllByUserId(defaultUser.getId());
        verifyNoMoreInteractions(refreshTokenRepository);
    }
}

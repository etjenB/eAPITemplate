package org.etjen.eAPITemplate.unit.service;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.impl.DefaultClaims;
import org.etjen.eAPITemplate.config.properties.security.AccountProperties;
import org.etjen.eAPITemplate.config.properties.security.EmailVerificationProperties;
import org.etjen.eAPITemplate.domain.model.EmailVerificationToken;
import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.etjen.eAPITemplate.domain.model.Role;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.domain.model.enums.AppRole;
import org.etjen.eAPITemplate.exception.auth.*;
import org.etjen.eAPITemplate.exception.auth.jwt.ExpiredOrRevokedRefreshTokenException;
import org.etjen.eAPITemplate.exception.auth.jwt.InvalidRefreshTokenException;
import org.etjen.eAPITemplate.exception.auth.jwt.RefreshTokenNotFoundException;
import org.etjen.eAPITemplate.repository.EmailVerificationTokenRepository;
import org.etjen.eAPITemplate.repository.RefreshTokenRepository;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.etjen.eAPITemplate.security.auth.RoleCache;
import org.etjen.eAPITemplate.security.jwt.JwtService;
import org.etjen.eAPITemplate.security.user.UserPrincipal;
import org.etjen.eAPITemplate.service.EmailService;
import org.etjen.eAPITemplate.service.custom.UserServiceImpl;
import org.etjen.eAPITemplate.web.payload.auth.RegistrationRequest;
import org.etjen.eAPITemplate.web.payload.auth.TokenPair;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceTests {
    @Mock
    private EmailVerificationProperties emailVerificationProperties;
    @Mock
    private UserRepository userRepository;
    @Mock
    private EmailVerificationTokenRepository emailVerificationTokenRepository;
    @Mock
    private EmailService emailService;
    @Mock
    private RoleCache roleCache;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    RefreshTokenRepository refreshTokenRepository;
    @Mock
    AuthenticationManager authenticationManager;
    @Mock
    JwtService jwtService;
    @Mock
    AccountProperties accountProperties;
    @InjectMocks
    private UserServiceImpl userServiceImpl;
    @Captor
    ArgumentCaptor<User> userCaptor;
    @Captor
    ArgumentCaptor<EmailVerificationToken> tokenCaptor;
    @Captor
    ArgumentCaptor<User> mailedUserCaptor;
    @Captor
    ArgumentCaptor<String> stringTokenCaptor;
    @Captor
    ArgumentCaptor<RefreshToken> refreshTokenCaptor;
    private Role roleUser = new Role(1, "ROLE_USER");
    private final String DEFAULT_PASSWORD = "Corners8829%";
    private final String HASHED_DEFAULT_PASSWORD = "$2a$10$FMqByHgNfU/iy2DBubUcpOv29O8sdUubtwLBQGQapCe3AHd3rxo1m";
    private final String DEFAULT_USERNAME = "user";
    private final String DEFAULT_EMAIL = "user@gmail.com";
    private final String DEFAULT_EMAIL_TOKEN = "103cda9b-95c4-4f6f-885e-b30fa2f382fa";
    private final String DEFAULT_REFRESH_TOKEN = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyYiIsImp0aSI6Ijg1ZTUxNzBmLWI3YWItNDdiNy1iNTdhLWYzM2EzNGViMTE3NSIsImlhdCI6MTc1NDQ4MjcyMywiZXhwIjoxNzU5NjY2NzIzfQ.IBZTGjR2nCwr7K36hOoYeoQGhh90wENRSmLmvkWKTK58Dtmt3ghqpEZBGrpbKvPJctZlVe9y0RKt-HT5PQ-mXg";
    private final String DEFAULT_RT_JTI = "85e5170f-b7ab-47b7-b57a-f33a34eb1175";
    private final String DEFAULT_ACCESS_TOKEN = "eyJhbGciOiJIUzUxMiJ9.eyJyb2xlcyI6WyJST0xFX1VTRVIiXSwic3ViIjoidXNlcmIiLCJqdGkiOiI1YzYzYzdlYi01ZDFjLTRkYWYtODIwYS1kMjgwMzIwMDU1NDgiLCJpYXQiOjE3NTU0NDkwMzcsImV4cCI6MTc1NTQ1MDIzN30.xQIiKft8OKxySzrmp3vOPI81Dz9-OdtxH1EG9BftFPvLRrkWcJs6fubwWsG_o92-r5vp41qyus9RsE7YEX_a6g";

    @BeforeEach
    void bindRequest() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("127.0.0.1");
        req.addHeader("User-Agent", "JUnit");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(req));
    }

    @AfterEach
    void clearRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    // ! register

    @Test
    void givenValidRegistrationRequest_whenRegister_thenSaveUserAndSendMail() {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest(DEFAULT_USERNAME, DEFAULT_EMAIL, DEFAULT_PASSWORD);
        BDDMockito.given(emailVerificationProperties.emailTokenTtl()).willReturn(Duration.ofHours(24));
        BDDMockito.given(userRepository.findByEmailIgnoreCase(any(String.class))).willReturn(Optional.empty());
        BDDMockito.given(roleCache.get(AppRole.USER)).willReturn(roleUser);
        BDDMockito.given(passwordEncoder.encode(DEFAULT_PASSWORD)).willReturn(HASHED_DEFAULT_PASSWORD);
        BDDMockito.given(userRepository.save(any(User.class)))
                .willAnswer(inv -> {
                    User u = inv.getArgument(0);
                    u.setId(1L);
                    return u;
                });

        // when
        userServiceImpl.register(registrationRequest);

        // then
        verify(userRepository, times(1)).findByEmailIgnoreCase(any(String.class));
        verify(roleCache, times(1)).get(any(AppRole.class));
        verify(userRepository, times(1)).save(any(User.class));
        verify(passwordEncoder, times(1)).encode(any(String.class));
        verify(emailVerificationTokenRepository, times(1)).save(any(EmailVerificationToken.class));
        verify(emailService, times(1)).sendVerificationMail(any(User.class), any(String.class));

        verify(userRepository).save(userCaptor.capture());
        verify(emailVerificationTokenRepository).save(tokenCaptor.capture());
        verify(emailService).sendVerificationMail(mailedUserCaptor.capture(), stringTokenCaptor.capture());

        var savedUser  = userCaptor.getValue();
        var savedToken = tokenCaptor.getValue();

        assertEquals(savedUser, savedToken.getUser());
        assertEquals(savedUser, mailedUserCaptor.getValue());
        assertEquals(savedToken.getToken(), stringTokenCaptor.getValue());
    }

    @Test
    void givenValidExistingEmailPendingVerification_whenRegister_thenSaveNewTokenAndSendMail() {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest(DEFAULT_USERNAME, DEFAULT_EMAIL, DEFAULT_PASSWORD);
        User user = User.builder()
                .id(1L)
                .username(registrationRequest.username())
                .email(registrationRequest.email())
                .password(registrationRequest.password())
                .status(AccountStatus.PENDING_VERIFICATION)
                .roles(Set.of(roleUser))
                .build();
        BDDMockito.given(emailVerificationProperties.emailTokenTtl()).willReturn(Duration.ofHours(24));
        BDDMockito.given(userRepository.findByEmailIgnoreCase(registrationRequest.email())).willReturn(Optional.of(user));

        // when
        userServiceImpl.register(registrationRequest);

        // then
        verify(userRepository, times(1)).findByEmailIgnoreCase(any(String.class));
        verify(emailVerificationTokenRepository, times(1)).save(any(EmailVerificationToken.class));
        verify(emailService, times(1)).sendVerificationMail(any(User.class), any(String.class));

        verify(roleCache, BDDMockito.never()).get(any(AppRole.class));
        verify(userRepository, BDDMockito.never()).save(any(User.class));
        verify(passwordEncoder, BDDMockito.never()).encode(any(String.class));

        verify(emailVerificationTokenRepository).save(tokenCaptor.capture());
        verify(emailService).sendVerificationMail(mailedUserCaptor.capture(), stringTokenCaptor.capture());

        var savedToken = tokenCaptor.getValue();

        assertEquals(savedToken.getUser(), user);
        assertEquals(mailedUserCaptor.getValue(), user);
        assertEquals(savedToken.getToken(), stringTokenCaptor.getValue());
    }

    @Test
    void givenValidExistingEmailSuspended_whenRegister_thenThrowAccountSuspendedException() {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest(DEFAULT_USERNAME, DEFAULT_EMAIL, DEFAULT_PASSWORD);
        User user = User.builder()
                .id(1L)
                .username(registrationRequest.username())
                .email(registrationRequest.email())
                .password(registrationRequest.password())
                .status(AccountStatus.SUSPENDED)
                .roles(Set.of(roleUser))
                .build();
        BDDMockito.given(emailVerificationProperties.emailTokenTtl()).willReturn(Duration.ofHours(24));
        BDDMockito.given(userRepository.findByEmailIgnoreCase(registrationRequest.email())).willReturn(Optional.of(user));

        // when

        // then
        assertThrowsExactly(AccountSuspendedException.class, () -> userServiceImpl.register(registrationRequest));

        verify(userRepository, times(1)).findByEmailIgnoreCase(any(String.class));

        verify(emailVerificationTokenRepository, BDDMockito.never()).save(any(EmailVerificationToken.class));
        verify(emailService, BDDMockito.never()).sendVerificationMail(any(User.class), any(String.class));
        verify(roleCache, BDDMockito.never()).get(any(AppRole.class));
        verify(userRepository, BDDMockito.never()).save(any(User.class));
        verify(passwordEncoder, BDDMockito.never()).encode(any(String.class));
    }

    @Test
    void givenValidExistingEmailDeleted_whenRegister_thenThrowAccountDeletedException() {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest(DEFAULT_USERNAME, DEFAULT_EMAIL, DEFAULT_PASSWORD);
        User user = User.builder()
                .id(1L)
                .username(registrationRequest.username())
                .email(registrationRequest.email())
                .password(registrationRequest.password())
                .status(AccountStatus.DELETED)
                .roles(Set.of(roleUser))
                .build();
        BDDMockito.given(emailVerificationProperties.emailTokenTtl()).willReturn(Duration.ofHours(24));
        BDDMockito.given(userRepository.findByEmailIgnoreCase(registrationRequest.email())).willReturn(Optional.of(user));

        // when

        // then
        assertThrowsExactly(AccountDeletedException.class, () -> userServiceImpl.register(registrationRequest));

        verify(userRepository, times(1)).findByEmailIgnoreCase(any(String.class));

        verify(emailVerificationTokenRepository, BDDMockito.never()).save(any(EmailVerificationToken.class));
        verify(emailService, BDDMockito.never()).sendVerificationMail(any(User.class), any(String.class));
        verify(roleCache, BDDMockito.never()).get(any(AppRole.class));
        verify(userRepository, BDDMockito.never()).save(any(User.class));
        verify(passwordEncoder, BDDMockito.never()).encode(any(String.class));
    }

    @Test
    void givenValidExistingEmailActive_whenRegister_thenThrowDuplicateEmailException() {
        // given
        RegistrationRequest registrationRequest = new RegistrationRequest(DEFAULT_USERNAME, DEFAULT_EMAIL, DEFAULT_PASSWORD);
        User user = User.builder()
                .id(1L)
                .username(registrationRequest.username())
                .email(registrationRequest.email())
                .password(registrationRequest.password())
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        BDDMockito.given(emailVerificationProperties.emailTokenTtl()).willReturn(Duration.ofHours(24));
        BDDMockito.given(userRepository.findByEmailIgnoreCase(registrationRequest.email())).willReturn(Optional.of(user));

        // when

        // then
        assertThrowsExactly(DuplicateEmailException.class, () -> userServiceImpl.register(registrationRequest));

        verify(userRepository, times(1)).findByEmailIgnoreCase(any(String.class));

        verify(emailVerificationTokenRepository, BDDMockito.never()).save(any(EmailVerificationToken.class));
        verify(emailService, BDDMockito.never()).sendVerificationMail(any(User.class), any(String.class));
        verify(roleCache, BDDMockito.never()).get(any(AppRole.class));
        verify(userRepository, BDDMockito.never()).save(any(User.class));
        verify(passwordEncoder, BDDMockito.never()).encode(any(String.class));
    }

    // ! verify

    @Test
    void givenValidToken_whenVerify_thenActivateUser() {
        // given
        User user = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .roles(Set.of(roleUser))
                .build();
        EmailVerificationToken emailVerificationToken = EmailVerificationToken.builder()
                .id(1L)
                .token(DEFAULT_EMAIL_TOKEN)
                .expiresAt(Instant.now().plus(Duration.ofHours(24)))
                .used(false)
                .issuedAt(Instant.now())
                .user(user)
                .build();
        BDDMockito.given(emailVerificationTokenRepository.findAndLockByToken(any(String.class))).willReturn(Optional.of(emailVerificationToken));

        // when
        userServiceImpl.verify(emailVerificationToken.getToken());

        // then
        User foundUser = emailVerificationToken.getUser();
        verify(emailVerificationTokenRepository).findAndLockByToken(stringTokenCaptor.capture());
        assertEquals(emailVerificationToken.getToken(), stringTokenCaptor.getValue());
        assertEquals(AccountStatus.ACTIVE, foundUser.getStatus());
        assertTrue(foundUser.isEmailVerified());
        assertTrue(emailVerificationToken.isUsed());
    }

    @Test
    void givenNonExistingToken_whenVerify_thenThrowEmailVerificationTokenNotFoundException() {
        // given
        BDDMockito.given(emailVerificationTokenRepository.findAndLockByToken(any(String.class))).willReturn(Optional.empty());

        // when

        // then
        assertThrowsExactly(EmailVerificationTokenNotFoundException.class, () -> userServiceImpl.verify(DEFAULT_EMAIL_TOKEN));

        verify(emailVerificationTokenRepository, times(1)).findAndLockByToken(any());
        verifyNoMoreInteractions(emailVerificationTokenRepository);
        verifyNoInteractions(userRepository); // method doesn't save
    }

    @Test
    void givenExistingExpiredToken_whenVerify_thenThrowEmailVerificationTokenExpiredException() {
        // given
        User user = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .roles(Set.of(roleUser))
                .build();
        EmailVerificationToken emailVerificationToken = EmailVerificationToken.builder()
                .id(1L)
                .token(DEFAULT_EMAIL_TOKEN)
                .expiresAt(Instant.now().minus(Duration.ofHours(1)))
                .used(false)
                .issuedAt(Instant.now().minus(Duration.ofHours(24)))
                .user(user)
                .build();
        BDDMockito.given(emailVerificationTokenRepository.findAndLockByToken(any(String.class))).willReturn(Optional.of(emailVerificationToken));

        AccountStatus statusBefore = user.getStatus();
        boolean verifiedBefore = user.isEmailVerified();
        boolean usedBefore = emailVerificationToken.isUsed();

        // when

        // then
        assertThrowsExactly(EmailVerificationTokenExpiredException.class, () -> userServiceImpl.verify(emailVerificationToken.getToken()));

        verify(emailVerificationTokenRepository, times(1)).findAndLockByToken(emailVerificationToken.getToken());
        verifyNoMoreInteractions(emailVerificationTokenRepository);
        verifyNoInteractions(userRepository);

        assertEquals(statusBefore, user.getStatus());
        assertEquals(verifiedBefore, user.isEmailVerified());
        assertEquals(usedBefore, emailVerificationToken.isUsed());
    }

    @Test
    void givenTokenForDeletedUser_whenVerify_thenThrowAccountDeletedException() {
        // given
        User user = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.DELETED)
                .roles(Set.of(roleUser))
                .build();
        EmailVerificationToken emailVerificationToken = EmailVerificationToken.builder()
                .id(1L)
                .token(DEFAULT_EMAIL_TOKEN)
                .expiresAt(Instant.now().plus(Duration.ofHours(20)))
                .used(false)
                .issuedAt(Instant.now().minus(Duration.ofHours(4)))
                .user(user)
                .build();
        BDDMockito.given(emailVerificationTokenRepository.findAndLockByToken(any(String.class))).willReturn(Optional.of(emailVerificationToken));

        AccountStatus statusBefore = user.getStatus();
        boolean verifiedBefore = user.isEmailVerified();
        boolean usedBefore = emailVerificationToken.isUsed();

        // when

        // then
        assertThrowsExactly(AccountDeletedException.class, () -> userServiceImpl.verify(emailVerificationToken.getToken()));

        verify(emailVerificationTokenRepository, times(1)).findAndLockByToken(emailVerificationToken.getToken());
        verifyNoMoreInteractions(emailVerificationTokenRepository);
        verifyNoInteractions(userRepository);

        assertEquals(statusBefore, user.getStatus());
        assertEquals(verifiedBefore, user.isEmailVerified());
        assertEquals(usedBefore, emailVerificationToken.isUsed());
    }

    @Test
    void givenExistingUsedToken_whenVerify_thenNoActivation() {
        // given
        User user = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .roles(Set.of(roleUser))
                .build();
        EmailVerificationToken emailVerificationToken = EmailVerificationToken.builder()
                .id(1L)
                .token(DEFAULT_EMAIL_TOKEN)
                .expiresAt(Instant.now().minus(Duration.ofHours(1)))
                .used(true)
                .issuedAt(Instant.now().minus(Duration.ofHours(24)))
                .user(user)
                .build();
        BDDMockito.given(emailVerificationTokenRepository.findAndLockByToken(any(String.class))).willReturn(Optional.of(emailVerificationToken));

        AccountStatus statusBefore = user.getStatus();
        boolean verifiedBefore = user.isEmailVerified();
        boolean usedBefore = emailVerificationToken.isUsed();

        // when
        userServiceImpl.verify(emailVerificationToken.getToken());

        // then
        verify(emailVerificationTokenRepository, times(1)).findAndLockByToken(emailVerificationToken.getToken());
        verifyNoMoreInteractions(emailVerificationTokenRepository);
        verifyNoInteractions(userRepository);

        assertEquals(statusBefore, user.getStatus());
        assertEquals(verifiedBefore, user.isEmailVerified());
        assertEquals(usedBefore, emailVerificationToken.isUsed());
    }

    // ! logout

    @Test
    void givenValidRefreshToken_whenLogout_thenRevokeToken() {
        // given
        HashMap<String, String> claimsMap = new HashMap<>();
        claimsMap.put("jti", DEFAULT_RT_JTI);
        DefaultClaims defaultClaims = new DefaultClaims(claimsMap);
        BDDMockito.given(jwtService.extractAllClaims(DEFAULT_REFRESH_TOKEN)).willReturn(defaultClaims);
        BDDMockito.given(refreshTokenRepository.revokeByTokenId(DEFAULT_RT_JTI)).willReturn(1);

        // when
        assertDoesNotThrow(() -> userServiceImpl.logout(DEFAULT_REFRESH_TOKEN));

        // then
        verify(jwtService).extractAllClaims(DEFAULT_REFRESH_TOKEN);
        verify(refreshTokenRepository).revokeByTokenId(DEFAULT_RT_JTI);
        verifyNoMoreInteractions(refreshTokenRepository);
    }

    @Test
    void givenInvalidRefreshToken_whenLogout_thenThrowInvalidRefreshTokenException() {
        // given
        String refreshToken = "invalid";
        BDDMockito.given(jwtService.extractAllClaims(refreshToken)).willThrow(JwtException.class);

        // when

        // then
        assertThrows(InvalidRefreshTokenException.class, () -> userServiceImpl.logout(refreshToken));
        verify(jwtService).extractAllClaims(refreshToken);
        verifyNoInteractions(refreshTokenRepository);
    }

    @Test
    void givenNonExistingRefreshToken_whenLogout_thenThrowRefreshTokenNotFoundException() {
        // given
        HashMap<String, String> claimsMap = new HashMap<>();
        claimsMap.put("jti", DEFAULT_RT_JTI);
        DefaultClaims defaultClaims = new DefaultClaims(claimsMap);
        BDDMockito.given(jwtService.extractAllClaims(DEFAULT_REFRESH_TOKEN)).willReturn(defaultClaims);
        BDDMockito.given(refreshTokenRepository.revokeByTokenId(DEFAULT_RT_JTI)).willReturn(0);

        // when

        // then
        assertThrows(RefreshTokenNotFoundException.class, () -> userServiceImpl.logout(DEFAULT_REFRESH_TOKEN));
        verify(jwtService).extractAllClaims(DEFAULT_REFRESH_TOKEN);
        verifyNoMoreInteractions(jwtService);
        verify(refreshTokenRepository).revokeByTokenId(DEFAULT_RT_JTI);
        verifyNoMoreInteractions(refreshTokenRepository);
    }

    // ! login

    @Test
    void givenValidLoginRequest_whenLogin_thenGenerateSaveAndReturnTokens() {
        // given
        User user = User.builder()
                .id(42L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(HASHED_DEFAULT_PASSWORD)
                .failedLoginAttempts(10)            // will be reset to 0
                .accountNonLocked(false)           // will be unlocked
                .lockedUntil(Instant.now().minus(Duration.ofMinutes(1)))
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        var principal = new UserPrincipal(user);
        Authentication auth = new UsernamePasswordAuthenticationToken(
                principal, "ignored", principal.getAuthorities());
        BDDMockito.given(authenticationManager.authenticate(any(Authentication.class)))
                .willReturn(auth);
        BDDMockito.given(userRepository.findByUsername(user.getUsername())).willReturn(Optional.of(user));
        BDDMockito.given(refreshTokenRepository.countByUserIdAndRevokedFalseAndExpiresAtAfter(eq(user.getId()), any(Instant.class))).willReturn(0L);
        BDDMockito.given(accountProperties.concurrentSessionsLimit()).willReturn(20);
        BDDMockito.given(jwtService.generateAccessToken(any(String.class), anyList(), any(String.class))).willReturn(DEFAULT_ACCESS_TOKEN);
        BDDMockito.given(jwtService.generateRefreshToken(any(String.class), any(String.class))).willReturn(DEFAULT_REFRESH_TOKEN);
        BDDMockito.given(jwtService.extractExpiration(any(String.class))).willReturn(Date.from(Instant.now().plus(Duration.ofDays(60))));

        // when
        TokenPair tokenPair = userServiceImpl.login(DEFAULT_USERNAME, DEFAULT_PASSWORD, false);

        // then
        assertNotNull(tokenPair);
        verify(authenticationManager).authenticate(any(Authentication.class));
        verify(userRepository).findByUsername(DEFAULT_USERNAME);
        verify(refreshTokenRepository).countByUserIdAndRevokedFalseAndExpiresAtAfter(eq(user.getId()), any(Instant.class));
        verify(accountProperties).concurrentSessionsLimit();
        verify(jwtService).extractExpiration(DEFAULT_REFRESH_TOKEN);

        var savedUserCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(savedUserCaptor.capture());
        var savedUser = savedUserCaptor.getValue();
        assertEquals(0, savedUser.getFailedLoginAttempts());
        assertTrue(savedUser.isAccountNonLocked());
        assertNull(savedUser.getLockedUntil());

        ArgumentCaptor<String> jtiAccessCaptor  = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> jtiRefreshCaptor = ArgumentCaptor.forClass(String.class);
        verify(jwtService, times(1)).generateAccessToken(eq(user.getUsername()), anyList(), jtiAccessCaptor.capture());
        verify(jwtService, times(1)).generateRefreshToken(eq(user.getUsername()), jtiRefreshCaptor.capture());

        verify(refreshTokenRepository, times(1)).save(refreshTokenCaptor.capture());
        var savedToken = refreshTokenCaptor.getValue();
        assertEquals(savedToken.getTokenId(), jtiAccessCaptor.getValue());
        assertEquals(savedToken.getTokenId(), jtiRefreshCaptor.getValue());
    }

    @Test
    void givenValidLoginRequestCappedSessionsAndRevoke_whenLogin_thenRevokeSessionsGenerateSaveAndReturnTokens() {
        // given
        User user = User.builder()
                .id(42L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(HASHED_DEFAULT_PASSWORD)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        var principal = new UserPrincipal(user);
        Authentication auth = new UsernamePasswordAuthenticationToken(
                principal, "ignored", principal.getAuthorities());
        BDDMockito.given(authenticationManager.authenticate(any(Authentication.class)))
                .willReturn(auth);
        BDDMockito.given(userRepository.findByUsername(user.getUsername())).willReturn(Optional.of(user));
        BDDMockito.given(refreshTokenRepository.countByUserIdAndRevokedFalseAndExpiresAtAfter(eq(user.getId()), any(Instant.class))).willReturn(25L);
        BDDMockito.given(accountProperties.concurrentSessionsLimit()).willReturn(20);
        RefreshToken foundRefreshToken = RefreshToken.builder()
                .id(1L)
                .tokenId(DEFAULT_RT_JTI)
                .expiresAt(Instant.now().plus(Duration.ofDays(5)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(55)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        BDDMockito.given(refreshTokenRepository.findFirstByUserIdAndRevokedFalseOrderByIssuedAtAsc(eq(user.getId()))).willReturn(Optional.of(foundRefreshToken));
        BDDMockito.given(jwtService.generateAccessToken(any(String.class), anyList(), any(String.class))).willReturn(DEFAULT_ACCESS_TOKEN);
        BDDMockito.given(jwtService.generateRefreshToken(any(String.class), any(String.class))).willReturn(DEFAULT_REFRESH_TOKEN);
        BDDMockito.given(jwtService.extractExpiration(any(String.class))).willReturn(Date.from(Instant.now().plus(Duration.ofDays(60))));

        // when
        TokenPair tokenPair = userServiceImpl.login(DEFAULT_USERNAME, DEFAULT_PASSWORD, true);

        // then
        assertNotNull(tokenPair);
        assertTrue(foundRefreshToken.isRevoked());
        verify(authenticationManager).authenticate(any(Authentication.class));
        verify(userRepository).findByUsername(DEFAULT_USERNAME);
        verify(refreshTokenRepository).countByUserIdAndRevokedFalseAndExpiresAtAfter(eq(user.getId()), any(Instant.class));
        verify(accountProperties).concurrentSessionsLimit();
        verify(refreshTokenRepository).findFirstByUserIdAndRevokedFalseOrderByIssuedAtAsc(eq(user.getId()));
        verify(jwtService).extractExpiration(DEFAULT_REFRESH_TOKEN);

        var savedUserCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(savedUserCaptor.capture());
        var savedUser = savedUserCaptor.getValue();
        assertEquals(0, savedUser.getFailedLoginAttempts());
        assertTrue(savedUser.isAccountNonLocked());
        assertNull(savedUser.getLockedUntil());

        ArgumentCaptor<String> jtiAccessCaptor  = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> jtiRefreshCaptor = ArgumentCaptor.forClass(String.class);
        verify(jwtService, times(1)).generateAccessToken(eq(user.getUsername()), anyList(), jtiAccessCaptor.capture());
        verify(jwtService, times(1)).generateRefreshToken(eq(user.getUsername()), jtiRefreshCaptor.capture());

        verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
    }

    @Test
    void givenNonExistingUsername_whenLogin_thenAuthenticationManagerThrowCustomUnauthorizedException() {
        // given
        BDDMockito.given(authenticationManager.authenticate(any(Authentication.class)))
                .willThrow(CustomUnauthorizedException.class);

        // when

        // then
        assertThrowsExactly(CustomUnauthorizedException.class, () -> userServiceImpl.login(DEFAULT_USERNAME, DEFAULT_PASSWORD, false));
    }

    @Test
    void givenExistingUsernameWrongPassword_whenLogin_thenAuthenticationManagerThrowCustomUnauthorizedExceptionAndLock() {
        // given
        User user = User.builder()
                .id(42L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(HASHED_DEFAULT_PASSWORD)
                .failedLoginAttempts(10)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        BDDMockito.given(authenticationManager.authenticate(any(Authentication.class)))
                .willThrow(CustomUnauthorizedException.class);
        BDDMockito.given(userRepository.findByUsername(user.getUsername()))
                .willReturn(Optional.of(user));
        BDDMockito.given(accountProperties.maxFailedAttempts()).willReturn(5);
        BDDMockito.given(accountProperties.lockDuration()).willReturn(Duration.ofMinutes(15));

        // when

        // then
        assertThrowsExactly(CustomUnauthorizedException.class, () -> userServiceImpl.login(DEFAULT_USERNAME, DEFAULT_PASSWORD, false));
        verify(userRepository).findByUsername(anyString());
        verify(userRepository).save(any(User.class));
        assertFalse(user.isAccountNonLocked());
        assertNotNull(user.getLockedUntil());
    }

    @Test
    void givenNonExistingUsername_whenLogin_thenUserRepositoryThrowCustomUnauthorizedException() {
        // ? this should never happen because it invalid username is given CustomUnauthorizedException will be thrown by authenticationManager

        // given
        User user = User.builder()
                .id(42L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(HASHED_DEFAULT_PASSWORD)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        var principal = new UserPrincipal(user);
        Authentication auth = new UsernamePasswordAuthenticationToken(
                principal, "ignored", principal.getAuthorities());
        BDDMockito.given(authenticationManager.authenticate(any(Authentication.class)))
                .willReturn(auth);
        BDDMockito.given(userRepository.findByUsername(anyString()))
                .willThrow(CustomUnauthorizedException.class);

        // when

        // then
        assertThrowsExactly(CustomUnauthorizedException.class, () -> userServiceImpl.login(DEFAULT_USERNAME, DEFAULT_PASSWORD, false));
        verify(authenticationManager).authenticate(any(Authentication.class));
    }

    @Test
    void givenValidLoginRequestForUserLockedAccount_whenLogin_thenThrowAccountLockedException() {
        // given
        int numberOfFailedLoginAttempts = 10;
        User user = User.builder()
                .id(42L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(HASHED_DEFAULT_PASSWORD)
                .failedLoginAttempts(numberOfFailedLoginAttempts)   // will stay same
                .accountNonLocked(false)                            // will stay locked
                .lockedUntil(Instant.now().plus(Duration.ofMinutes(10)))
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        var principal = new UserPrincipal(user);
        Authentication auth = new UsernamePasswordAuthenticationToken(
                principal, "ignored", principal.getAuthorities());
        BDDMockito.given(authenticationManager.authenticate(any(Authentication.class)))
                .willReturn(auth);
        BDDMockito.given(userRepository.findByUsername(user.getUsername())).willReturn(Optional.of(user));

        // when

        // then
        assertThrowsExactly(AccountLockedException.class, () -> userServiceImpl.login(DEFAULT_USERNAME, DEFAULT_PASSWORD, false));
        verify(authenticationManager).authenticate(any(Authentication.class));
        verify(userRepository).findByUsername(anyString());
        verifyNoMoreInteractions(userRepository);
        verifyNoInteractions(refreshTokenRepository);
        assertEquals(numberOfFailedLoginAttempts, user.getFailedLoginAttempts());
        assertFalse(user.isAccountNonLocked());
    }

    @Test
    void givenValidLoginRequestForUserPendingVerification_whenLogin_thenThrowEmailNotVerifiedException() {
        // given
        User user = User.builder()
                .id(42L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(HASHED_DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .roles(Set.of(roleUser))
                .build();
        var principal = new UserPrincipal(user);
        Authentication auth = new UsernamePasswordAuthenticationToken(
                principal, "ignored", principal.getAuthorities());
        BDDMockito.given(authenticationManager.authenticate(any(Authentication.class)))
                .willReturn(auth);
        BDDMockito.given(userRepository.findByUsername(user.getUsername())).willReturn(Optional.of(user));

        // when

        // then
        assertThrowsExactly(EmailNotVerifiedException.class, () -> userServiceImpl.login(DEFAULT_USERNAME, DEFAULT_PASSWORD, false));
        verify(authenticationManager).authenticate(any(Authentication.class));
        verify(userRepository).findByUsername(anyString());
        verifyNoMoreInteractions(userRepository);
        verifyNoInteractions(refreshTokenRepository);
    }

    @Test
    void givenValidLoginRequestForUserSuspended_whenLogin_thenThrowAccountSuspendedException() {
        // given
        User user = User.builder()
                .id(42L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(HASHED_DEFAULT_PASSWORD)
                .status(AccountStatus.SUSPENDED)
                .roles(Set.of(roleUser))
                .build();
        var principal = new UserPrincipal(user);
        Authentication auth = new UsernamePasswordAuthenticationToken(
                principal, "ignored", principal.getAuthorities());
        BDDMockito.given(authenticationManager.authenticate(any(Authentication.class)))
                .willReturn(auth);
        BDDMockito.given(userRepository.findByUsername(user.getUsername())).willReturn(Optional.of(user));

        // when

        // then
        assertThrowsExactly(AccountSuspendedException.class, () -> userServiceImpl.login(DEFAULT_USERNAME, DEFAULT_PASSWORD, false));
        verify(authenticationManager).authenticate(any(Authentication.class));
        verify(userRepository).findByUsername(anyString());
        verifyNoMoreInteractions(userRepository);
        verifyNoInteractions(refreshTokenRepository);
    }

    @Test
    void givenValidLoginRequestForUserDeleted_whenLogin_thenThrowAccountDeletedException() {
        // given
        User user = User.builder()
                .id(42L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(HASHED_DEFAULT_PASSWORD)
                .status(AccountStatus.DELETED)
                .roles(Set.of(roleUser))
                .build();
        var principal = new UserPrincipal(user);
        Authentication auth = new UsernamePasswordAuthenticationToken(
                principal, "ignored", principal.getAuthorities());
        BDDMockito.given(authenticationManager.authenticate(any(Authentication.class)))
                .willReturn(auth);
        BDDMockito.given(userRepository.findByUsername(user.getUsername())).willReturn(Optional.of(user));

        // when

        // then
        assertThrowsExactly(AccountDeletedException.class, () -> userServiceImpl.login(DEFAULT_USERNAME, DEFAULT_PASSWORD, false));
        verify(authenticationManager).authenticate(any(Authentication.class));
        verify(userRepository).findByUsername(anyString());
        verifyNoMoreInteractions(userRepository);
        verifyNoInteractions(refreshTokenRepository);
    }

    @Test
    void givenValidLoginRequestCappedSessionsAndNoRevoke_whenLogin_thenThrowConcurrentSessionLimitException() {
        // given
        User user = User.builder()
                .id(42L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(HASHED_DEFAULT_PASSWORD)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        var principal = new UserPrincipal(user);
        Authentication auth = new UsernamePasswordAuthenticationToken(
                principal, "ignored", principal.getAuthorities());
        BDDMockito.given(authenticationManager.authenticate(any(Authentication.class)))
                .willReturn(auth);
        BDDMockito.given(userRepository.findByUsername(user.getUsername())).willReturn(Optional.of(user));
        BDDMockito.given(refreshTokenRepository.countByUserIdAndRevokedFalseAndExpiresAtAfter(eq(user.getId()), any(Instant.class))).willReturn(25L);
        BDDMockito.given(accountProperties.concurrentSessionsLimit()).willReturn(20);

        // when

        // then
        assertThrowsExactly(ConcurrentSessionLimitException.class, () -> userServiceImpl.login(DEFAULT_USERNAME, DEFAULT_PASSWORD, false));
        verify(authenticationManager).authenticate(any(Authentication.class));
        verify(userRepository).findByUsername(DEFAULT_USERNAME);
        verify(userRepository).save(any(User.class));
        verify(refreshTokenRepository).countByUserIdAndRevokedFalseAndExpiresAtAfter(eq(user.getId()), any(Instant.class));
        verify(accountProperties, times(2)).concurrentSessionsLimit();
        verifyNoMoreInteractions(refreshTokenRepository);
    }

    // RefreshTokenNotFoundException in revokeOldestByUserId() will not be covered

    @Test
    void givenLockedAccountUser_whenLogin_thenAuthenticationManagerThrowAccountLockedException() {
        // given
        BDDMockito.given(authenticationManager.authenticate(any(Authentication.class)))
                .willThrow(AccountLockedException.class);

        // when

        // then
        assertThrowsExactly(AccountLockedException.class, () -> userServiceImpl.login(DEFAULT_USERNAME, DEFAULT_PASSWORD, false));
        verifyNoInteractions(userRepository);
        verifyNoInteractions(refreshTokenRepository);
        verifyNoInteractions(accountProperties);
        verifyNoInteractions(jwtService);
    }

    // JwtGenerationException will not be covered

    // ! refresh

    @Test
    void givenValidRefreshToken_whenRefresh_thenGenerateSaveAndReturnNewTokens() {
        // given
        HashMap<String, String> claimsMap = new HashMap<>();
        claimsMap.put("jti", DEFAULT_RT_JTI);
        User user = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        claimsMap.put("sub", user.getUsername());
        DefaultClaims defaultClaims = new DefaultClaims(claimsMap);
        BDDMockito.given(jwtService.extractAllClaims(any(String.class))).willReturn(defaultClaims);
        RefreshToken foundRefreshToken = RefreshToken.builder()
                .id(1L)
                .tokenId(DEFAULT_RT_JTI)
                .expiresAt(Instant.now().plus(Duration.ofDays(59)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(1)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        BDDMockito.given(refreshTokenRepository.findAndLockByTokenId(DEFAULT_RT_JTI)).willReturn(Optional.of(foundRefreshToken));
        BDDMockito.given(jwtService.generateAccessToken(any(String.class), anyList(), any(String.class))).willReturn(DEFAULT_ACCESS_TOKEN);
        String newRefreshToken = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyYiIsImp0aSI6IjVjNjNjN2ViLTVkMWMtNGRhZi04MjBhLWQyODAzMjAwNTU0OCIsImlhdCI6MTc1NTQ0OTAzNywiZXhwIjoxNzYwNjMzMDM3fQ.qtU_MriFErxcubBF0_WhqrZ02VcUoHxUaL3E0LUE5O-PNQHuJXiCuGZDsXwqS8sVLcS8qT-ZqqNP8rAGP8nSjA";
        BDDMockito.given(jwtService.generateRefreshToken(any(String.class), any(String.class))).willReturn(newRefreshToken);
        BDDMockito.given(jwtService.extractExpiration(any(String.class))).willReturn(Date.from(Instant.now().plus(Duration.ofDays(60))));

        // when
        TokenPair pair = userServiceImpl.refresh(DEFAULT_REFRESH_TOKEN);

        // then
        assertTrue(foundRefreshToken.isRevoked());

        assertEquals(DEFAULT_ACCESS_TOKEN, pair.accessToken());
        assertEquals(newRefreshToken, pair.refreshToken());

        ArgumentCaptor<String> jtiAccessCaptor  = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> jtiRefreshCaptor = ArgumentCaptor.forClass(String.class);
        verify(jwtService, times(1)).generateAccessToken(anyString(), anyList(), jtiAccessCaptor.capture());
        verify(jwtService, times(1)).generateRefreshToken(eq(user.getUsername()), jtiRefreshCaptor.capture());

        verify(refreshTokenRepository, times(1)).save(refreshTokenCaptor.capture());
        var savedToken = refreshTokenCaptor.getValue();
        assertNotEquals(foundRefreshToken.getTokenId(), savedToken.getTokenId());
        assertEquals(savedToken.getTokenId(), jtiAccessCaptor.getValue());
        assertEquals(savedToken.getTokenId(), jtiRefreshCaptor.getValue());
    }

    @Test
    void givenInvalidRefreshToken_whenRefresh_thenThrowInvalidRefreshTokenException() {
        // given
        BDDMockito.given(jwtService.extractAllClaims(anyString())).willThrow(new RuntimeException("bad jwt"));

        // when

        // then
        assertThrowsExactly(InvalidRefreshTokenException.class, () -> userServiceImpl.refresh("invalid token"));
        verifyNoInteractions(refreshTokenRepository);
        verify(jwtService, never()).generateAccessToken(anyString(), anyList(), anyString());
        verify(jwtService, never()).generateRefreshToken(anyString(), anyString());
        verify(jwtService, never()).extractExpiration(anyString());
    }

    @Test
    void givenNonExistingTokenId_whenRefresh_thenThrowInvalidRefreshTokenException() {
        // given
        var claims = new DefaultClaims(Map.of("jti","abc", "sub","user"));
        BDDMockito.given(jwtService.extractAllClaims(anyString())).willReturn(claims);
        BDDMockito.given(refreshTokenRepository.findAndLockByTokenId(anyString())).willReturn(Optional.empty());

        // when

        // then
        assertThrowsExactly(InvalidRefreshTokenException.class, () -> userServiceImpl.refresh(DEFAULT_REFRESH_TOKEN));
        verify(jwtService, never()).generateAccessToken(anyString(), anyList(), anyString());
        verify(jwtService, never()).generateRefreshToken(anyString(), anyString());
        verify(jwtService, never()).extractExpiration(anyString());
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    void givenTokenUserPendingVerification_whenRefresh_thenThrowEmailNotVerifiedException() {
        // given
        HashMap<String, String> claimsMap = new HashMap<>();
        claimsMap.put("jti", DEFAULT_RT_JTI);
        User user = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .roles(Set.of(roleUser))
                .build();
        claimsMap.put("sub", user.getUsername());
        DefaultClaims defaultClaims = new DefaultClaims(claimsMap);
        BDDMockito.given(jwtService.extractAllClaims(any(String.class))).willReturn(defaultClaims);
        RefreshToken foundRefreshToken = RefreshToken.builder()
                .id(1L)
                .tokenId(DEFAULT_RT_JTI)
                .expiresAt(Instant.now().minus(Duration.ofDays(1)))
                .revoked(true)
                .issuedAt(Instant.now().minus(Duration.ofDays(61)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        BDDMockito.given(refreshTokenRepository.findAndLockByTokenId(DEFAULT_RT_JTI)).willReturn(Optional.of(foundRefreshToken));

        // when

        // then
        assertThrowsExactly(EmailNotVerifiedException.class, () -> userServiceImpl.refresh(DEFAULT_REFRESH_TOKEN));
        verify(jwtService, never()).generateAccessToken(anyString(), anyList(), anyString());
        verify(jwtService, never()).generateRefreshToken(anyString(), anyString());
        verify(jwtService, never()).extractExpiration(anyString());
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    void givenTokenUserSuspended_whenRefresh_thenThrowAccountSuspendedException() {
        // given
        HashMap<String, String> claimsMap = new HashMap<>();
        claimsMap.put("jti", DEFAULT_RT_JTI);
        User user = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.SUSPENDED)
                .roles(Set.of(roleUser))
                .build();
        claimsMap.put("sub", user.getUsername());
        DefaultClaims defaultClaims = new DefaultClaims(claimsMap);
        BDDMockito.given(jwtService.extractAllClaims(any(String.class))).willReturn(defaultClaims);
        RefreshToken foundRefreshToken = RefreshToken.builder()
                .id(1L)
                .tokenId(DEFAULT_RT_JTI)
                .expiresAt(Instant.now().minus(Duration.ofDays(1)))
                .revoked(true)
                .issuedAt(Instant.now().minus(Duration.ofDays(61)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        BDDMockito.given(refreshTokenRepository.findAndLockByTokenId(DEFAULT_RT_JTI)).willReturn(Optional.of(foundRefreshToken));

        // when

        // then
        assertThrowsExactly(AccountSuspendedException.class, () -> userServiceImpl.refresh(DEFAULT_REFRESH_TOKEN));
        verify(jwtService, never()).generateAccessToken(anyString(), anyList(), anyString());
        verify(jwtService, never()).generateRefreshToken(anyString(), anyString());
        verify(jwtService, never()).extractExpiration(anyString());
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    void givenTokenUserDeleted_whenRefresh_thenThrowAccountDeletedException() {
        // given
        HashMap<String, String> claimsMap = new HashMap<>();
        claimsMap.put("jti", DEFAULT_RT_JTI);
        User user = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.DELETED)
                .roles(Set.of(roleUser))
                .build();
        claimsMap.put("sub", user.getUsername());
        DefaultClaims defaultClaims = new DefaultClaims(claimsMap);
        BDDMockito.given(jwtService.extractAllClaims(any(String.class))).willReturn(defaultClaims);
        RefreshToken foundRefreshToken = RefreshToken.builder()
                .id(1L)
                .tokenId(DEFAULT_RT_JTI)
                .expiresAt(Instant.now().minus(Duration.ofDays(1)))
                .revoked(true)
                .issuedAt(Instant.now().minus(Duration.ofDays(61)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        BDDMockito.given(refreshTokenRepository.findAndLockByTokenId(DEFAULT_RT_JTI)).willReturn(Optional.of(foundRefreshToken));

        // when

        // then
        assertThrowsExactly(AccountDeletedException.class, () -> userServiceImpl.refresh(DEFAULT_REFRESH_TOKEN));
        verify(jwtService, never()).generateAccessToken(anyString(), anyList(), anyString());
        verify(jwtService, never()).generateRefreshToken(anyString(), anyString());
        verify(jwtService, never()).extractExpiration(anyString());
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    void givenRevokedToken_whenRefresh_thenThrowExpiredOrRevokedRefreshTokenException() {
        // given
        HashMap<String, String> claimsMap = new HashMap<>();
        claimsMap.put("jti", DEFAULT_RT_JTI);
        User user = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        claimsMap.put("sub", user.getUsername());
        DefaultClaims defaultClaims = new DefaultClaims(claimsMap);
        BDDMockito.given(jwtService.extractAllClaims(any(String.class))).willReturn(defaultClaims);
        RefreshToken foundRefreshToken = RefreshToken.builder()
                .id(1L)
                .tokenId(DEFAULT_RT_JTI)
                .expiresAt(Instant.now().plus(Duration.ofDays(59)))
                .revoked(true)
                .issuedAt(Instant.now().minus(Duration.ofDays(1)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        BDDMockito.given(refreshTokenRepository.findAndLockByTokenId(DEFAULT_RT_JTI)).willReturn(Optional.of(foundRefreshToken));

        // when

        // then
        assertThrowsExactly(ExpiredOrRevokedRefreshTokenException.class, () -> userServiceImpl.refresh(DEFAULT_REFRESH_TOKEN));
        verify(jwtService, never()).generateAccessToken(anyString(), anyList(), anyString());
        verify(jwtService, never()).generateRefreshToken(anyString(), anyString());
        verify(jwtService, never()).extractExpiration(anyString());
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }

    @Test
    void givenExpiredToken_whenRefresh_thenThrowExpiredOrRevokedRefreshTokenException() {
        // given
        HashMap<String, String> claimsMap = new HashMap<>();
        claimsMap.put("jti", DEFAULT_RT_JTI);
        User user = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.ACTIVE)
                .roles(Set.of(roleUser))
                .build();
        claimsMap.put("sub", user.getUsername());
        DefaultClaims defaultClaims = new DefaultClaims(claimsMap);
        BDDMockito.given(jwtService.extractAllClaims(any(String.class))).willReturn(defaultClaims);
        RefreshToken foundRefreshToken = RefreshToken.builder()
                .id(1L)
                .tokenId(DEFAULT_RT_JTI)
                .expiresAt(Instant.now().minus(Duration.ofDays(1)))
                .revoked(false)
                .issuedAt(Instant.now().minus(Duration.ofDays(61)))
                .ipAddress("0:0:0:0:0:0:0:1")
                .userAgent("PostmanRuntime/7.44.1")
                .user(user)
                .build();
        BDDMockito.given(refreshTokenRepository.findAndLockByTokenId(DEFAULT_RT_JTI)).willReturn(Optional.of(foundRefreshToken));

        // when

        // then
        assertThrowsExactly(ExpiredOrRevokedRefreshTokenException.class, () -> userServiceImpl.refresh(DEFAULT_REFRESH_TOKEN));
        verify(jwtService, never()).generateAccessToken(anyString(), anyList(), anyString());
        verify(jwtService, never()).generateRefreshToken(anyString(), anyString());
        verify(jwtService, never()).extractExpiration(anyString());
        verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
    }
}

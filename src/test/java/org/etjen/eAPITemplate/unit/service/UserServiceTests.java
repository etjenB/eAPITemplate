package org.etjen.eAPITemplate.unit.service;

import org.etjen.eAPITemplate.config.properties.security.AccountProperties;
import org.etjen.eAPITemplate.config.properties.security.EmailVerificationProperties;
import org.etjen.eAPITemplate.domain.model.EmailVerificationToken;
import org.etjen.eAPITemplate.domain.model.Role;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.domain.model.enums.AppRole;
import org.etjen.eAPITemplate.exception.auth.*;
import org.etjen.eAPITemplate.repository.EmailVerificationTokenRepository;
import org.etjen.eAPITemplate.repository.RefreshTokenRepository;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.etjen.eAPITemplate.security.auth.RoleCache;
import org.etjen.eAPITemplate.security.jwt.JwtService;
import org.etjen.eAPITemplate.service.EmailService;
import org.etjen.eAPITemplate.service.custom.UserServiceImpl;
import org.etjen.eAPITemplate.web.payload.auth.RegistrationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

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
    private Role roleUser;
    private final String DEFAULT_PASSWORD = "Corners8829%";
    private final String HASHED_DEFAULT_PASSWORD = "$2a$10$FMqByHgNfU/iy2DBubUcpOv29O8sdUubtwLBQGQapCe3AHd3rxo1m";
    private final String DEFAULT_USERNAME = "user";
    private final String DEFAULT_EMAIL = "user@gmail.com";
    private final String DEFAULT_TOKEN = "103cda9b-95c4-4f6f-885e-b30fa2f382fa";

    @BeforeEach
    void setUp() {
        roleUser = new Role();
        roleUser.setId(1);
        roleUser.setName("ROLE_USER");
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
                .token(DEFAULT_TOKEN)
                .expiresAt(Instant.now().plus(Duration.ofHours(24)))
                .used(false)
                .issuedAt(Instant.now())
                .user(user)
                .build();
        BDDMockito.given(emailVerificationTokenRepository.findByToken(any(String.class))).willReturn(Optional.of(emailVerificationToken));

        // when
        userServiceImpl.verify(emailVerificationToken.getToken());

        // then
        User foundUser = emailVerificationToken.getUser();
        verify(emailVerificationTokenRepository).findByToken(stringTokenCaptor.capture());
        assertEquals(emailVerificationToken.getToken(), stringTokenCaptor.getValue());
        assertEquals(AccountStatus.ACTIVE, foundUser.getStatus());
        assertTrue(foundUser.isEmailVerified());
        assertTrue(emailVerificationToken.isUsed());
    }

    @Test
    void givenNonExistingToken_whenVerify_thenThrowEmailVerificationTokenNotFoundException() {
        // given
        BDDMockito.given(emailVerificationTokenRepository.findByToken(any(String.class))).willReturn(Optional.empty());

        // when

        // then
        assertThrowsExactly(EmailVerificationTokenNotFoundException.class, () -> userServiceImpl.verify(DEFAULT_TOKEN));

        verify(emailVerificationTokenRepository, times(1)).findByToken(any());
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
                .token(DEFAULT_TOKEN)
                .expiresAt(Instant.now().minus(Duration.ofHours(1)))
                .used(false)
                .issuedAt(Instant.now().minus(Duration.ofHours(24)))
                .user(user)
                .build();
        BDDMockito.given(emailVerificationTokenRepository.findByToken(any(String.class))).willReturn(Optional.of(emailVerificationToken));

        AccountStatus statusBefore = user.getStatus();
        boolean verifiedBefore = user.isEmailVerified();
        boolean usedBefore = emailVerificationToken.isUsed();

        // when

        // then
        assertThrowsExactly(EmailVerificationTokenExpiredException.class, () -> userServiceImpl.verify(emailVerificationToken.getToken()));

        verify(emailVerificationTokenRepository, times(1)).findByToken(emailVerificationToken.getToken());
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
                .token(DEFAULT_TOKEN)
                .expiresAt(Instant.now().minus(Duration.ofHours(1)))
                .used(true)
                .issuedAt(Instant.now().minus(Duration.ofHours(24)))
                .user(user)
                .build();
        BDDMockito.given(emailVerificationTokenRepository.findByToken(any(String.class))).willReturn(Optional.of(emailVerificationToken));

        AccountStatus statusBefore = user.getStatus();
        boolean verifiedBefore = user.isEmailVerified();
        boolean usedBefore = emailVerificationToken.isUsed();

        // when
        userServiceImpl.verify(emailVerificationToken.getToken());

        // then
        verify(emailVerificationTokenRepository, times(1)).findByToken(emailVerificationToken.getToken());
        verifyNoMoreInteractions(emailVerificationTokenRepository);
        verifyNoInteractions(userRepository);

        assertEquals(statusBefore, user.getStatus());
        assertEquals(verifiedBefore, user.isEmailVerified());
        assertEquals(usedBefore, emailVerificationToken.isUsed());
    }
}

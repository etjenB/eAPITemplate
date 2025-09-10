package org.etjen.eAPITemplate.unit.security;

import org.etjen.eAPITemplate.domain.model.Role;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedException;
import org.etjen.eAPITemplate.exception.auth.UserNotFoundException;
import org.etjen.eAPITemplate.security.provider.CustomAuthenticationProvider;
import org.etjen.eAPITemplate.security.user.UserDetailsServiceImpl;
import org.etjen.eAPITemplate.security.user.UserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class CustomAuthenticationProviderTests {
    @Mock
    private UserDetailsServiceImpl userDetailsService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @InjectMocks
    private CustomAuthenticationProvider customAuthenticationProvider;
    private final String DEFAULT_PASSWORD = "Corners8829%";
    private final String DEFAULT_USERNAME = "user";
    private final String DEFAULT_EMAIL = "user@gmail.com";
    private String DEFAULT_USER_NOT_FOUND_ENCODED_PASSWORD_HASH = "encoded";
    private Role roleUser = new Role(1, "ROLE_USER");

    @Test
    void givenValidAuth_whenAuthenticate_thenMatchesCalledOnceAndReturnSameAuth() {
        // given
        User user = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .roles(Set.of(roleUser))
                .build();
        UserDetails userDetails = new UserPrincipal(user);
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                userDetails, DEFAULT_PASSWORD, userDetails.getAuthorities());
        BDDMockito.given(userDetailsService.loadUserByUsername(user.getUsername())).willReturn(userDetails);
        BDDMockito.given(passwordEncoder.matches(auth.getCredentials().toString(), user.getPassword())).willReturn(true);

        // when
        Authentication returnedAuth = customAuthenticationProvider.authenticate(auth);

        // then
        verify(userDetailsService).loadUserByUsername(user.getUsername());
        verify(passwordEncoder).matches(auth.getCredentials().toString(), user.getPassword());
        assertEquals(user.getPassword(), returnedAuth.getCredentials().toString());
    }

    @Test
    void givenNonExistingUser_whenAuthenticate_thenMatchesCalledOnceAndThrowCustomUnauthorizedException() {
        // given
        BDDMockito.given(passwordEncoder.encode(anyString())).willReturn(DEFAULT_USER_NOT_FOUND_ENCODED_PASSWORD_HASH);
        ReflectionTestUtils.invokeMethod(customAuthenticationProvider, "initDummyHash");
        User user = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .roles(Set.of(roleUser))
                .build();
        UserDetails userDetails = new UserPrincipal(user);
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                userDetails, DEFAULT_PASSWORD, userDetails.getAuthorities());
        BDDMockito.given(userDetailsService.loadUserByUsername(user.getUsername())).willThrow(UserNotFoundException.class);

        // when

        // then
        assertThrowsExactly(CustomUnauthorizedException.class, () -> customAuthenticationProvider.authenticate(auth));
        verify(passwordEncoder).matches(auth.getCredentials().toString(), DEFAULT_USER_NOT_FOUND_ENCODED_PASSWORD_HASH);
        verifyNoMoreInteractions(passwordEncoder);
    }

    @Test
    void givenExistingUserWithIncorrectPassword_whenAuthenticate_thenThrowCustomUnauthorizedException() {
        // given
        User user = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .roles(Set.of(roleUser))
                .build();
        UserDetails userDetails = new UserPrincipal(user);
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                userDetails, DEFAULT_PASSWORD, userDetails.getAuthorities());
        BDDMockito.given(userDetailsService.loadUserByUsername(user.getUsername())).willReturn(userDetails);
        BDDMockito.given(passwordEncoder.matches(auth.getCredentials().toString(), user.getPassword())).willReturn(false);

        // when

        // then
        assertThrowsExactly(CustomUnauthorizedException.class, () -> customAuthenticationProvider.authenticate(auth));
        verify(passwordEncoder).matches(auth.getCredentials().toString(), user.getPassword());
        verifyNoMoreInteractions(passwordEncoder);
    }
}

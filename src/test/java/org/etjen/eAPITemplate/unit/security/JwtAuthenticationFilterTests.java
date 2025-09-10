package org.etjen.eAPITemplate.unit.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.etjen.eAPITemplate.domain.model.Role;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.security.jwt.JwtAuthenticationFilter;
import org.etjen.eAPITemplate.security.jwt.JwtService;
import org.etjen.eAPITemplate.security.user.UserDetailsServiceImpl;
import org.etjen.eAPITemplate.security.user.UserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import java.io.IOException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class JwtAuthenticationFilterTests {
    @Mock
    private JwtService jwtService;
    @Mock
    private UserDetailsServiceImpl userDetailsService;
    @Mock
    private HttpServletRequest httpServletRequest;
    @Mock
    private HttpServletResponse httpServletResponse;
    @Mock
    private FilterChain filterChain;
    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;
    private String DEFAULT_ACCESS_TOKEN = "eyJhbGciOiJIUzUxMiJ9.eyJyb2xlcyI6WyJST0xFX1VTRVIiXSwic3ViIjoidXNlcmIiLCJqdGkiOiJkYjZkZDhiYi04Yjk4LTQyOTMtYjlkMi1iNWRkMzY3ZjBmMTMiLCJpYXQiOjE3NTU4Njg0NDcsImV4cCI6MTc1NTg2OTY0N30.NBSR39v3GPUmCpu_kTujEdp27tgJglC18U_GKIbgn2qpSv-enAmSeJELHsyuA_DVd_LSjJNiyAwFnYBBHtqE7Q";
    private String DEFAULT_JTI = "db6dd8bb-8b98-4293-b9d2-b5dd367f0f13";
    private final String DEFAULT_PASSWORD = "Corners8829%";
    private final String DEFAULT_USERNAME = "user";
    private final String DEFAULT_EMAIL = "user@gmail.com";
    private Role roleUser = new Role(1, "ROLE_USER");

    @Test
    void givenValidBearerToken_whenFilterRuns_thenSetsAuthWithJti() throws ServletException, IOException {
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
        BDDMockito.given(httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("Bearer " + DEFAULT_ACCESS_TOKEN);
        BDDMockito.given(jwtService.extractUserName(DEFAULT_ACCESS_TOKEN)).willReturn(DEFAULT_USERNAME);
        BDDMockito.given(jwtService.extractClaim(eq(DEFAULT_ACCESS_TOKEN), any())).willReturn(DEFAULT_JTI);
        BDDMockito.given(userDetailsService.loadUserByUsername(DEFAULT_USERNAME)).willReturn(userDetails);
        BDDMockito.given(jwtService.validateToken(DEFAULT_ACCESS_TOKEN, userDetails)).willReturn(true);

        try {
            // when
            jwtAuthenticationFilter.doFilter(httpServletRequest, httpServletResponse, filterChain);

            // then
            var auth = SecurityContextHolder.getContext().getAuthentication();
            assertNotNull(auth, "Authentication should be set");
            assertEquals(DEFAULT_JTI, auth.getCredentials(), "JTI must be stored in credentials");
            assertSame(userDetails, auth.getPrincipal(), "Principal must be the loaded UserDetails");
            assertTrue(auth.isAuthenticated());
            verify(filterChain).doFilter(httpServletRequest, httpServletResponse);

            verify(jwtService).extractUserName(DEFAULT_ACCESS_TOKEN);
            verify(jwtService).extractClaim(eq(DEFAULT_ACCESS_TOKEN), any());
            verify(userDetailsService).loadUserByUsername(DEFAULT_USERNAME);
            verify(jwtService).validateToken(DEFAULT_ACCESS_TOKEN, userDetails);

            verify(httpServletResponse, never()).setStatus(anyInt());
            verify(httpServletResponse, never()).setContentType(anyString());
            verify(httpServletResponse, never()).getWriter();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }
}

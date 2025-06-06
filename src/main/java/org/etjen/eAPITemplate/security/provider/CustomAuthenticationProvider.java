package org.etjen.eAPITemplate.security.provider;

import org.etjen.eAPITemplate.exception.auth.AccountLockedException;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedExpection;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.etjen.eAPITemplate.security.user.UserDetailsServiceImpl;
import org.etjen.eAPITemplate.security.user.UserPrincipal;
import java.util.Date;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsServiceImpl userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public CustomAuthenticationProvider(UserDetailsServiceImpl userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication auth) throws CustomUnauthorizedExpection, AccountLockedException {
        String username = auth.getName();
        String rawPassword = auth.getCredentials().toString();

        UserPrincipal user = (UserPrincipal) userDetailsService.loadUserByUsername(username);

        if (user.getLockedUntil() != null && user.getLockedUntil().after(new Date())){
            throw new AccountLockedException("Account is locked");
        }

        if (passwordEncoder.matches(rawPassword, user.getPassword())) {
            return new UsernamePasswordAuthenticationToken(
                    user,
                    user.getPassword(),
                    user.getAuthorities()
            );
        } else {
            throw new CustomUnauthorizedExpection("Invalid username or password");
        }
    }

    @Override
    public boolean supports(Class<?> authType) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authType);
    }
}

package org.etjen.eAPITemplate.security.provider;

import jakarta.annotation.PostConstruct;
import org.etjen.eAPITemplate.exception.auth.AccountLockedException;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedException;
import org.etjen.eAPITemplate.exception.auth.UserNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.etjen.eAPITemplate.security.user.UserDetailsServiceImpl;
import org.etjen.eAPITemplate.security.user.UserPrincipal;
import java.time.Instant;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsServiceImpl userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private String userNotFoundEncodedPassword;

    @PostConstruct
    void initDummyHash() {
        userNotFoundEncodedPassword = passwordEncoder.encode("userNotFoundButYouDontKnow");
    }

    public CustomAuthenticationProvider(UserDetailsServiceImpl userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication auth) throws CustomUnauthorizedException, AccountLockedException {
        String username = auth.getName();
        String rawPassword = auth.getCredentials().toString();

        // ! since loadUserByUsername will try to find user if it doesn't find user it quickly gives back
        // ! UserNotFoundException and API responds in about 20ms but if the uer exists and password is incorrect
        // ! it will take about 700ms to match the passwords with password encoder, because of that an attacker has a way
        // ! to know if the username actually exists in the database, which is not good and we also have to do dummy
        // ! password comparison if the username is not found in the database i.e. we do Timing Attack protection in that way
        UserPrincipal user;
        try {
            user = (UserPrincipal) userDetailsService.loadUserByUsername(username);
        } catch (UserNotFoundException e) {
            passwordEncoder.matches(rawPassword, userNotFoundEncodedPassword);
            throw new CustomUnauthorizedException();
        }

        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now())){
            throw new AccountLockedException();
        }

        if (passwordEncoder.matches(rawPassword, user.getPassword())) {
            return new UsernamePasswordAuthenticationToken(
                    user,
                    user.getPassword(),
                    user.getAuthorities()
            );
        } else {
            throw new CustomUnauthorizedException();
        }
    }

    @Override
    public boolean supports(Class<?> authType) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authType);
    }
}

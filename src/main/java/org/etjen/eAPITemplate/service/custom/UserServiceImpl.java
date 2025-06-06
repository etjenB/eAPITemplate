package org.etjen.eAPITemplate.service.custom;

import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.exception.auth.AccountLockedException;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedExpection;
import org.etjen.eAPITemplate.exception.auth.jwt.JwtGenerationException;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.etjen.eAPITemplate.security.config.SecurityProperties;
import org.etjen.eAPITemplate.security.jwt.JwtService;
import org.etjen.eAPITemplate.security.user.UserPrincipal;
import org.etjen.eAPITemplate.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final SecurityProperties securityProperties;

    @Autowired
    public UserServiceImpl(UserRepository userRepository, AuthenticationManager authenticationManager, JwtService jwtService, SecurityProperties securityProperties) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.securityProperties = securityProperties;
    }

    @Override
    public User save(User user) {
        return userRepository.save(user);
    }

    @Override
    public String login(String username, String password) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            this.onLoginSuccess(username);
            UserPrincipal p = (UserPrincipal) auth.getPrincipal();
            List<String> roles = p.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
            return jwtService.generateToken(username, roles);
        }
        catch (CustomUnauthorizedExpection ex) {
            this.onLoginFailure(username);
            throw new CustomUnauthorizedExpection(ex.getMessage());
        }
        catch (AccountLockedException ex) {
            throw new AccountLockedException(ex.getMessage());
        }
        catch (JwtGenerationException ex) {
            throw new JwtGenerationException(ex.getMessage());
        }
        catch (RuntimeException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public void onLoginFailure(String username) {
        User user = userRepository.findByUsername(username);
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        if (attempts >= securityProperties.getMaxFailedAttempts()) {
            user.setAccountNonLocked(false);
            user.setLockedUntil(new Date(System.currentTimeMillis() + securityProperties.getLockDurationMs()));
        }
        userRepository.save(user);
    }

    @Override
    public void onLoginSuccess(String username) {
        User user = userRepository.findByUsername(username);
        // reset failed attempts and unlock if needed
        user.setFailedLoginAttempts(0);
        user.setAccountNonLocked(true);
        user.setLockedUntil(null);
        userRepository.save(user);
    }
}

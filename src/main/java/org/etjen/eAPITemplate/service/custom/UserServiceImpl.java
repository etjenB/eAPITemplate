package org.etjen.eAPITemplate.service.custom;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.transaction.Transactional;
import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.etjen.eAPITemplate.domain.model.Role;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.exception.auth.AccountLockedException;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedExpection;
import org.etjen.eAPITemplate.exception.auth.jwt.ExpiredOrRevokedRefreshTokenExpection;
import org.etjen.eAPITemplate.exception.auth.jwt.InvalidRefreshTokenExpection;
import org.etjen.eAPITemplate.exception.auth.jwt.JwtGenerationException;
import org.etjen.eAPITemplate.exception.auth.jwt.RefreshTokenNotFoundException;
import org.etjen.eAPITemplate.repository.RefreshTokenRepository;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.etjen.eAPITemplate.security.config.SecurityProperties;
import org.etjen.eAPITemplate.security.jwt.JwtService;
import org.etjen.eAPITemplate.security.user.UserPrincipal;
import org.etjen.eAPITemplate.service.UserService;
import org.etjen.eAPITemplate.web.payload.auth.TokenPair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final SecurityProperties securityProperties;

    @Autowired
    public UserServiceImpl(UserRepository userRepository, RefreshTokenRepository refreshTokenRepository, AuthenticationManager authenticationManager, JwtService jwtService, SecurityProperties securityProperties) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.securityProperties = securityProperties;
    }

    @Override
    public User save(User user) {
        return userRepository.save(user);
    }

    @Override
    @Transactional
    public void logout(String refreshToken) {
        String jti;
        try {
            jti = jwtService.extractAllClaims(refreshToken).getId();
        } catch (JwtException | IllegalArgumentException ex) {
            throw new InvalidRefreshTokenExpection("Malformed or expired refresh token");
        }

        refreshTokenRepository.revokeByTokenId(jti).orElseThrow(() -> new RefreshTokenNotFoundException(jti));
    }

    @Override
    @Transactional
    public TokenPair login(String username, String password) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            this.onLoginSuccess(username);
            UserPrincipal p = (UserPrincipal) auth.getPrincipal();
            List<String> roles = p.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
            String jti = UUID.randomUUID().toString();
            String accessToken = jwtService.generateAccessToken(username, roles, jti);
            String refreshToken = jwtService.generateRefreshToken(username, jti);
            RefreshToken refreshTokenObject = RefreshToken.builder()
                    .tokenId(jti)
                    .issuedAt(Instant.now())
                    .expiresAt(jwtService.extractExpiration(refreshToken).toInstant())
                    .revoked(false)
                    .user(userRepository.findByUsername(username).orElseThrow(CustomUnauthorizedExpection::new))
                    .ipAddress(RequestContextHolder.currentRequestAttributes() instanceof ServletRequestAttributes sra
                            ? sra.getRequest().getRemoteAddr()
                            : null)
                    .userAgent(RequestContextHolder.currentRequestAttributes() instanceof ServletRequestAttributes sra
                            ? sra.getRequest().getHeader("User-Agent")
                            : null)
                    .build();
            refreshTokenRepository.save(refreshTokenObject);
            return new TokenPair(accessToken, refreshToken);
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
        User user = userRepository.findByUsername(username).orElseThrow(CustomUnauthorizedExpection::new);
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        if (attempts >= securityProperties.getMaxFailedAttempts()) {
            user.setAccountNonLocked(false);
            user.setLockedUntil(Instant.now().plusMillis(securityProperties.getLockDurationMs()));
        }
        userRepository.save(user);
    }

    @Override
    public void onLoginSuccess(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(CustomUnauthorizedExpection::new);
        // reset failed attempts and unlock if needed
        user.setFailedLoginAttempts(0);
        user.setAccountNonLocked(true);
        user.setLockedUntil(null);
        userRepository.save(user);
    }

    @Transactional
    public TokenPair refresh(String refreshJwt) throws InvalidRefreshTokenExpection, ExpiredOrRevokedRefreshTokenExpection {
        Claims claims;
        try {
            claims = jwtService.extractAllClaims(refreshJwt); // signature + exp checked here
        } catch (Exception ex) {
            throw new InvalidRefreshTokenExpection("Malformed or expired refresh token");
        }
        String jti = claims.getId();
        RefreshToken oldRefreshToken = refreshTokenRepository.findAndLockByTokenId(jti)
                .orElseThrow(() -> new InvalidRefreshTokenExpection("Invalid refresh token"));
        if (oldRefreshToken.isRevoked() || oldRefreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new ExpiredOrRevokedRefreshTokenExpection("Expired or revoked refresh token");
        }

        oldRefreshToken.setRevoked(true);
        // ? refreshTokenRepository.save(oldRefreshToken); - not needed because JPA flushes on commit

        List<String> roles = oldRefreshToken.getUser().getRoles()
                .stream().map(Role::getName).toList();

        String newJti = UUID.randomUUID().toString();
        String newAccessToken = jwtService.generateAccessToken(claims.getSubject(), roles, newJti);
        String newRefreshToken = jwtService.generateRefreshToken(claims.getSubject(), newJti);

        RefreshToken newRefreshTokenObject = RefreshToken.builder()
                .tokenId(newJti)
                .issuedAt(Instant.now())
                .expiresAt(jwtService.extractExpiration(newRefreshToken).toInstant())
                .revoked(false)
                .user(oldRefreshToken.getUser())
                .ipAddress(RequestContextHolder.currentRequestAttributes() instanceof ServletRequestAttributes sra
                        ? sra.getRequest().getRemoteAddr()
                        : null)
                .userAgent(RequestContextHolder.currentRequestAttributes() instanceof ServletRequestAttributes sra
                        ? sra.getRequest().getHeader("User-Agent")
                        : null)
                .build();
        refreshTokenRepository.save(newRefreshTokenObject);
        return new TokenPair(newAccessToken, newRefreshToken);
    }
}

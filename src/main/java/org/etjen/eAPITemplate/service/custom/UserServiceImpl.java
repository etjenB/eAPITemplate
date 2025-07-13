package org.etjen.eAPITemplate.service.custom;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.config.properties.security.AccountProperties;
import org.etjen.eAPITemplate.config.properties.security.EmailVerificationProperties;
import org.etjen.eAPITemplate.domain.model.EmailVerificationToken;
import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.etjen.eAPITemplate.domain.model.Role;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.domain.model.enums.AppRole;
import org.etjen.eAPITemplate.exception.auth.AccountLockedException;
import org.etjen.eAPITemplate.exception.auth.ConcurrentSessionLimitException;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedException;
import org.etjen.eAPITemplate.exception.auth.jwt.ExpiredOrRevokedRefreshTokenException;
import org.etjen.eAPITemplate.exception.auth.jwt.InvalidRefreshTokenException;
import org.etjen.eAPITemplate.exception.auth.jwt.JwtGenerationException;
import org.etjen.eAPITemplate.exception.auth.jwt.RefreshTokenNotFoundException;
import org.etjen.eAPITemplate.repository.EmailVerificationTokenRepository;
import org.etjen.eAPITemplate.repository.RefreshTokenRepository;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.etjen.eAPITemplate.security.auth.RoleCache;
import org.etjen.eAPITemplate.security.jwt.JwtService;
import org.etjen.eAPITemplate.security.user.UserPrincipal;
import org.etjen.eAPITemplate.service.EmailService;
import org.etjen.eAPITemplate.service.UserService;
import org.etjen.eAPITemplate.web.payload.auth.RegistrationRequest;
import org.etjen.eAPITemplate.web.payload.auth.TokenPair;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final EmailService emailService;
    private final AccountProperties accountProperties;
    private final EmailVerificationProperties emailVerificationProperties;
    private final PasswordEncoder passwordEncoder;
    private final RoleCache roleCache;

    @Override
    @Transactional
    public void register(RegistrationRequest registrationRequest) {
        Role userRole = roleCache.get(AppRole.USER);
        User user = userRepository.save(User.builder()
                .username(registrationRequest.username())
                .email(registrationRequest.email().toLowerCase(Locale.ROOT))
                .password(passwordEncoder.encode(registrationRequest.password()))
                .status(AccountStatus.PENDING_VERIFICATION)
                .roles(Set.of(userRole))
                .build());

        String token = UUID.randomUUID().toString();
        Instant expiry = Instant.now().plus(emailVerificationProperties.emailTokenTtl());
        emailVerificationTokenRepository.save(new EmailVerificationToken(null, token, expiry, false, Instant.now(), user));

        emailService.sendVerificationMail(user, token);
    }

    @Override
    @Transactional
    public void logout(String refreshToken) {
        String jti;
        try {
            jti = jwtService.extractAllClaims(refreshToken).getId();
        } catch (JwtException | IllegalArgumentException ex) {
            throw new InvalidRefreshTokenException("Malformed or expired refresh token");
        }

        refreshTokenRepository.revokeByTokenId(jti).orElseThrow(() -> new RefreshTokenNotFoundException(jti));
    }

    @Override
    public TokenPair login(String username, String password, boolean revokeOldest) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            User user = userRepository.findByUsername(username).orElseThrow(CustomUnauthorizedException::new);
            this.onLoginSuccess(user);
            long active = refreshTokenRepository.countByUserIdAndRevokedFalseAndExpiresAtAfter(
                    user.getId(), Instant.now());
            if (active >= accountProperties.concurrentSessionsLimit()) {
                if (!revokeOldest) {
                    throw new ConcurrentSessionLimitException(accountProperties.concurrentSessionsLimit(), username);
                }
                revokeOldestByUserId(user.getId());
            }
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
                    .user(userRepository.findByUsername(username).orElseThrow(CustomUnauthorizedException::new))
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
        catch (CustomUnauthorizedException ex) {
            this.onLoginFailure(username);
            throw new CustomUnauthorizedException(ex.getMessage());
        }
        catch (ConcurrentSessionLimitException ex) {
            throw new ConcurrentSessionLimitException(ex.getMessage());
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
        User user = userRepository.findByUsername(username).orElseThrow(CustomUnauthorizedException::new);
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        if (attempts >= accountProperties.maxFailedAttempts()) {
            user.setAccountNonLocked(false);
            user.setLockedUntil(Instant.now().plus(accountProperties.lockDuration()));
        }
        userRepository.save(user);
    }

    @Override
    public void onLoginSuccess(User user) {
        user.setFailedLoginAttempts(0);
        // unlock if needed
        if (!user.isAccountNonLocked()) {
            user.setAccountNonLocked(true);
            user.setLockedUntil(null);
        }
        userRepository.save(user);
    }

    public void revokeOldestByUserId(Long userId) {
        RefreshToken oldest = refreshTokenRepository
                .findFirstByUserIdAndRevokedFalseOrderByIssuedAtAsc(userId)
                .orElseThrow(() -> new RefreshTokenNotFoundException("No active tokens"));

        oldest.setRevoked(true);
        refreshTokenRepository.save(oldest);
    }

    @Transactional
    public TokenPair refresh(String refreshJwt) throws InvalidRefreshTokenException, ExpiredOrRevokedRefreshTokenException {
        Claims claims;
        try {
            claims = jwtService.extractAllClaims(refreshJwt); // signature + exp checked here
        } catch (Exception ex) {
            throw new InvalidRefreshTokenException("Malformed or expired refresh token");
        }
        String jti = claims.getId();
        RefreshToken oldRefreshToken = refreshTokenRepository.findAndLockByTokenId(jti)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));
        if (oldRefreshToken.isRevoked() || oldRefreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new ExpiredOrRevokedRefreshTokenException("Expired or revoked refresh token");
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

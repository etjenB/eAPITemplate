package org.etjen.eAPITemplate.service.custom;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.domain.model.RefreshToken;
import org.etjen.eAPITemplate.exception.auth.jwt.RefreshTokenNotFoundException;
import org.etjen.eAPITemplate.exception.auth.jwt.RefreshTokensForUserNotFoundException;
import org.etjen.eAPITemplate.repository.RefreshTokenRepository;
import org.etjen.eAPITemplate.service.SessionService;
import org.etjen.eAPITemplate.web.mapper.SessionMapper;
import org.etjen.eAPITemplate.web.payload.session.SessionDto;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class SessionServiceImpl implements SessionService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final SessionMapper sessionMapper;

    @Override
    public List<SessionDto> list(Long userId) {
        List<RefreshToken> tokens = refreshTokenRepository.findByUserId(userId).orElseThrow(() -> new RefreshTokensForUserNotFoundException(userId));
        // pull the JTI from the SecurityContext from credentials where we stored it
        String currentJti = SecurityContextHolder.getContext()
                .getAuthentication()
                .getCredentials().toString();
        return sessionMapper.toDtos(tokens, currentJti);
    }

    @Override
    public SessionDto get(Long userId, String tokenId) {
        RefreshToken token = refreshTokenRepository.findByTokenId(tokenId).orElseThrow(() -> new RefreshTokenNotFoundException(tokenId, userId));
        String currentJti = SecurityContextHolder.getContext()
                .getAuthentication()
                .getCredentials().toString();
        return sessionMapper.toDto(token, currentJti);
    }

    @Override
    public void revoke(Long userId, String tokenId) {
        int updated = refreshTokenRepository
                .revokeByTokenIdAndUserId(tokenId, userId);
        if (updated == 0) {
            throw new RefreshTokenNotFoundException(tokenId, userId);
        }
    }

    @Override
    public void revokeAll(Long userId) {
        int updated = refreshTokenRepository
                .revokeAllByUserId(userId);
        if (updated == 0) {
            throw new RefreshTokensForUserNotFoundException(userId);
        }
    }
}

package org.etjen.eAPITemplate.service;

import org.etjen.eAPITemplate.web.payload.session.SessionDto;
import java.util.List;

public interface SessionService {
    List<SessionDto> list(Long userId);
    SessionDto get(Long userId, String sessionId);
    void revoke(Long userId, String sessionId);
    void revokeAll(Long userId);
}

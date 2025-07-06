package org.etjen.eAPITemplate.web.payload.auth;

public record LoginResponse(
        String access_token,
        long   expires_in_ms,
        String token_type
) {}
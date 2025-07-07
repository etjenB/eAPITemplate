package org.etjen.eAPITemplate.exception.auth.jwt;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.RefreshTokenNotFoundExceptionCode;

public class RefreshTokenNotFoundException extends RuntimeException {
    public static int code = RefreshTokenNotFoundExceptionCode.getCode();
    public RefreshTokenNotFoundException() {
        super("Refresh token not found");
    }
    public RefreshTokenNotFoundException(String tokenId, Long userId) {
        super("Refresh token %s for user %d not found".formatted(tokenId, userId));
    }
    public RefreshTokenNotFoundException(String tokenId) {
        super("Refresh token %s not found".formatted(tokenId));
    }
}

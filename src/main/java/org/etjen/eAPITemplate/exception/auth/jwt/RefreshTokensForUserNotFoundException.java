package org.etjen.eAPITemplate.exception.auth.jwt;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.RefreshTokensForUserNotFoundExceptionCode;

public class RefreshTokensForUserNotFoundException extends RuntimeException {
    public static int code = RefreshTokensForUserNotFoundExceptionCode.getCode();
    public RefreshTokensForUserNotFoundException(String message) {
        super(message);
    }
    public RefreshTokensForUserNotFoundException(Long userId) {
        super("Refresh tokens for user %d not found".formatted(userId));
    }
}

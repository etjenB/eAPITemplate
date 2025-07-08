package org.etjen.eAPITemplate.exception.auth.jwt;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.InvalidRefreshTokenExpectionCode;

public class InvalidRefreshTokenException extends RuntimeException {
    public static int code = InvalidRefreshTokenExpectionCode.getCode();
    public InvalidRefreshTokenException(String message) {
        super(message);
    }
}

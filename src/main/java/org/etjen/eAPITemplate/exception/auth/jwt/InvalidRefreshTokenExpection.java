package org.etjen.eAPITemplate.exception.auth.jwt;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.InvalidRefreshTokenExpectionCode;

public class InvalidRefreshTokenExpection extends RuntimeException {
    public static int code = InvalidRefreshTokenExpectionCode.getCode();
    public InvalidRefreshTokenExpection(String message) {
        super(message);
    }
}

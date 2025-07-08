package org.etjen.eAPITemplate.exception.auth.jwt;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.ExpiredOrRevokedRefreshTokenExpectionCode;

public class ExpiredOrRevokedRefreshTokenException extends RuntimeException {
    public static int code = ExpiredOrRevokedRefreshTokenExpectionCode.getCode();
    public ExpiredOrRevokedRefreshTokenException(String message) {
        super(message);
    }
}

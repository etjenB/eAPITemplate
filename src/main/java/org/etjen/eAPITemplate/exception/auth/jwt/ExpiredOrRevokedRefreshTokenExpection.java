package org.etjen.eAPITemplate.exception.auth.jwt;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.ExpiredOrRevokedRefreshTokenExpectionCode;

public class ExpiredOrRevokedRefreshTokenExpection extends RuntimeException {
    public static int code = ExpiredOrRevokedRefreshTokenExpectionCode.getCode();
    public ExpiredOrRevokedRefreshTokenExpection(String message) {
        super(message);
    }
}

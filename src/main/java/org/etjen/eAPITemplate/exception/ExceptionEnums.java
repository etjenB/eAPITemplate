package org.etjen.eAPITemplate.exception;

import lombok.Getter;
import org.springframework.http.converter.HttpMessageNotReadableException;

@Getter
public enum ExceptionEnums {
    ExceptionCode(100),
    MethodArgumentNotValidExceptionCode(101),
    CustomUnauthorizedExceptionCode(102),
    AccountLockedExceptionCode(103),
    JwtGenerationExceptionCode(104),
    InvalidRefreshTokenExpectionCode(105),
    ExpiredOrRevokedRefreshTokenExpectionCode(106),
    AuthorizationDeniedExceptionCode(107),
    MissingRequestCookieExceptionCode(108),
    RefreshTokenNotFoundExceptionCode(109),
    RefreshTokensForUserNotFoundExceptionCode(110),
    UserNotFoundExceptionCode(111),
    ConcurrentSessionLimitExceptionCode(112),
    HttpMessageNotReadableExceptionCode(113);

    private final int code;

    ExceptionEnums(int code) {
        this.code = code;
    }

}

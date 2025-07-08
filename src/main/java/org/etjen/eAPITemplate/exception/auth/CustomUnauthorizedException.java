package org.etjen.eAPITemplate.exception.auth;

import org.springframework.security.core.AuthenticationException;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.CustomUnauthorizedExceptionCode;

public class CustomUnauthorizedException extends AuthenticationException {
    public static int code = CustomUnauthorizedExceptionCode.getCode();
    public CustomUnauthorizedException(String message) { super(message); }
    public CustomUnauthorizedException() { super("Invalid username or password"); }
}

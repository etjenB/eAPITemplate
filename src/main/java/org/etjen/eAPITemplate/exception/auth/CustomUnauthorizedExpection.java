package org.etjen.eAPITemplate.exception.auth;

import org.springframework.security.core.AuthenticationException;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.CustomUnauthorizedExceptionCode;

public class CustomUnauthorizedExpection extends AuthenticationException {
    public static int code = CustomUnauthorizedExceptionCode.getCode();
    public CustomUnauthorizedExpection(String message) { super(message); }
    public CustomUnauthorizedExpection() { super("Invalid username or password"); }
}

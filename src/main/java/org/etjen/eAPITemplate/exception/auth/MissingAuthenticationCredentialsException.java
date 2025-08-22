package org.etjen.eAPITemplate.exception.auth;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.MissingAuthenticationCredentialsExceptionCode;

public class MissingAuthenticationCredentialsException extends RuntimeException {
    public static int code = MissingAuthenticationCredentialsExceptionCode.getCode();
    public MissingAuthenticationCredentialsException(String message) {
        super(message);
    }
    public MissingAuthenticationCredentialsException() {
        super("Missing authentication credentials");
    }
}

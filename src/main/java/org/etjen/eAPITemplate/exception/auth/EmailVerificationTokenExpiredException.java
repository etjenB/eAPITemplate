package org.etjen.eAPITemplate.exception.auth;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.EmailVerificationTokenExpiredExceptionCode;

public class EmailVerificationTokenExpiredException extends RuntimeException {
    public static int code = EmailVerificationTokenExpiredExceptionCode.getCode();
    public EmailVerificationTokenExpiredException() {
        super("Email verification token expired");
    }
    public EmailVerificationTokenExpiredException(String token) {
        super("Email verification token %s expired".formatted(token));
    }
}

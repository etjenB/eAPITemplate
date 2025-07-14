package org.etjen.eAPITemplate.exception.auth;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.EmailVerificationTokenNotFoundExceptionCode;

public class EmailVerificationTokenNotFoundException extends RuntimeException {
    public static int code = EmailVerificationTokenNotFoundExceptionCode.getCode();
    public EmailVerificationTokenNotFoundException() {
        super("Email verification token not found");
    }
    public EmailVerificationTokenNotFoundException(String token) {
        super("Email verification token %s not found".formatted(token));
    }
}

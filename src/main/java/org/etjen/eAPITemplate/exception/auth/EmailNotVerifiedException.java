package org.etjen.eAPITemplate.exception.auth;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.EmailNotVerifiedExceptionCode;

public class EmailNotVerifiedException extends RuntimeException {
    public static int code = EmailNotVerifiedExceptionCode.getCode();
    public EmailNotVerifiedException(String message) {
        super(message);
    }
    public EmailNotVerifiedException() {
        super("Email address not verified");
    }
}

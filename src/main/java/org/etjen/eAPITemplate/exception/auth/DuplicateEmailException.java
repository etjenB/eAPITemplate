package org.etjen.eAPITemplate.exception.auth;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.DuplicateEmailExceptionCode;

public class DuplicateEmailException extends RuntimeException {
    public static int code = DuplicateEmailExceptionCode.getCode();
    public DuplicateEmailException(String message) {
        super(message);
    }
    public DuplicateEmailException() {
        super("Email is already in use");
    }
}

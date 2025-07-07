package org.etjen.eAPITemplate.exception.auth;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.UserNotFoundExceptionCode;

public class UserNotFoundException extends RuntimeException {
    public static int code = UserNotFoundExceptionCode.getCode();
    public UserNotFoundException(String message) {
        super(message);
    }
}

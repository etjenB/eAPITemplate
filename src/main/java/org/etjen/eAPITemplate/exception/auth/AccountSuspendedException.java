package org.etjen.eAPITemplate.exception.auth;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.AccountSuspendedExceptionCode;

public class AccountSuspendedException extends RuntimeException {
    public static int code = AccountSuspendedExceptionCode.getCode();
    public AccountSuspendedException(String message) {
        super(message);
    }
    public AccountSuspendedException() {
        super("Account is suspended");
    }
}

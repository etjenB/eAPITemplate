package org.etjen.eAPITemplate.exception.auth;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.AccountLockedExceptionCode;

public class AccountLockedException extends RuntimeException {
    public static int code = AccountLockedExceptionCode.getCode();
    public AccountLockedException(String message) {
        super(message);
    }
}

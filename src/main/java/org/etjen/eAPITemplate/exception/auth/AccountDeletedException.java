package org.etjen.eAPITemplate.exception.auth;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.AccountDeletedExceptionCode;

public class AccountDeletedException extends RuntimeException {
    public static int code = AccountDeletedExceptionCode.getCode();
    public AccountDeletedException(String message) {
        super(message);
    }
    public AccountDeletedException() {
        super("Account is deleted");
    }
}

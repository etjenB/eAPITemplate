package org.etjen.eAPITemplate.exception.auth;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.ConcurrentSessionLimitExceptionCode;

public class ConcurrentSessionLimitException extends RuntimeException {
    public static int code = ConcurrentSessionLimitExceptionCode.getCode();
    public ConcurrentSessionLimitException(String message) {
        super(message);
    }
    public ConcurrentSessionLimitException(int concurrentSessionsLimit, String username) {
        super("Concurrent sessions limit reached for username: " + username + ", sessions limit is " + concurrentSessionsLimit);
    }
}

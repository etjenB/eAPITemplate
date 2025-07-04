package org.etjen.eAPITemplate.exception.auth.jwt;

import static org.etjen.eAPITemplate.exception.ExceptionEnums.JwtGenerationExceptionCode;

public class JwtGenerationException extends RuntimeException {
    public static int code = JwtGenerationExceptionCode.getCode();
    public JwtGenerationException(String message) {
        super(message);
    }
}

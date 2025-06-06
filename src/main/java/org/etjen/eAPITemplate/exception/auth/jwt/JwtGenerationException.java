package org.etjen.eAPITemplate.exception.auth.jwt;

public class JwtGenerationException extends RuntimeException {
    public JwtGenerationException(String message) {
        super(message);
    }
}

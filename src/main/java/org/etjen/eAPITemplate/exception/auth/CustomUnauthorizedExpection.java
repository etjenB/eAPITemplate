package org.etjen.eAPITemplate.exception.auth;

import org.springframework.security.core.AuthenticationException;

public class CustomUnauthorizedExpection extends AuthenticationException {
    public CustomUnauthorizedExpection(String message) { super(message); }
}

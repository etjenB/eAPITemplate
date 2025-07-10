package org.etjen.eAPITemplate.service;

import org.springframework.security.authentication.password.CompromisedPasswordDecision;

public interface CompromisedPasswordChecker {
    CompromisedPasswordDecision check(String password);
}

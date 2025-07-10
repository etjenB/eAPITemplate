package org.etjen.eAPITemplate.service.custom;

import org.etjen.eAPITemplate.service.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.stereotype.Service;

@Service
public class CompromisedPasswordCheckerImpl implements CompromisedPasswordChecker {

    @Override
    public CompromisedPasswordDecision check(String password) {
        HaveIBeenPwnedRestApiPasswordChecker checker = new HaveIBeenPwnedRestApiPasswordChecker();
        return checker.check(password);
    }
}

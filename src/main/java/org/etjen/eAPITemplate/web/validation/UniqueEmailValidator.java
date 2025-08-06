package org.etjen.eAPITemplate.web.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.config.properties.web.ValidationProperties;
import org.etjen.eAPITemplate.repository.EmailVerificationTokenRepository;
import org.springframework.stereotype.Component;
import java.time.Instant;

@Component
@RequiredArgsConstructor
public class UniqueEmailValidator implements ConstraintValidator<UniqueEmail, String> {
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final ValidationProperties validationProperties;

    @Override public boolean isValid(String email, ConstraintValidatorContext ctx) {
        if (email == null) return false;

        // someone requested a token < cooldown ago
        boolean coolingDown = emailVerificationTokenRepository.existsRecentUnexpired(email, Instant.now().minus(validationProperties.emailVerificationCooldown()));
        return !coolingDown;
    }
}

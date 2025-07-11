package org.etjen.eAPITemplate.web.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.config.properties.web.ValidationProperties;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.repository.EmailVerificationTokenRepository;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.springframework.stereotype.Component;
import java.time.Instant;

@Component
@RequiredArgsConstructor
public class UniqueEmailValidator implements ConstraintValidator<UniqueEmail, String> {
    private final UserRepository userRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final ValidationProperties validationProperties;

    @Override public boolean isValid(String email, ConstraintValidatorContext ctx) {
        if (email == null) return false;

        // already registered and ACTIVE
        if (userRepository.existsByEmailIgnoreCaseAndStatus(email, AccountStatus.ACTIVE)) return false;

        // someone requested a token < cooldown ago
        boolean coolingDown = emailVerificationTokenRepository.existsRecentUnexpired(email, Instant.now().minus(validationProperties.emailVerificationCooldown()));
        return !coolingDown;
    }
}

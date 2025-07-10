package org.etjen.eAPITemplate.web.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.repository.UserRepository;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UniqueUsernameValidator
        implements ConstraintValidator<UniqueUsername, String> {
    private final UserRepository userRepository;

    @Override
    public boolean isValid(String username, ConstraintValidatorContext ctx) {
        if (username == null) return false;
        return !userRepository.existsByUsernameIgnoreCase(username);
    }
}

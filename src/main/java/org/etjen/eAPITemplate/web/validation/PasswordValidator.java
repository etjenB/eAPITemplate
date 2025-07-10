package org.etjen.eAPITemplate.web.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.service.CompromisedPasswordChecker;
import org.springframework.stereotype.Component;
import java.util.regex.Pattern;

@Component
@RequiredArgsConstructor
public class PasswordValidator implements ConstraintValidator<Password, String> {
    public final CompromisedPasswordChecker compromisedPasswordChecker;

    private static final Pattern COMPLEX =
            Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).+$");

    @Override
    public boolean isValid(String pwd, ConstraintValidatorContext ctx) {
        if (pwd == null) return false;

        int len = pwd.length();
        if (len < 8 || len > 64) return false;

        // allow ≥15 chars without composition
        if (len < 15 && !COMPLEX.matcher(pwd).matches()) return false;

        // breach-list check via HaveIBeenPwned API
        if (compromisedPasswordChecker.check(pwd).isCompromised()) {
            buildCompromisedViolation(ctx);
            return false;
        }

        return true;
    }

    private void buildCompromisedViolation(ConstraintValidatorContext ctx) {
        ctx.disableDefaultConstraintViolation();
        ctx.buildConstraintViolationWithTemplate("This password has already been breached.")
                .addConstraintViolation();
    }
}

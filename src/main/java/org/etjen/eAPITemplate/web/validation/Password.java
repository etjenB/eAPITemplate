package org.etjen.eAPITemplate.web.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = PasswordValidator.class)
@Target({
    ElementType.FIELD,
    ElementType.PARAMETER,
    ElementType.RECORD_COMPONENT
})
@Retention(RetentionPolicy.RUNTIME)
public @interface Password {
    String message() default "Password needs to either be longer than 15 character or between 8 to 15 characters with at least one: upper case, lower case and number.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}

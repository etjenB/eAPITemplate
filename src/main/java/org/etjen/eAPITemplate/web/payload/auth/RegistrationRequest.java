package org.etjen.eAPITemplate.web.payload.auth;

import jakarta.validation.constraints.*;
import org.etjen.eAPITemplate.web.validation.Password;
import org.etjen.eAPITemplate.web.validation.UniqueEmail;
import org.etjen.eAPITemplate.web.validation.UniqueUsername;

public record RegistrationRequest (
        @NotBlank(message = "Username must not be blank.")
        @Size(min = 5, max = 50, message = "Username length must be between 5 and 50.")
        @Pattern(regexp = "^[a-zA-Z0-9_.-]+$")
        @UniqueUsername
        String username,

        @NotBlank(message = "Email must not be blank.")
        @Size(max = 100, message = "Email length is maximum 100 characters.")
        @Email
        @UniqueEmail
        String email,

        @Password
        String password
) {}

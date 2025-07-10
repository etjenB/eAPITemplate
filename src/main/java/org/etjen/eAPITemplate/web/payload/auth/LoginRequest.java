package org.etjen.eAPITemplate.web.payload.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class LoginRequest {
    @NotNull
    @NotBlank(message = "Username must not be blank")
    @Size(min = 5, max = 50, message = "Username length must be between 5 and 50")
    private String username;

    @NotNull
    @NotBlank(message = "Password must not be blank")
    @Size(min = 8, max = 64, message = "Password length must be between 8 and 64")
    private String password;
}

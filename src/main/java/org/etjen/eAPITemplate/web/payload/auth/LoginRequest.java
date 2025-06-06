package org.etjen.eAPITemplate.web.payload.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class LoginRequest {
    @NotNull
    @NotBlank(message = "Username must not be blank")
    @Size(min = 3, max = 50, message = "Username length must be between 3 and 50")
    private String username;

    @NotNull
    @NotBlank(message = "Password must not be blank")
    @Size(min = 4, max = 100, message = "Password length must be between 4 and 100")
    private String password;
}

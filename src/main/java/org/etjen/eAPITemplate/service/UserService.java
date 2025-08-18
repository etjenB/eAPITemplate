package org.etjen.eAPITemplate.service;

import jakarta.validation.Valid;
import org.etjen.eAPITemplate.web.payload.auth.RegistrationRequest;
import org.etjen.eAPITemplate.web.payload.auth.TokenPair;

public interface UserService {
    void register(@Valid RegistrationRequest registrationRequest);
    void verify(String token);
    void logout(String refreshToken);
    TokenPair login(String username, String password, boolean revokeOldest);
    TokenPair refresh(String refreshJwt);
}

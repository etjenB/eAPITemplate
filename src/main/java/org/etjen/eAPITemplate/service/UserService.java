package org.etjen.eAPITemplate.service;

import jakarta.validation.Valid;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.web.payload.auth.RegistrationRequest;
import org.etjen.eAPITemplate.web.payload.auth.TokenPair;

public interface UserService {
    User save(User u);
    void register(@Valid RegistrationRequest registrationRequest);
    void logout(String refreshToken);
    TokenPair login(String username, String password, boolean revokeOldest);
    void onLoginFailure(String username);
    void onLoginSuccess(User user);
    TokenPair refresh(String refreshJwt);
}

package org.etjen.eAPITemplate.service;

import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedExpection;
import org.etjen.eAPITemplate.web.payload.auth.TokenPair;

public interface UserService {
    User save(User u);
    void logout(String refreshToken);
    TokenPair login(String username, String password) throws CustomUnauthorizedExpection;
    void onLoginFailure(String username);
    void onLoginSuccess(String username);
    TokenPair refresh(String refreshJwt);
}

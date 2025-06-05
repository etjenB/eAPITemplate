package org.etjen.eAPITemplate.service;

import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.exception.auth.CustomUnauthorizedExpection;

public interface UserService {
    User save(User u);
    String login(String username, String password) throws CustomUnauthorizedExpection;
}

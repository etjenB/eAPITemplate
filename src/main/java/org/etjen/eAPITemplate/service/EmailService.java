package org.etjen.eAPITemplate.service;

import org.etjen.eAPITemplate.domain.model.User;

public interface EmailService {
    void sendVerificationMail(User user, String token);
}

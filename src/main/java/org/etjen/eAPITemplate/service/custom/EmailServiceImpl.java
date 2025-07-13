package org.etjen.eAPITemplate.service.custom;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.config.properties.app.AppProperties;
import org.etjen.eAPITemplate.domain.model.EmailOutbox;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.repository.EmailOutboxRepository;
import org.etjen.eAPITemplate.service.EmailService;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {
    private final EmailOutboxRepository emailOutboxRepository;
    private final AppProperties appProperties;

    @Override
    @Transactional
    public void sendVerificationMail(User user, String token) {
        String verifyLink = UriComponentsBuilder
                .fromUriString(appProperties.baseUrl())
                .path("/auth/verify")
                .queryParam("token", token)
                .toUriString();
        EmailOutbox row = EmailOutbox.builder()
                .aggregateId(user.getId())
                .toAddress(user.getEmail())
                .subject("Verify your account")
                .body("Click: " + verifyLink)
                .build();
        emailOutboxRepository.save(row);
    }
}

package org.etjen.eAPITemplate.scheduler;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.etjen.eAPITemplate.config.properties.email.SesProperties;
import org.etjen.eAPITemplate.domain.model.EmailOutbox;
import org.etjen.eAPITemplate.domain.model.enums.MailStatus;
import org.etjen.eAPITemplate.repository.EmailOutboxRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SesEmailSenderJob {
    private static final Logger logger = LoggerFactory.getLogger(SesEmailSenderJob.class);
    private final SesProperties sesProperties;
    private final EmailOutboxRepository emailOutboxRepository;
    private final MailSender mailSender;

    @Scheduled(fixedDelayString = "${email.ses.retryBackoff}")
    @Transactional
    public void dispatch() {
        PageRequest page = PageRequest.of(0, 500);
        List<EmailOutbox> batch = emailOutboxRepository.findBatch(page);

        for (EmailOutbox row : batch) {
            try {
                SimpleMailMessage mailMessage = new SimpleMailMessage();
                mailMessage.setFrom(sesProperties.from());
                mailMessage.setSubject(row.getSubject());
                mailMessage.setText(row.getBody());
                mailMessage.setTo(row.getToAddress());
                mailSender.send(mailMessage);      // -> AWS
                row.markSent();        // idempotent
            } catch (Exception ex) {
                int tries = row.getAttempts() + 1;
                row.setAttempts(tries);
                row.setLastError(ex.getMessage());
                if (tries >= sesProperties.maxRetries()){
                    row.setStatus(MailStatus.DEAD);
                }
                logger.error("Send failed for id={}, attempt {}", row.getId(), tries, ex);
            }
        }
    }
}

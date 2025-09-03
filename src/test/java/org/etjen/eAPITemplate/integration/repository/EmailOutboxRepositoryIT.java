package org.etjen.eAPITemplate.integration.repository;

import jakarta.persistence.EntityManager;
import org.etjen.eAPITemplate.domain.model.EmailOutbox;
import org.etjen.eAPITemplate.domain.model.enums.MailStatus;
import org.etjen.eAPITemplate.integration.AbstractContainerBase;
import org.etjen.eAPITemplate.repository.EmailOutboxRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class EmailOutboxRepositoryIT extends AbstractContainerBase {
    @Autowired
    JdbcTemplate jdbc;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private EmailOutboxRepository emailOutboxRepository;
    private EmailOutbox defaultEmailOutbox;

    @BeforeEach
    void setUp() {
        jdbc.execute("TRUNCATE TABLE email_outbox RESTART IDENTITY CASCADE");
        final String USER_ADDRESS = "alice@example.com";
        final String USER_SUBJECT = "Verify your account";
        final String USER_BODY = "Click: https://app.example.com/auth/verify?token=abc123";
        defaultEmailOutbox = EmailOutbox.builder()
                .aggregateId(1L)
                .toAddress(USER_ADDRESS)
                .subject(USER_SUBJECT)
                .body(USER_BODY)
                .status(MailStatus.PENDING)
                .createdAt(Instant.now())
                .attempts(0)
                .build();
        emailOutboxRepository.saveAndFlush(defaultEmailOutbox);
        entityManager.clear();
    }

    // ! findBatch

    @Test
    void givenPageRequest_whenFindBatch_thenReturnListCreatedAtAsc() {
        // given
        final String USER_ADDRESS_2 = "bob@example.com";
        final String USER_SUBJECT_2 = "Password reset";
        final String USER_BODY_2 = "Reset link: https://app.example.com/auth/reset?token=def456";
        EmailOutbox emailOutbox2 = EmailOutbox.builder()
                .aggregateId(2L)
                .toAddress(USER_ADDRESS_2)
                .subject(USER_SUBJECT_2)
                .body(USER_BODY_2)
                .status(MailStatus.PENDING)
                .createdAt(Instant.now().minus(Duration.ofHours(2)))                // middle
                .attempts(0)
                .build();
        final String USER_ADDRESS_3 = "carol@example.com";
        final String USER_SUBJECT_3 = "Welcome!";
        final String USER_BODY_3 = "Welcome to our app";
        EmailOutbox emailOutbox3 = EmailOutbox.builder()
                .aggregateId(3L)
                .toAddress(USER_ADDRESS_3)
                .subject(USER_SUBJECT_3)
                .body(USER_BODY_3)
                .status(MailStatus.PENDING)
                .createdAt(Instant.now().minus(Duration.ofHours(4)))                // oldest
                .attempts(0)
                .build();
        emailOutboxRepository.saveAllAndFlush(List.of(emailOutbox2, emailOutbox3));
        entityManager.clear();

        // when
        List<EmailOutbox> emailOutboxList = emailOutboxRepository.findBatch(PageRequest.of(0, 2));

        // then
        assertEquals(2, emailOutboxList.size());
        assertEquals(emailOutbox3.getId(), emailOutboxList.getFirst().getId());
    }

    @Test
    void givenPageRequest_whenFindBatch_thenReturnListOfPendingOnlyCreatedAtAsc() {
        // given
        final String USER_ADDRESS_2 = "bob@example.com";
        final String USER_SUBJECT_2 = "Password reset";
        final String USER_BODY_2 = "Reset link: https://app.example.com/auth/reset?token=def456";
        EmailOutbox emailOutbox2 = EmailOutbox.builder()
                .aggregateId(2L)
                .toAddress(USER_ADDRESS_2)
                .subject(USER_SUBJECT_2)
                .body(USER_BODY_2)
                .status(MailStatus.SENT)
                .createdAt(Instant.now().minus(Duration.ofHours(2)))            // middle
                .attempts(0)
                .build();
        final String USER_ADDRESS_3 = "carol@example.com";
        final String USER_SUBJECT_3 = "Welcome!";
        final String USER_BODY_3 = "Welcome to our app";
        EmailOutbox emailOutbox3 = EmailOutbox.builder()
                .aggregateId(3L)
                .toAddress(USER_ADDRESS_3)
                .subject(USER_SUBJECT_3)
                .body(USER_BODY_3)
                .status(MailStatus.DEAD)
                .createdAt(Instant.now().minus(Duration.ofHours(4)))            // oldest
                .attempts(0)
                .build();
        emailOutboxRepository.saveAllAndFlush(List.of(emailOutbox2, emailOutbox3));
        entityManager.clear();

        // when
        List<EmailOutbox> emailOutboxList = emailOutboxRepository.findBatch(PageRequest.of(0, 500));

        // then
        assertEquals(1, emailOutboxList.size());
        assertEquals(defaultEmailOutbox.getId(), emailOutboxList.getFirst().getId());
    }
}

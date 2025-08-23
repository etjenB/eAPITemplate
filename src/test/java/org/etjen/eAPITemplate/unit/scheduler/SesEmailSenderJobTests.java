package org.etjen.eAPITemplate.unit.scheduler;

import org.etjen.eAPITemplate.config.properties.email.SesProperties;
import org.etjen.eAPITemplate.domain.model.EmailOutbox;
import org.etjen.eAPITemplate.domain.model.enums.MailStatus;
import org.etjen.eAPITemplate.repository.EmailOutboxRepository;
import org.etjen.eAPITemplate.scheduler.SesEmailSenderJob;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageRequest;
import org.springframework.mail.MailSendException;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class SesEmailSenderJobTests {
    @Mock
    private SesProperties sesProperties;
    @Mock
    private EmailOutboxRepository emailOutboxRepository;
    @Mock
    private MailSender mailSender;
    @InjectMocks
    private SesEmailSenderJob sesEmailSenderJob;

    @Test
    void givenListOfEmailOutbox_whenDispatch_thenDispatchAllMails() {
        // given
        final String USER_ADDRESS_1 = "alice@example.com";
        final String USER_SUBJECT_1 = "Verify your account";
        final String USER_BODY_1 = "Click: https://app.example.com/auth/verify?token=abc123";
        EmailOutbox emailOutbox1 = EmailOutbox.builder()
                .id(101L)
                .aggregateId(1L)
                .toAddress(USER_ADDRESS_1)
                .subject(USER_SUBJECT_1)
                .body(USER_BODY_1)
                .status(MailStatus.PENDING)
                .attempts(0)
                .build();

        final String USER_ADDRESS_2 = "bob@example.com";
        final String USER_SUBJECT_2 = "Password reset";
        final String USER_BODY_2 = "Reset link: https://app.example.com/auth/reset?token=def456";
        EmailOutbox emailOutbox2 = EmailOutbox.builder()
                .id(102L)
                .aggregateId(2L)
                .toAddress(USER_ADDRESS_2)
                .subject(USER_SUBJECT_2)
                .body(USER_BODY_2)
                .status(MailStatus.PENDING)
                .attempts(0)
                .build();

        final String USER_ADDRESS_3 = "carol@example.com";
        final String USER_SUBJECT_3 = "Welcome!";
        final String USER_BODY_3 = "Welcome to our app";
        EmailOutbox emailOutbox3 = EmailOutbox.builder()
                .id(103L)
                .aggregateId(3L)
                .toAddress(USER_ADDRESS_3)
                .subject(USER_SUBJECT_3)
                .body(USER_BODY_3)
                .status(MailStatus.PENDING)
                .attempts(0)
                .build();

        BDDMockito.given(emailOutboxRepository.findBatch(any(PageRequest.class))).willReturn(List.of(emailOutbox1, emailOutbox2, emailOutbox3));
        final String API_MAIL_ADDRESS = "api@gmail.com";
        BDDMockito.given(sesProperties.from()).willReturn(API_MAIL_ADDRESS);

        // when
        sesEmailSenderJob.dispatch();

        // then
        verify(emailOutboxRepository).findBatch(any(PageRequest.class));
        ArgumentCaptor<SimpleMailMessage> simpleMailMessageArgumentCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, times(3)).send(simpleMailMessageArgumentCaptor.capture());
        List<SimpleMailMessage> sentMails = simpleMailMessageArgumentCaptor.getAllValues();
        assertThat(sentMails.size()).isEqualTo(3);
        assertThat(sentMails)
                .extracting(
                        simpleMailMessage -> {
                            Assertions.assertNotNull(simpleMailMessage.getTo());
                            return simpleMailMessage.getTo()[0];
                        },
                        SimpleMailMessage::getFrom,
                        SimpleMailMessage::getSubject,
                        SimpleMailMessage::getText)
                .containsExactlyInAnyOrder(
                        tuple(USER_ADDRESS_1,API_MAIL_ADDRESS,USER_SUBJECT_1,USER_BODY_1),
                        tuple(USER_ADDRESS_2,API_MAIL_ADDRESS,USER_SUBJECT_2,USER_BODY_2),
                        tuple(USER_ADDRESS_3,API_MAIL_ADDRESS,USER_SUBJECT_3,USER_BODY_3)
                );
    }

    @Test
    void givenEmptyListOfEmailOutbox_whenDispatch_thenDoNothing() {
        // given
        BDDMockito.given(emailOutboxRepository.findBatch(any(PageRequest.class))).willReturn(List.of());

        // when
        sesEmailSenderJob.dispatch();

        // then
        verifyNoInteractions(sesProperties);
        verifyNoInteractions(mailSender);
    }

    @Test
    void givenListOfEmailOutboxWithWrongMail_whenDispatch_thenThrowExceptionIncrementAttempts() {
        // given
        final String USER_ADDRESS_1 = "alice@example.com";
        final String USER_SUBJECT_1 = "Verify your account";
        final String USER_BODY_1 = "Click: https://app.example.com/auth/verify?token=abc123";
        EmailOutbox emailOutbox1 = EmailOutbox.builder()
                .id(101L)
                .aggregateId(1L)
                .toAddress(USER_ADDRESS_1)
                .subject(USER_SUBJECT_1)
                .body(USER_BODY_1)
                .status(MailStatus.PENDING)
                .attempts(0)
                .build();

        final String USER_ADDRESS_2 = "bob@example.com";
        final String USER_SUBJECT_2 = "Password reset";
        final String USER_BODY_2 = "Reset link: https://app.example.com/auth/reset?token=def456";
        EmailOutbox emailOutbox2 = EmailOutbox.builder()
                .id(102L)
                .aggregateId(2L)
                .toAddress(USER_ADDRESS_2)
                .subject(USER_SUBJECT_2)
                .body(USER_BODY_2)
                .status(MailStatus.PENDING)
                .attempts(0)
                .build();

        final String USER_ADDRESS_3 = "carol@example.com";
        final String USER_SUBJECT_3 = "Welcome!";
        final String USER_BODY_3 = "Welcome to our app";
        EmailOutbox emailOutbox3 = EmailOutbox.builder()
                .id(103L)
                .aggregateId(3L)
                .toAddress(USER_ADDRESS_3)
                .subject(USER_SUBJECT_3)
                .body(USER_BODY_3)
                .status(MailStatus.PENDING)
                .attempts(0)
                .build();
        Integer attemptsForUser3 = emailOutbox3.getAttempts();

        BDDMockito.given(emailOutboxRepository.findBatch(any(PageRequest.class))).willReturn(List.of(emailOutbox1, emailOutbox2, emailOutbox3));
        final String API_MAIL_ADDRESS = "api@gmail.com";
        BDDMockito.given(sesProperties.from()).willReturn(API_MAIL_ADDRESS);
        // will throw exception for just user 3
        BDDMockito.willAnswer(inv -> {
            SimpleMailMessage m = inv.getArgument(0);
            String[] to = m.getTo();
            if (to != null && Arrays.stream(to).anyMatch(USER_ADDRESS_3::equalsIgnoreCase)) {
                throw new MailSendException("fail USER_ADDRESS_3");
            }
            return null;
        }).given(mailSender).send(any(SimpleMailMessage.class));
        BDDMockito.given(sesProperties.maxRetries()).willReturn(20);

        // when
        sesEmailSenderJob.dispatch();

        // then
        verify(emailOutboxRepository).findBatch(any(PageRequest.class));
        ArgumentCaptor<SimpleMailMessage> simpleMailMessageArgumentCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, times(3)).send(simpleMailMessageArgumentCaptor.capture());
        List<SimpleMailMessage> sentMails = simpleMailMessageArgumentCaptor.getAllValues();
        assertThat(sentMails.size()).isEqualTo(3);
        assertThat(sentMails)
                .extracting(
                        simpleMailMessage -> {
                            Assertions.assertNotNull(simpleMailMessage.getTo());
                            return simpleMailMessage.getTo()[0];
                        },
                        SimpleMailMessage::getFrom,
                        SimpleMailMessage::getSubject,
                        SimpleMailMessage::getText)
                .containsExactlyInAnyOrder(
                        tuple(USER_ADDRESS_1,API_MAIL_ADDRESS,USER_SUBJECT_1,USER_BODY_1),
                        tuple(USER_ADDRESS_2,API_MAIL_ADDRESS,USER_SUBJECT_2,USER_BODY_2),
                        tuple(USER_ADDRESS_3,API_MAIL_ADDRESS,USER_SUBJECT_3,USER_BODY_3)
                );
        verify(sesProperties).maxRetries();
        assertThat(emailOutbox1.getStatus()).isEqualTo(MailStatus.SENT);
        assertThat(emailOutbox2.getStatus()).isEqualTo(MailStatus.SENT);
        assertThat(emailOutbox3.getAttempts()).isEqualTo(++attemptsForUser3);
        assertThat(emailOutbox3.getStatus()).isEqualTo(MailStatus.PENDING);
    }

    @Test
    void givenListOfEmailOutboxWithWrongMails_whenDispatch_thenThrowExceptionIncrementAttemptsAndSetStatusDead() {
        // given
        final String USER_ADDRESS_1 = "alice@example.com";
        final String USER_SUBJECT_1 = "Verify your account";
        final String USER_BODY_1 = "Click: https://app.example.com/auth/verify?token=abc123";
        EmailOutbox emailOutbox1 = EmailOutbox.builder()
                .id(101L)
                .aggregateId(1L)
                .toAddress(USER_ADDRESS_1)
                .subject(USER_SUBJECT_1)
                .body(USER_BODY_1)
                .status(MailStatus.PENDING)
                .attempts(0)
                .build();

        final String USER_ADDRESS_2 = "bob@example.com";
        final String USER_SUBJECT_2 = "Password reset";
        final String USER_BODY_2 = "Reset link: https://app.example.com/auth/reset?token=def456";
        EmailOutbox emailOutbox2 = EmailOutbox.builder()
                .id(102L)
                .aggregateId(2L)
                .toAddress(USER_ADDRESS_2)
                .subject(USER_SUBJECT_2)
                .body(USER_BODY_2)
                .status(MailStatus.PENDING)
                .attempts(19)                  // ! will be set to status DEAD
                .build();
        Integer attemptsForUser2 = emailOutbox2.getAttempts();

        final String USER_ADDRESS_3 = "carol@example.com";
        final String USER_SUBJECT_3 = "Welcome!";
        final String USER_BODY_3 = "Welcome to our app";
        EmailOutbox emailOutbox3 = EmailOutbox.builder()
                .id(103L)
                .aggregateId(3L)
                .toAddress(USER_ADDRESS_3)
                .subject(USER_SUBJECT_3)
                .body(USER_BODY_3)
                .status(MailStatus.PENDING)
                .attempts(0)
                .build();
        Integer attemptsForUser3 = emailOutbox3.getAttempts();

        BDDMockito.given(emailOutboxRepository.findBatch(any(PageRequest.class))).willReturn(List.of(emailOutbox1, emailOutbox2, emailOutbox3));
        final String API_MAIL_ADDRESS = "api@gmail.com";
        BDDMockito.given(sesProperties.from()).willReturn(API_MAIL_ADDRESS);
        // will throw exception for just user 3
        BDDMockito.willAnswer(inv -> {
            SimpleMailMessage m = inv.getArgument(0);
            String[] to = m.getTo();
            if (to != null && Arrays.stream(to).anyMatch(address -> USER_ADDRESS_3.equalsIgnoreCase(address) || USER_ADDRESS_2.equalsIgnoreCase(address))) {
                throw new MailSendException("fail USER_ADDRESS_2 and USER_ADDRESS_3");
            }
            return null;
        }).given(mailSender).send(any(SimpleMailMessage.class));
        BDDMockito.given(sesProperties.maxRetries()).willReturn(20);

        // when
        sesEmailSenderJob.dispatch();

        // then
        verify(emailOutboxRepository).findBatch(any(PageRequest.class));
        ArgumentCaptor<SimpleMailMessage> simpleMailMessageArgumentCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, times(3)).send(simpleMailMessageArgumentCaptor.capture());
        List<SimpleMailMessage> sentMails = simpleMailMessageArgumentCaptor.getAllValues();
        assertThat(sentMails.size()).isEqualTo(3);
        assertThat(sentMails)
                .extracting(
                        simpleMailMessage -> {
                            Assertions.assertNotNull(simpleMailMessage.getTo());
                            return simpleMailMessage.getTo()[0];
                        },
                        SimpleMailMessage::getFrom,
                        SimpleMailMessage::getSubject,
                        SimpleMailMessage::getText)
                .containsExactlyInAnyOrder(
                        tuple(USER_ADDRESS_1,API_MAIL_ADDRESS,USER_SUBJECT_1,USER_BODY_1),
                        tuple(USER_ADDRESS_2,API_MAIL_ADDRESS,USER_SUBJECT_2,USER_BODY_2),
                        tuple(USER_ADDRESS_3,API_MAIL_ADDRESS,USER_SUBJECT_3,USER_BODY_3)
                );
        verify(sesProperties, times(2)).maxRetries();
        assertThat(emailOutbox1.getStatus()).isEqualTo(MailStatus.SENT);
        assertThat(emailOutbox2.getAttempts()).isEqualTo(++attemptsForUser2);
        assertThat(emailOutbox2.getStatus()).isEqualTo(MailStatus.DEAD);
        assertThat(emailOutbox3.getAttempts()).isEqualTo(++attemptsForUser3);
        assertThat(emailOutbox3.getStatus()).isEqualTo(MailStatus.PENDING);
    }
}

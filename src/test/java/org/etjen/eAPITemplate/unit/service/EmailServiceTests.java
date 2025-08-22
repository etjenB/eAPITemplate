package org.etjen.eAPITemplate.unit.service;

import org.etjen.eAPITemplate.config.properties.app.AppProperties;
import org.etjen.eAPITemplate.domain.model.EmailOutbox;
import org.etjen.eAPITemplate.domain.model.Role;
import org.etjen.eAPITemplate.domain.model.User;
import org.etjen.eAPITemplate.domain.model.enums.AccountStatus;
import org.etjen.eAPITemplate.repository.EmailOutboxRepository;
import org.etjen.eAPITemplate.service.custom.EmailServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class EmailServiceTests {
    @Mock
    private EmailOutboxRepository emailOutboxRepository;
    @Mock
    private AppProperties appProperties;
    @InjectMocks
    private EmailServiceImpl emailServiceImpl;
    private User defaultUser;
    private String defaultVerifyToken;

    @BeforeEach
    void setUp() {
        defaultVerifyToken = UUID.randomUUID().toString();
        Role roleUser = new Role();
        roleUser.setId(1);
        roleUser.setName("ROLE_USER");
        String DEFAULT_PASSWORD = "Corners8829%";
        String DEFAULT_USERNAME = "user";
        String DEFAULT_EMAIL = "user@gmail.com";
        defaultUser = User.builder()
                .id(1L)
                .username(DEFAULT_USERNAME)
                .email(DEFAULT_EMAIL)
                .password(DEFAULT_PASSWORD)
                .status(AccountStatus.PENDING_VERIFICATION)
                .roles(Set.of(roleUser))
                .build();
    }

    @Test
    void givenValidUserAndToken_whenSendVerificationMail_thenSaveToEmailOutbox() {
        // given
        String token = defaultVerifyToken;
        BDDMockito.given(appProperties.baseUrl()).willReturn("http://localhost");

        // when
        emailServiceImpl.sendVerificationMail(defaultUser, token);

        // then
        ArgumentCaptor<EmailOutbox> captor = ArgumentCaptor.forClass(EmailOutbox.class);
        verify(emailOutboxRepository).save(captor.capture());
        EmailOutbox saved = captor.getValue();
        String expectedLink = "http://localhost/auth/verify?token=" + token;
        assertEquals(defaultUser.getId(), saved.getAggregateId());
        assertEquals(defaultUser.getEmail(), saved.getToAddress());
        assertEquals("Verify your account", saved.getSubject());
        assertEquals("Click: " + expectedLink, saved.getBody());
        verifyNoMoreInteractions(emailOutboxRepository, appProperties);
    }

    @Test
    void givenBaseUrlWithTrailingSlash_whenSendVerificationMail_thenNoDoubleSlash() {
        // given
        BDDMockito.given(appProperties.baseUrl()).willReturn("http://localhost/");
        String token = defaultVerifyToken;

        // when
        emailServiceImpl.sendVerificationMail(defaultUser, token);

        // then
        ArgumentCaptor<EmailOutbox> captor = ArgumentCaptor.forClass(EmailOutbox.class);
        verify(emailOutboxRepository).save(captor.capture());
        assertTrue(captor.getValue().getBody().contains("http://localhost/auth/verify?token=" + token));
    }
}

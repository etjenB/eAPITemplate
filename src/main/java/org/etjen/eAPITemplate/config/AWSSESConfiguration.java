package org.etjen.eAPITemplate.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.MailSender;
import io.awspring.cloud.ses.SimpleEmailServiceMailSender;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ses.SesClient;
import org.etjen.eAPITemplate.config.properties.email.SesProperties;

@Configuration
@RequiredArgsConstructor
@EnableConfigurationProperties(SesProperties.class)
public class AWSSESConfiguration {
    private final SesProperties sesProperties;

    @Bean
    SesClient sesClient() {
        return SesClient.builder()
                .credentialsProvider(
                        StaticCredentialsProvider.create(
                                AwsBasicCredentials.create(sesProperties.accessKey(), sesProperties.secretKey())))
                .region(Region.of(sesProperties.region()))
                .build();
    }

    @Bean
    MailSender mailSender(SesClient sesClient) {
        return new SimpleEmailServiceMailSender(sesClient);   // SDK v2 variant
    }
}

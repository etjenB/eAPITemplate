package org.etjen.eAPITemplate.config.properties.email;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.time.Duration;

@ConfigurationProperties(prefix = "email.ses")
public record SesProperties (
        String region,
        String accessKey,
        String secretKey,
        String from,
        Duration retryBackoff,
        Integer maxRetries
) { }

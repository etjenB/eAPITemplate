package org.etjen.eAPITemplate.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Data
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {
    private int maxFailedAttempts;
    private long lockDurationMs;
}
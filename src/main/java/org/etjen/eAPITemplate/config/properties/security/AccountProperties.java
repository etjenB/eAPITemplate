package org.etjen.eAPITemplate.config.properties.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "security.account")
public record AccountProperties (
        Integer maxFailedAttempts,
        Duration lockDuration,
        Integer concurrentSessionsLimit
) { }

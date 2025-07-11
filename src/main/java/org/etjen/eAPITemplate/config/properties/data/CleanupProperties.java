package org.etjen.eAPITemplate.config.properties.data;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "data.cleanup")
public record CleanupProperties (
        String refreshTokensCron
) { }

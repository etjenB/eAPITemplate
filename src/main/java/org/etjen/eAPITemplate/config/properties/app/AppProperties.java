package org.etjen.eAPITemplate.config.properties.app;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
public record AppProperties (
        String baseUrl
) { }

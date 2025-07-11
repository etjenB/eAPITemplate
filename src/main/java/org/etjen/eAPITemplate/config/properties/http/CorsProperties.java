package org.etjen.eAPITemplate.config.properties.http;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "http.cors")
public record CorsProperties (
        String allowedOrigins
) { }
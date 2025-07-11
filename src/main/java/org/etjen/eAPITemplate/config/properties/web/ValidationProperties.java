package org.etjen.eAPITemplate.config.properties.web;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.time.Duration;

@ConfigurationProperties(prefix = "web.validation")
public record ValidationProperties (
        Duration emailVerificationCooldown
) { }

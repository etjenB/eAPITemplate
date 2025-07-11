package org.etjen.eAPITemplate.config.properties.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.time.Duration;

@ConfigurationProperties(prefix = "security.email-verification")
public record EmailVerificationProperties (
        Duration emailTokenTtl
) { }
